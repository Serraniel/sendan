// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// CompatUpload is the per-upload state the third-party compatibility protocol
// needs and this project's own does not.
//
// It exists in its own table because of AuthKey: that protocol has the server
// verify a download by computing an HMAC itself, so the server must hold the
// client's key in a usable form. Sendan's own model stores a hash and cannot
// produce a valid authenticator for an upload it did not receive one for.
// Keeping the weaker credential in a separate table makes that difference
// structural rather than something a reviewer has to notice.
type CompatUpload struct {
	ID string

	// AuthKey is the client's HMAC key. The server can authenticate as the
	// downloader with it, which is the property the native model does not have.
	AuthKey []byte

	// Nonce is replaced on every successful authentication, so a captured
	// Authorization header does not work twice.
	Nonce []byte

	// Metadata is the client's own encrypted metadata, in that protocol's
	// format. Opaque here.
	Metadata []byte

	// RequiresPassword is disclosed before any authentication, because the
	// protocol's clients need it to know whether to prompt.
	RequiresPassword bool
}

// CompatStore is implemented by stores that can hold compatibility uploads.
//
// Separate from [Store] for the same reason [Rekeyer] is: nothing on the native
// path needs it, and a core interface that every backend must satisfy should
// not grow a method for a mode that is off by default.
type CompatStore interface {
	// CreateCompat stores an upload and its compatibility state together.
	//
	// In one transaction: an upload row without its compatibility row cannot be
	// authenticated by anybody, and a compatibility row without its upload
	// refers to content that does not exist.
	CreateCompat(ctx context.Context, u *Upload, c *CompatUpload) error

	// Compat returns the compatibility state for an upload, or ErrNotFound.
	Compat(ctx context.Context, id string) (*CompatUpload, error)

	// RotateCompatNonce replaces the stored nonce.
	RotateCompatNonce(ctx context.Context, id string, nonce []byte) error
}

// CreateCompat stores an upload and its compatibility state in one transaction.
func (s *SQLite) CreateCompat(ctx context.Context, u *Upload, c *CompatUpload) error {
	return createCompat(ctx, s.db, identity, u, c)
}

// CreateCompat stores an upload and its compatibility state in one transaction.
func (p *Postgres) CreateCompat(ctx context.Context, u *Upload, c *CompatUpload) error {
	return createCompat(ctx, p.db, rebind, u, c)
}

// Compat returns the compatibility state for an upload.
func (s *SQLite) Compat(ctx context.Context, id string) (*CompatUpload, error) {
	return compatRow(ctx, s.db, identity, id)
}

// Compat returns the compatibility state for an upload.
func (p *Postgres) Compat(ctx context.Context, id string) (*CompatUpload, error) {
	return compatRow(ctx, p.db, rebind, id)
}

// RotateCompatNonce replaces the stored nonce, so one authenticator works once.
func (s *SQLite) RotateCompatNonce(ctx context.Context, id string, nonce []byte) error {
	return rotateCompatNonce(ctx, s.db, identity, id, nonce)
}

// RotateCompatNonce replaces the stored nonce, so one authenticator works once.
func (p *Postgres) RotateCompatNonce(ctx context.Context, id string, nonce []byte) error {
	return rotateCompatNonce(ctx, p.db, rebind, id, nonce)
}

const insertCompat = `INSERT INTO compat_uploads
	(id, auth_key, nonce, metadata, requires_password)
	VALUES (?, ?, ?, ?, ?)`

const selectCompat = `SELECT id, auth_key, nonce, metadata, requires_password
	FROM compat_uploads WHERE id = ?`

// createCompat writes both rows or neither.
func createCompat(
	ctx context.Context,
	db *sql.DB,
	bind func(string) string,
	u *Upload,
	c *CompatUpload,
) error {
	if err := validateCompat(u, c); err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// The upload row itself goes through the same statement the native path
	// uses, so a compatibility upload is subject to every constraint and every
	// lifecycle rule an ordinary one is.
	if err := validateShared(u); err != nil {
		return err
	}
	salt, memory, iterations, parallelism := passwordColumns(u)
	if _, err := tx.ExecContext(ctx, bind(insertUpload),
		u.ID, u.WrappedFileKey, u.WrapNonce, u.MetadataEnvelope, u.MetadataNonce,
		u.AuthTokenHash, u.OwnerTokenHash, u.AtRestKey,
		salt, memory, iterations, parallelism,
		u.Size, u.CreatedAt.Unix(), nullableUnix(u.ExpiresAt),
		u.MaxDownloads, u.DownloadCount, u.BytesServed, nullableUnix(u.CompletedAt),
	); err != nil {
		return fmt.Errorf("store: create: %w", err)
	}

	if _, err := tx.ExecContext(ctx, bind(insertCompat),
		c.ID, c.AuthKey, c.Nonce, c.Metadata, c.RequiresPassword); err != nil {
		return fmt.Errorf("store: create compat: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// validateCompat refuses a pairing that cannot be served.
func validateCompat(u *Upload, c *CompatUpload) error {
	switch {
	case u == nil || c == nil:
		return ErrInvalid
	case u.ID != c.ID:
		return fmt.Errorf("%w: the upload and its compatibility row have different identifiers", ErrInvalid)
	case len(c.AuthKey) == 0:
		return fmt.Errorf("%w: a compatibility upload with no authentication key can never be downloaded", ErrInvalid)
	case len(c.Nonce) == 0:
		return fmt.Errorf("%w: a compatibility upload needs a nonce to authenticate against", ErrInvalid)
	// The envelope columns describe this project's own format, and a
	// compatibility upload has none of them. The schema enforces all-or-none;
	// this says so before the database has to.
	case u.WrappedFileKey != nil || u.WrapNonce != nil ||
		u.MetadataEnvelope != nil || u.MetadataNonce != nil:
		return fmt.Errorf("%w: a compatibility upload carries no envelope in this project's format", ErrInvalid)
	}
	return nil
}

func compatRow(ctx context.Context, db *sql.DB, bind func(string) string, id string) (*CompatUpload, error) {
	var c CompatUpload
	err := db.QueryRowContext(ctx, bind(selectCompat), id).
		Scan(&c.ID, &c.AuthKey, &c.Nonce, &c.Metadata, &c.RequiresPassword)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: read compat: %w", err)
	}
	return &c, nil
}

func rotateCompatNonce(ctx context.Context, db *sql.DB, bind func(string) string, id string, nonce []byte) error {
	if len(nonce) == 0 {
		return fmt.Errorf("%w: an empty nonce would let one authenticator work twice", ErrInvalid)
	}
	res, err := db.ExecContext(ctx, bind(`UPDATE compat_uploads SET nonce = ? WHERE id = ?`), nonce, id)
	if err != nil {
		return fmt.Errorf("store: rotate nonce: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: rotate nonce: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
