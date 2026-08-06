// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	// modernc.org/sqlite is a pure Go implementation. A cgo driver such as
	// mattn/go-sqlite3 would be faster, but the release build sets
	// CGO_ENABLED=0 for the static binary, the scratch container image and
	// reproducible builds, all of which cgo would forfeit.
	_ "modernc.org/sqlite"
)

// SQLite is a [Store] backed by a single SQLite database file.
type SQLite struct {
	db *sql.DB
}

var _ Store = (*SQLite)(nil)

// OpenSQLite opens or creates the database at path and applies any pending
// migrations.
//
// Pass ":memory:" for an ephemeral database, which the tests use.
func OpenSQLite(ctx context.Context, path string) (*SQLite, error) {
	dsn := path
	if path != ":memory:" {
		if dir := filepath.Dir(path); dir != "." {
			if err := ensureDir(dir); err != nil {
				return nil, err
			}
		}
		// WAL keeps readers from blocking the writer, which matters because a
		// download holds its transaction only briefly but arrives concurrently.
		// busy_timeout prevents a concurrent writer from failing outright.
		// secure_delete overwrites the content of a deleted row with zeroes
		// rather than merely marking its page free. Without it the row survives
		// verbatim in the database file until the page is reused, and that row
		// holds the blob's at-rest key: an attacker recovering it could decrypt
		// a blob that outlived its unlink. It costs write amplification that
		// this workload will not notice.
		dsn = path + "?_pragma=journal_mode(WAL)" +
			"&_pragma=busy_timeout(5000)" +
			"&_pragma=foreign_keys(1)" +
			"&_pragma=secure_delete(ON)"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// A file-backed SQLite database tolerates one writer. Serialising here is
	// clearer than discovering it as intermittent lock contention.
	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	s := &SQLite{db: db}
	if err := migrate(ctx, db, "sqlite", identity); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Create stores a new upload, returning ErrConflict if the identifier is
// already in use.
func (s *SQLite) Create(ctx context.Context, u *Upload) error {
	if err := validate(u); err != nil {
		return err
	}

	salt, memory, iterations, parallelism := passwordColumns(u)

	_, err := s.db.ExecContext(ctx, insertUpload,
		u.ID, u.WrappedFileKey, u.WrapNonce, u.MetadataEnvelope, u.MetadataNonce,
		u.AuthTokenHash, u.OwnerTokenHash, u.AtRestKey,
		salt, memory, iterations, parallelism,
		u.Size, u.CreatedAt.Unix(), nullableUnix(u.ExpiresAt), u.MaxDownloads, u.DownloadCount, u.BytesServed, nullableUnix(u.CompletedAt),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("%w: %s", ErrConflict, u.ID)
		}
		return fmt.Errorf("store: create: %w", err)
	}
	return nil
}

// Get returns a live upload, or ErrNotFound if it has expired or is
// exhausted at now.
func (s *SQLite) Get(ctx context.Context, id string, now time.Time) (*Upload, error) {
	u, err := scanUpload(s.db.QueryRowContext(ctx, selectUpload, id))
	if err != nil {
		return nil, err
	}
	// Lazy expiry: a dead upload is unreachable even when the reaper is behind.
	// Reporting not-found rather than expired keeps "never existed" and
	// "existed and is gone" indistinguishable to a caller.
	if !u.Live(now) {
		return nil, ErrNotFound
	}
	return u, nil
}

// RecordServed adds n bytes to the served total and returns the upload as it
// stands afterwards.
//
// The accumulation and the recomputed count are a single statement, so
// concurrent transfers cannot lose each other's bytes.
func (s *SQLite) RecordServed(ctx context.Context, id string, n int64) (*Upload, error) {
	if n < 0 {
		return nil, fmt.Errorf("store: record served: negative byte count %d", n)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, recordServed, n, n, id)
	if err != nil {
		return nil, fmt.Errorf("store: record served: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("store: record served: %w", err)
	}
	if affected == 0 {
		// A transfer may still be in flight when the reaper removes what it was
		// reading. Reporting that is more useful than failing.
		return nil, ErrNotFound
	}

	u, err := scanUpload(tx.QueryRowContext(ctx, selectUpload, id))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return u, nil
}

// Delete removes the row outright. There is no soft delete: the row is the only
// copy of the at-rest key, so removing it is what destroys the content.
func (s *SQLite) Delete(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, deleteUpload, id); err != nil {
		return fmt.Errorf("store: delete: %w", err)
	}
	return nil
}

// ListDead returns identifiers of uploads the reaper should remove, at most
// limit of them.
func (s *SQLite) ListDead(ctx context.Context, now, abandoned time.Time, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, selectDead, now.Unix(), abandoned.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("store: list dead: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanIDs(rows)
}

// Checkpoint flushes the write-ahead log into the database file and truncates
// it.
//
// This is part of the deletion guarantee rather than a performance measure.
// Deleting a row removes it from the database file, but the pre-deletion pages
// remain in the write-ahead log until a checkpoint retires them, so an upload's
// metadata — including the at-rest key that makes its blob readable — would
// otherwise survive on disk after the upload was deleted.
func (s *SQLite) Checkpoint(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("store: checkpoint: %w", err)
	}
	return nil
}

// Close releases the database handle.
func (s *SQLite) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("store: close: %w", err)
	}
	return nil
}

func scanUpload(row scannable) (*Upload, error) {
	var (
		u                  Upload
		salt               []byte
		memory, iters, par sql.NullInt64
		createdAt          int64
		expiresAt          sql.NullInt64
		completedAt        sql.NullInt64
	)
	err := row.Scan(
		&u.ID, &u.WrappedFileKey, &u.WrapNonce, &u.MetadataEnvelope, &u.MetadataNonce,
		&u.AuthTokenHash, &u.OwnerTokenHash, &u.AtRestKey,
		&salt, &memory, &iters, &par,
		&u.Size, &createdAt, &expiresAt, &u.MaxDownloads, &u.DownloadCount, &u.BytesServed, &completedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan: %w", err)
	}

	u.CreatedAt = time.Unix(createdAt, 0).UTC()
	if completedAt.Valid {
		u.CompletedAt = time.Unix(completedAt.Int64, 0).UTC()
	}
	if expiresAt.Valid {
		u.ExpiresAt = time.Unix(expiresAt.Int64, 0).UTC()
	}
	if salt != nil {
		u.Password = &PasswordParams{
			Salt:        salt,
			MemoryKiB:   uint32(memory.Int64), //nolint:gosec // constrained on write
			Iterations:  uint32(iters.Int64),  //nolint:gosec // constrained on write
			Parallelism: uint8(par.Int64),     //nolint:gosec // constrained on write
		}
	}
	return &u, nil
}

func nullableUnix(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.Unix()
}

func validate(u *Upload) error {
	switch {
	case u == nil:
		return fmt.Errorf("%w: nil", ErrInvalid)
	case u.ID == "":
		return fmt.Errorf("%w: empty identifier", ErrInvalid)
	case len(u.WrappedFileKey) == 0 || len(u.WrapNonce) == 0:
		return fmt.Errorf("%w: missing wrapped file key", ErrInvalid)
	case len(u.MetadataEnvelope) == 0 || len(u.MetadataNonce) == 0:
		return fmt.Errorf("%w: missing metadata envelope", ErrInvalid)
	case len(u.AuthTokenHash) == 0:
		return fmt.Errorf("%w: missing auth token hash", ErrInvalid)
	case len(u.OwnerTokenHash) == 0:
		return fmt.Errorf("%w: missing owner token hash", ErrInvalid)
	case len(u.AtRestKey) == 0:
		return fmt.Errorf("%w: missing at-rest key", ErrInvalid)
	case u.Size < 0:
		return fmt.Errorf("%w: negative size", ErrInvalid)
	case u.MaxDownloads < 0:
		return fmt.Errorf("%w: negative download limit", ErrInvalid)
	case u.CreatedAt.IsZero():
		return fmt.Errorf("%w: missing creation time", ErrInvalid)
	}
	if u.Password != nil {
		p := u.Password
		if len(p.Salt) == 0 || p.MemoryKiB == 0 || p.Iterations == 0 || p.Parallelism == 0 {
			return fmt.Errorf("%w: incomplete password parameters", ErrInvalid)
		}
	}
	return nil
}

func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store: create directory: %w", err)
	}
	return nil
}

// Complete marks an upload as finished being written, which is what makes it
// reachable. Completing one that is already complete is not an error: a client
// may retry the final request without knowing the first succeeded.
func (s *SQLite) Complete(ctx context.Context, id string, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, completeUpload, now.Unix(), id); err != nil {
		return fmt.Errorf("store: complete: %w", err)
	}
	return nil
}

// Pending returns an upload that is still being written, and only such an
// upload.
func (s *SQLite) Pending(ctx context.Context, id string) (*Upload, error) {
	return scanUpload(s.db.QueryRowContext(ctx, selectPending, id))
}
