// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	// modernc.org/sqlite is a pure Go implementation. A cgo driver such as
	// mattn/go-sqlite3 would be faster, but the release build sets
	// CGO_ENABLED=0 for the static binary, the scratch container image and
	// reproducible builds, all of which cgo would forfeit.
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

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
		dsn = path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
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
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// migrate applies every embedded migration that has not already run.
//
// Migrations are applied in filename order and recorded by name, so adding one
// is a matter of dropping a file in. There is deliberately no down migration:
// reversing a schema change on a store whose whole purpose is to forget things
// is not a operation worth offering.
func (s *SQLite) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			name       TEXT PRIMARY KEY NOT NULL,
			applied_at INTEGER NOT NULL
		)`); err != nil {
		return fmt.Errorf("store: create migration table: %w", err)
	}

	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("store: read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var applied int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, name).Scan(&applied); err != nil {
			return fmt.Errorf("store: check migration %s: %w", name, err)
		}
		if applied > 0 {
			continue
		}

		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("store: read migration %s: %w", name, err)
		}

		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("store: begin migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: apply migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)`,
			name, time.Now().Unix()); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: record migration %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit migration %s: %w", name, err)
		}
	}
	return nil
}

// Create stores a new upload, returning ErrConflict if the identifier is
// already in use.
func (s *SQLite) Create(ctx context.Context, u *Upload) error {
	if err := validate(u); err != nil {
		return err
	}

	var salt []byte
	var memory, iterations, parallelism any
	if u.Password != nil {
		salt = u.Password.Salt
		memory = int64(u.Password.MemoryKiB)
		iterations = int64(u.Password.Iterations)
		parallelism = int64(u.Password.Parallelism)
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO uploads (
			id, wrapped_file_key, wrap_nonce, metadata_envelope, metadata_nonce,
			auth_token_hash, owner_token_hash, at_rest_key,
			password_salt, argon2_memory_kib, argon2_iterations, argon2_parallelism,
			size, created_at, expires_at, max_downloads, download_count
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		u.ID, u.WrappedFileKey, u.WrapNonce, u.MetadataEnvelope, u.MetadataNonce,
		u.AuthTokenHash, u.OwnerTokenHash, u.AtRestKey,
		salt, memory, iterations, parallelism,
		u.Size, u.CreatedAt.Unix(), nullableUnix(u.ExpiresAt), u.MaxDownloads, u.DownloadCount,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("%w: %s", ErrConflict, u.ID)
		}
		return fmt.Errorf("store: create: %w", err)
	}
	return nil
}

const selectColumns = `
	id, wrapped_file_key, wrap_nonce, metadata_envelope, metadata_nonce,
	auth_token_hash, owner_token_hash, at_rest_key,
	password_salt, argon2_memory_kib, argon2_iterations, argon2_parallelism,
	size, created_at, expires_at, max_downloads, download_count`

// Get returns a live upload, or ErrNotFound if it has expired or is
// exhausted at now.
func (s *SQLite) Get(ctx context.Context, id string, now time.Time) (*Upload, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT`+selectColumns+` FROM uploads WHERE id = ?`, id)

	u, err := scanUpload(row)
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

// ClaimDownload reserves one download and returns the upload.
//
// The reservation and the limit check are a single statement. Reading the
// count, deciding, then incrementing would let concurrent requests all observe
// the same count and collectively exceed the limit.
func (s *SQLite) ClaimDownload(ctx context.Context, id string, now time.Time) (*Upload, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`UPDATE uploads
		    SET download_count = download_count + 1
		  WHERE id = ?
		    AND (expires_at IS NULL OR expires_at > ?)
		    AND (max_downloads = 0 OR download_count < max_downloads)`,
		id, now.Unix())
	if err != nil {
		return nil, fmt.Errorf("store: claim: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("store: claim: %w", err)
	}

	if affected == 0 {
		// Distinguish "no such upload" from "limit reached" only for the
		// caller's logging; both are reported to a client as not found.
		u, err := scanUpload(tx.QueryRowContext(ctx,
			`SELECT`+selectColumns+` FROM uploads WHERE id = ?`, id))
		if err != nil {
			return nil, err
		}
		if u.Exhausted() {
			return nil, ErrExhausted
		}
		return nil, ErrNotFound
	}

	u, err := scanUpload(tx.QueryRowContext(ctx,
		`SELECT`+selectColumns+` FROM uploads WHERE id = ?`, id))
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
	if _, err := s.db.ExecContext(ctx, `DELETE FROM uploads WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: delete: %w", err)
	}
	return nil
}

// ListDead returns identifiers of uploads the reaper should remove, at most
// limit of them.
func (s *SQLite) ListDead(ctx context.Context, now time.Time, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id FROM uploads
		  WHERE (expires_at IS NOT NULL AND expires_at <= ?)
		     OR (max_downloads > 0 AND download_count >= max_downloads)
		  LIMIT ?`, now.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("store: list dead: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: scan: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate: %w", err)
	}
	return ids, nil
}

// Close releases the database handle.
func (s *SQLite) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("store: close: %w", err)
	}
	return nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanUpload(row scannable) (*Upload, error) {
	var (
		u                  Upload
		salt               []byte
		memory, iters, par sql.NullInt64
		createdAt          int64
		expiresAt          sql.NullInt64
	)
	err := row.Scan(
		&u.ID, &u.WrappedFileKey, &u.WrapNonce, &u.MetadataEnvelope, &u.MetadataNonce,
		&u.AuthTokenHash, &u.OwnerTokenHash, &u.AtRestKey,
		&salt, &memory, &iters, &par,
		&u.Size, &createdAt, &expiresAt, &u.MaxDownloads, &u.DownloadCount,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan: %w", err)
	}

	u.CreatedAt = time.Unix(createdAt, 0).UTC()
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
