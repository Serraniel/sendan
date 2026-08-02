// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	// pgx's database/sql driver is pure Go, matching the CGO_ENABLED=0
	// constraint that also chose modernc.org/sqlite.
	_ "github.com/jackc/pgx/v5/stdlib"
)

// uniqueViolation is PostgreSQL's SQLSTATE for a duplicate key.
const uniqueViolation = "23505"

// Postgres is a [Store] backed by PostgreSQL.
//
// # Deletion is weaker here than on SQLite
//
// SQLite is configured with secure_delete, which zeroes a deleted row's content
// rather than merely marking its page free. PostgreSQL has no equivalent: a
// deleted row remains as a dead tuple until vacuumed, and even then the pages
// are marked reusable rather than overwritten.
//
// Checkpoint therefore runs VACUUM, which is the strongest reclamation
// available without an exclusive lock, but it cannot promise that the bytes are
// gone from the disk. An operator who needs the stronger guarantee should use
// SQLite, or use issue #73's master key so that a recovered at-rest key is
// useless without a secret held outside the database.
//
// This is documented rather than hidden because the difference is real.
type Postgres struct {
	db *sql.DB
}

var _ Store = (*Postgres)(nil)

// OpenPostgres connects to PostgreSQL and applies any pending migrations.
func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	p := &Postgres{db: db}
	if err := migrate(ctx, db, "postgres", rebind); err != nil {
		_ = db.Close()
		return nil, err
	}
	return p, nil
}

// rebind converts the ? placeholders used throughout this package into the
// numbered form PostgreSQL requires, so one set of statements serves both
// backends and the two cannot drift apart.
func rebind(query string) string {
	var out []byte
	n := 0
	for i := range len(query) {
		if query[i] != '?' {
			out = append(out, query[i])
			continue
		}
		n++
		out = append(out, '$')
		out = append(out, []byte(fmt.Sprintf("%d", n))...)
	}
	return string(out)
}

// Create stores a new upload, returning ErrConflict if the identifier is
// already in use.
func (p *Postgres) Create(ctx context.Context, u *Upload) error {
	if err := validate(u); err != nil {
		return err
	}
	salt, memory, iterations, parallelism := passwordColumns(u)

	_, err := p.db.ExecContext(ctx, rebind(insertUpload),
		u.ID, u.WrappedFileKey, u.WrapNonce, u.MetadataEnvelope, u.MetadataNonce,
		u.AuthTokenHash, u.OwnerTokenHash, u.AtRestKey,
		salt, memory, iterations, parallelism,
		u.Size, u.CreatedAt.Unix(), nullableUnix(u.ExpiresAt), u.MaxDownloads, u.DownloadCount,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return fmt.Errorf("%w: %s", ErrConflict, u.ID)
		}
		return fmt.Errorf("store: create: %w", err)
	}
	return nil
}

// Get returns a live upload, or ErrNotFound if it has expired or is exhausted
// at now.
func (p *Postgres) Get(ctx context.Context, id string, now time.Time) (*Upload, error) {
	u, err := scanUpload(p.db.QueryRowContext(ctx, rebind(selectUpload), id))
	if err != nil {
		return nil, err
	}
	if !u.Live(now) {
		return nil, ErrNotFound
	}
	return u, nil
}

// ClaimDownload reserves one download and returns the upload.
//
// As with SQLite the reservation and the limit check are one statement, so
// concurrent requests cannot collectively exceed the limit.
func (p *Postgres) ClaimDownload(ctx context.Context, id string, now time.Time) (*Upload, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, rebind(claimDownload), id, now.Unix())
	if err != nil {
		return nil, fmt.Errorf("store: claim: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("store: claim: %w", err)
	}

	if affected == 0 {
		u, err := scanUpload(tx.QueryRowContext(ctx, rebind(selectUpload), id))
		if err != nil {
			return nil, err
		}
		if u.Exhausted() {
			return nil, ErrExhausted
		}
		return nil, ErrNotFound
	}

	u, err := scanUpload(tx.QueryRowContext(ctx, rebind(selectUpload), id))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return u, nil
}

// Delete removes the row outright.
func (p *Postgres) Delete(ctx context.Context, id string) error {
	if _, err := p.db.ExecContext(ctx, rebind(deleteUpload), id); err != nil {
		return fmt.Errorf("store: delete: %w", err)
	}
	return nil
}

// ListDead returns identifiers of uploads the reaper should remove.
func (p *Postgres) ListDead(ctx context.Context, now time.Time, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := p.db.QueryContext(ctx, rebind(selectDead), now.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("store: list dead: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanIDs(rows)
}

// Checkpoint vacuums the uploads table.
//
// This reclaims the space of deleted rows, but see the note on [Postgres]: it
// cannot promise the bytes are gone from disk the way SQLite's secure_delete
// does. VACUUM is used rather than VACUUM FULL because the latter takes an
// exclusive lock and would stall every download while it runs.
func (p *Postgres) Checkpoint(ctx context.Context) error {
	if _, err := p.db.ExecContext(ctx, `VACUUM uploads`); err != nil {
		return fmt.Errorf("store: vacuum: %w", err)
	}
	return nil
}

// Close releases the connection pool.
func (p *Postgres) Close() error {
	if err := p.db.Close(); err != nil {
		return fmt.Errorf("store: close: %w", err)
	}
	return nil
}

// TruncateForTesting removes every upload.
//
// It exists so the conformance suite can hand each test an empty store, since a
// PostgreSQL instance is shared across tests where a SQLite file is not. It is
// never called by the server.
func (p *Postgres) TruncateForTesting(ctx context.Context) error {
	if _, err := p.db.ExecContext(ctx, `TRUNCATE TABLE uploads`); err != nil {
		return fmt.Errorf("store: truncate: %w", err)
	}
	return nil
}
