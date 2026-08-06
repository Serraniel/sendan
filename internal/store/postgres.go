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
// SQLite is configured with secure_delete, which zeroes a deleted row's content,
// and its write-ahead log is truncated after reaping. PostgreSQL offers neither
// control directly.
//
// Measured behaviour, verified against PostgreSQL 17:
//
//   - After DELETE the row remains in the heap file as a dead tuple.
//   - After VACUUM it is gone from the heap. Checkpoint therefore runs VACUUM,
//     which is why it is part of the deletion path rather than a maintenance
//     nicety.
//   - The row remains in the write-ahead log until that segment is recycled,
//     and PostgreSQL offers no equivalent of truncating it on demand. This is
//     the residual exposure.
//
// What a recovered row yields is the at-rest key, and therefore the ability to
// decrypt a blob that also survived its own deletion. That is the end-to-end
// ciphertext, not the content: reading it still requires the link secret, which
// never reaches this process.
//
// An operator who wants the stronger guarantee should use SQLite, encrypt the
// database volume, or use issue #73's master key so that a recovered at-rest key
// is useless without a secret held outside the database.
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
		u.Size, u.CreatedAt.Unix(), nullableUnix(u.ExpiresAt), u.MaxDownloads, u.DownloadCount, u.BytesServed, nullableUnix(u.CompletedAt),
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

// RecordServed adds n bytes to the served total and returns the upload as it
// stands afterwards.
//
// As with SQLite the accumulation and the recomputed count are one statement,
// so concurrent transfers cannot lose each other's bytes.
func (p *Postgres) RecordServed(ctx context.Context, id string, n int64) (*Upload, error) {
	if n < 0 {
		return nil, fmt.Errorf("store: record served: negative byte count %d", n)
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, rebind(recordServed), n, n, id)
	if err != nil {
		return nil, fmt.Errorf("store: record served: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("store: record served: %w", err)
	}
	if affected == 0 {
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
func (p *Postgres) ListDead(ctx context.Context, now, abandoned time.Time, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := p.db.QueryContext(ctx, rebind(selectDead), now.Unix(), abandoned.Unix(), limit)
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

// Complete marks an upload as finished being written, which is what makes it
// reachable. Completing one that is already complete is not an error: a client
// may retry the final request without knowing the first succeeded.
func (p *Postgres) Complete(ctx context.Context, id string, now time.Time) error {
	if _, err := p.db.ExecContext(ctx, rebind(completeUpload), now.Unix(), id); err != nil {
		return fmt.Errorf("store: complete: %w", err)
	}
	return nil
}

// Pending returns an upload that is still being written, and only such an
// upload.
func (p *Postgres) Pending(ctx context.Context, id string) (*Upload, error) {
	return scanUpload(p.db.QueryRowContext(ctx, rebind(selectPending), id))
}
