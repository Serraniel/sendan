// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"
	"time"
)

//go:embed migrations/*/*.sql
var migrationFS embed.FS

// The statements every backend runs.
//
// They are shared rather than written per backend so the two cannot drift into
// different semantics. Placeholders are written in the ? form and rewritten for
// backends that require another, which is the only dialect difference the
// queries need.
const (
	uploadColumns = `
		id, wrapped_file_key, wrap_nonce, metadata_envelope, metadata_nonce,
		auth_token_hash, owner_token_hash, at_rest_key,
		password_salt, argon2_memory_kib, argon2_iterations, argon2_parallelism,
		size, created_at, expires_at, max_downloads, download_count, bytes_served`

	insertUpload = `INSERT INTO uploads (
		id, wrapped_file_key, wrap_nonce, metadata_envelope, metadata_nonce,
		auth_token_hash, owner_token_hash, at_rest_key,
		password_salt, argon2_memory_kib, argon2_iterations, argon2_parallelism,
		size, created_at, expires_at, max_downloads, download_count, bytes_served
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

	selectUpload = `SELECT` + uploadColumns + ` FROM uploads WHERE id = ?`

	// Accumulation and the derived count are one statement. Reading the total,
	// dividing, then writing back would let concurrent transfers observe the
	// same total and lose each other's bytes.
	//
	// download_count is recomputed rather than incremented, so it is always
	// exactly the number of whole files served. A size of zero cannot occur for
	// a stored upload, but dividing by it would panic the database rather than
	// return an error, so it is guarded.
	recordServed = `UPDATE uploads
	    SET bytes_served = bytes_served + ?,
	        download_count = CASE WHEN size > 0
	                              THEN (bytes_served + ?) / size
	                              ELSE download_count
	                         END
	  WHERE id = ?`

	deleteUpload = `DELETE FROM uploads WHERE id = ?`

	selectDead = `SELECT id FROM uploads
	  WHERE (expires_at IS NOT NULL AND expires_at <= ?)
	     OR (max_downloads > 0 AND download_count >= max_downloads)
	  LIMIT ?`
)

// scannable is satisfied by both *sql.Row and *sql.Rows.
type scannable interface {
	Scan(dest ...any) error
}

// identity leaves a query unchanged, for backends that use ? placeholders.
func identity(query string) string { return query }

// passwordColumns flattens optional password parameters into column values.
func passwordColumns(u *Upload) (salt []byte, memory, iterations, parallelism any) {
	if u.Password == nil {
		return nil, nil, nil, nil
	}
	return u.Password.Salt,
		int64(u.Password.MemoryKiB),
		int64(u.Password.Iterations),
		int64(u.Password.Parallelism)
}

func scanIDs(rows *sql.Rows) ([]string, error) {
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

// migrate applies every embedded migration for a dialect that has not run.
//
// Migrations are applied in filename order and recorded by name, so adding one
// is a matter of dropping in a file. There are deliberately no down migrations:
// reversing a schema change on a store whose purpose is to forget things is not
// an operation worth offering.
func migrate(ctx context.Context, db *sql.DB, dialect string, bind func(string) string) error {
	if _, err := db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			name       TEXT PRIMARY KEY NOT NULL,
			applied_at BIGINT NOT NULL
		)`); err != nil {
		return fmt.Errorf("store: create migration table: %w", err)
	}

	dir := "migrations/" + dialect
	entries, err := migrationFS.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("store: read migrations for %s: %w", dialect, err)
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
		if err := db.QueryRowContext(ctx,
			bind(`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`), name).Scan(&applied); err != nil {
			return fmt.Errorf("store: check migration %s: %w", name, err)
		}
		if applied > 0 {
			continue
		}

		body, err := migrationFS.ReadFile(dir + "/" + name)
		if err != nil {
			return fmt.Errorf("store: read migration %s: %w", name, err)
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("store: begin migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: apply migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx,
			bind(`INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)`),
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
