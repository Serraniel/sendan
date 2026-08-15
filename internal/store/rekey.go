// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Rekeyer is implemented by stores that can rewrite every stored at-rest key.
//
// Separate from [Store] because nothing serving requests needs it: it exists
// for the rotation command, and widening the interface every backend must
// satisfy for the sake of one offline operation would make the contract harder
// to read for no gain.
type Rekeyer interface {
	// Rekey passes every stored at-rest key through fn and writes back what it
	// returns. It reports how many rows changed.
	//
	// Rows fn leaves untouched are not written, so running a rotation twice
	// with the same keys is a no-op rather than a second layer of wrapping.
	Rekey(ctx context.Context, fn func(stored []byte) ([]byte, error)) (int, error)
}

// Rewrap builds the transformation a rotation applies.
//
// Either key may be nil: no old key means the stored keys are unwrapped and
// wrapping is being turned on, and no new key means it is being turned off.
// Both nil is refused, because it would rewrite every row to what it already
// says.
func Rewrap(oldKey, newKey []byte) (func([]byte) ([]byte, error), error) {
	if len(oldKey) == 0 && len(newKey) == 0 {
		return nil, errors.New("store: neither an old nor a new master key was given")
	}

	var from, to *wrapping
	if len(oldKey) > 0 {
		w, err := WithMasterKey(nil, oldKey)
		if err != nil {
			return nil, err
		}
		from = w.(*wrapping)
	}
	if len(newKey) > 0 {
		w, err := WithMasterKey(nil, newKey)
		if err != nil {
			return nil, err
		}
		to = w.(*wrapping)
	}

	return func(stored []byte) ([]byte, error) {
		key := stored
		if from != nil {
			var err error
			if key, err = from.unwrap(stored); err != nil {
				return nil, err
			}
		} else if len(stored) != MasterKeySize {
			// Wrapped rows with no old key to open them. Continuing would wrap
			// a wrapped key and leave the row unopenable by anything.
			return nil, ErrWrongMasterKey
		}

		if to == nil {
			return key, nil
		}
		return to.wrap(key)
	}, nil
}

// Rekey rewrites every at-rest key in one transaction.
//
// One transaction because a rotation that stopped halfway would leave a
// database where some rows need the old key and some the new, and no single
// configuration could read it.
func (s *SQLite) Rekey(ctx context.Context, fn func([]byte) ([]byte, error)) (int, error) {
	return rekey(ctx, s.db, identity, fn)
}

// Rekey rewrites every at-rest key in one transaction.
func (p *Postgres) Rekey(ctx context.Context, fn func([]byte) ([]byte, error)) (int, error) {
	return rekey(ctx, p.db, rebind, fn)
}

func rekey(ctx context.Context, db *sql.DB, bind func(string) string, fn func([]byte) ([]byte, error)) (int, error) {
	type row struct {
		id  string
		key []byte
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin rotation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Read entirely before writing. Rewriting while iterating is undefined in
	// SQLite, and an at-rest key is 61 bytes: a million uploads is sixty
	// megabytes, which is a rotation that fits in memory on anything that could
	// hold a million uploads.
	var pending []row
	rows, err := tx.QueryContext(ctx, bind(`SELECT id, at_rest_key FROM uploads`))
	if err != nil {
		return 0, fmt.Errorf("store: read at-rest keys: %w", err)
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.key); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("store: read at-rest key: %w", err)
		}
		pending = append(pending, r)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("store: read at-rest keys: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("store: read at-rest keys: %w", err)
	}

	changed := 0
	for i, r := range pending {
		next, err := fn(r.key)
		if err != nil {
			// By position, not by identifier. A rotation that failed on one row
			// has almost certainly failed on all of them, and naming uploads in
			// operator output is the habit this project does not have.
			return 0, fmt.Errorf("store: upload %d of %d: %w", i+1, len(pending), err)
		}
		if string(next) == string(r.key) {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			bind(`UPDATE uploads SET at_rest_key = ? WHERE id = ?`), next, r.id); err != nil {
			return 0, fmt.Errorf("store: write at-rest key: %w", err)
		}
		changed++
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit rotation: %w", err)
	}
	return changed, nil
}
