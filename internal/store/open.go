// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package store

import (
	"context"
	"fmt"
	"strings"
)

// Open returns the metadata store described by a location.
//
// Accepted forms:
//
//	sqlite:<path>        a SQLite database file, created if absent
//	postgres://<dsn>     a PostgreSQL connection string
//	postgresql://<dsn>   the same
//
// An unrecognised form is an error rather than a fallback to the default. A
// server that quietly stores data somewhere other than where the operator asked
// is worse than one that refuses to start.
func Open(ctx context.Context, location string) (Store, error) {
	switch {
	case strings.HasPrefix(location, "sqlite:"):
		path := strings.TrimPrefix(location, "sqlite:")
		if path == "" {
			return nil, fmt.Errorf("store: sqlite location has no path: %q", location)
		}
		return OpenSQLite(ctx, path)

	case strings.HasPrefix(location, "postgres://"), strings.HasPrefix(location, "postgresql://"):
		return OpenPostgres(ctx, location)

	default:
		return nil, fmt.Errorf(
			"store: unrecognised database location %q: expected sqlite:<path> or postgres://<dsn>", location)
	}
}
