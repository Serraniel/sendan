// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package store_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Serraniel/sendan/internal/store"
	"github.com/Serraniel/sendan/internal/store/storetest"
)

// Both backends are held to one definition of correct behaviour. A backend that
// merely has tests is a second set of assumptions; a backend that passes this
// suite behaves the same way as the other.

func TestSQLiteConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		s, err := store.OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "sendan.db"))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	})
}

// SENDAN_TEST_POSTGRES is set by continuous integration, which runs a
// PostgreSQL service container. Locally the suite skips unless a developer
// points it at their own database, so a missing PostgreSQL never blocks work on
// unrelated code.
func TestPostgresConformance(t *testing.T) {
	dsn := os.Getenv("SENDAN_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("SENDAN_TEST_POSTGRES is not set; skipping the PostgreSQL conformance suite")
	}

	storetest.Run(t, func(t *testing.T) store.Store {
		s, err := store.OpenPostgres(t.Context(), dsn)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		// Each test gets an empty store, so clear anything a previous one left.
		if err := s.TruncateForTesting(t.Context()); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	})
}
