// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package store_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Serraniel/sendan/internal/store"
)

func TestOpenSelectsSQLite(t *testing.T) {
	s, err := store.Open(t.Context(), "sqlite:"+filepath.Join(t.TempDir(), "sendan.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()
	if _, ok := s.(*store.SQLite); !ok {
		t.Fatalf("got %T, want *store.SQLite", s)
	}
}

// An unrecognised location must be a startup error, not a silent fallback to
// the default. Quietly storing data somewhere other than where the operator
// asked is worse than refusing to start.
func TestOpenRejectsUnknownLocations(t *testing.T) {
	for _, location := range []string{
		"",
		"/var/lib/sendan.db",
		"mysql://localhost/sendan",
		"sqlite:",
		"file:data/sendan.db",
		"SQLITE:/tmp/x.db",
	} {
		t.Run(location, func(t *testing.T) {
			s, err := store.Open(t.Context(), location)
			if err == nil {
				_ = s.Close()
				t.Fatal("accepted an unrecognised location")
			}
			// The message must say what is accepted, or an operator is left guessing.
			if !strings.Contains(err.Error(), "sqlite:") || !strings.Contains(err.Error(), "postgres://") {
				if !strings.Contains(err.Error(), "no path") {
					t.Errorf("error does not name the accepted forms: %v", err)
				}
			}
		})
	}
}

func TestOpenFailsOnAnUnreachableDatabase(t *testing.T) {
	// A syntactically valid location pointing nowhere must fail at startup.
	if s, err := store.Open(t.Context(), "sqlite:/proc/nonexistent/sendan.db"); err == nil {
		_ = s.Close()
		t.Fatal("opening an unwritable path reported success")
	}
}
