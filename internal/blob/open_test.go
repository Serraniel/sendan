// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package blob_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Serraniel/sendan/internal/blob"
)

func TestOpenSelectsFilesystem(t *testing.T) {
	s, err := blob.Open(t.Context(), "file:"+filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, ok := s.(*blob.FS); !ok {
		t.Fatalf("got %T, want *blob.FS", s)
	}
}

func TestOpenRejectsUnknownLocations(t *testing.T) {
	for _, location := range []string{
		"",
		"/var/lib/blobs",
		"gcs://bucket",
		"file:",
		"s3://",
		"FILE:/tmp/blobs",
	} {
		t.Run(location, func(t *testing.T) {
			if _, err := blob.Open(t.Context(), location); err == nil {
				t.Fatal("accepted an unrecognised location")
			}
		})
	}
}

func TestOpenNamesTheAcceptedForms(t *testing.T) {
	_, err := blob.Open(t.Context(), "gcs://bucket")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "file:") || !strings.Contains(err.Error(), "s3://") {
		t.Fatalf("error does not name the accepted forms: %v", err)
	}
}
