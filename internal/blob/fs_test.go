// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package blob

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testID = "AAAABBBBCCCCDDDDEEEEFF" // 22 characters, valid alphabet

func newTestFS(t *testing.T) *FS {
	t.Helper()
	s, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return s
}

func TestPutOpenDelete(t *testing.T) {
	s := newTestFS(t)
	ctx := t.Context()
	content := bytes.Repeat([]byte{0x42}, 1<<16)

	n, err := s.Put(ctx, testID, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if n != int64(len(content)) {
		t.Fatalf("put reported %d bytes, want %d", n, len(content))
	}

	r, err := s.Open(ctx, testID)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = r.Close()
	if !bytes.Equal(got, content) {
		t.Fatal("content changed in storage")
	}

	if err := s.Delete(ctx, testID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Open(ctx, testID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound after delete", err)
	}
}

// Expiry and manual revocation can race. Neither should fail because the other
// won, so deleting an absent blob is not an error.
func TestDeleteIsIdempotent(t *testing.T) {
	s := newTestFS(t)
	for i := range 3 {
		if err := s.Delete(t.Context(), testID); err != nil {
			t.Fatalf("delete %d: %v", i, err)
		}
	}
}

// Identifiers arrive from request paths. A crafted value must never address a
// file outside the storage root.
func TestIdentifiersAreValidatedStrictly(t *testing.T) {
	s := newTestFS(t)
	ctx := t.Context()

	for _, id := range []string{
		"",
		"short",
		strings.Repeat("A", idLength-1),
		strings.Repeat("A", idLength+1),
		"../../../../etc/passwd",
		"..AAAAAAAAAAAAAAAAAAAA",
		"AAAAAAAAAA/AAAAAAAAAAA",
		`AAAAAAAAAA\AAAAAAAAAAA`,
		"AAAAAAAAAA.AAAAAAAAAAA",
		"AAAAAAAAAA%AAAAAAAAAAA",
		"AAAAAAAAAA AAAAAAAAAAA",
		"AAAAAAAAAA\x00AAAAAAAAAA",
		"AAAAAAAAAA+AAAAAAAAAAA", // standard base64, not base64url
		"AAAAAAAAAA=AAAAAAAAAAA",
	} {
		t.Run(strings.ReplaceAll(id, "/", "_"), func(t *testing.T) {
			if _, err := s.Put(ctx, id, strings.NewReader("x")); !errors.Is(err, ErrInvalidID) {
				t.Errorf("put: got %v, want ErrInvalidID", err)
			}
			if _, err := s.Open(ctx, id); !errors.Is(err, ErrInvalidID) {
				t.Errorf("open: got %v, want ErrInvalidID", err)
			}
			if err := s.Delete(ctx, id); !errors.Is(err, ErrInvalidID) {
				t.Errorf("delete: got %v, want ErrInvalidID", err)
			}
		})
	}
}

// Nothing a rejected identifier names may be created or removed.
func TestRejectedIdentifiersTouchNothing(t *testing.T) {
	root := t.TempDir()
	s, err := NewFS(root)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	outside := filepath.Join(filepath.Dir(root), "outside.txt")
	if err := os.WriteFile(outside, []byte("untouched"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, _ = s.Put(t.Context(), "../outside.txt", strings.NewReader("overwritten"))
	_ = s.Delete(t.Context(), "../outside.txt")

	got, err := os.ReadFile(outside) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatalf("the file outside the root was removed: %v", err)
	}
	if string(got) != "untouched" {
		t.Fatal("a file outside the storage root was overwritten")
	}
}

// A reader must never observe a partial blob, and a failed write must leave
// nothing behind for the reaper to find.
func TestFailedPutLeavesNothingBehind(t *testing.T) {
	root := t.TempDir()
	s, err := NewFS(root)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	want := errors.New("read failed midway")
	_, err = s.Put(t.Context(), testID, io.MultiReader(
		bytes.NewReader(bytes.Repeat([]byte{1}, 4096)),
		errReader{want},
	))
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want the underlying read error", err)
	}

	if _, err := s.Open(t.Context(), testID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a partial blob is readable: %v", err)
	}
	assertNoFilesUnder(t, root)
}

func TestCancelledPutLeavesNothingBehind(t *testing.T) {
	root := t.TempDir()
	s, err := NewFS(root)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.Put(ctx, testID, bytes.NewReader(bytes.Repeat([]byte{1}, 4096))); err == nil {
		t.Fatal("a cancelled put reported success")
	}
	assertNoFilesUnder(t, root)
}

// An instance that has expired everything must not keep an empty tree
// describing how many uploads it once held.
func TestDeletePrunesEmptyShardDirectories(t *testing.T) {
	root := t.TempDir()
	s, err := NewFS(root)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := s.Put(t.Context(), testID, strings.NewReader("x")); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := s.Delete(t.Context(), testID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("storage root still contains %d entries after deleting the only blob", len(entries))
	}
}

func TestOpenSupportsSeeking(t *testing.T) {
	s := newTestFS(t)
	content := []byte("0123456789abcdef")
	if _, err := s.Put(t.Context(), testID, bytes.NewReader(content)); err != nil {
		t.Fatalf("put: %v", err)
	}

	r, err := s.Open(t.Context(), testID)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = r.Close() }()

	if _, err := r.Seek(10, io.SeekStart); err != nil {
		t.Fatalf("seek: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "abcdef" {
		t.Fatalf("got %q, want %q", got, "abcdef")
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func assertNoFilesUnder(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			t.Errorf("residual file left behind: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
