// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Package blobtest is the conformance suite every [blob.Store] must pass.
//
// It exists for the same reason as the store suite: a backend that merely has
// tests is a second set of assumptions, whereas a backend that passes this
// suite behaves the same way as the first. Only the [blob.Store] interface is
// used, so anything depending on how a backend arranges its storage belongs in
// that backend's own tests.
package blobtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Serraniel/sendan/internal/blob"
)

// Factory returns a store for one test. Identifiers are random, so backends
// that cannot cheaply start empty may share one instance.
type Factory func(t *testing.T) blob.Store

// Run executes the conformance suite.
func Run(t *testing.T, newStore Factory) {
	t.Helper()

	for name, fn := range map[string]func(*testing.T, Factory){
		"RoundTrip":                 testRoundTrip,
		"EmptyBlob":                 testEmptyBlob,
		"LargeBlob":                 testLargeBlob,
		"MissingBlob":               testMissingBlob,
		"DeleteIsIdempotent":        testDeleteIsIdempotent,
		"IdentifiersAreValidated":   testIdentifiersAreValidated,
		"FailedPutStoresNothing":    testFailedPutStoresNothing,
		"CancelledPutStoresNothing": testCancelledPutStoresNothing,
		"SeekFromStart":             testSeekFromStart,
		"SeekFromEndAndCurrent":     testSeekFromEndAndCurrent,
		"OverwriteReplaces":         testOverwriteReplaces,
	} {
		t.Run(name, func(t *testing.T) { fn(t, newStore) })
	}
}

// NewID returns a valid random blob identifier.
func NewID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func read(t *testing.T, s blob.Store, id string) []byte {
	t.Helper()
	r, err := s.Open(t.Context(), id)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = r.Close() }()
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return got
}

func testRoundTrip(t *testing.T, newStore Factory) {
	s := newStore(t)
	id := NewID(t)
	content := bytes.Repeat([]byte{0x42}, 1<<16)

	n, err := s.Put(t.Context(), id, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if n != int64(len(content)) {
		t.Fatalf("put reported %d bytes, want %d", n, len(content))
	}
	if got := read(t, s, id); !bytes.Equal(got, content) {
		t.Fatal("content changed in storage")
	}

	if err := s.Delete(t.Context(), id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Open(t.Context(), id); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("after delete: got %v, want ErrNotFound", err)
	}
}

// An empty upload is legitimate: the content encoding still emits a header and
// a final record, but a backend must not treat zero bytes as absence.
func testEmptyBlob(t *testing.T, newStore Factory) {
	s := newStore(t)
	id := NewID(t)

	if _, err := s.Put(t.Context(), id, bytes.NewReader(nil)); err != nil {
		t.Fatalf("put: %v", err)
	}
	if got := read(t, s, id); len(got) != 0 {
		t.Fatalf("read %d bytes back from an empty blob", len(got))
	}
	if err := s.Delete(t.Context(), id); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func testLargeBlob(t *testing.T, newStore Factory) {
	s := newStore(t)
	id := NewID(t)

	// Larger than one multipart part boundary would be slow here; this is
	// enough to exercise chunked transfer without making the suite tedious.
	const size = 5 << 20
	content := make([]byte, size)
	for i := range content {
		content[i] = byte(i % 251)
	}

	if _, err := s.Put(t.Context(), id, bytes.NewReader(content)); err != nil {
		t.Fatalf("put: %v", err)
	}
	if got := read(t, s, id); !bytes.Equal(got, content) {
		t.Fatal("a large blob changed in storage")
	}
	_ = s.Delete(t.Context(), id)
}

func testMissingBlob(t *testing.T, newStore Factory) {
	s := newStore(t)
	if _, err := s.Open(t.Context(), NewID(t)); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

// Expiry and revocation race, and neither should fail because the other won.
func testDeleteIsIdempotent(t *testing.T, newStore Factory) {
	s := newStore(t)
	id := NewID(t)
	for i := range 3 {
		if err := s.Delete(t.Context(), id); err != nil {
			t.Fatalf("delete %d of an absent blob: %v", i, err)
		}
	}
}

// Identifiers arrive from request paths. Every backend must reject anything
// that is not one, rather than relying on the layer above to have checked.
func testIdentifiersAreValidated(t *testing.T, newStore Factory) {
	s := newStore(t)
	for _, id := range []string{
		"",
		"short",
		strings.Repeat("A", 21),
		strings.Repeat("A", 23),
		"../../../../etc/passwd",
		"AAAAAAAAAA/AAAAAAAAAAA",
		`AAAAAAAAAA\AAAAAAAAAAA`,
		"AAAAAAAAAA.AAAAAAAAAAA",
		"AAAAAAAAAA+AAAAAAAAAAA",
		"AAAAAAAAAA=AAAAAAAAAAA",
		"AAAAAAAAAA AAAAAAAAAAA",
	} {
		name := strings.ReplaceAll(id, "/", "_")
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			if _, err := s.Put(t.Context(), id, strings.NewReader("x")); !errors.Is(err, blob.ErrInvalidID) {
				t.Errorf("put: got %v, want ErrInvalidID", err)
			}
			if _, err := s.Open(t.Context(), id); !errors.Is(err, blob.ErrInvalidID) {
				t.Errorf("open: got %v, want ErrInvalidID", err)
			}
			if err := s.Delete(t.Context(), id); !errors.Is(err, blob.ErrInvalidID) {
				t.Errorf("delete: got %v, want ErrInvalidID", err)
			}
		})
	}
}

// A reader must never observe a partial blob, and a failed write must leave
// nothing for the reaper to find.
func testFailedPutStoresNothing(t *testing.T, newStore Factory) {
	s := newStore(t)
	id := NewID(t)

	want := errors.New("read failed midway")
	_, err := s.Put(t.Context(), id, io.MultiReader(
		bytes.NewReader(bytes.Repeat([]byte{1}, 4096)),
		errReader{want},
	))
	if err == nil {
		t.Fatal("a failing read reported success")
	}
	if _, err := s.Open(t.Context(), id); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("a partial blob is readable: %v", err)
	}
}

func testCancelledPutStoresNothing(t *testing.T, newStore Factory) {
	s := newStore(t)
	id := NewID(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.Put(ctx, id, bytes.NewReader(bytes.Repeat([]byte{1}, 4096))); err == nil {
		t.Fatal("a cancelled put reported success")
	}
	if _, err := s.Open(context.Background(), id); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("a cancelled blob is readable: %v", err)
	}
}

// Range requests depend on seeking, including to offsets that are not aligned
// to anything convenient.
func testSeekFromStart(t *testing.T, newStore Factory) {
	s := newStore(t)
	id := NewID(t)
	content := []byte("0123456789abcdefghijklmnopqrstuvwxyz")

	if _, err := s.Put(t.Context(), id, bytes.NewReader(content)); err != nil {
		t.Fatalf("put: %v", err)
	}
	for _, offset := range []int64{0, 1, 10, 17, int64(len(content)) - 1} {
		r, err := s.Open(t.Context(), id)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if _, err := r.Seek(offset, io.SeekStart); err != nil {
			t.Fatalf("offset %d: seek: %v", offset, err)
		}
		got, err := io.ReadAll(r)
		_ = r.Close()
		if err != nil {
			t.Fatalf("offset %d: read: %v", offset, err)
		}
		if !bytes.Equal(got, content[offset:]) {
			t.Fatalf("offset %d: got %q, want %q", offset, got, content[offset:])
		}
	}
	_ = s.Delete(t.Context(), id)
}

func testSeekFromEndAndCurrent(t *testing.T, newStore Factory) {
	s := newStore(t)
	id := NewID(t)
	content := []byte("0123456789abcdefghijklmnopqrstuvwxyz")

	if _, err := s.Put(t.Context(), id, bytes.NewReader(content)); err != nil {
		t.Fatalf("put: %v", err)
	}
	r, err := s.Open(t.Context(), id)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = r.Close() }()

	if _, err := r.Seek(-6, io.SeekEnd); err != nil {
		t.Fatalf("seek from end: %v", err)
	}
	got := make([]byte, 6)
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "uvwxyz" {
		t.Fatalf("seek from end: got %q, want %q", got, "uvwxyz")
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("rewind: %v", err)
	}
	if _, err := r.Seek(10, io.SeekCurrent); err != nil {
		t.Fatalf("relative seek: %v", err)
	}
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "abcdef" {
		t.Fatalf("relative seek: got %q, want %q", got, "abcdef")
	}
	_ = s.Delete(t.Context(), id)
}

// Identifiers are random so this should not arise in practice, but a backend
// must not append or interleave if it does.
func testOverwriteReplaces(t *testing.T, newStore Factory) {
	s := newStore(t)
	id := NewID(t)

	if _, err := s.Put(t.Context(), id, strings.NewReader("first version, longer")); err != nil {
		t.Fatalf("first put: %v", err)
	}
	if _, err := s.Put(t.Context(), id, strings.NewReader("second")); err != nil {
		t.Fatalf("second put: %v", err)
	}
	if got := read(t, s, id); string(got) != "second" {
		t.Fatalf("got %q, want %q", got, "second")
	}
	_ = s.Delete(t.Context(), id)
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }
