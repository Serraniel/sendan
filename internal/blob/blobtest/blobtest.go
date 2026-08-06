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
		"RoundTrip":                           testRoundTrip,
		"EmptyBlob":                           testEmptyBlob,
		"LargeBlob":                           testLargeBlob,
		"MissingBlob":                         testMissingBlob,
		"DeleteIsIdempotent":                  testDeleteIsIdempotent,
		"IdentifiersAreValidated":             testIdentifiersAreValidated,
		"FailedPutStoresNothing":              testFailedPutStoresNothing,
		"CancelledPutStoresNothing":           testCancelledPutStoresNothing,
		"SeekFromStart":                       testSeekFromStart,
		"SeekFromEndAndCurrent":               testSeekFromEndAndCurrent,
		"ChunkedUploadMatchesAWholeOne":       testChunkedUploadMatchesAWholeOne,
		"ChunksMustContinueWhereTheLastEnded": testChunksMustContinueWhereTheLastEnded,
		"PartialUploadIsNotReadable":          testPartialUploadIsNotReadable,
		"ResumingReportsTheStoredLength":      testResumingReportsTheStoredLength,
		"DeleteDiscardsAPartialUpload":        testDeleteDiscardsAPartialUpload,
		"OverwriteReplaces":                   testOverwriteReplaces,
		"FinishRequiresAnUpload":              testFinishRequiresAnUpload,
		"ChunkedWritesValidateIdentifiers":    testChunkedWritesValidateIdentifiers,
		"AFailedChunkKeepsWhatArrived":        testAFailedChunkKeepsWhatArrived,
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

// A chunked upload must produce exactly the bytes a single write would have.
// Anything else means the two paths diverge, and the difference would be
// discovered by a recipient whose file does not decrypt.
func testChunkedUploadMatchesAWholeOne(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := t.Context()

	want := make([]byte, 300*1024)
	for i := range want {
		want[i] = byte(i % 251)
	}

	const chunked = "CHUNKEDAAAAAAAAAAAAAAA"
	const whole = "WHOLEAAAAAAAAAAAAAAAAA"

	// Deliberately uneven chunks, including several that are not a multiple of
	// any block size, so an implementation that assumes alignment fails here.
	// The final chunk is whatever remains, computed rather than written out: an
	// arithmetic slip in a fixture is a failure that says nothing about the code.
	sizes := []int{1, 4095, 65536, 100000}
	sent := 0
	for _, n := range sizes {
		sent += n
	}
	sizes = append(sizes, len(want)-sent)

	var offset int64
	for _, size := range sizes {
		n, err := s.WriteChunk(ctx, chunked, offset, bytes.NewReader(want[offset:offset+int64(size)]))
		if err != nil {
			t.Fatalf("chunk at %d: %v", offset, err)
		}
		if n != int64(size) {
			t.Fatalf("chunk at %d wrote %d bytes, want %d", offset, n, size)
		}
		offset += n
	}
	if offset != int64(len(want)) {
		t.Fatalf("wrote %d bytes in total, want %d", offset, len(want))
	}
	if err := s.Finish(ctx, chunked); err != nil {
		t.Fatalf("finish: %v", err)
	}

	if _, err := s.Put(ctx, whole, bytes.NewReader(want)); err != nil {
		t.Fatalf("put: %v", err)
	}

	for _, id := range []string{chunked, whole} {
		rc, err := s.Open(ctx, id)
		if err != nil {
			t.Fatalf("open %s: %v", id, err)
		}
		got, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: read %d bytes that differ from what was written", id, len(got))
		}
	}
}

// A client reports where it believes it stopped. Writing at a position that
// does not match what is stored would leave a gap or an overlap, which the
// recipient discovers as a file that does not decrypt.
func testChunksMustContinueWhereTheLastEnded(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := t.Context()
	const id = "OFFSETAAAAAAAAAAAAAAAA"

	if _, err := s.WriteChunk(ctx, id, 0, bytes.NewReader([]byte("hello"))); err != nil {
		t.Fatalf("first chunk: %v", err)
	}

	for _, offset := range []int64{0, 3, 6, 100} {
		if _, err := s.WriteChunk(ctx, id, offset, bytes.NewReader([]byte("x"))); !errors.Is(err, blob.ErrOffset) {
			t.Errorf("chunk at %d after 5 bytes: got %v, want ErrOffset", offset, err)
		}
	}
	// The correct offset still works, so the upload is not poisoned by refusals.
	if _, err := s.WriteChunk(ctx, id, 5, bytes.NewReader([]byte(" world"))); err != nil {
		t.Fatalf("resuming at the right offset: %v", err)
	}
}

// A half-written upload must never be readable: what it decrypts to is not what
// the uploader sent, and serving it would hand a recipient a corrupt file.
func testPartialUploadIsNotReadable(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := t.Context()
	const id = "PARTIALAAAAAAAAAAAAAAA"

	if _, err := s.WriteChunk(ctx, id, 0, bytes.NewReader([]byte("half a file"))); err != nil {
		t.Fatalf("chunk: %v", err)
	}
	if _, err := s.Open(ctx, id); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("open before finish: got %v, want ErrNotFound", err)
	}

	if err := s.Finish(ctx, id); err != nil {
		t.Fatalf("finish: %v", err)
	}
	rc, err := s.Open(ctx, id)
	if err != nil {
		t.Fatalf("open after finish: %v", err)
	}
	_ = rc.Close()
}

func testResumingReportsTheStoredLength(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := t.Context()
	const id = "LENGTHAAAAAAAAAAAAAAAA"

	if _, err := s.Length(ctx, id); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("length of an upload that has not begun: got %v, want ErrNotFound", err)
	}

	var total int64
	for _, size := range []int{10, 20, 30} {
		if _, err := s.WriteChunk(ctx, id, total, bytes.NewReader(make([]byte, size))); err != nil {
			t.Fatalf("chunk: %v", err)
		}
		total += int64(size)

		got, err := s.Length(ctx, id)
		if err != nil {
			t.Fatalf("length: %v", err)
		}
		if got != total {
			t.Fatalf("length reports %d, want %d - a client would resume from the wrong place", got, total)
		}
	}
}

// An upload that is never finished is a leftover like any other, and it holds
// the same content a finished one would.
func testDeleteDiscardsAPartialUpload(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := t.Context()
	const id = "ABANDONEDAAAAAAAAAAAAA"

	if _, err := s.WriteChunk(ctx, id, 0, bytes.NewReader([]byte("abandoned"))); err != nil {
		t.Fatalf("chunk: %v", err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Length(ctx, id); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("a partial upload survived deletion: %v", err)
	}
}

// Finishing an upload that never began must fail rather than create an empty
// blob. A client that gets this wrong should be told, not handed a zero-length
// file that its recipient discovers is empty.
func testFinishRequiresAnUpload(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := t.Context()
	const id = "NEVERSTARTEDAAAAAAAAAA"

	if err := s.Finish(ctx, id); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
	if _, err := s.Open(ctx, id); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("finishing nothing created a blob: %v", err)
	}
}

// Identifiers reach the chunked path from request paths too, so the same
// allowlist applies. A separator here would address a spool file outside the
// storage root.
func testChunkedWritesValidateIdentifiers(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := t.Context()

	for _, id := range []string{"", "short", "../../../../etc/passwd", "AAAAAAAAAA/AAAAAAAAAAA"} {
		t.Run(id, func(t *testing.T) {
			if _, err := s.WriteChunk(ctx, id, 0, bytes.NewReader([]byte("x"))); !errors.Is(err, blob.ErrInvalidID) {
				t.Errorf("WriteChunk: got %v, want ErrInvalidID", err)
			}
			if _, err := s.Length(ctx, id); !errors.Is(err, blob.ErrInvalidID) {
				t.Errorf("Length: got %v, want ErrInvalidID", err)
			}
			if err := s.Finish(ctx, id); !errors.Is(err, blob.ErrInvalidID) {
				t.Errorf("Finish: got %v, want ErrInvalidID", err)
			}
		})
	}
}

// failingReader yields n bytes and then fails, standing in for a connection
// that drops mid-chunk.
type failingReader struct {
	data []byte
	n    int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, errors.New("connection reset")
	}
	n := min(min(len(p), r.n), len(r.data))
	copy(p, r.data[:n])
	r.data = r.data[n:]
	r.n -= n
	return n, nil
}

// A chunk that fails part-way keeps the bytes that arrived. Discarding them
// would make every interruption restart the upload, which is what resumability
// exists to avoid - and the client is told the new length so it can continue.
func testAFailedChunkKeepsWhatArrived(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := t.Context()
	const id = "INTERRUPTEDAAAAAAAAAAA"

	body := bytes.Repeat([]byte("x"), 1000)
	if _, err := s.WriteChunk(ctx, id, 0, &failingReader{data: body, n: 400}); err == nil {
		t.Fatal("a reader that failed part-way was reported as a success")
	}

	got, err := s.Length(ctx, id)
	if err != nil {
		t.Fatalf("length after a failed chunk: %v", err)
	}
	if got != 400 {
		t.Fatalf("length is %d after 400 bytes arrived: a client would resume from the wrong place", got)
	}

	// Resuming from the reported length completes the upload.
	if _, err := s.WriteChunk(ctx, id, got, bytes.NewReader(body[got:])); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if err := s.Finish(ctx, id); err != nil {
		t.Fatalf("finish: %v", err)
	}

	rc, err := s.Open(ctx, id)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = rc.Close() }()
	final, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(final, body) {
		t.Errorf("the resumed upload holds %d bytes that differ from what was sent", len(final))
	}
}
