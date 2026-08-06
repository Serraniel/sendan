// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package blob

import (
	"bytes"
	"crypto/aes"
	"errors"
	"io"
	fs2 "io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

func newShredder(t *testing.T) (*Shredder, *FS) {
	t.Helper()
	inner := newTestFS(t)
	return NewShredder(inner), inner
}

func testKey() []byte { return bytes.Repeat([]byte{0x5A}, AtRestKeySize) }

func filledContent(n int) []byte {
	b := make([]byte, n)
	r := rand.New(rand.NewSource(int64(n))) //nolint:gosec // deterministic test data
	_, _ = r.Read(b)
	return b
}

func TestShredderRoundTrip(t *testing.T) {
	s, _ := newShredder(t)
	for _, size := range []int{0, 1, 15, 16, 17, 4096, 1 << 17} {
		content := filledContent(size)
		if _, err := s.Put(t.Context(), testID, testKey(), bytes.NewReader(content)); err != nil {
			t.Fatalf("size %d: put: %v", size, err)
		}
		r, err := s.Open(t.Context(), testID, testKey())
		if err != nil {
			t.Fatalf("size %d: open: %v", size, err)
		}
		got, err := io.ReadAll(r)
		_ = r.Close()
		if err != nil {
			t.Fatalf("size %d: read: %v", size, err)
		}
		if !bytes.Equal(got, content) {
			t.Fatalf("size %d: round trip changed the content", size)
		}
		_ = s.Delete(t.Context(), testID)
	}
}

// The whole point: what reaches the disk must not be the plaintext handed in.
func TestStoredBytesAreNotThePlaintext(t *testing.T) {
	s, inner := newShredder(t)
	content := bytes.Repeat([]byte("SENSITIVE"), 512)

	if _, err := s.Put(t.Context(), testID, testKey(), bytes.NewReader(content)); err != nil {
		t.Fatalf("put: %v", err)
	}

	raw, err := inner.Open(t.Context(), testID)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	stored, err := io.ReadAll(raw)
	_ = raw.Close()
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}

	if bytes.Equal(stored, content) {
		t.Fatal("the blob was stored unencrypted")
	}
	if bytes.Contains(stored, []byte("SENSITIVE")) {
		t.Fatal("plaintext is recognisable in the stored blob")
	}
	if len(stored) != len(content) {
		t.Fatalf("stored %d bytes for %d of plaintext: the stream cipher must not change length",
			len(stored), len(content))
	}
}

// Deleting the database row is what destroys the data. Without the key, a
// surviving blob must be unrecoverable.
func TestWrongKeyDoesNotRecoverContent(t *testing.T) {
	s, _ := newShredder(t)
	content := bytes.Repeat([]byte("SENSITIVE"), 128)
	if _, err := s.Put(t.Context(), testID, testKey(), bytes.NewReader(content)); err != nil {
		t.Fatalf("put: %v", err)
	}

	other := bytes.Repeat([]byte{0x5B}, AtRestKeySize)
	r, err := s.Open(t.Context(), testID, other)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	// CTR is unauthenticated by design, so this yields garbage rather than an
	// error. What matters is that the garbage is not the content.
	if bytes.Equal(got, content) {
		t.Fatal("a different key recovered the content")
	}
	if bytes.Contains(got, []byte("SENSITIVE")) {
		t.Fatal("plaintext is recognisable when decrypted with the wrong key")
	}
}

// Two uploads of identical content must not produce identical blobs, or an
// operator could identify duplicates on disk.
func TestDistinctKeysProduceDistinctCiphertext(t *testing.T) {
	s, inner := newShredder(t)
	content := bytes.Repeat([]byte{0x11}, 4096)

	read := func(id string, key []byte) []byte {
		if _, err := s.Put(t.Context(), id, key, bytes.NewReader(content)); err != nil {
			t.Fatalf("put: %v", err)
		}
		raw, err := inner.Open(t.Context(), id)
		if err != nil {
			t.Fatalf("open raw: %v", err)
		}
		b, err := io.ReadAll(raw)
		_ = raw.Close()
		if err != nil {
			t.Fatalf("read raw: %v", err)
		}
		return b
	}

	a := read(testID, testKey())
	b := read("ZZZZYYYYXXXXWWWWVVVVUU", bytes.Repeat([]byte{0x77}, AtRestKeySize))
	if bytes.Equal(a, b) {
		t.Fatal("identical content under different keys produced identical ciphertext")
	}
}

// Range requests depend on this. Seeking must land on the correct plaintext,
// including offsets that are not block aligned, which is where a counter
// arithmetic error would show.
func TestSeekingDecryptsCorrectlyAtEveryOffset(t *testing.T) {
	s, _ := newShredder(t)
	const size = 4096
	content := filledContent(size)
	if _, err := s.Put(t.Context(), testID, testKey(), bytes.NewReader(content)); err != nil {
		t.Fatalf("put: %v", err)
	}

	offsets := []int64{
		0, 1, 15, aes.BlockSize, aes.BlockSize + 1, 17, 100, 255, 256, 1000,
		size - aes.BlockSize, size - 1,
	}
	for _, offset := range offsets {
		r, err := s.Open(t.Context(), testID, testKey())
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
			t.Fatalf("offset %d: decrypted the wrong plaintext", offset)
		}
	}
}

func TestSeekRelativeAndFromEnd(t *testing.T) {
	s, _ := newShredder(t)
	content := filledContent(1024)
	if _, err := s.Put(t.Context(), testID, testKey(), bytes.NewReader(content)); err != nil {
		t.Fatalf("put: %v", err)
	}

	r, err := s.Open(t.Context(), testID, testKey())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = r.Close() }()

	if _, err := r.Seek(-100, io.SeekEnd); err != nil {
		t.Fatalf("seek from end: %v", err)
	}
	got := make([]byte, 100)
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, content[924:]) {
		t.Fatal("seek from end decrypted the wrong plaintext")
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("rewind: %v", err)
	}
	if _, err := r.Seek(500, io.SeekCurrent); err != nil {
		t.Fatalf("relative seek: %v", err)
	}
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, content[500:600]) {
		t.Fatal("relative seek decrypted the wrong plaintext")
	}
}

func TestAtRestKeysAreRandomAndSized(t *testing.T) {
	a, err := NewAtRestKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, err := NewAtRestKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(a) != AtRestKeySize {
		t.Fatalf("key is %d bytes, want %d", len(a), AtRestKeySize)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two generated keys are identical")
	}
}

func TestMalformedKeysAreRejected(t *testing.T) {
	s, _ := newShredder(t)
	for _, key := range [][]byte{nil, make([]byte, AtRestKeySize-1), make([]byte, AtRestKeySize+1)} {
		if _, err := s.Put(t.Context(), testID, key, bytes.NewReader(nil)); !errors.Is(err, ErrAtRestKey) {
			t.Errorf("put with %d-byte key: got %v, want ErrAtRestKey", len(key), err)
		}
		if _, err := s.Open(t.Context(), testID, key); !errors.Is(err, ErrAtRestKey) {
			t.Errorf("open with %d-byte key: got %v, want ErrAtRestKey", len(key), err)
		}
	}
}

// The counter arithmetic must carry correctly across byte boundaries, which is
// where an off-by-one silently repeats a keystream.
func TestCounterIncrementCarries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		start []byte
		add   int64
		want  []byte
	}{
		{"zero", make([]byte, 16), 0, make([]byte, 16)},
		{
			"one",
			make([]byte, 16),
			1,
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			"carry across one byte",
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF},
			1,
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
		},
		{
			"carry across two bytes",
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF},
			1,
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0},
		},
		{
			"large addend",
			make([]byte, 16),
			0x0102030405,
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := bytes.Clone(tc.start)
			incrementCounter(got, uint64(tc.add))
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("got %x, want %x", got, tc.want)
			}
		})
	}
}

// A blob written in one pass and read back at an arbitrary offset must agree,
// which is the property that fails if Put and Open derive different keystreams.
func FuzzShredderSeekRoundTrip(f *testing.F) {
	f.Add(100, 0)
	f.Add(4096, 4095)

	f.Fuzz(func(t *testing.T, size, offset int) {
		if size < 0 || size > 1<<16 || offset < 0 {
			t.Skip()
		}
		s, _ := newShredder(t)
		content := filledContent(size)
		if _, err := s.Put(t.Context(), testID, testKey(), bytes.NewReader(content)); err != nil {
			t.Fatalf("put: %v", err)
		}
		if size == 0 {
			return
		}
		at := int64(offset % size)

		r, err := s.Open(t.Context(), testID, testKey())
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer func() { _ = r.Close() }()
		if _, err := r.Seek(at, io.SeekStart); err != nil {
			t.Fatalf("seek: %v", err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(got, content[at:]) {
			t.Fatalf("size %d offset %d: decrypted the wrong plaintext", size, at)
		}
	})
}

// A chunked upload must decrypt to exactly what a single write would produce.
// The keystream is positioned at each chunk's offset, so an error in that
// positioning shows up as content that decrypts to noise from the first chunk
// boundary onwards - and only for uploads that were resumed.
func TestChunkedEncryptionMatchesWholeEncryption(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFS(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s := NewShredder(fs)
	ctx := t.Context()

	key, err := NewAtRestKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	want := make([]byte, 200*1024)
	for i := range want {
		want[i] = byte(i * 7 % 253)
	}

	const chunked = "CHUNKENCAAAAAAAAAAAAAA"
	// Sizes chosen to cross AES block boundaries mid-chunk: 1 and 4095 are not
	// multiples of 16, so the keystream must be aligned part-way through a
	// block for the result to match.
	sizes := []int{1, 4095, 65536}
	sent := 0
	for _, n := range sizes {
		sent += n
	}
	sizes = append(sizes, len(want)-sent)

	var offset int64
	for _, size := range sizes {
		n, err := s.WriteChunk(ctx, chunked, key, offset, bytes.NewReader(want[offset:offset+int64(size)]))
		if err != nil {
			t.Fatalf("chunk at %d: %v", offset, err)
		}
		offset += n
	}
	if err := s.Finish(ctx, chunked); err != nil {
		t.Fatalf("finish: %v", err)
	}

	rc, err := s.Open(ctx, chunked, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = rc.Close() }()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("a chunked upload decrypts differently from the first difference at byte %d", i)
			}
		}
		t.Fatalf("read %d bytes, want %d", len(got), len(want))
	}
}

// The stored bytes must be ciphertext. A partial upload holds the same content
// a finished one would, so it gets the same protection.
func TestPartialUploadIsStoredEncrypted(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFS(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s := NewShredder(fs)

	key, err := NewAtRestKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	plaintext := []byte("a recognisable run of plaintext that must not reach the disk")
	if _, err := s.WriteChunk(t.Context(), "PARTENCAAAAAAAAAAAAAAA", key, 0, bytes.NewReader(plaintext)); err != nil {
		t.Fatalf("chunk: %v", err)
	}

	var found bool
	err = filepath.WalkDir(dir, func(path string, d fs2.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err //nolint:nilerr // directories are skipped, errors propagate
		}
		data, readErr := os.ReadFile(path) //nolint:gosec // walking a temporary directory in a test
		if readErr != nil {
			return nil //nolint:nilerr // unreadable files are not evidence
		}
		if bytes.Contains(data, plaintext) {
			t.Errorf("plaintext found in %s", path)
		}
		found = true
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if !found {
		t.Fatal("no file was written, so this proves nothing")
	}
}

func TestShredderChunkedLifecycle(t *testing.T) {
	s := NewShredder(mustFS(t))
	ctx := t.Context()
	key, err := NewAtRestKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	const id = "SHREDCHUNKAAAAAAAAAAAA"

	if _, err := s.Length(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("length before any chunk: got %v, want ErrNotFound", err)
	}

	if _, err := s.WriteChunk(ctx, id, key, 0, bytes.NewReader([]byte("hello "))); err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	n, err := s.Length(ctx, id)
	if err != nil {
		t.Fatalf("length: %v", err)
	}
	if n != 6 {
		t.Fatalf("length %d, want 6 - a client would resume from the wrong place", n)
	}

	// The offset is in plaintext bytes, which for CTR are also ciphertext
	// bytes; a wrong offset must be refused rather than silently written.
	if _, err := s.WriteChunk(ctx, id, key, 3, bytes.NewReader([]byte("x"))); !errors.Is(err, ErrOffset) {
		t.Fatalf("chunk at the wrong offset: got %v, want ErrOffset", err)
	}
	if _, err := s.WriteChunk(ctx, id, key, 6, bytes.NewReader([]byte("world"))); err != nil {
		t.Fatalf("second chunk: %v", err)
	}
	if err := s.Finish(ctx, id); err != nil {
		t.Fatalf("finish: %v", err)
	}

	rc, err := s.Open(ctx, id, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello world" {
		t.Errorf("read %q, want %q", got, "hello world")
	}
}

func TestShredderChunkRejectsBadArguments(t *testing.T) {
	s := NewShredder(mustFS(t))
	key, err := NewAtRestKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	if _, err := s.WriteChunk(t.Context(), "NEGATIVEAAAAAAAAAAAAAA", key, -1, bytes.NewReader(nil)); err == nil {
		t.Error("a negative offset was accepted, which would position the keystream before the start")
	}
	short := make([]byte, AtRestKeySize-1)
	if _, err := s.WriteChunk(t.Context(), "SHORTKEYAAAAAAAAAAAAAA", short, 0, bytes.NewReader(nil)); !errors.Is(err, ErrAtRestKey) {
		t.Errorf("a short key: got %v, want ErrAtRestKey", err)
	}
}

func mustFS(t *testing.T) *FS {
	t.Helper()
	fs, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return fs
}
