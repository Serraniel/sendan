// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package blob

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// AtRestKeySize is the length of a per-upload at-rest key.
const AtRestKeySize = 32

// labelAtRestIV domain-separates the counter block from any other use of the
// at-rest key.
const labelAtRestIV = "sendan/at-rest/iv/v1"

// ErrAtRestKey reports a malformed at-rest key.
var ErrAtRestKey = errors.New("blob: invalid at-rest key")

// Shredder encrypts blobs at rest under a key held in the upload's database
// row, so that deleting the row destroys the data.
//
// # Why this exists
//
// Overwriting a file is not deletion on modern hardware. Copy-on-write
// filesystems write elsewhere and leave the original block intact, and SSD wear
// levelling may retain several superseded copies that no filesystem operation
// can reach. Sendan promises that an expired upload leaves nothing behind, and
// on such hardware that promise cannot be kept by unlinking alone.
//
// Encrypting each blob under a key stored only in its database row turns
// deletion into an operation that succeeds regardless: once the row is gone,
// any surviving block is unrecoverable ciphertext. See docs/design.md §3.
//
// # Why this is not authenticated
//
// AES-CTR provides confidentiality and no integrity, which is deliberate. The
// bytes handed to this layer are already end-to-end encrypted with AES-GCM, so
// tampering is detected by the client on decryption, where it must be detected
// regardless of what the server does. Adding a second authentication tag here
// would defend the server against a threat the client already defends against,
// at the cost of losing the seekability that range requests need.
//
// This layer is therefore not a security boundary. Its only job is to make a
// deleted key mean deleted data.
type Shredder struct {
	inner Store
}

// NewShredder wraps a store so that blobs are encrypted at rest.
func NewShredder(inner Store) *Shredder { return &Shredder{inner: inner} }

// NewAtRestKey returns a fresh random at-rest key.
//
// One key per upload, never reused. That is what allows a fixed counter block:
// with a unique key, a fixed starting counter cannot repeat a keystream.
func NewAtRestKey() ([]byte, error) {
	key := make([]byte, AtRestKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("blob: generate at-rest key: %w", err)
	}
	return key, nil
}

// stream builds the CTR keystream for a key, positioned at byte offset.
func stream(key []byte, offset int64) (cipher.Stream, int, error) {
	if len(key) != AtRestKeySize {
		return nil, 0, fmt.Errorf("%w: %d bytes, want %d", ErrAtRestKey, len(key), AtRestKeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, fmt.Errorf("blob: new cipher: %w", err)
	}

	// The counter block is derived from the key rather than stored. The key is
	// unique per upload, so the derived value is too, and there is no extra
	// field for an operator to lose or an implementation to forget.
	iv, err := hkdf.Key(sha256.New, key, nil, labelAtRestIV, block.BlockSize())
	if err != nil {
		return nil, 0, fmt.Errorf("blob: derive counter: %w", err)
	}

	// A negative offset would wrap the counter arithmetic below, so it is
	// rejected rather than clamped: it can only arise from a caller bug.
	if offset < 0 {
		return nil, 0, fmt.Errorf("blob: negative offset %d", offset)
	}
	// Advance the counter to the block containing offset, then discard the
	// bytes before it within that block.
	//nolint:gosec // offset is checked non-negative immediately above
	blocks, skip := blockOffset(uint64(offset))
	incrementCounter(iv, blocks)

	return cipher.NewCTR(block, iv), skip, nil
}

// blockOffset splits a byte offset into the number of whole AES blocks before
// it and the remainder within the block containing it.
//
//nolint:gosec // aes.BlockSize is the constant 16, so the remainder is under 16
func blockOffset(position uint64) (blocks uint64, skip int) {
	return position / aes.BlockSize, int(position % aes.BlockSize)
}

// incrementCounter adds n to the big-endian counter in place.
//
// The parameter is unsigned so that no caller can wrap the counter with a
// negative value, and each octet is masked explicitly, so truncation to a byte
// is the intended operation rather than an overflow.
func incrementCounter(counter []byte, n uint64) {
	carry := n
	for i := len(counter) - 1; i >= 0 && carry > 0; i-- {
		sum := uint64(counter[i]) + carry&0xFF
		counter[i] = byte(sum & 0xFF)
		carry = carry>>8 + sum>>8
	}
}

// Put encrypts r under key and stores it.
func (s *Shredder) Put(ctx context.Context, id string, key []byte, r io.Reader) (int64, error) {
	ctr, skip, err := stream(key, 0)
	if err != nil {
		return 0, err
	}
	if skip != 0 {
		return 0, errors.New("blob: unexpected offset at start of stream")
	}
	return s.inner.Put(ctx, id, &cipher.StreamReader{S: ctr, R: r})
}

// Open returns the decrypted blob, still seekable.
func (s *Shredder) Open(ctx context.Context, id string, key []byte) (io.ReadSeekCloser, error) {
	if len(key) != AtRestKeySize {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrAtRestKey, len(key), AtRestKeySize)
	}
	inner, err := s.inner.Open(ctx, id)
	if err != nil {
		return nil, err
	}
	d := &decryptingReader{inner: inner, key: key}
	if err := d.reseek(0); err != nil {
		_ = inner.Close()
		return nil, err
	}
	return d, nil
}

// Delete removes the blob. The at-rest key lives in the database row, so
// deleting that row is what actually destroys the content.
func (s *Shredder) Delete(ctx context.Context, id string) error {
	return s.inner.Delete(ctx, id)
}

// decryptingReader decrypts a blob and keeps it seekable by rebuilding the
// keystream at the requested offset.
type decryptingReader struct {
	inner  io.ReadSeekCloser
	key    []byte
	ctr    cipher.Stream
	skip   int
	offset int64
}

func (d *decryptingReader) reseek(offset int64) error {
	ctr, skip, err := stream(d.key, offset)
	if err != nil {
		return err
	}
	d.ctr, d.skip, d.offset = ctr, skip, offset
	return nil
}

func (d *decryptingReader) Read(p []byte) (int, error) {
	// Consume the partial block preceding the requested offset, so the
	// keystream lines up with the ciphertext.
	for d.skip > 0 {
		discard := make([]byte, min(d.skip, aes.BlockSize))
		d.ctr.XORKeyStream(discard, discard)
		d.skip -= len(discard)
	}

	n, err := d.inner.Read(p)
	if n > 0 {
		d.ctr.XORKeyStream(p[:n], p[:n])
		d.offset += int64(n)
	}
	return n, err
}

func (d *decryptingReader) Seek(offset int64, whence int) (int64, error) {
	pos, err := d.inner.Seek(offset, whence)
	if err != nil {
		return 0, fmt.Errorf("blob: seek: %w", err)
	}
	// The keystream is positional, so it must be rebuilt rather than continued.
	if err := d.reseek(pos); err != nil {
		return 0, err
	}
	return pos, nil
}

func (d *decryptingReader) Close() error { return d.inner.Close() }
