// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// AES-GCM nonce reuse under one key discloses the authentication key, not
// merely one message. It is the single most damaging mistake available in this
// package, and these tests exist so that a refactor which reintroduces it fails
// loudly rather than passing quietly.
//
// See spec §5.3 and issue #14.

func TestRecordNonceIsUniquePerSequence(t *testing.T) {
	base := [12]byte{}
	for i := range base {
		base[i] = byte(0xA0 + i)
	}

	seen := make(map[string]uint64, 1<<16)
	check := func(seq uint64) {
		n := hex.EncodeToString(recordNonce(base, seq))
		if prev, ok := seen[n]; ok {
			t.Fatalf("nonce collision: sequence %d and %d both produce %s", prev, seq, n)
		}
		seen[n] = seq
	}

	// Exhaustively over the low range, where an arithmetic slip is most likely.
	const exhaustive = 1 << 16
	for seq := uint64(0); seq < exhaustive; seq++ {
		check(seq)
	}
	// Then boundary values above that range, where a byte-order or off-by-one
	// error in the counter would show. None may repeat a value already checked.
	for _, seq := range []uint64{
		exhaustive, exhaustive + 1,
		1<<24 - 1, 1 << 24, 1<<24 + 1,
		1<<32 - 1, 1 << 32, 1<<32 + 1,
		1<<40 - 1, 1 << 40,
		maxSequence - 2, maxSequence - 1,
	} {
		if seq < exhaustive {
			t.Fatalf("boundary value %d is already covered by the exhaustive range", seq)
		}
		check(seq)
	}
}

func TestRecordNonceIsDeterministic(t *testing.T) {
	base := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	for _, seq := range []uint64{0, 1, 255, 256, 1 << 20} {
		if !bytes.Equal(recordNonce(base, seq), recordNonce(base, seq)) {
			t.Fatalf("sequence %d produced two different nonces", seq)
		}
	}
}

// The counter must advance on every seal. If a refactor ever made the sequence
// settable, resettable, or optional, this fails.
func TestRecordSealerAdvancesOnEverySeal(t *testing.T) {
	aead, err := newAEAD(bytes.Repeat([]byte{0x33}, derivedKeySize))
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	s := &recordSealer{aead: aead, nonceBase: [12]byte{}}

	plaintext := []byte("identical plaintext")
	seen := make(map[string]int, 512)
	for i := range 512 {
		record, err := s.seal(plaintext)
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		key := hex.EncodeToString(record)
		if prev, ok := seen[key]; ok {
			t.Fatalf("identical ciphertext at seals %d and %d: the nonce was reused", prev, i)
		}
		seen[key] = i
	}
	if s.seq != 512 {
		t.Fatalf("counter is %d after 512 seals, want 512", s.seq)
	}
}

func TestRecordSealerRefusesToWrapTheCounter(t *testing.T) {
	aead, err := newAEAD(bytes.Repeat([]byte{0x44}, derivedKeySize))
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	s := &recordSealer{aead: aead, seq: maxSequence - 1}

	if _, err := s.seal([]byte("last")); err != nil {
		t.Fatalf("the final permitted seal must succeed: %v", err)
	}
	// Exhaustion is an error, never a wrap back to a used sequence value.
	if _, err := s.seal([]byte("one too many")); !errors.Is(err, ErrContent) {
		t.Fatalf("got %v, want ErrContent once the sequence is exhausted", err)
	}
	if _, err := s.seal([]byte("still refused")); !errors.Is(err, ErrContent) {
		t.Fatalf("got %v, want ErrContent on every subsequent attempt", err)
	}
}

// Encrypting the same plaintext under the same key must never produce the same
// stream, because the content salt is random per stream. This is the property
// that would break first if a fixed or derived salt were substituted.
func TestStreamsOfIdenticalContentNeverRepeat(t *testing.T) {
	plaintext := bytes.Repeat([]byte{0x5A}, 3*maxRecordPlaintext)
	seen := make(map[string]struct{}, 16)
	for i := range 16 {
		stream := seal(t, testFileKey(), plaintext)
		key := hex.EncodeToString(stream)
		if _, ok := seen[key]; ok {
			t.Fatalf("stream %d is byte-identical to an earlier one", i)
		}
		seen[key] = struct{}{}
	}
}

// Within one stream every record must be distinct even when the plaintext
// repeats, which is only true if each record gets its own nonce.
func TestRecordsWithinAStreamAreDistinct(t *testing.T) {
	// Several records of identical content.
	plaintext := bytes.Repeat([]byte{0x77}, 5*maxRecordPlaintext)
	stream := seal(t, testFileKey(), plaintext)
	body := stream[headerSize:]

	seen := make(map[string]int, 8)
	for i := 0; i+RecordSize <= len(body); i += RecordSize {
		key := hex.EncodeToString(body[i : i+RecordSize])
		if prev, ok := seen[key]; ok {
			t.Fatalf("records at offsets %d and %d are identical: the nonce was reused", prev, i)
		}
		seen[key] = i
	}
	if len(seen) < 4 {
		t.Fatalf("expected several full records to compare, got %d", len(seen))
	}
}
