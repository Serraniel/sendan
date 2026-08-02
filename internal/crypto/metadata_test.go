// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package crypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func metadataKey() []byte { return bytes.Repeat([]byte{0x0C}, derivedKeySize) }

func TestMetadataRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    Metadata
	}{
		{"ordinary", Metadata{Name: "report.pdf", Type: "application/pdf", Size: 1048576}},
		{"all empty", Metadata{Name: "", Type: "", Size: 0}},
		{"non-ascii name", Metadata{Name: "日本語のファイル.txt", Type: "text/plain", Size: 42}},
		{"quotes and slashes", Metadata{Name: `quote" backslash\ slash/`, Type: "text/plain", Size: 1}},
		{"emoji and max safe size", Metadata{Name: "emoji 🔐.bin", Type: "application/octet-stream", Size: 9007199254740991}},
		{"very long name", Metadata{Name: strings.Repeat("a", 4096), Type: "text/plain", Size: 7}},
		{"separators", Metadata{Name: "a b c", Type: "text/plain", Size: 2}},
	} {
		m := tc.m
		t.Run(tc.name, func(t *testing.T) {
			nonce, envelope, err := SealMetadata(metadataKey(), m)
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			got, err := OpenMetadata(metadataKey(), nonce, envelope)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if got != m {
				t.Fatalf("got %+v, want %+v", got, m)
			}
		})
	}
}

func TestMetadataEnvelopeHidesTheFilename(t *testing.T) {
	m := Metadata{Name: "verysecretfilename.pdf", Type: "application/pdf", Size: 10}
	_, envelope, err := SealMetadata(metadataKey(), m)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(envelope, []byte(m.Name)) {
		t.Fatal("the filename appears in the envelope in cleartext")
	}
}

// Padding exists so that ciphertext length does not disclose filename length.
// Names of very different lengths must produce identically sized envelopes as
// long as they fall in the same block.
func TestMetadataIsPaddedToBlockMultiples(t *testing.T) {
	var sizes []int
	for _, n := range []int{1, 5, 20, 50} {
		_, envelope, err := SealMetadata(metadataKey(), Metadata{
			Name: strings.Repeat("a", n), Type: "text/plain", Size: 1,
		})
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		sizes = append(sizes, len(envelope))
	}
	for i := 1; i < len(sizes); i++ {
		if sizes[i] != sizes[0] {
			t.Fatalf("envelope sizes differ across short names (%v): filename length leaks", sizes)
		}
	}

	// Crossing a block boundary must add exactly one block.
	_, small, err := SealMetadata(metadataKey(), Metadata{Name: strings.Repeat("a", 8), Type: "", Size: 1})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	_, large, err := SealMetadata(metadataKey(), Metadata{Name: strings.Repeat("a", 600), Type: "", Size: 1})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if (len(large)-len(small))%metadataPadBlock != 0 {
		t.Fatalf("envelope grew by %d bytes, not a multiple of the %d byte block", len(large)-len(small), metadataPadBlock)
	}
}

func TestOpenMetadataRejectsTampering(t *testing.T) {
	nonce, envelope, err := SealMetadata(metadataKey(), Metadata{Name: "a.txt", Type: "text/plain", Size: 3})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	corrupt := bytes.Clone(envelope)
	corrupt[0] ^= 0x01
	badNonce := bytes.Clone(nonce)
	badNonce[0] ^= 0x01
	otherKey := bytes.Repeat([]byte{0x0D}, derivedKeySize)

	for _, tc := range []struct {
		name     string
		key      []byte
		nonce    []byte
		envelope []byte
	}{
		{"flipped bit", metadataKey(), nonce, corrupt},
		{"wrong nonce", metadataKey(), badNonce, envelope},
		{"wrong key", otherKey, nonce, envelope},
		{"truncated", metadataKey(), nonce, envelope[:len(envelope)-1]},
		{"short nonce", metadataKey(), nonce[:NonceSize-1], envelope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := OpenMetadata(tc.key, tc.nonce, tc.envelope); !errors.Is(err, ErrMetadata) {
				t.Fatalf("got %v, want ErrMetadata", err)
			}
		})
	}
}

func TestSealMetadataRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    Metadata
	}{
		{"invalid utf-8 name", Metadata{Name: string([]byte{0xFF, 0xFE}), Type: "text/plain"}},
		{"invalid utf-8 type", Metadata{Name: "a", Type: string([]byte{0xFF})}},
		{"negative size", Metadata{Name: "a", Type: "text/plain", Size: -1}},
		{"size above 2^53-1", Metadata{Name: "a", Type: "text/plain", Size: MaxMetadataSize + 1}},
		{"max int64 size", Metadata{Name: "a", Type: "text/plain", Size: 1<<63 - 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := SealMetadata(metadataKey(), tc.m); !errors.Is(err, ErrMetadata) {
				t.Fatalf("got %v, want ErrMetadata", err)
			}
		})
	}
}

// The encoding is the cross-language contract. encoding/json would escape
// HTML-significant characters and U+2028/U+2029, which JSON.stringify does not,
// so these expectations are what keep the two implementations byte-identical.
func TestDeterministicJSONEncoding(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    Metadata
		want string
	}{
		{
			"plain",
			Metadata{Name: "a.txt", Type: "text/plain", Size: 3},
			`{"name":"a.txt","type":"text/plain","size":3}`,
		},
		{
			"html significant characters are not escaped",
			Metadata{Name: `<a>&"b"`, Type: "text/plain", Size: 1},
			`{"name":"<a>&\"b\"","type":"text/plain","size":1}`,
		},
		{
			"line and paragraph separators are literal",
			Metadata{Name: "a b c", Type: "", Size: 0},
			"{\"name\":\"a b c\",\"type\":\"\",\"size\":0}",
		},
		{
			"control characters use short escapes",
			Metadata{Name: "a\nb\tc\rd", Type: "", Size: 0},
			`{"name":"a\nb\tc\rd","type":"","size":0}`,
		},
		{
			"other control characters use \\u00xx lowercase",
			Metadata{Name: "a\x01\x1fb", Type: "", Size: 0},
			`{"name":"a\u0001\u001fb","type":"","size":0}`,
		},
		{
			"backslash",
			Metadata{Name: `a\b`, Type: "", Size: 0},
			`{"name":"a\\b","type":"","size":0}`,
		},
		{
			"non-ascii is literal utf-8",
			Metadata{Name: "日本語", Type: "", Size: 0},
			`{"name":"日本語","type":"","size":0}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.m.encode()
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}

// A size above 2^53-1 is representable in Go but not in a JavaScript number,
// where it would silently round rather than fail. Rejecting it in both
// directions keeps the two implementations from disagreeing about a size.
func TestSizeIsBoundedToJavaScriptSafeIntegers(t *testing.T) {
	if MaxMetadataSize != 9007199254740991 {
		t.Fatalf("MaxMetadataSize is %d, want Number.MAX_SAFE_INTEGER", MaxMetadataSize)
	}

	nonce, envelope, err := SealMetadata(metadataKey(), Metadata{Name: "big.bin", Type: "", Size: MaxMetadataSize})
	if err != nil {
		t.Fatalf("the maximum safe size must be accepted: %v", err)
	}
	got, err := OpenMetadata(metadataKey(), nonce, envelope)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got.Size != MaxMetadataSize {
		t.Fatalf("size round-tripped as %d, want %d", got.Size, MaxMetadataSize)
	}

	// An envelope from another implementation could carry an out-of-range size,
	// so decoding must reject it rather than trust the producer.
	oversized := []byte(`{"name":"a","type":"","size":9007199254740993}`)
	aead, err := newAEAD(metadataKey())
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	badNonce, err := randomBytes(NonceSize)
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	forged := aead.Seal(nil, badNonce, pad(oversized), []byte(aadMetadata))
	if _, err := OpenMetadata(metadataKey(), badNonce, forged); !errors.Is(err, ErrMetadata) {
		t.Fatalf("got %v, want ErrMetadata for an out-of-range size", err)
	}
}

func TestPadUnpadRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 255, 256, 257, 511, 512, 513, 1000} {
		plaintext := bytes.Repeat([]byte{0x5A}, n)
		padded := pad(plaintext)
		if len(padded)%metadataPadBlock != 0 {
			t.Fatalf("n=%d: padded length %d is not a block multiple", n, len(padded))
		}
		if len(padded) <= n {
			t.Fatalf("n=%d: padding must always add at least one byte", n)
		}
		got, err := unpad(padded)
		if err != nil {
			t.Fatalf("n=%d: unpad: %v", n, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("n=%d: round trip changed the plaintext", n)
		}
	}
}

func TestUnpadRejectsMalformedPadding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		padded []byte
	}{
		{"empty", nil},
		{"not a block multiple", make([]byte, metadataPadBlock+1)},
		{"all zero, no 0x80 marker", make([]byte, metadataPadBlock)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := unpad(tc.padded); !errors.Is(err, ErrMetadata) {
				t.Fatalf("got %v, want ErrMetadata", err)
			}
		})
	}
}
