// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package crypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// metadataPadBlock is the padding granularity, per spec §7. Padding blunts the
// disclosure of filename length through ciphertext length.
const metadataPadBlock = 256

// MaxMetadataSize is the largest representable upload size, 2^53 - 1.
//
// Go encodes any int64 faithfully, but JavaScript numbers are IEEE-754 doubles
// and silently round anything larger: 9007199254740993 parses back as
// 9007199254740992. Bounding the value here means the two implementations
// cannot disagree about a size, at the cost of a ceiling of 8 PiB.
const MaxMetadataSize int64 = 1<<53 - 1

// ErrMetadata reports a malformed or unopenable metadata envelope.
var ErrMetadata = errors.New("crypto: invalid metadata")

// Metadata describes an upload. It is encrypted client-side; a server never
// sees any of it.
type Metadata struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

// SealMetadata encrypts metadata under the metadata key (spec §7).
func SealMetadata(metadataKey []byte, m Metadata) (nonce, envelope []byte, err error) {
	plaintext, err := m.encode()
	if err != nil {
		return nil, nil, err
	}
	aead, err := newAEAD(metadataKey)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = randomBytes(NonceSize)
	if err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, pad(plaintext), []byte(aadMetadata)), nil
}

// OpenMetadata decrypts an envelope produced by [SealMetadata].
func OpenMetadata(metadataKey, nonce, envelope []byte) (Metadata, error) {
	aead, err := newAEAD(metadataKey)
	if err != nil {
		return Metadata{}, err
	}
	if len(nonce) != NonceSize {
		return Metadata{}, ErrMetadata
	}
	padded, err := aead.Open(nil, nonce, envelope, []byte(aadMetadata))
	if err != nil {
		return Metadata{}, ErrMetadata
	}
	plaintext, err := unpad(padded)
	if err != nil {
		return Metadata{}, err
	}

	dec := json.NewDecoder(bytes.NewReader(plaintext))
	dec.DisallowUnknownFields()
	var m Metadata
	if err := dec.Decode(&m); err != nil {
		return Metadata{}, ErrMetadata
	}
	// Reject on the way out as well as on the way in: an envelope may have been
	// produced by a different implementation, or by an older version of this one.
	if m.Size < 0 || m.Size > MaxMetadataSize {
		return Metadata{}, ErrMetadata
	}
	return m, nil
}

// encode produces the deterministic JSON encoding required by spec §7.1.
//
// encoding/json is deliberately not used here. It escapes U+2028 and U+2029
// unconditionally and HTML-significant characters by default, neither of which
// JSON.stringify does, so the two implementations would produce different
// ciphertext for the same filename and the shared vectors would diverge.
func (m Metadata) encode() ([]byte, error) {
	if !utf8.ValidString(m.Name) || !utf8.ValidString(m.Type) {
		return nil, fmt.Errorf("%w: name and type must be valid UTF-8", ErrMetadata)
	}
	if m.Size < 0 || m.Size > MaxMetadataSize {
		return nil, fmt.Errorf("%w: size must be between 0 and %d", ErrMetadata, MaxMetadataSize)
	}

	var b strings.Builder
	b.WriteString(`{"name":`)
	encodeJSONString(&b, m.Name)
	b.WriteString(`,"type":`)
	encodeJSONString(&b, m.Type)
	b.WriteString(`,"size":`)
	b.WriteString(strconv.FormatInt(m.Size, 10))
	b.WriteByte('}')
	return []byte(b.String()), nil
}

// encodeJSONString applies the minimal escaping of spec §7.1: quote, reverse
// solidus, and the C0 control characters. Everything else, including all
// non-ASCII, is emitted literally as UTF-8.
func encodeJSONString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(`\u`)
				const hex = "0123456789abcdef"
				b.WriteByte('0')
				b.WriteByte('0')
				b.WriteByte(hex[(r>>4)&0xF])
				b.WriteByte(hex[r&0xF])
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// pad applies ISO/IEC 7816-4 padding to a multiple of metadataPadBlock: a
// single 0x80 octet followed by 0x00 octets. Padding is always added, so a
// plaintext that is already aligned still gains a full block.
func pad(plaintext []byte) []byte {
	total := ((len(plaintext) + 1 + metadataPadBlock - 1) / metadataPadBlock) * metadataPadBlock
	padded := make([]byte, total)
	copy(padded, plaintext)
	padded[len(plaintext)] = 0x80
	return padded
}

func unpad(padded []byte) ([]byte, error) {
	if len(padded) == 0 || len(padded)%metadataPadBlock != 0 {
		return nil, ErrMetadata
	}
	i := len(padded) - 1
	for i >= 0 && padded[i] == 0x00 {
		i--
	}
	if i < 0 || padded[i] != 0x80 {
		return nil, ErrMetadata
	}
	return padded[:i], nil
}
