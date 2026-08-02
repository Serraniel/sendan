// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package crypto

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Content encoding parameters, per spec §5.
const (
	// RecordSize is the fixed record size in bytes.
	RecordSize = 65536

	// ContentSaltSize is the length of the per-upload content salt.
	ContentSaltSize = 16

	// headerSize is cSalt(16) || rs(4) || idlen(1), with an empty keyid.
	headerSize = ContentSaltSize + 4 + 1

	// maxRecordPlaintext is the record size less the GCM tag and the delimiter.
	maxRecordPlaintext = RecordSize - 16 - 1

	delimiterNonFinal = 0x01
	delimiterFinal    = 0x02

	// maxSequence bounds the record counter well below the point at which the
	// 96-bit nonce space could wrap. Exceeding it would risk nonce reuse, which
	// discloses the GCM authentication key.
	maxSequence = 1 << 48
)

// Info strings for content key derivation, per spec §5.1.
//
// The aes256gcm designation is deliberate: RFC 8188 defines only aes128gcm, and
// Sendan uses the same framing with a 256-bit key. A distinct info string keeps
// the two from ever deriving the same key material.
var (
	infoContentKey   = "Content-Encoding: aes256gcm\x00"
	infoContentNonce = "Content-Encoding: nonce\x00"
)

// ErrContent reports a malformed, truncated, or tampered content stream.
var ErrContent = errors.New("crypto: invalid content stream")

// deriveContentKeys produces the content encryption key and nonce base from the
// file key and the content salt.
func deriveContentKeys(fileKey, contentSalt []byte) (cek []byte, nonceBase [12]byte, err error) {
	if len(fileKey) != FileKeySize {
		return nil, nonceBase, fmt.Errorf("%w: file key is %d bytes, want %d", ErrKeyMaterial, len(fileKey), FileKeySize)
	}
	if len(contentSalt) != ContentSaltSize {
		return nil, nonceBase, fmt.Errorf("%w: content salt is %d bytes, want %d", ErrKeyMaterial, len(contentSalt), ContentSaltSize)
	}

	prk, err := hkdf.Extract(sha256.New, fileKey, contentSalt)
	if err != nil {
		return nil, nonceBase, fmt.Errorf("crypto: hkdf extract: %w", err)
	}
	cek, err = hkdf.Expand(sha256.New, prk, infoContentKey, 32)
	if err != nil {
		return nil, nonceBase, fmt.Errorf("crypto: hkdf expand content key: %w", err)
	}
	nb, err := hkdf.Expand(sha256.New, prk, infoContentNonce, 12)
	if err != nil {
		return nil, nonceBase, fmt.Errorf("crypto: hkdf expand nonce: %w", err)
	}
	copy(nonceBase[:], nb)
	return cek, nonceBase, nil
}

// recordNonce derives the nonce for a record, per spec §5.3:
// the nonce base exclusive-ORed with the big-endian record sequence number.
//
// The sequence number is a strict counter and is never random. Two records of
// one stream must never share a nonce; see the warning in spec §5.3.
func recordNonce(base [12]byte, seq uint64) []byte {
	n := base
	// The counter is 96-bit big-endian, but a uint64 sequence can only occupy
	// the low eight octets, so the leading four are always zero.
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], seq)
	for i, b := range counter {
		n[4+i] ^= b
	}
	return n[:]
}

// Encryptor encrypts a byte stream into the Sendan content encoding.
//
// Close must be called and its error checked: the final record carries the
// terminating delimiter, and without it a decryptor correctly treats the stream
// as truncated.
type Encryptor struct {
	w             io.Writer
	aead          cipher.AEAD
	pendingHeader []byte
	nonceBase     [12]byte
	seq           uint64
	buf           []byte
	n             int
	headerWritten bool
	closed        bool
	err           error
}

// NewEncryptor returns an [Encryptor] writing to w.
//
// It generates a random content salt, which is emitted in the header.
func NewEncryptor(w io.Writer, fileKey []byte) (*Encryptor, error) {
	salt, err := randomBytes(ContentSaltSize)
	if err != nil {
		return nil, err
	}
	return newEncryptorWithSalt(w, fileKey, salt)
}

// newEncryptorWithSalt allows tests and the vector generator to pin the salt.
// Callers outside this package must use [NewEncryptor] so the salt is random.
func newEncryptorWithSalt(w io.Writer, fileKey, contentSalt []byte) (*Encryptor, error) {
	cek, nonceBase, err := deriveContentKeys(fileKey, contentSalt)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(cek)
	if err != nil {
		return nil, err
	}

	header := make([]byte, 0, headerSize)
	header = append(header, contentSalt...)
	header = binary.BigEndian.AppendUint32(header, RecordSize)
	header = append(header, 0) // idlen: the keyid is always empty

	return &Encryptor{
		w:             w,
		aead:          aead,
		pendingHeader: header,
		nonceBase:     nonceBase,
		buf:           make([]byte, maxRecordPlaintext),
	}, nil
}

// writeHeader emits the header lazily, so constructing an Encryptor performs
// no I/O.
func (e *Encryptor) writeHeader() error {
	if e.headerWritten {
		return nil
	}
	if _, err := e.w.Write(e.pendingHeader); err != nil {
		return fmt.Errorf("crypto: write header: %w", err)
	}
	e.headerWritten = true
	return nil
}

// Write buffers plaintext, emitting a record whenever a full one accumulates
// and further data is known to follow.
//
// A full buffer is never emitted eagerly, because whether it is the final
// record is not known until either more data arrives or Close is called.
func (e *Encryptor) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	if e.closed {
		return 0, errors.New("crypto: write after close")
	}

	written := 0
	for len(p) > 0 {
		if e.n == maxRecordPlaintext {
			// The buffer is full and more data remains, so this record is
			// certainly not the final one.
			if err := e.flush(false); err != nil {
				e.err = err
				return written, err
			}
		}
		k := copy(e.buf[e.n:], p)
		e.n += k
		p = p[k:]
		written += k
	}
	return written, nil
}

// Close emits the final record and must be called exactly once.
func (e *Encryptor) Close() error {
	if e.err != nil {
		return e.err
	}
	if e.closed {
		return nil
	}
	e.closed = true
	if err := e.flush(true); err != nil {
		e.err = err
		return err
	}
	return nil
}

func (e *Encryptor) flush(final bool) error {
	if err := e.writeHeader(); err != nil {
		return err
	}
	if e.seq >= maxSequence {
		return fmt.Errorf("%w: record sequence exhausted", ErrContent)
	}

	delimiter := byte(delimiterNonFinal)
	if final {
		delimiter = delimiterFinal
	}

	plaintext := make([]byte, e.n+1)
	copy(plaintext, e.buf[:e.n])
	plaintext[e.n] = delimiter

	record := e.aead.Seal(nil, recordNonce(e.nonceBase, e.seq), plaintext, nil)
	if _, err := e.w.Write(record); err != nil {
		return fmt.Errorf("crypto: write record: %w", err)
	}
	e.seq++
	e.n = 0
	return nil
}

// Decryptor decrypts a stream produced by [Encryptor].
type Decryptor struct {
	r         io.Reader
	aead      cipher.AEAD
	nonceBase [12]byte
	seq       uint64
	fileKey   []byte

	plain      []byte
	off        int
	headerRead bool
	sawFinal   bool
	err        error
	record     []byte
}

// NewDecryptor returns a [Decryptor] reading from r.
//
// The header is parsed on the first Read, so constructing one performs no I/O.
func NewDecryptor(r io.Reader, fileKey []byte) (*Decryptor, error) {
	if len(fileKey) != FileKeySize {
		return nil, fmt.Errorf("%w: file key is %d bytes, want %d", ErrKeyMaterial, len(fileKey), FileKeySize)
	}
	return &Decryptor{r: r, fileKey: fileKey, record: make([]byte, RecordSize)}, nil
}

func (d *Decryptor) readHeader() error {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(d.r, header); err != nil {
		return ErrContent
	}

	salt := header[:ContentSaltSize]
	rs := binary.BigEndian.Uint32(header[ContentSaltSize : ContentSaltSize+4])
	idlen := header[ContentSaltSize+4]

	// The record size and key identifier are fixed by the specification. They
	// are validated rather than honoured: accepting a value from the stream
	// would be a negotiated parameter, which spec §11 forbids.
	if rs != RecordSize || idlen != 0 {
		return ErrContent
	}

	cek, nonceBase, err := deriveContentKeys(d.fileKey, salt)
	if err != nil {
		return ErrContent
	}
	aead, err := newAEAD(cek)
	if err != nil {
		return ErrContent
	}
	d.aead = aead
	d.nonceBase = nonceBase
	d.headerRead = true
	return nil
}

// Read implements [io.Reader].
//
// A stream that ends without a final record yields [ErrContent] rather than a
// short read, so truncation can never be mistaken for a complete file.
func (d *Decryptor) Read(p []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	if !d.headerRead {
		if err := d.readHeader(); err != nil {
			d.err = err
			return 0, err
		}
	}

	for d.off == len(d.plain) {
		if d.sawFinal {
			d.err = io.EOF
			return 0, io.EOF
		}
		if err := d.nextRecord(); err != nil {
			d.err = err
			return 0, err
		}
	}

	n := copy(p, d.plain[d.off:])
	d.off += n
	return n, nil
}

func (d *Decryptor) nextRecord() error {
	if d.seq >= maxSequence {
		return ErrContent
	}

	n, err := io.ReadFull(d.r, d.record)
	switch {
	case err == nil:
	case errors.Is(err, io.ErrUnexpectedEOF):
		// A short record is permitted only as the last one in the stream.
	case errors.Is(err, io.EOF):
		// The stream ended without a record carrying the final delimiter.
		return ErrContent
	default:
		return ErrContent
	}

	plaintext, err := d.aead.Open(nil, recordNonce(d.nonceBase, d.seq), d.record[:n], nil)
	if err != nil {
		return ErrContent
	}
	if len(plaintext) == 0 {
		return ErrContent
	}

	// The delimiter is the final octet. Optional zero padding, which RFC 8188
	// permits, is deliberately not accepted: it would make two distinct
	// encodings of one plaintext valid, and malleability of any kind is not
	// worth the flexibility here.
	delimiter := plaintext[len(plaintext)-1]
	switch delimiter {
	case delimiterFinal:
		d.sawFinal = true
	case delimiterNonFinal:
		// A non-final record must be full; otherwise a truncated stream could
		// be presented as a complete one.
		if n != RecordSize {
			return ErrContent
		}
	default:
		return ErrContent
	}

	d.plain = plaintext[:len(plaintext)-1]
	d.off = 0
	d.seq++

	if d.sawFinal {
		// Nothing may follow the final record.
		var probe [1]byte
		if extra, _ := d.r.Read(probe[:]); extra > 0 {
			return ErrContent
		}
	}
	return nil
}
