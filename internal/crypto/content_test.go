// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"testing"
)

func testFileKey() []byte { return bytes.Repeat([]byte{0x11}, FileKeySize) }

func seal(t *testing.T, fileKey, plaintext []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc, err := NewEncryptor(&buf, fileKey)
	if err != nil {
		t.Fatalf("new encryptor: %v", err)
	}
	if _, err := enc.Write(plaintext); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return buf.Bytes()
}

func open(t *testing.T, fileKey, stream []byte) ([]byte, error) {
	t.Helper()
	dec, err := NewDecryptor(bytes.NewReader(stream), fileKey)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(dec)
}

func TestContentRoundTrip(t *testing.T) {
	for _, size := range []int{
		0, 1, 17, 1024,
		maxRecordPlaintext - 1,
		maxRecordPlaintext,
		maxRecordPlaintext + 1,
		2 * maxRecordPlaintext,
		2*maxRecordPlaintext + 1,
		5*maxRecordPlaintext + 12345,
	} {
		plaintext := make([]byte, size)
		if _, err := rand.New(rand.NewSource(int64(size))).Read(plaintext); err != nil { //nolint:gosec // deterministic test data
			t.Fatalf("fill: %v", err)
		}

		stream := seal(t, testFileKey(), plaintext)
		got, err := open(t, testFileKey(), stream)
		if err != nil {
			t.Fatalf("size %d: decrypt: %v", size, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("size %d: round trip changed the content", size)
		}
	}
}

// Every full record must be exactly RecordSize bytes, or the framing is wrong
// and a decryptor cannot tell where one record ends and the next begins.
func TestContentRecordFraming(t *testing.T) {
	for _, tc := range []struct {
		size        int
		wantRecords int
	}{
		{0, 1},
		{1, 1},
		{maxRecordPlaintext, 1},
		{maxRecordPlaintext + 1, 2},
		{2 * maxRecordPlaintext, 2},
		{2*maxRecordPlaintext + 1, 3},
	} {
		stream := seal(t, testFileKey(), make([]byte, tc.size))
		body := stream[headerSize:]

		full := len(body) / RecordSize
		rem := len(body) % RecordSize
		records := full
		if rem != 0 {
			records++
		}
		if records != tc.wantRecords {
			t.Errorf("size %d: got %d records, want %d", tc.size, records, tc.wantRecords)
		}
	}
}

func TestContentHeaderFormat(t *testing.T) {
	stream := seal(t, testFileKey(), []byte("hello"))
	if len(stream) < headerSize {
		t.Fatal("stream shorter than the header")
	}
	header := stream[:headerSize]

	if rs := binary.BigEndian.Uint32(header[ContentSaltSize : ContentSaltSize+4]); rs != RecordSize {
		t.Errorf("record size in header is %d, want %d", rs, RecordSize)
	}
	if idlen := header[ContentSaltSize+4]; idlen != 0 {
		t.Errorf("idlen is %d, want 0", idlen)
	}

	other := seal(t, testFileKey(), []byte("hello"))
	if bytes.Equal(header[:ContentSaltSize], other[:ContentSaltSize]) {
		t.Error("two streams share a content salt: the salt is not random")
	}
}

// Truncation must be detected. A decryptor that returned the partial plaintext
// would let an attacker silently shorten a file.
func TestContentTruncationIsDetected(t *testing.T) {
	plaintext := make([]byte, 3*maxRecordPlaintext)
	stream := seal(t, testFileKey(), plaintext)

	for _, tc := range []struct {
		name string
		cut  int
	}{
		{"header only", headerSize},
		{"one whole record dropped", headerSize + 2*RecordSize},
		{"mid record", headerSize + RecordSize + 100},
		{"one byte short", len(stream) - 1},
		{"empty stream", 0},
		{"partial header", headerSize - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := open(t, testFileKey(), stream[:tc.cut]); !errors.Is(err, ErrContent) {
				t.Fatalf("got %v, want ErrContent", err)
			}
		})
	}
}

func TestContentTamperingIsDetected(t *testing.T) {
	plaintext := make([]byte, 2*maxRecordPlaintext+50)
	stream := seal(t, testFileKey(), plaintext)

	flip := func(at int) []byte {
		s := bytes.Clone(stream)
		s[at] ^= 0x01
		return s
	}

	for _, tc := range []struct {
		name   string
		stream []byte
	}{
		{"salt in header", flip(0)},
		{"record size in header", flip(ContentSaltSize)},
		{"idlen in header", flip(ContentSaltSize + 4)},
		{"first record ciphertext", flip(headerSize + 10)},
		{"first record tag", flip(headerSize + RecordSize - 1)},
		{"last record", flip(len(stream) - 5)},
		{"trailing data appended", append(bytes.Clone(stream), 0x00)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := open(t, testFileKey(), tc.stream); !errors.Is(err, ErrContent) {
				t.Fatalf("got %v, want ErrContent", err)
			}
		})
	}
}

// Records are bound to their position by the nonce, so moving or repeating one
// must fail even though each record is individually well formed.
func TestContentRecordsAreOrderBound(t *testing.T) {
	plaintext := make([]byte, 3*maxRecordPlaintext)
	stream := seal(t, testFileKey(), plaintext)
	body := stream[headerSize:]

	swapped := bytes.Clone(stream)
	copy(swapped[headerSize:headerSize+RecordSize], body[RecordSize:2*RecordSize])
	copy(swapped[headerSize+RecordSize:headerSize+2*RecordSize], body[:RecordSize])
	if _, err := open(t, testFileKey(), swapped); !errors.Is(err, ErrContent) {
		t.Errorf("reordered records: got %v, want ErrContent", err)
	}

	replayed := bytes.Clone(stream)
	copy(replayed[headerSize+RecordSize:headerSize+2*RecordSize], body[:RecordSize])
	if _, err := open(t, testFileKey(), replayed); !errors.Is(err, ErrContent) {
		t.Errorf("replayed record: got %v, want ErrContent", err)
	}
}

func TestContentWrongFileKeyFails(t *testing.T) {
	stream := seal(t, testFileKey(), []byte("secret"))
	wrong := bytes.Repeat([]byte{0x22}, FileKeySize)
	if _, err := open(t, wrong, stream); !errors.Is(err, ErrContent) {
		t.Fatalf("got %v, want ErrContent", err)
	}
}

// The record size and key identifier are fixed by the specification. Honouring
// a value taken from the stream would make them negotiated parameters, which
// spec §11 forbids.
func TestContentRejectsNonSpecHeaderValues(t *testing.T) {
	stream := seal(t, testFileKey(), []byte("hello"))

	badRS := bytes.Clone(stream)
	binary.BigEndian.PutUint32(badRS[ContentSaltSize:ContentSaltSize+4], 4096)
	if _, err := open(t, testFileKey(), badRS); !errors.Is(err, ErrContent) {
		t.Errorf("alternative record size: got %v, want ErrContent", err)
	}

	badID := bytes.Clone(stream)
	badID[ContentSaltSize+4] = 4
	if _, err := open(t, testFileKey(), badID); !errors.Is(err, ErrContent) {
		t.Errorf("non-empty key identifier: got %v, want ErrContent", err)
	}
}

func TestContentEncryptorRejectsWriteAfterClose(t *testing.T) {
	var buf bytes.Buffer
	enc, err := NewEncryptor(&buf, testFileKey())
	if err != nil {
		t.Fatalf("new encryptor: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := enc.Write([]byte("x")); err == nil {
		t.Fatal("write after close was accepted")
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("second close should be a no-op, got %v", err)
	}
}

func TestContentRejectsBadKeySizes(t *testing.T) {
	if _, err := NewEncryptor(io.Discard, make([]byte, FileKeySize-1)); !errors.Is(err, ErrKeyMaterial) {
		t.Errorf("encryptor: got %v, want ErrKeyMaterial", err)
	}
	if _, err := NewDecryptor(bytes.NewReader(nil), make([]byte, FileKeySize-1)); !errors.Is(err, ErrKeyMaterial) {
		t.Errorf("decryptor: got %v, want ErrKeyMaterial", err)
	}
}

// Writing in awkward chunk sizes must produce the same stream as one large
// write, or the record boundaries would depend on how a caller happened to
// buffer its input.
func TestContentWriteChunkingIsIrrelevant(t *testing.T) {
	plaintext := make([]byte, 3*maxRecordPlaintext+77)
	if _, err := rand.New(rand.NewSource(7)).Read(plaintext); err != nil { //nolint:gosec // deterministic test data
		t.Fatalf("fill: %v", err)
	}
	salt := bytes.Repeat([]byte{0x33}, ContentSaltSize)

	reference := func(chunk int) []byte {
		var buf bytes.Buffer
		enc, err := newEncryptorWithSalt(&buf, testFileKey(), salt)
		if err != nil {
			t.Fatalf("new encryptor: %v", err)
		}
		for off := 0; off < len(plaintext); off += chunk {
			end := min(off+chunk, len(plaintext))
			if _, err := enc.Write(plaintext[off:end]); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		if err := enc.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		return buf.Bytes()
	}

	want := reference(len(plaintext))
	for _, chunk := range []int{1, 7, 4096, maxRecordPlaintext - 1, maxRecordPlaintext, maxRecordPlaintext + 1} {
		if got := reference(chunk); !bytes.Equal(got, want) {
			t.Errorf("chunk size %d produced a different stream", chunk)
		}
	}
}

func FuzzContentRoundTrip(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("a"))
	f.Add(bytes.Repeat([]byte{0xAB}, maxRecordPlaintext))
	f.Add(bytes.Repeat([]byte{0xCD}, maxRecordPlaintext+1))

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		stream := seal(t, testFileKey(), plaintext)
		got, err := open(t, testFileKey(), stream)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatal("round trip changed the content")
		}
	})
}

// Any single-bit change anywhere in a stream must be rejected. This is the
// property that makes truncation, reordering and modification all one failure.
func FuzzContentBitFlipIsRejected(f *testing.F) {
	f.Add(0, 0)
	f.Add(5, 3)

	stream := func() []byte {
		var buf bytes.Buffer
		enc, _ := newEncryptorWithSalt(&buf, testFileKey(), bytes.Repeat([]byte{0x44}, ContentSaltSize))
		_, _ = enc.Write(make([]byte, maxRecordPlaintext+500))
		_ = enc.Close()
		return buf.Bytes()
	}()

	f.Fuzz(func(t *testing.T, pos, bit int) {
		if pos < 0 || bit < 0 {
			t.Skip()
		}
		s := bytes.Clone(stream)
		s[pos%len(s)] ^= 1 << (bit % 8)
		if bytes.Equal(s, stream) {
			t.Skip()
		}
		if _, err := open(t, testFileKey(), s); err == nil {
			t.Fatalf("a modified stream decrypted successfully (byte %d, bit %d)", pos%len(stream), bit%8)
		}
	})
}

// The declared length is checked against the encoder itself, not against a
// second copy of the arithmetic - which would agree with a wrong answer just as
// readily.
func TestEncodedContentLengthMatchesTheEncoder(t *testing.T) {
	sizes := []int64{
		0, 1, headerSize,
		maxRecordPlaintext - 1, maxRecordPlaintext, maxRecordPlaintext + 1,
		2*maxRecordPlaintext - 1, 2 * maxRecordPlaintext, 2*maxRecordPlaintext + 1,
		3*maxRecordPlaintext + 4321,
	}

	key := bytes.Repeat([]byte{0x11}, FileKeySize)
	for _, size := range sizes {
		var out bytes.Buffer
		e, err := NewEncryptor(&out, key)
		if err != nil {
			t.Fatalf("%d bytes: encryptor: %v", size, err)
		}
		if _, err := e.Write(make([]byte, size)); err != nil {
			t.Fatalf("%d bytes: write: %v", size, err)
		}
		if err := e.Close(); err != nil {
			t.Fatalf("%d bytes: close: %v", size, err)
		}

		want := int64(out.Len())
		got, err := EncodedContentLength(size)
		if err != nil {
			t.Fatalf("%d bytes: %v", size, err)
		}
		if got != want {
			t.Errorf("plaintext of %d bytes: declared %d, encoder produced %d", size, got, want)
		}
	}
}

// Sizes nobody would have thought to enumerate. A calculation right only at the
// boundaries somebody wrote down is right by coincidence.
func TestEncodedContentLengthMatchesTheEncoderAtArbitrarySizes(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, FileKeySize)
	for i := 0; i < 16; i++ {
		size := int64(rand.Intn(3 * maxRecordPlaintext))

		var out bytes.Buffer
		e, err := NewEncryptor(&out, key)
		if err != nil {
			t.Fatalf("encryptor: %v", err)
		}
		if _, err := e.Write(make([]byte, size)); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := e.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		got, err := EncodedContentLength(size)
		if err != nil {
			t.Fatalf("%d bytes: %v", size, err)
		}
		if got != int64(out.Len()) {
			t.Errorf("plaintext of %d bytes: declared %d, encoder produced %d", size, got, out.Len())
		}
	}
}

func TestEncodedContentLengthRefusesWhatIsNotAByteCount(t *testing.T) {
	if _, err := EncodedContentLength(-1); err == nil {
		t.Error("a negative length was accepted")
	}
}

// forgeStream builds a one-record stream whose plaintext is exactly what the
// caller asks for, bypassing the encryptor.
//
// The encryptor cannot produce these: it always appends a delimiter and never
// pads. That is the point — §5.4 says a decryptor must reject them anyway,
// because a decryptor's job is to refuse what some other encoder might emit.
func forgeStream(t *testing.T, fileKey, recordPlaintext []byte) []byte {
	t.Helper()

	contentSalt := bytes.Repeat([]byte{0x11}, ContentSaltSize)
	cek, nonceBase, err := deriveContentKeys(fileKey, contentSalt)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	aead, err := newAEAD(cek)
	if err != nil {
		t.Fatalf("aead: %v", err)
	}

	header := make([]byte, 0, headerSize)
	header = append(header, contentSalt...)
	header = binary.BigEndian.AppendUint32(header, RecordSize)
	header = append(header, 0)

	return aead.Seal(header, recordNonce(nonceBase, 0), recordPlaintext, nil)
}

// §5.4: "A record's plaintext ends in anything other than 0x01 or 0x02".
//
// RFC 8188 permits zero padding after the delimiter. Accepting it would make
// two distinct encodings of one plaintext valid, which is malleability this
// profile refuses. Nothing else in either language's tests covers this: both
// implementations reject it, and until now neither would have noticed if they
// stopped.
func TestContentRejectsPaddingAfterTheDelimiter(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"final delimiter then one zero", []byte{'h', 'i', delimiterFinal, 0x00}},
		{"final delimiter then many zeros", append([]byte{'h', 'i', delimiterFinal}, make([]byte, 32)...)},
		{"no delimiter at all", []byte{'h', 'i'}},
		{"an unassigned delimiter", []byte{'h', 'i', 0x03}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := forgeStream(t, testFileKey(), tc.payload)
			if _, err := open(t, testFileKey(), stream); !errors.Is(err, ErrContent) {
				t.Errorf("got %v, want ErrContent", err)
			}
		})
	}
}

// §5.4: "A record's plaintext is empty — there is no delimiter to inspect."
//
// The record still authenticates, so this is not caught by the tag. Reading the
// final octet of an empty slice is also how a decryptor panics.
func TestContentRejectsAnEmptyRecordPlaintext(t *testing.T) {
	stream := forgeStream(t, testFileKey(), nil)

	if _, err := open(t, testFileKey(), stream); !errors.Is(err, ErrContent) {
		t.Errorf("got %v, want ErrContent", err)
	}
}
