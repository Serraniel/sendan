// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package upload

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	tus "github.com/tus/tusd/v2/pkg/handler"

	"github.com/Serraniel/sendan/internal/blob"
	"github.com/Serraniel/sendan/internal/crypto"
	"github.com/Serraniel/sendan/internal/logging"
	"github.com/Serraniel/sendan/internal/store"
)

// validMeta is the metadata a conforming client sends.
func validMeta() tus.MetaData {
	return tus.MetaData{
		metaWrappedFileKey: string(bytes.Repeat([]byte{0x01}, crypto.WrappedFileKeySize)),
		metaWrapNonce:      string(bytes.Repeat([]byte{0x02}, crypto.NonceSize)),
		metaEnvelope:       string(bytes.Repeat([]byte{0x03}, 256+crypto.TagSize)),
		metaEnvelopeNonce:  string(bytes.Repeat([]byte{0x04}, crypto.NonceSize)),
		metaAuthTokenHash:  string(bytes.Repeat([]byte{0x05}, sha256.Size)),
		metaOwnerTokenHash: string(bytes.Repeat([]byte{0x06}, sha256.Size)),
	}
}

// These checks sit behind tus's own, which rejects the same requests first. That
// makes them unreachable through the HTTP layer and is exactly why they are
// tested here: they are the layer that still holds if the protocol handler's
// configuration changes, and a check nothing exercises is a check nobody knows
// is broken.
func TestTusStoreRejectsUndeclaredLength(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	ts := NewTusStore(h.svc, 1024)

	_, err := ts.NewUpload(t.Context(), tus.FileInfo{SizeIsDeferred: true, MetaData: validMeta()})
	if err == nil {
		t.Fatal("an upload of undeclared length was accepted, so the size limit is unenforceable")
	}
}

func TestTusStoreEnforcesTheSizeLimit(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	ts := NewTusStore(h.svc, 1024)

	if _, err := ts.NewUpload(t.Context(), tus.FileInfo{Size: 2048, MetaData: validMeta()}); err == nil {
		t.Fatal("an upload beyond the limit was accepted")
	}
	if _, err := ts.NewUpload(t.Context(), tus.FileInfo{Size: 1024, MetaData: validMeta()}); err != nil {
		t.Fatalf("an upload at the limit was refused: %v", err)
	}

	// Zero means unbounded, which is a legitimate choice and must not be
	// confused with a limit of zero bytes.
	unbounded := NewTusStore(h.svc, 0)
	if _, err := unbounded.NewUpload(t.Context(), tus.FileInfo{Size: 1 << 30, MetaData: validMeta()}); err != nil {
		t.Fatalf("an unbounded instance refused a large upload: %v", err)
	}
}

// The blob is finished before the row is marked complete. A crash between the
// two leaves a finished blob belonging to an incomplete row, which the reaper
// removes; the reverse would publish a row whose content was never finished,
// and a recipient would be served something that decrypts to nothing.
func TestFinishLeavesTheRowIncompleteWhenTheBlobCannotBeFinished(t *testing.T) {
	h := newHarness(t, defaultPolicy())

	failing := New(h.store, blob.NewShredder(failingStore{}), defaultPolicy(),
		logging.New(io.Discard, logging.Options{Format: "json"}))
	failing.now = h.svc.now

	ts := NewTusStore(failing, 0)
	up, err := ts.NewUpload(t.Context(), tus.FileInfo{Size: 4, MetaData: validMeta()})
	if err != nil {
		t.Fatalf("new upload: %v", err)
	}
	info, err := up.GetInfo(t.Context())
	if err != nil {
		t.Fatalf("info: %v", err)
	}

	if err := up.FinishUpload(t.Context()); err == nil {
		t.Fatal("finishing succeeded despite the blob store failing")
	}

	// The row must still be unreachable, and still writable, so the reaper
	// collects it rather than a recipient receiving it.
	if _, err := h.store.Get(t.Context(), info.ID, h.clock); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the upload became readable after a failed finish: %v", err)
	}
	if _, err := h.store.Pending(t.Context(), info.ID); err != nil {
		t.Errorf("the upload is no longer pending, so the reaper's abandonment path will not find it: %v", err)
	}
}

// The uploader's requested lifetime is subject to the instance policy, and an
// excessive request is rejected rather than clamped: an uploader who asked for a
// week and silently received a day would believe their file outlives what it
// does.
func TestTusStoreAppliesTheRetentionPolicy(t *testing.T) {
	h := newHarness(t, Policy{DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour})
	ts := NewTusStore(h.svc, 0)

	meta := validMeta()
	meta[metaTTLSeconds] = "86400" // a day, beyond the two-hour maximum
	if _, err := ts.NewUpload(t.Context(), tus.FileInfo{Size: 4, MetaData: meta}); err == nil {
		t.Fatal("a lifetime beyond the maximum was accepted")
	}

	within := validMeta()
	within[metaTTLSeconds] = "5400" // ninety minutes
	up, err := ts.NewUpload(t.Context(), tus.FileInfo{Size: 4, MetaData: within})
	if err != nil {
		t.Fatalf("a lifetime within the maximum was refused: %v", err)
	}
	info, _ := up.GetInfo(t.Context())

	row, err := h.store.Pending(t.Context(), info.ID)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if want := h.clock.Add(90 * time.Minute); !row.ExpiresAt.Equal(want) {
		t.Errorf("expiry %s, want %s", row.ExpiresAt, want)
	}
}

// An upload in progress must not be readable through the protocol either. The
// download endpoint verifies a token first; this one would not.
func TestTusStoreRefusesToReadBackAnUpload(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	ts := NewTusStore(h.svc, 0)

	up, err := ts.NewUpload(t.Context(), tus.FileInfo{Size: 4, MetaData: validMeta()})
	if err != nil {
		t.Fatalf("new upload: %v", err)
	}
	if _, err := up.GetReader(t.Context()); err == nil {
		t.Fatal("an upload in progress was readable without a token")
	}
}

// Every fault in a client's metadata is reported at once, so a client fixing
// its request does not discover them one round trip at a time.
func TestTusStoreReportsEveryMetadataFault(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	ts := NewTusStore(h.svc, 0)

	meta := validMeta()
	delete(meta, metaWrappedFileKey)
	meta[metaWrapNonce] = "short"

	_, err := ts.NewUpload(t.Context(), tus.FileInfo{Size: 4, MetaData: meta})
	if err == nil {
		t.Fatal("malformed metadata was accepted")
	}
	msg := err.Error()
	for _, want := range []string{metaWrappedFileKey, metaWrapNonce} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error does not mention %s, so a client would fix one fault at a time:\n%s", want, msg)
		}
	}
}

// A parameter larger than its field must be refused rather than truncated. A
// parallelism of 300 stored as 44 would make a client derive with parameters
// the uploader never chose, producing a file nobody can open.
func TestArgon2ParametersAreBoundedNotTruncated(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	ts := NewTusStore(h.svc, 0)

	meta := validMeta()
	meta[metaPasswordSalt] = string(bytes.Repeat([]byte{0x5A}, crypto.PasswordSaltSize))
	meta[metaArgon2Memory] = "65536"
	meta[metaArgon2Iterations] = "3"
	meta[metaArgon2Parallel] = "300" // beyond a uint8

	if _, err := ts.NewUpload(t.Context(), tus.FileInfo{Size: 4, MetaData: meta}); err == nil {
		t.Fatal("a parallelism of 300 was accepted, and would have been stored as 44")
	}

	meta[metaArgon2Parallel] = "1"
	up, err := ts.NewUpload(t.Context(), tus.FileInfo{Size: 4, MetaData: meta})
	if err != nil {
		t.Fatalf("a valid parameter set was refused: %v", err)
	}
	info, _ := up.GetInfo(t.Context())
	row, err := h.store.Pending(t.Context(), info.ID)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if row.Password.Parallelism != 1 || row.Password.MemoryKiB != 65536 {
		t.Errorf("parameters %+v", row.Password)
	}
}

// The full lifecycle through the adapter, including resumption. A resumed
// request arrives on a new handle, which has to reload the at-rest key: without
// that the chunk would be encrypted under the wrong key and the file would
// decrypt to noise from the resumption point onwards.
func TestTusStoreLifecycleIncludingResumption(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	ts := NewTusStore(h.svc, 0)

	body := []byte(strings.Repeat("sendan..", 300)) // 2400 bytes
	up, err := ts.NewUpload(t.Context(), tus.FileInfo{Size: int64(len(body)), MetaData: validMeta()})
	if err != nil {
		t.Fatalf("new upload: %v", err)
	}
	info, _ := up.GetInfo(t.Context())

	n, err := up.WriteChunk(t.Context(), 0, bytes.NewReader(body[:1000]))
	if err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	if n != 1000 {
		t.Fatalf("wrote %d bytes, want 1000", n)
	}

	// A fresh handle, as a resumed request would produce.
	resumed, err := ts.GetUpload(t.Context(), info.ID)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	at, err := resumed.GetInfo(t.Context())
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	if at.Offset != 1000 {
		t.Fatalf("a resumed upload reports offset %d, so a client would continue from the wrong place", at.Offset)
	}
	if at.Size != int64(len(body)) {
		t.Errorf("a resumed upload reports size %d, want %d", at.Size, len(body))
	}

	// A chunk that does not continue where the stored bytes end.
	if _, err := resumed.WriteChunk(t.Context(), 500, bytes.NewReader([]byte("x"))); err == nil {
		t.Error("a chunk at the wrong offset was accepted")
	}

	if _, err := resumed.WriteChunk(t.Context(), at.Offset, bytes.NewReader(body[1000:])); err != nil {
		t.Fatalf("resumed chunk: %v", err)
	}
	if err := resumed.FinishUpload(t.Context()); err != nil {
		t.Fatalf("finish: %v", err)
	}

	// What comes out is what went in, which is what proves the key was reloaded
	// rather than regenerated.
	row, err := h.store.Get(t.Context(), info.ID, h.clock)
	if err != nil {
		t.Fatalf("the completed upload is unreachable: %v", err)
	}
	rc, err := h.blobs.Open(t.Context(), info.ID, row.AtRestKey)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = rc.Close() }()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, body) {
		for i := range got {
			if i < len(body) && got[i] != body[i] {
				t.Fatalf("a resumed upload differs from the first byte at %d", i)
			}
		}
		t.Fatalf("read %d bytes, want %d", len(got), len(body))
	}
}

// A completed upload is not writable through the protocol, and neither is one
// that never existed.
func TestTusStoreGetUploadRefusesWhatCannotBeWritten(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	ts := NewTusStore(h.svc, 0)

	up, err := ts.NewUpload(t.Context(), tus.FileInfo{Size: 4, MetaData: validMeta()})
	if err != nil {
		t.Fatalf("new upload: %v", err)
	}
	info, _ := up.GetInfo(t.Context())

	if _, err := up.WriteChunk(t.Context(), 0, bytes.NewReader([]byte("abcd"))); err != nil {
		t.Fatalf("chunk: %v", err)
	}
	if err := up.FinishUpload(t.Context()); err != nil {
		t.Fatalf("finish: %v", err)
	}

	if _, err := ts.GetUpload(t.Context(), info.ID); err == nil {
		t.Error("a completed upload is still writable, so its content could be replaced")
	}
	if _, err := ts.GetUpload(t.Context(), "NOSUCHAAAAAAAAAAAAAAAA"); err == nil {
		t.Error("an unknown upload was accepted")
	}
}

// The policy default applies when an instance does not choose one, so an
// operator who sets nothing still gets abandoned uploads collected.
func TestIncompleteTTLFallsBackToTheDefault(t *testing.T) {
	h := newHarness(t, Policy{DefaultTTL: time.Hour, MaxTTL: time.Hour})
	if got := h.svc.incompleteTTL(); got != DefaultIncompleteTTL {
		t.Errorf("incompleteTTL is %s with no policy set, want %s", got, DefaultIncompleteTTL)
	}

	chosen := newHarness(t, Policy{DefaultTTL: time.Hour, MaxTTL: time.Hour, IncompleteTTL: time.Minute})
	if got := chosen.svc.incompleteTTL(); got != time.Minute {
		t.Errorf("incompleteTTL is %s, want the configured minute", got)
	}
}

// A count that does not fit an int must be refused rather than wrapped. On a
// platform where int is 32 bits, a large value would become a download limit
// the uploader never set.
func TestOutOfRangeCountsAreRefused(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	ts := NewTusStore(h.svc, 0)

	for _, value := range []string{"4294967296", "9223372036854775807"} {
		meta := validMeta()
		meta[metaMaxDownloads] = value
		if _, err := ts.NewUpload(t.Context(), tus.FileInfo{Size: 4, MetaData: meta}); err == nil {
			t.Errorf("maxDownloads of %s was accepted", value)
		}
	}

	// A value that fits is still accepted, so the bound is not simply refusing
	// everything.
	meta := validMeta()
	meta[metaMaxDownloads] = "5"
	up, err := ts.NewUpload(t.Context(), tus.FileInfo{Size: 4, MetaData: meta})
	if err != nil {
		t.Fatalf("a download limit of five was refused: %v", err)
	}
	info, _ := up.GetInfo(t.Context())
	row, err := h.store.Pending(t.Context(), info.ID)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if row.MaxDownloads != 5 {
		t.Errorf("max downloads %d, want 5", row.MaxDownloads)
	}
}

// The Argon2id memory parameter is a uint32, so a value beyond it must be
// refused for the same reason parallelism is.
func TestArgon2MemoryIsBounded(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	ts := NewTusStore(h.svc, 0)

	meta := validMeta()
	meta[metaPasswordSalt] = string(bytes.Repeat([]byte{0x5A}, crypto.PasswordSaltSize))
	meta[metaArgon2Memory] = "4294967296" // one beyond a uint32
	meta[metaArgon2Iterations] = "3"
	meta[metaArgon2Parallel] = "1"

	if _, err := ts.NewUpload(t.Context(), tus.FileInfo{Size: 4, MetaData: meta}); err == nil {
		t.Fatal("an out-of-range memory parameter was accepted")
	}
}
