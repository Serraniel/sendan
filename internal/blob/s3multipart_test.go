// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package blob_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/Serraniel/sendan/internal/blob"
)

// The conformance suite covers the contract every backend keeps, with blobs
// small enough to fit in one part. These cover what is specific to storing a
// chunked upload as a multipart upload, which the conformance cases never
// reach: the part boundary, and that nothing is kept on this machine.

// s3Config gives each test a namespace of its own, so nothing carries between
// them or between runs.
func s3Config(t *testing.T) blob.S3Config {
	t.Helper()

	raw := os.Getenv("SENDAN_TEST_S3")
	if raw == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("SENDAN_TEST_S3 is unset in CI: the object store service container is " +
				"missing, and skipping here would leave multipart uploads untested behind a " +
				"green check")
		}
		t.Skip("SENDAN_TEST_S3 is not set; skipping the multipart tests")
	}

	cfg, err := blob.ParseS3URL(raw)
	if err != nil {
		t.Fatalf("parse SENDAN_TEST_S3: %v", err)
	}

	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("random prefix: %v", err)
	}
	cfg.Prefix = path.Join(cfg.Prefix, hex.EncodeToString(suffix))
	return cfg
}

func s3Store(t *testing.T, cfg blob.S3Config) *blob.S3 {
	t.Helper()
	s, err := blob.NewS3(t.Context(), cfg)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return s
}

func digest(t *testing.T, r io.Reader) string {
	t.Helper()
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		t.Fatalf("digest: %v", err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// The case the tail object exists for. A part must be at least 5 MiB, and a
// client that sends less than that per request would otherwise never fill one -
// the offset would stay at zero however much it sent, and the upload would
// never end.
func TestChunksSmallerThanAPartStillMakeProgress(t *testing.T) {
	s := s3Store(t, s3Config(t))
	ctx := t.Context()

	// Twelve mebibytes in one-mebibyte chunks: two whole parts and a remainder,
	// from requests none of which could be a part on their own.
	const chunk = 1 << 20
	content := make([]byte, 12*chunk)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}

	const id = "chunkedacrossparts----"
	var offset int64
	for offset < int64(len(content)) {
		end := min(offset+chunk, int64(len(content)))

		n, err := s.WriteChunk(ctx, id, offset, bytes.NewReader(content[offset:end]))
		if err != nil {
			t.Fatalf("chunk at %d: %v", offset, err)
		}
		if n != end-offset {
			t.Fatalf("chunk at %d wrote %d bytes, want %d", offset, n, end-offset)
		}
		offset += n

		// The offset a resuming client would be given has to be the offset the
		// next chunk is accepted at, whether or not a part boundary fell here.
		stored, err := s.Length(ctx, id)
		if err != nil {
			t.Fatalf("length at %d: %v", offset, err)
		}
		if stored != offset {
			t.Fatalf("stored %d bytes after writing %d", stored, offset)
		}
	}

	if err := s.Finish(ctx, id); err != nil {
		t.Fatalf("finish: %v", err)
	}

	r, err := s.Open(ctx, id)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = r.Close() }()

	if got, want := digest(t, r), digest(t, bytes.NewReader(content)); got != want {
		t.Error("what came back is not what went in")
	}
}

// A chunk that lands exactly on a part boundary leaves no tail, and the next
// one starts a new part. Off-by-one country: an implementation that always
// wrote a tail would store an empty object, and one that never did would lose
// the boundary case.
func TestAChunkEndingOnAPartBoundary(t *testing.T) {
	s := s3Store(t, s3Config(t))
	ctx := t.Context()

	const part = 5 << 20
	content := make([]byte, 2*part)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}

	const id = "exactpartboundary-----"
	if _, err := s.WriteChunk(ctx, id, 0, bytes.NewReader(content[:part])); err != nil {
		t.Fatalf("first part: %v", err)
	}
	if got, err := s.Length(ctx, id); err != nil || got != part {
		t.Fatalf("length after one whole part: %d, %v", got, err)
	}
	if _, err := s.WriteChunk(ctx, id, part, bytes.NewReader(content[part:])); err != nil {
		t.Fatalf("second part: %v", err)
	}
	if err := s.Finish(ctx, id); err != nil {
		t.Fatalf("finish: %v", err)
	}

	r, err := s.Open(ctx, id)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = r.Close() }()

	if got, want := digest(t, r), digest(t, bytes.NewReader(content)); got != want {
		t.Error("what came back is not what went in")
	}
}

// The point of the change. A second instance - another replica behind a load
// balancer, or the same one after a restart - continues an upload it never saw
// the beginning of, because nothing about it was ever held in the first
// process.
func TestASecondInstanceResumesAnUpload(t *testing.T) {
	cfg := s3Config(t)
	ctx := context.Background()

	first := s3Store(t, cfg)

	const part = 5 << 20
	content := make([]byte, part+1234)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}

	const id = "resumedelsewhere------"
	const cut = part + 100
	if _, err := first.WriteChunk(ctx, id, 0, bytes.NewReader(content[:cut])); err != nil {
		t.Fatalf("first instance: %v", err)
	}

	second := s3Store(t, cfg)

	stored, err := second.Length(ctx, id)
	if err != nil {
		t.Fatalf("the second instance cannot see the upload: %v", err)
	}
	if stored != cut {
		t.Fatalf("the second instance sees %d bytes, want %d", stored, cut)
	}

	if _, err := second.WriteChunk(ctx, id, stored, bytes.NewReader(content[cut:])); err != nil {
		t.Fatalf("second instance: %v", err)
	}
	if err := second.Finish(ctx, id); err != nil {
		t.Fatalf("finish: %v", err)
	}

	r, err := second.Open(ctx, id)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = r.Close() }()

	if got, want := digest(t, r), digest(t, bytes.NewReader(content)); got != want {
		t.Error("an upload finished by another instance is not what was sent")
	}
}

// The cost this change exists to remove. A partial upload used to occupy local
// disk equal to its size; it must now occupy none.
func TestAPartialUploadTouchesNoLocalDisk(t *testing.T) {
	s := s3Store(t, s3Config(t))
	ctx := t.Context()

	before := spoolFiles(t)

	content := make([]byte, (5<<20)+4096)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteChunk(ctx, "nolocaldiskatall------", 0, bytes.NewReader(content)); err != nil {
		t.Fatalf("chunk: %v", err)
	}

	if after := spoolFiles(t); after != before {
		t.Errorf("a partial upload left %d files in the temporary directory", after-before)
	}
}

func spoolFiles(t *testing.T) int {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(os.TempDir(), "sendan-spool", "*", "*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	return len(matches)
}

// An abandoned multipart upload holds storage exactly as an abandoned spool
// file held disk. Deleting is what the reaper calls, so this is what stops
// unfinished uploads accumulating in the bucket forever.
func TestDeleteAbortsAnUnfinishedMultipartUpload(t *testing.T) {
	cfg := s3Config(t)
	s := s3Store(t, cfg)
	ctx := t.Context()

	content := make([]byte, (5<<20)+7000)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}

	const id = "abandonedupload-------"
	if _, err := s.WriteChunk(ctx, id, 0, bytes.NewReader(content)); err != nil {
		t.Fatalf("chunk: %v", err)
	}
	if _, err := s.Length(ctx, id); err != nil {
		t.Fatalf("the upload should exist before it is deleted: %v", err)
	}

	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Gone entirely, not merely unreadable: an aborted upload stops being
	// charged for, an orphaned one does not.
	if _, err := s.Length(ctx, id); !errors.Is(err, blob.ErrNotFound) {
		t.Errorf("after deleting, Length gave %v, want ErrNotFound", err)
	}
	if _, err := s.Open(ctx, id); !errors.Is(err, blob.ErrNotFound) {
		t.Errorf("after deleting, Open gave %v, want ErrNotFound", err)
	}
}

// An upload of nothing is still an upload somebody asked to store. A multipart
// upload with no parts cannot be completed, so this is the one case that does
// not end in CompleteMultipartUpload - and the blob still has to exist.
func TestAnUploadOfNothingFinishes(t *testing.T) {
	s := s3Store(t, s3Config(t))
	ctx := t.Context()

	const id = "uploadofnothing-------"
	if _, err := s.WriteChunk(ctx, id, 0, bytes.NewReader(nil)); err != nil {
		t.Fatalf("empty chunk: %v", err)
	}
	if err := s.Finish(ctx, id); err != nil {
		t.Fatalf("finish: %v", err)
	}

	r, err := s.Open(ctx, id)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = r.Close() }()

	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(b) != 0 {
		t.Errorf("an empty upload read back %d bytes", len(b))
	}
}

// failingReader delivers some bytes and then fails, as a connection dropped
// mid-request does.
type failingReader struct {
	data []byte
	at   int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.at >= len(r.data) {
		return 0, errors.New("connection reset")
	}
	n := copy(p, r.data[r.at:])
	r.at += n
	return n, nil
}

// A chunk that fails partway must keep what arrived, so the client resumes from
// where the bytes end rather than re-sending everything. Across a part boundary,
// because that is where whole parts and the tail have to agree with each other.
func TestAFailedChunkKeepsWhatArrivedAcrossAPartBoundary(t *testing.T) {
	s := s3Store(t, s3Config(t))
	ctx := t.Context()

	const part = 5 << 20
	content := make([]byte, part+9000)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}

	const id = "failedacrosspart------"
	written, err := s.WriteChunk(ctx, id, 0, &failingReader{data: content})
	if err == nil {
		t.Fatal("a reader that failed was reported as success")
	}

	stored, err := s.Length(ctx, id)
	if err != nil {
		t.Fatalf("length after a failed chunk: %v", err)
	}
	if stored != written {
		t.Errorf("reported %d bytes written but stored %d; a client resuming at "+
			"the reported offset would leave a gap", written, stored)
	}

	// And the upload continues from there.
	if _, err := s.WriteChunk(ctx, id, stored, bytes.NewReader(content[stored:])); err != nil {
		t.Fatalf("resuming after a failure: %v", err)
	}
	if err := s.Finish(ctx, id); err != nil {
		t.Fatalf("finish: %v", err)
	}

	r, err := s.Open(ctx, id)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = r.Close() }()

	if got, want := digest(t, r), digest(t, bytes.NewReader(content)); got != want {
		t.Error("an upload resumed after a failure is not what was sent")
	}
}
