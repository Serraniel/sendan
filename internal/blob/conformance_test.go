// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package blob_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path"
	"testing"

	"github.com/Serraniel/sendan/internal/blob"
	"github.com/Serraniel/sendan/internal/blob/blobtest"
)

func TestFSConformance(t *testing.T) {
	blobtest.Run(t, func(t *testing.T) blob.Store {
		s, err := blob.NewFS(t.TempDir())
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		return s
	})
}

// SENDAN_TEST_S3 is set by continuous integration, which runs a MinIO service
// container. In CI a missing variable is a failure rather than a skip: a
// skipped test is indistinguishable from a passing one, so a misconfigured
// container would leave this backend untested behind a green check.
func TestS3Conformance(t *testing.T) {
	raw := os.Getenv("SENDAN_TEST_S3")
	if raw == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("SENDAN_TEST_S3 is unset in CI: the object store service container is missing or misconfigured, " +
				"and skipping here would leave the backend untested behind a green check")
		}
		t.Skip("SENDAN_TEST_S3 is not set; skipping the S3 conformance suite")
	}

	cfg, err := blob.ParseS3URL(raw)
	if err != nil {
		t.Fatalf("parse SENDAN_TEST_S3: %v", err)
	}

	blobtest.Run(t, func(t *testing.T) blob.Store {
		// A prefix per store, so each case gets a namespace of its own. The
		// filesystem factory gets this from t.TempDir; without it the object
		// store would carry state between cases and between runs - which is
		// how the partial-upload cases first failed, resuming a spool file an
		// earlier run had left behind.
		suffix := make([]byte, 8)
		if _, err := rand.Read(suffix); err != nil {
			t.Fatalf("random prefix: %v", err)
		}
		isolated := cfg
		isolated.Prefix = path.Join(cfg.Prefix, hex.EncodeToString(suffix))

		s, err := blob.NewS3(t.Context(), isolated)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		return s
	})
}

func TestParseS3URL(t *testing.T) {
	cfg, err := blob.ParseS3URL("s3://key:secret@localhost:9000/sendan/instance-one?ssl=false&region=eu-central-1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Endpoint != "localhost:9000" || cfg.Bucket != "sendan" || cfg.Prefix != "instance-one" {
		t.Fatalf("got %+v", cfg)
	}
	if cfg.AccessKeyID != "key" || cfg.SecretAccessKey != "secret" {
		t.Fatal("credentials were not parsed")
	}
	if cfg.UseSSL {
		t.Error("ssl=false was ignored")
	}
	if cfg.Region != "eu-central-1" {
		t.Errorf("region = %q", cfg.Region)
	}

	// TLS is the default: an operator who forgets the parameter gets the safe
	// behaviour rather than a plaintext connection.
	secure, err := blob.ParseS3URL("s3://k:s@example.com/bucket")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !secure.UseSSL {
		t.Error("TLS must be the default")
	}

	for _, bad := range []string{
		"file:///tmp/blobs",
		"s3://",
		"s3://endpoint-only",
		"://nonsense",
	} {
		if _, err := blob.ParseS3URL(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// The shredder seeks by rebuilding the keystream at an offset, and an object
// store seeks by issuing range requests. The two composing correctly is what
// makes a resumed download work against S3, and neither suite covers it alone.
func TestShredderOverS3(t *testing.T) {
	raw := os.Getenv("SENDAN_TEST_S3")
	if raw == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("SENDAN_TEST_S3 is unset in CI")
		}
		t.Skip("SENDAN_TEST_S3 is not set")
	}
	cfg, err := blob.ParseS3URL(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	inner, err := blob.NewS3(t.Context(), cfg)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	s := blob.NewShredder(inner)
	id := blobtest.NewID(t)
	key, err := blob.NewAtRestKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	content := make([]byte, 40000)
	for i := range content {
		content[i] = byte(i % 251)
	}
	if _, err := s.Put(t.Context(), id, key, bytes.NewReader(content)); err != nil {
		t.Fatalf("put: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(context.Background(), id) })

	// Offsets that are not block aligned are where a keystream error shows.
	for _, offset := range []int64{0, 1, 15, 16, 17, 4095, 20000, 39999} {
		r, err := s.Open(t.Context(), id, key)
		if err != nil {
			t.Fatalf("offset %d: open: %v", offset, err)
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

	// And the stored object must not be the plaintext.
	rawObj, err := inner.Open(t.Context(), id)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	stored, err := io.ReadAll(rawObj)
	_ = rawObj.Close()
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if bytes.Equal(stored, content) {
		t.Fatal("the object was stored unencrypted")
	}
}
