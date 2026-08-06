// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package blob

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3 stores blobs in an S3-compatible object store.
//
// minio-go is used rather than the AWS SDK: it is pure Go, far smaller, and
// targets the S3 protocol rather than one vendor's implementation of it, which
// matters because the deployments this serves are usually MinIO, Garage or
// Backblaze rather than AWS.
//
// The bytes stored here have already passed through [Shredder], so an object
// store operator sees ciphertext whose key lives in the metadata database.
type S3 struct {
	client *minio.Client
	bucket string
	prefix string

	// spool holds chunked uploads on local disk until they are complete.
	//
	// Objects are immutable, so an object store cannot be appended to. The
	// alternative is a multipart upload, whose parts must be at least 5 MiB
	// except the last - a constraint tus clients know nothing about, so chunks
	// would have to be buffered to a part boundary anyway. Spooling the whole
	// upload is the same idea with the part tracking removed.
	//
	// The cost is local disk equal to the upload, and that a partial upload
	// does not survive losing the machine it was spooled on. Both are recorded
	// in docs/design.md; multipart is issue #111.
	spool spool
}

var _ Store = (*S3)(nil)

// S3Config describes an object store.
type S3Config struct {
	// Endpoint is the host and optional port, without a scheme.
	Endpoint string
	Bucket   string
	// Prefix is an optional key prefix, so one bucket can hold more than one
	// instance's blobs.
	Prefix          string
	AccessKeyID     string
	SecretAccessKey string
	Region          string
	UseSSL          bool
}

// ParseS3URL builds a configuration from an s3:// URL.
//
// The form is s3://key:secret@endpoint/bucket/prefix, with ?ssl=false for a
// plaintext endpoint such as a local MinIO.
func ParseS3URL(raw string) (S3Config, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return S3Config{}, fmt.Errorf("blob: parse storage url: %w", err)
	}
	if u.Scheme != "s3" {
		return S3Config{}, fmt.Errorf("blob: storage url scheme is %q, want s3", u.Scheme)
	}
	if u.Host == "" {
		return S3Config{}, errors.New("blob: storage url has no endpoint")
	}

	parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 2)
	if parts[0] == "" {
		return S3Config{}, errors.New("blob: storage url has no bucket")
	}

	cfg := S3Config{
		Endpoint: u.Host,
		Bucket:   parts[0],
		Region:   u.Query().Get("region"),
		UseSSL:   u.Query().Get("ssl") != "false",
	}
	if len(parts) > 1 {
		cfg.Prefix = strings.Trim(parts[1], "/")
	}
	if u.User != nil {
		cfg.AccessKeyID = u.User.Username()
		cfg.SecretAccessKey, _ = u.User.Password()
	}
	return cfg, nil
}

// NewS3 connects to an object store and verifies the bucket exists.
//
// The bucket is not created. Creating one silently would hide a typo in the
// configuration behind a working but wrong deployment.
func NewS3(ctx context.Context, cfg S3Config) (*S3, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("blob: no bucket configured")
	}

	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("blob: connect: %w", err)
	}

	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("blob: check bucket: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("blob: bucket %q does not exist", cfg.Bucket)
	}

	// One spool directory per bucket and prefix, so two instances sharing a
	// machine do not collide, and so a restart finds what it left behind.
	spoolDir := filepath.Join(os.TempDir(), "sendan-spool",
		fmt.Sprintf("%x", sha256.Sum256([]byte(cfg.Endpoint+"/"+cfg.Bucket+"/"+cfg.Prefix))))
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		return nil, fmt.Errorf("blob: create spool directory: %w", err)
	}

	return &S3{
		client: client,
		bucket: cfg.Bucket,
		prefix: strings.Trim(cfg.Prefix, "/"),
		spool:  spool{dir: spoolDir},
	}, nil
}

// key maps an identifier to an object key, validating it first.
//
// The same allowlist as the filesystem backend applies. An object store has no
// notion of parent directories, but a key containing a separator would still
// place the object somewhere the instance does not expect, and consistency
// between backends is worth more than reasoning about each one's quirks.
func (s *S3) key(id string) (string, error) {
	if err := validateID(id); err != nil {
		return "", err
	}
	if s.prefix == "" {
		return id, nil
	}
	return s.prefix + "/" + id, nil
}

// Put stores the contents of r.
//
// The size is unknown, so minio streams with multipart uploads. A failed or
// cancelled transfer aborts the multipart upload rather than leaving parts
// behind, which is what keeps a partial blob from being readable.
func (s *S3) Put(ctx context.Context, id string, r io.Reader) (int64, error) {
	key, err := s.key(id)
	if err != nil {
		return 0, err
	}
	info, err := s.client.PutObject(ctx, s.bucket, key, r, -1, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return 0, fmt.Errorf("blob: put: %w", err)
	}
	return info.Size, nil
}

// Open returns the object. minio's reader satisfies io.ReadSeekCloser by
// issuing range requests, so seeking works without buffering the blob.
func (s *S3) Open(ctx context.Context, id string) (io.ReadSeekCloser, error) {
	key, err := s.key(id)
	if err != nil {
		return nil, err
	}
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("blob: open: %w", err)
	}
	// GetObject is lazy: it reports a missing object only on first use, so
	// absence has to be established here rather than surfacing mid-download.
	if _, err := obj.Stat(); err != nil {
		_ = obj.Close()
		if isNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("blob: stat: %w", err)
	}
	return obj, nil
}

// Delete removes the object. Removing one that does not exist is not an error.
func (s *S3) Delete(ctx context.Context, id string) error {
	key, err := s.key(id)
	if err != nil {
		return err
	}
	if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil && !isNotFound(err) {
		return fmt.Errorf("blob: delete: %w", err)
	}

	// Reached even when no object exists, because the case that matters most is
	// an upload that was never finished: there is no object, only a spool file
	// holding everything the uploader sent.
	return s.spool.remove(id)
}

func isNotFound(err error) bool {
	var resp minio.ErrorResponse
	if errors.As(err, &resp) {
		return resp.Code == "NoSuchKey" || resp.StatusCode == 404
	}
	return false
}

// WriteChunk appends to a partial upload held on local disk.
func (s *S3) WriteChunk(ctx context.Context, id string, offset int64, r io.Reader) (int64, error) {
	return s.spool.writeChunk(ctx, id, offset, r)
}

// Length reports how many bytes of a partial upload are stored.
func (s *S3) Length(_ context.Context, id string) (int64, error) {
	return s.spool.length(id)
}

// Finish uploads the spooled bytes as an object and discards the spool.
//
// The object appears only once it is complete, because a single PutObject is
// atomic from a reader's point of view: there is no window in which a partial
// object is readable.
func (s *S3) Finish(ctx context.Context, id string) error {
	key, err := s.key(id)
	if err != nil {
		return err
	}

	f, err := s.spool.open(id)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("blob: stat partial: %w", err)
	}

	if _, err := s.client.PutObject(ctx, s.bucket, key, f, info.Size(),
		minio.PutObjectOptions{ContentType: "application/octet-stream"}); err != nil {
		return fmt.Errorf("blob: finish: %w", err)
	}

	// Removed only after the object exists. A crash between the two leaves a
	// spool file, which the reaper discards; the reverse would lose the upload.
	if err := f.Close(); err != nil {
		return fmt.Errorf("blob: close partial: %w", err)
	}
	return s.spool.remove(id)
}
