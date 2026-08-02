// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
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

	return &S3{client: client, bucket: cfg.Bucket, prefix: strings.Trim(cfg.Prefix, "/")}, nil
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
	if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("blob: delete: %w", err)
	}
	return nil
}

func isNotFound(err error) bool {
	var resp minio.ErrorResponse
	if errors.As(err, &resp) {
		return resp.Code == "NoSuchKey" || resp.StatusCode == 404
	}
	return false
}
