// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Command s3-bucket creates the bucket the S3 tests expect, and waits for the
// object store to be able to serve it.
//
// # Why this exists rather than a client binary
//
// The fixture used to download the object store vendor's own command-line
// client. That broke twice over, and both failures were the same shape: a
// third party decided what the fixture ran. First the archived client's URL
// began answering with a notice page, which `curl` without --fail wrote to a
// path on PATH and the next line executed. Then the server image itself
// stopped being anonymously pullable. Each time a green branch turned red
// without a commit touching it.
//
// This has no such dependency. It speaks S3 with the library the application
// already speaks S3 with, so the fixture is built from the same code under
// test and is as reproducible as the module graph - which is pinned.
//
// # Credentials
//
// From SENDAN_TEST_S3, the variable the tests themselves read. Never an
// argument: an argument appears in the process list, in shell history, and in
// whatever a continuous-integration job records of a step's command line.
// Taking the same variable also means the fixture cannot create a bucket in a
// place the tests are not looking at.
//
// # Why it waits, and why it writes
//
// A container is accepting connections before it is serving its API, and an
// object store that is still electing or opening its store answers a perfectly
// well-formed request with a 500. Retrying here keeps that out of the
// workflow, where the alternative is a health-check loop per server and a
// sleep long enough for the slowest runner.
//
// Creating the bucket is not enough to know the store can hold anything.
// Buckets are metadata; the disk is not. On a nearly full disk a store refuses
// to allocate space for data while answering every metadata request happily -
// so this created the bucket, reported success, and the first upload in the
// suite then blocked until the test timeout, ten minutes later, with a stack
// in the S3 client and nothing about disks anywhere. So it stores a byte and
// removes it again. What is being proven is that a `put` can complete, which
// is the only readiness that matters to what runs next.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Serraniel/sendan/internal/blob"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// How long to keep trying. Generous, because the cost of being wrong is
// asymmetric: a few seconds of waiting against a red check on an unrelated
// pull request.
const (
	patience = 90 * time.Second
	interval = time.Second
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "s3-bucket: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	raw := os.Getenv("SENDAN_TEST_S3")
	if raw == "" {
		return errors.New("SENDAN_TEST_S3 is unset; there is no object store to prepare")
	}

	cfg, err := blob.ParseS3URL(raw)
	if err != nil {
		return err
	}

	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), patience)
	defer cancel()

	var last error
	for {
		if err := ensure(ctx, client, cfg); err != nil {
			last = err
		} else if err := probe(ctx, client, cfg); err != nil {
			last = err
		} else {
			fmt.Printf("bucket %q on %s holds what is put in it\n", cfg.Bucket, cfg.Endpoint)
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("the object store did not become ready within %s; last attempt: %w", patience, last)
		case <-time.After(interval):
		}
	}
}

// ensure creates the bucket if it is absent, and reports success if it is
// already there.
//
// Already existing is not an error: the fixture runs again on a rerun of a job
// whose store survived, and a second run must be as quiet as the first.
func ensure(ctx context.Context, client *minio.Client, cfg blob.S3Config) error {
	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return fmt.Errorf("check bucket: %w", err)
	}
	if exists {
		return nil
	}

	err = client.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{Region: cfg.Region})
	if err == nil {
		return nil
	}
	// A concurrent creation is the same outcome as ours.
	if minio.ToErrorResponse(err).Code == "BucketAlreadyOwnedByYou" {
		return nil
	}
	return fmt.Errorf("create bucket: %w", err)
}

// probe writes an object and removes it.
//
// Under a prefix of its own, so it cannot be mistaken for a blob and cannot
// collide with a test that is listing. The removal is not deferred to a
// cleanup: if it fails, that is worth reporting too, since a store that
// accepts writes and refuses deletes fails the suite later for a reason this
// would have named here.
func probe(ctx context.Context, client *minio.Client, cfg blob.S3Config) error {
	const key = "sendan-fixture-probe/writable"

	_, err := client.PutObject(ctx, cfg.Bucket, key, strings.NewReader("."), 1, minio.PutObjectOptions{})
	if err != nil {
		return fmt.Errorf("the store took the bucket but not an object, which is what a full disk looks like: %w", err)
	}
	if err := client.RemoveObject(ctx, cfg.Bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("remove probe object: %w", err)
	}
	return nil
}
