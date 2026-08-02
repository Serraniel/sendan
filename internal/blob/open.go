// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package blob

import (
	"context"
	"fmt"
	"strings"
)

// Open returns the blob store described by a location.
//
// Accepted forms:
//
//	file:<path>                             a directory, created if absent
//	s3://key:secret@endpoint/bucket/prefix  an S3-compatible object store
//
// An unrecognised form is an error rather than a fallback to the default, for
// the same reason as [store.Open]: storing uploads somewhere other than where
// the operator asked is worse than refusing to start.
func Open(ctx context.Context, location string) (Store, error) {
	switch {
	case strings.HasPrefix(location, "file:"):
		path := strings.TrimPrefix(location, "file:")
		if path == "" {
			return nil, fmt.Errorf("blob: file location has no path: %q", location)
		}
		return NewFS(path)

	case strings.HasPrefix(location, "s3://"):
		cfg, err := ParseS3URL(location)
		if err != nil {
			return nil, err
		}
		return NewS3(ctx, cfg)

	default:
		return nil, fmt.Errorf(
			"blob: unrecognised storage location %q: expected file:<path> or s3://<endpoint>/<bucket>", location)
	}
}
