// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Package blob stores upload ciphertext.
//
// Everything here handles bytes that are already end-to-end encrypted, so a
// blob store never sees plaintext and never holds a key that could recover it.
// Its own at-rest encryption exists for a different purpose: see [Shredder].
package blob

import (
	"context"
	"errors"
	"io"
)

// ErrNotFound reports that no blob exists under an identifier.
var ErrNotFound = errors.New("blob: not found")

// ErrInvalidID reports an identifier that is not well formed.
//
// Identifiers reach this package from request paths, so rejecting anything
// unexpected is what keeps a crafted value from escaping the storage root.
var ErrInvalidID = errors.New("blob: invalid identifier")

// Store is streaming blob storage.
//
// Implementations must never require the whole blob in memory: a single upload
// may be larger than the machine's RAM.
type Store interface {
	// Put stores the contents of r under id and reports how many bytes were
	// written. A failed Put leaves nothing behind, including on cancellation.
	Put(ctx context.Context, id string, r io.Reader) (int64, error)

	// Open returns the blob positioned at its start. Seeking is supported so
	// that a download can be resumed with a range request.
	Open(ctx context.Context, id string) (io.ReadSeekCloser, error)

	// Delete removes the blob. Deleting one that does not exist is not an
	// error: expiry and manual revocation can race, and neither should fail
	// because the other won.
	Delete(ctx context.Context, id string) error
}
