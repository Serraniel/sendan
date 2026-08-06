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

// ErrOffset reports a chunk written at a position that is not where the stored
// partial upload ends.
//
// It is a distinct error because a client can act on it: the correct response
// is to ask how much was stored and resume from there, not to retry the same
// chunk.
var ErrOffset = errors.New("blob: chunk does not continue the upload")

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

	// Delete removes the blob, and any partial upload under the same
	// identifier. Deleting one that does not exist is not an error: expiry and
	// manual revocation can race, and neither should fail because the other
	// won.
	Delete(ctx context.Context, id string) error

	// WriteChunk appends r to a partial upload under id, which must begin at
	// offset. It reports how many bytes were written.
	//
	// The offset is checked rather than trusted. A client resuming an
	// interrupted upload reports where it believes it stopped, and writing at a
	// position that does not match what is stored would leave a blob with a gap
	// or an overlap - content that decrypts to nothing at the point of failure,
	// discovered by the recipient rather than by the server.
	//
	// A partial upload is not readable and does not exist as a blob until
	// Finish is called.
	WriteChunk(ctx context.Context, id string, offset int64, r io.Reader) (int64, error)

	// Length reports how many bytes of a partial upload are stored, which is
	// where a resuming client must continue from. It returns ErrNotFound if
	// there is no partial upload under id.
	Length(ctx context.Context, id string) (int64, error)

	// Finish promotes a partial upload to a blob. Until it returns, Open
	// reports ErrNotFound: a half-written upload must never be readable, since
	// what it decrypts to is not what the uploader sent.
	Finish(ctx context.Context, id string) error
}
