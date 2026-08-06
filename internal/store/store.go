// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Package store persists upload metadata.
//
// Everything here is opaque to the server. The wrapped file key, the metadata
// envelope and the token hashes are all values the client produced; none can be
// interpreted without the link secret, which never reaches this process.
//
// # No tombstones
//
// Sendan promises that an expired upload leaves nothing behind. There is
// deliberately no deleted_at column, no soft-delete flag and no audit table
// keyed by upload identifier: deletion removes the row. See docs/design.md §3.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound reports that no live upload exists under an identifier.
	//
	// An expired or exhausted upload is reported as not found rather than as
	// expired, so that a caller cannot distinguish "never existed" from
	// "existed and is gone".
	ErrNotFound = errors.New("store: not found")

	// ErrExhausted reports that an upload exists but its download limit is
	// already reached.
	ErrExhausted = errors.New("store: download limit reached")

	// ErrConflict reports an attempt to create an upload that already exists.
	ErrConflict = errors.New("store: already exists")

	// ErrInvalid reports malformed input.
	ErrInvalid = errors.New("store: invalid upload")
)

// PasswordParams are the Argon2id parameters for a password-protected upload.
//
// They are stored unencrypted because a client must know them before it can
// derive anything. They disclose only that a password exists.
type PasswordParams struct {
	Salt        []byte
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
}

// Upload is one stored upload.
//
// Every byte slice here is client-produced ciphertext or a hash. The server
// cannot read any of it.
type Upload struct {
	// ID is the base64url file identifier, also the blob store key.
	ID string

	// WrappedFileKey and WrapNonce are the file key sealed under a key derived
	// from the link secret (spec §6).
	WrappedFileKey []byte
	WrapNonce      []byte

	// MetadataEnvelope and MetadataNonce hold the encrypted filename, media
	// type and size (spec §7).
	MetadataEnvelope []byte
	MetadataNonce    []byte

	// AuthTokenHash verifies a download token (spec §8.1). The server never
	// holds the token itself.
	AuthTokenHash []byte
	// OwnerTokenHash verifies a revocation request (spec §8.2).
	OwnerTokenHash []byte

	// AtRestKey encrypts the blob on disk, so deleting this row destroys the
	// content. See internal/blob and issue #73.
	AtRestKey []byte

	// Password is nil unless the upload is password protected.
	Password *PasswordParams

	// Size is the stored ciphertext length in bytes.
	Size int64

	CreatedAt time.Time
	// ExpiresAt is zero when the upload never expires, which requires
	// SENDAN_ALLOW_INFINITE_TTL.
	ExpiresAt time.Time

	// MaxDownloads is zero when there is no download limit.
	MaxDownloads int
	// DownloadCount is how many whole files' worth of bytes have been served.
	// It is derived from BytesServed rather than incremented per request, so a
	// resumed transfer counts once and an abandoned one counts for what it
	// actually consumed.
	DownloadCount int

	// BytesServed is the total content served for this upload.
	BytesServed int64

	// CompletedAt is zero while the upload is still being written.
	//
	// An upload exists before it is complete, because chunks are encrypted with
	// this row's at-rest key as they arrive. Until it is finished, the content
	// is only partly written and decrypts to nothing past the point the
	// uploader stopped, so it must not be reachable.
	CompletedAt time.Time
}

// Expired reports whether the upload has passed its deadline at now.
func (u *Upload) Expired(now time.Time) bool {
	return !u.ExpiresAt.IsZero() && !now.Before(u.ExpiresAt)
}

// Exhausted reports whether the upload has reached its download limit.
func (u *Upload) Exhausted() bool {
	return u.MaxDownloads > 0 && u.DownloadCount >= u.MaxDownloads
}

// Complete reports whether the upload finished being written.
func (u *Upload) Complete() bool { return !u.CompletedAt.IsZero() }

// Live reports whether the upload may still be downloaded.
//
// Completeness is checked here rather than at each call site, so that an
// incomplete upload is unreachable by the same mechanism that already makes an
// expired one unreachable. A second rule kept somewhere else is a rule some
// path will not apply.
func (u *Upload) Live(now time.Time) bool {
	return u.Complete() && !u.Expired(now) && !u.Exhausted()
}

// Store persists upload metadata.
//
// Implementations must be safe for concurrent use.
type Store interface {
	// Create stores a new upload, returning ErrConflict if the identifier is
	// already in use.
	Create(ctx context.Context, u *Upload) error

	// Get returns a live upload. An upload that has expired or is exhausted at
	// now yields ErrNotFound, which is how lazy expiry is enforced even when
	// the reaper is behind.
	Get(ctx context.Context, id string, now time.Time) (*Upload, error)

	// RecordServed adds n bytes to an upload's served total and returns the
	// upload as it stands afterwards.
	//
	// The download count is recomputed from the total rather than incremented,
	// so it is always exactly the number of whole files served. Accumulating
	// and recomputing are one operation: reading the total, dividing, then
	// writing back would let concurrent transfers lose each other's bytes.
	//
	// Serving to an upload that no longer exists is not an error. A transfer
	// may still be in flight when the reaper removes what it was reading, and
	// failing there would turn a race into an error nobody can act on.
	RecordServed(ctx context.Context, id string, n int64) (*Upload, error)

	// Delete removes the upload. Deleting one that does not exist is not an
	// error: expiry and revocation race, and neither should fail because the
	// other won.
	Delete(ctx context.Context, id string) error

	// Complete marks an upload as finished being written, making it reachable.
	// Completing one that is already complete is not an error.
	Complete(ctx context.Context, id string, now time.Time) error

	// ListDead returns identifiers of uploads the reaper should remove: those
	// expired or exhausted at now, and those still incomplete that were created
	// at or before abandoned. At most limit are returned.
	//
	// An abandoned upload holds an at-rest key and a partial blob that nothing
	// will ever finish, so it is a leftover like any other.
	ListDead(ctx context.Context, now, abandoned time.Time, limit int) ([]string, error)

	// Checkpoint retires any write-ahead log, so that deleted rows do not
	// survive on disk in pages the log still holds. Implementations without a
	// write-ahead log may make this a no-op.
	Checkpoint(ctx context.Context) error

	// Close releases the underlying resources.
	Close() error
}
