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
	// DownloadCount is how many downloads have been claimed.
	DownloadCount int
}

// Expired reports whether the upload has passed its deadline at now.
func (u *Upload) Expired(now time.Time) bool {
	return !u.ExpiresAt.IsZero() && !now.Before(u.ExpiresAt)
}

// Exhausted reports whether the upload has reached its download limit.
func (u *Upload) Exhausted() bool {
	return u.MaxDownloads > 0 && u.DownloadCount >= u.MaxDownloads
}

// Live reports whether the upload may still be downloaded.
func (u *Upload) Live(now time.Time) bool {
	return !u.Expired(now) && !u.Exhausted()
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

	// ClaimDownload atomically reserves one download and returns the upload.
	//
	// The reservation and the limit check are one operation on purpose. Reading
	// the count, deciding, then incrementing would let concurrent requests all
	// pass the check and exceed the limit, which is a security defect rather
	// than a cosmetic one.
	ClaimDownload(ctx context.Context, id string, now time.Time) (*Upload, error)

	// Delete removes the upload. Deleting one that does not exist is not an
	// error: expiry and revocation race, and neither should fail because the
	// other won.
	Delete(ctx context.Context, id string) error

	// ListDead returns identifiers of uploads that have expired or are
	// exhausted at now, for the reaper to remove. At most limit are returned.
	ListDead(ctx context.Context, now time.Time, limit int) ([]string, error)

	// Close releases the underlying resources.
	Close() error
}
