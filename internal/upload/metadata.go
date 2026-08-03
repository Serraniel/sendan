// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package upload

import (
	"context"
	"time"

	"github.com/Serraniel/sendan/internal/store"
)

// PublicMetadata is everything a client may learn about an upload before
// downloading it, and nothing else.
//
// It exists as a separate type rather than passing store.Upload outward because
// that struct also holds AtRestKey, which decrypts the blob, and the token
// hashes. Handing those to a serialisation layer and relying on it to omit them
// puts the confidentiality of every upload one forgotten field away from a
// disclosure. A type that never carries them cannot leak them.
//
// Every field here is either ciphertext the server cannot read, a parameter the
// client needs in order to derive keys, or a lifetime the client is entitled to
// see.
type PublicMetadata struct {
	ID string

	// Ciphertext, meaningless without the link secret from the URL fragment.
	WrappedFileKey   []byte
	WrapNonce        []byte
	MetadataEnvelope []byte
	MetadataNonce    []byte

	// Password is nil unless a password is required. Its parameters are
	// necessarily public: a client cannot derive anything without them. They
	// disclose only that a password exists. See spec §9.
	Password *store.PasswordParams

	// ExpiresAt is zero when the upload never expires.
	ExpiresAt time.Time

	// MaxDownloads is zero when there is no limit.
	MaxDownloads  int
	DownloadCount int
}

// Metadata returns what a client needs to decide what to do with an upload.
//
// It reads without claiming a download. Opening a link previews it - a chat
// client generating a preview, a user checking a filename - and any of that
// consuming the download allowance would exhaust a limited upload before its
// recipient ever fetched the content. Only the content endpoint claims.
//
// An upload that has expired or exhausted its allowance yields ErrNotFound,
// identically to one that never existed, because liveness is evaluated on read.
func (s *Service) Metadata(ctx context.Context, id string) (*PublicMetadata, error) {
	u, err := s.store.Get(ctx, id, s.now())
	if err != nil {
		return nil, err
	}

	// Copied field by field on purpose. A future field added to store.Upload
	// does not become public by default; someone has to decide to add it here.
	return &PublicMetadata{
		ID:               u.ID,
		WrappedFileKey:   u.WrappedFileKey,
		WrapNonce:        u.WrapNonce,
		MetadataEnvelope: u.MetadataEnvelope,
		MetadataNonce:    u.MetadataNonce,
		Password:         u.Password,
		ExpiresAt:        u.ExpiresAt,
		MaxDownloads:     u.MaxDownloads,
		DownloadCount:    u.DownloadCount,
	}, nil
}
