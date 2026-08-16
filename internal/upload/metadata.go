// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package upload

import (
	"context"
	"errors"
	"fmt"
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

	// Compatibility reports that this upload was made through the third-party
	// compatibility endpoints rather than Sendan's own.
	//
	// It matters to whoever receives it: that protocol enforces a password in
	// the server rather than in the key, so such an upload is protected less
	// well than a native one and an interface showing the two alike would be
	// claiming protection the file does not have.
	//
	// Answered by the row itself. An upload in this project's format carries an
	// envelope in it, and one made through the other protocol carries none -
	// which the schema enforces is all-or-nothing rather than partly each.
	Compatibility bool
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
		Compatibility:    len(u.WrappedFileKey) == 0,
	}, nil
}

// RecordServed accounts for content served to a client.
//
// The download counter counts transfers, not requests: n bytes are added to the
// upload's running total, and the count is recomputed as the number of whole
// files that total represents. Resuming a transfer is therefore free, because
// each byte is charged once, and abandoning one repeatedly is charged for what
// it consumed.
//
// An upload the reaper has already removed is not an error. A transfer may
// still be in flight when its deadline passes, and failing there would report a
// race nobody can act on.
func (s *Service) RecordServed(ctx context.Context, id string, n int64) error {
	if n <= 0 {
		return nil
	}
	if _, err := s.store.RecordServed(ctx, id, n); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("upload: record served: %w", err)
	}
	return nil
}
