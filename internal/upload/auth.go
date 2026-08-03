// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package upload

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Serraniel/sendan/internal/crypto"
	"github.com/Serraniel/sendan/internal/store"
)

var (
	// ErrUnauthorized reports a download token that does not match.
	ErrUnauthorized = errors.New("upload: invalid download token")

	// ErrTooManyAttempts reports that this upload has received too many failed
	// attempts recently. It is about the upload, not the caller: the limit
	// exists to bound how hard one file may be attacked, from anywhere.
	ErrTooManyAttempts = errors.New("upload: too many attempts")
)

// Authenticate verifies a download token against an upload (spec §8.1).
//
// The token derives from the same key schedule as the content keys, so
// producing a valid one requires the link secret and, where set, the password.
// That is what makes this the control behind the guarantee that nobody who
// could not have decrypted a file is able to consume one of its downloads.
//
// It does not claim a download. Checking a password is not using the file, and
// a limited upload whose allowance was spent by password attempts would be
// destroyed by anyone who could reach it.
//
// # On what this is and is not
//
// Confidentiality does not rest here. The password contributes to the
// key-wrapping key (spec §4), so ciphertext obtained by any means remains
// useless without it, and this check being bypassed would disclose nothing. It
// exists so that a wrong password is reported before ciphertext is streamed,
// and so that the download counter cannot be spent by someone who cannot read
// the file.
func (s *Service) Authenticate(ctx context.Context, id string, token []byte) error {
	_, err := s.authenticated(ctx, id, token)
	return err
}

// authenticated verifies a token and returns the upload it belongs to.
//
// Content needs the row it just authenticated - for the at-rest key and the
// size - and fetching it a second time would both cost a query and open a
// window in which the upload could vanish between the check and the read.
func (s *Service) authenticated(ctx context.Context, id string, token []byte) (*store.Upload, error) {
	u, err := s.store.Get(ctx, id, s.now())
	if err != nil {
		return nil, err
	}

	// The allowance is consumed before the comparison, not after, so that an
	// attempt costs the attacker whatever its outcome. Checking first and
	// charging only for failures would leave the budget untouched by a
	// correctly guessed token, which is the case worth bounding.
	if s.attempts != nil && !s.attempts.Allow(id) {
		return nil, ErrTooManyAttempts
	}

	if subtle.ConstantTimeCompare(crypto.AuthTokenHash(token), u.AuthTokenHash) != 1 {
		return nil, ErrUnauthorized
	}

	// A correct token clears the record. Someone holding it is the intended
	// recipient, and without this a recipient who mistyped a password four
	// times would stay throttled for as long as the bucket survives, having
	// since proved they are entitled to the file.
	if s.attempts != nil {
		s.attempts.Forget(id)
	}
	return u, nil
}

// RetryAfter reports how long until this upload accepts another attempt.
func (s *Service) RetryAfter(id string) (d time.Duration) {
	if s.attempts == nil {
		return 0
	}
	return s.attempts.Retry(id)
}

// Content verifies a download token and opens the upload's ciphertext.
//
// The reader is seekable, so a caller may serve byte ranges from it without
// holding the content in memory. Closing it is the caller's responsibility.
//
// Verification happens first, and that ordering is the guarantee: producing a
// valid token requires the link secret and, where set, the password, so nobody
// who could not have decrypted a file can cause its content to be read or its
// allowance to be spent.
func (s *Service) Content(ctx context.Context, id string, token []byte) (io.ReadSeekCloser, int64, error) {
	u, err := s.authenticated(ctx, id, token)
	if err != nil {
		return nil, 0, err
	}

	rc, err := s.blobs.Open(ctx, id, u.AtRestKey)
	if err != nil {
		return nil, 0, fmt.Errorf("upload: open content: %w", err)
	}
	return rc, u.Size, nil
}
