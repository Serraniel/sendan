// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package upload

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/Serraniel/sendan/internal/crypto"
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
	u, err := s.store.Get(ctx, id, s.now())
	if err != nil {
		return err
	}

	// The allowance is consumed before the comparison, not after, so that an
	// attempt costs the attacker whatever its outcome. Checking first and
	// charging only for failures would leave the budget untouched by a
	// correctly guessed token, which is the case worth bounding.
	if s.attempts != nil && !s.attempts.Allow(id) {
		return ErrTooManyAttempts
	}

	if subtle.ConstantTimeCompare(crypto.AuthTokenHash(token), u.AuthTokenHash) != 1 {
		return ErrUnauthorized
	}

	// A correct token clears the record. Someone holding it is the intended
	// recipient, and without this a recipient who mistyped a password four
	// times would stay throttled for as long as the bucket survives, having
	// since proved they are entitled to the file.
	if s.attempts != nil {
		s.attempts.Forget(id)
	}
	return nil
}

// RetryAfter reports how long until this upload accepts another attempt.
func (s *Service) RetryAfter(id string) (d time.Duration) {
	if s.attempts == nil {
		return 0
	}
	return s.attempts.Retry(id)
}
