// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package crypto

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

// PasswordSaltSize is the length of an Argon2id salt, per spec §3.
const PasswordSaltSize = 16

// Default Argon2id parameters, per spec §4.
//
// Chosen to remain tolerable on a low-end phone, since the browser performs
// this work. They are stored per upload so they can be raised later without
// invalidating existing links.
const (
	DefaultMemoryKiB   uint32 = 64 * 1024
	DefaultIterations  uint32 = 3
	DefaultParallelism uint8  = 1
)

// PasswordParams are the Argon2id parameters for one upload.
//
// They are stored unencrypted alongside the upload because a client must know
// them before it can derive anything. They disclose only that a password exists.
type PasswordParams struct {
	Salt        []byte
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
}

// NewPasswordParams returns the default parameters with a fresh random salt.
func NewPasswordParams() (PasswordParams, error) {
	salt, err := randomBytes(PasswordSaltSize)
	if err != nil {
		return PasswordParams{}, err
	}
	return PasswordParams{
		Salt:        salt,
		MemoryKiB:   DefaultMemoryKiB,
		Iterations:  DefaultIterations,
		Parallelism: DefaultParallelism,
	}, nil
}

func (p PasswordParams) validate(password string) error {
	// An empty password is rejected, per spec §4. It denotes a meaningless
	// state - an upload marked password-protected that any link holder can
	// open - and the browser's Argon2id implementation refuses it outright, so
	// accepting it here would make the two implementations disagree.
	if password == "" {
		return fmt.Errorf("%w: password must not be empty", ErrKeyMaterial)
	}
	if len(p.Salt) != PasswordSaltSize {
		return fmt.Errorf("%w: password salt is %d bytes, want %d", ErrKeyMaterial, len(p.Salt), PasswordSaltSize)
	}
	if p.MemoryKiB == 0 || p.Iterations == 0 || p.Parallelism == 0 {
		return fmt.Errorf("%w: argon2id parameters must all be non-zero", ErrKeyMaterial)
	}
	return nil
}

// hash stretches the password with Argon2id.
//
// The password is taken as its UTF-8 encoding with no normalisation, matching
// spec §4. Normalising would silently change which passwords open which files
// across implementations, so it is deliberately not done.
func (p PasswordParams) hash(password string) []byte {
	return argon2.IDKey(
		[]byte(password),
		p.Salt,
		p.Iterations,
		p.MemoryKiB,
		p.Parallelism,
		derivedKeySize,
	)
}
