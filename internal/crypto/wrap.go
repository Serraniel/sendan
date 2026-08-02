// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// Additional authenticated data, per spec §6 and §7. These bind a ciphertext to
// its purpose, so an envelope cannot be substituted for a wrapped key.
const (
	aadWrap     = "sendan/v1/wrap"
	aadMetadata = "sendan/v1/meta"
)

// WrapFileKey encrypts a file key under the wrapping key (spec §6).
//
// The nonce is random and returned alongside the ciphertext. Changing a
// password re-derives the wrapping key and re-wraps the same file key with a
// fresh nonce, which touches 48 bytes rather than re-encrypting the content.
func WrapFileKey(wrappingKey, fileKey []byte) (nonce, wrapped []byte, err error) {
	if len(fileKey) != FileKeySize {
		return nil, nil, fmt.Errorf("%w: file key is %d bytes, want %d", ErrKeyMaterial, len(fileKey), FileKeySize)
	}
	aead, err := newAEAD(wrappingKey)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = randomBytes(NonceSize)
	if err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, fileKey, []byte(aadWrap)), nil
}

// UnwrapFileKey recovers a file key wrapped by [WrapFileKey].
//
// A wrong wrapping key and a corrupt container both yield [ErrUnwrap] and are
// not distinguishable by the caller, per spec §13 invariant 5. Reporting which
// occurred would tell an attacker holding the ciphertext whether a guessed
// password was correct.
func UnwrapFileKey(wrappingKey, nonce, wrapped []byte) ([]byte, error) {
	aead, err := newAEAD(wrappingKey)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceSize {
		return nil, ErrUnwrap
	}
	fileKey, err := aead.Open(nil, nonce, wrapped, []byte(aadWrap))
	if err != nil {
		return nil, ErrUnwrap
	}
	if len(fileKey) != FileKeySize {
		return nil, ErrUnwrap
	}
	return fileKey, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != derivedKeySize {
		return nil, fmt.Errorf("%w: key is %d bytes, want %d", ErrKeyMaterial, len(key), derivedKeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	return aead, nil
}
