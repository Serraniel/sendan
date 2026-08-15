// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MasterKeySize is the length of a master key, in bytes.
const MasterKeySize = 32

// Prefix bytes for a stored at-rest key.
//
// A key stored before wrapping was enabled is 32 raw bytes with no room for a
// marker, so the marker distinguishes the two by being something a raw key
// cannot be: a 61-byte value. Length alone would do it, and would also silently
// misread the first byte of some future format as a version.
const wrappedV1 byte = 1

// wrappedSize is a version byte, a nonce, and the key with its tag.
const wrappedSize = 1 + 12 + MasterKeySize + 16

var (
	// ErrMasterKeySize reports a master key that is not 32 bytes.
	ErrMasterKeySize = fmt.Errorf("store: a master key must be %d bytes", MasterKeySize)

	// ErrWrongMasterKey reports an at-rest key that will not unwrap.
	//
	// Almost always the wrong key rather than damaged data, and worth saying so:
	// an operator who has just changed a deployment is far more likely to have
	// mounted the wrong secret than to have corrupted a database.
	ErrWrongMasterKey = errors.New(
		"store: the at-rest key will not unwrap with this master key; " +
			"if the key was changed, uploads written under the previous one need " +
			"rotating rather than restarting")
)

// ParseMasterKey reads a master key from text.
//
// Hex or base64, because a 32-byte binary file is awkward to move through the
// places secrets travel - a Kubernetes secret, a compose file, a password
// manager - and every one of them carries text without comment.
func ParseMasterKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("store: the master key is empty")
	}

	if key, err := hex.DecodeString(s); err == nil {
		if len(key) != MasterKeySize {
			return nil, ErrMasterKeySize
		}
		return key, nil
	}

	// Both alphabets, and with or without padding, so a key copied from
	// anywhere works rather than failing on a character somebody cannot see.
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if key, err := enc.DecodeString(s); err == nil {
			if len(key) != MasterKeySize {
				return nil, ErrMasterKeySize
			}
			return key, nil
		}
	}
	return nil, errors.New("store: the master key is neither hex nor base64")
}

// NewMasterKey returns a fresh master key as hex.
func NewMasterKey() (string, error) {
	key := make([]byte, MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("store: generate master key: %w", err)
	}
	return hex.EncodeToString(key), nil
}

// wrapping is a Store that keeps at-rest keys wrapped under a master key.
//
// The per-file key stays random and per-file; only its stored form changes. So
// crypto-shredding is untouched - deleting the row still destroys the only copy
// of the key that opens the blob.
//
// What this protects is a cold copy of the database: a backup, a volume
// snapshot, a disk that left the building. It does nothing against a live host,
// where the master key is in memory by definition. It is defence in depth on
// the layer below the content guarantee, which rests on the link secret and is
// unaffected either way.
type wrapping struct {
	Store
	aead cipher.AEAD
}

// WithMasterKey wraps at-rest keys under key, which must be 32 bytes.
func WithMasterKey(s Store, key []byte) (Store, error) {
	if len(key) != MasterKeySize {
		return nil, ErrMasterKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("store: master key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("store: master key: %w", err)
	}
	return &wrapping{Store: s, aead: aead}, nil
}

// wrap encrypts an at-rest key for storage.
func (w *wrapping) wrap(key []byte) ([]byte, error) {
	nonce := make([]byte, w.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("store: nonce: %w", err)
	}
	out := make([]byte, 0, wrappedSize)
	out = append(out, wrappedV1)
	out = append(out, nonce...)
	return w.aead.Seal(out, nonce, key, nil), nil
}

// unwrap decrypts a stored at-rest key.
//
// A key stored before wrapping was enabled is passed through unchanged, so
// turning the feature on does not strand what is already there. Those rows stay
// unwrapped until they are rotated, which is what the rotation command is for.
func (w *wrapping) unwrap(stored []byte) ([]byte, error) {
	// Length decides, not the first byte. A raw key is 32 random bytes, so one
	// in 256 of them begins with the version marker, and reading the marker
	// first would fail on those and only those - a bug that appears in well
	// under one percent of rows and never in a test that uses a fixed key.
	switch {
	case len(stored) == MasterKeySize:
		return stored, nil
	case len(stored) != wrappedSize:
		return nil, fmt.Errorf(
			"store: an at-rest key is %d bytes wrapped or %d bytes unwrapped, and this is %d",
			wrappedSize, MasterKeySize, len(stored))
	case stored[0] != wrappedV1:
		return nil, fmt.Errorf("store: unknown at-rest key format %d", stored[0])
	}

	nonce := stored[1 : 1+w.aead.NonceSize()]
	key, err := w.aead.Open(nil, nonce, stored[1+w.aead.NonceSize():], nil)
	if err != nil {
		return nil, ErrWrongMasterKey
	}
	return key, nil
}

func (w *wrapping) Create(ctx context.Context, u *Upload) error {
	// On a copy, because the caller keeps using the key it passed in - to
	// encrypt the blob. Wrapping it in place would hand the encryption a
	// wrapped key and store nothing that opens the result.
	wrapped, err := w.wrap(u.AtRestKey)
	if err != nil {
		return err
	}
	stored := *u
	stored.AtRestKey = wrapped
	return w.Store.Create(ctx, &stored)
}

func (w *wrapping) Get(ctx context.Context, id string, now time.Time) (*Upload, error) {
	return w.opened(w.Store.Get(ctx, id, now))
}

func (w *wrapping) Pending(ctx context.Context, id string) (*Upload, error) {
	return w.opened(w.Store.Pending(ctx, id))
}

func (w *wrapping) RecordServed(ctx context.Context, id string, n int64) (*Upload, error) {
	return w.opened(w.Store.RecordServed(ctx, id, n))
}

func (w *wrapping) opened(u *Upload, err error) (*Upload, error) {
	if err != nil || u == nil {
		return u, err
	}
	if u.AtRestKey, err = w.unwrap(u.AtRestKey); err != nil {
		return nil, err
	}
	return u, nil
}
