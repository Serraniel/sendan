// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestWrapUnwrapRoundTrip(t *testing.T) {
	keys, err := DeriveKeys(fixedFileID(), fixedLinkSecret())
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	fileKey := bytes.Repeat([]byte{0x09}, FileKeySize)

	nonce, wrapped, err := WrapFileKey(keys.Wrapping, fileKey)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if bytes.Contains(wrapped, fileKey) {
		t.Fatal("the wrapped blob contains the plaintext file key")
	}

	got, err := UnwrapFileKey(keys.Wrapping, nonce, wrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, fileKey) {
		t.Fatal("unwrapped file key does not match")
	}
}

func TestWrapUsesAFreshNonceEachTime(t *testing.T) {
	keys, err := DeriveKeys(fixedFileID(), fixedLinkSecret())
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	fileKey := bytes.Repeat([]byte{0x09}, FileKeySize)

	n1, w1, err := WrapFileKey(keys.Wrapping, fileKey)
	if err != nil {
		t.Fatalf("first wrap: %v", err)
	}
	n2, w2, err := WrapFileKey(keys.Wrapping, fileKey)
	if err != nil {
		t.Fatalf("second wrap: %v", err)
	}
	if bytes.Equal(n1, n2) {
		t.Fatal("nonce was reused across two wraps under the same key")
	}
	if bytes.Equal(w1, w2) {
		t.Fatal("two wraps of the same key produced identical ciphertext")
	}
}

// A wrong password and a corrupt container must be indistinguishable
// (spec §13 invariant 5). Distinguishing them would let an attacker holding
// only the ciphertext test password guesses offline and know when one is right.
func TestUnwrapFailuresAreIndistinguishable(t *testing.T) {
	params := fixedPasswordParams()
	right, err := DeriveKeysWithPassword(fixedFileID(), fixedLinkSecret(), "right", params)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	wrong, err := DeriveKeysWithPassword(fixedFileID(), fixedLinkSecret(), "wrong", params)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	fileKey := bytes.Repeat([]byte{0x09}, FileKeySize)
	nonce, wrapped, err := WrapFileKey(right.Wrapping, fileKey)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	corrupt := bytes.Clone(wrapped)
	corrupt[0] ^= 0x01

	badNonce := bytes.Clone(nonce)
	badNonce[0] ^= 0x01

	for _, tc := range []struct {
		name    string
		key     []byte
		nonce   []byte
		wrapped []byte
	}{
		{"wrong password", wrong.Wrapping, nonce, wrapped},
		{"corrupt ciphertext", right.Wrapping, nonce, corrupt},
		{"wrong nonce", right.Wrapping, badNonce, wrapped},
		{"truncated ciphertext", right.Wrapping, nonce, wrapped[:len(wrapped)-1]},
		{"empty ciphertext", right.Wrapping, nonce, nil},
		{"short nonce", right.Wrapping, nonce[:NonceSize-1], wrapped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := UnwrapFileKey(tc.key, tc.nonce, tc.wrapped)
			if !errors.Is(err, ErrUnwrap) {
				t.Fatalf("got %v, want ErrUnwrap", err)
			}
			if err.Error() != ErrUnwrap.Error() {
				t.Fatalf("error message %q differs from the generic one and leaks the cause", err)
			}
		})
	}
}

// Changing a password must re-wrap the same file key rather than re-encrypt the
// content, so the previously wrapped blob must stop opening and the new one must
// yield the identical file key.
func TestRewrapAfterPasswordChange(t *testing.T) {
	params := fixedPasswordParams()
	oldKeys, err := DeriveKeysWithPassword(fixedFileID(), fixedLinkSecret(), "old", params)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	fileKey := bytes.Repeat([]byte{0x09}, FileKeySize)
	oldNonce, oldWrapped, err := WrapFileKey(oldKeys.Wrapping, fileKey)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	recovered, err := UnwrapFileKey(oldKeys.Wrapping, oldNonce, oldWrapped)
	if err != nil {
		t.Fatalf("unwrap with old password: %v", err)
	}

	newKeys, err := DeriveKeysWithPassword(fixedFileID(), fixedLinkSecret(), "new", params)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	newNonce, newWrapped, err := WrapFileKey(newKeys.Wrapping, recovered)
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}

	got, err := UnwrapFileKey(newKeys.Wrapping, newNonce, newWrapped)
	if err != nil {
		t.Fatalf("unwrap with new password: %v", err)
	}
	if !bytes.Equal(got, fileKey) {
		t.Fatal("file key changed across a password change")
	}
	if _, err := UnwrapFileKey(oldKeys.Wrapping, newNonce, newWrapped); !errors.Is(err, ErrUnwrap) {
		t.Fatal("the old password still opens the rewrapped key")
	}
}

func TestWrapRejectsMalformedInput(t *testing.T) {
	key := bytes.Repeat([]byte{0x0A}, derivedKeySize)
	for _, tc := range []struct {
		name    string
		key     []byte
		fileKey []byte
	}{
		{"short wrapping key", make([]byte, derivedKeySize-1), bytes.Repeat([]byte{1}, FileKeySize)},
		{"nil wrapping key", nil, bytes.Repeat([]byte{1}, FileKeySize)},
		{"short file key", key, make([]byte, FileKeySize-1)},
		{"nil file key", key, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := WrapFileKey(tc.key, tc.fileKey); !errors.Is(err, ErrKeyMaterial) {
				t.Fatalf("got %v, want ErrKeyMaterial", err)
			}
		})
	}
}

// The additional authenticated data binds a ciphertext to its purpose, so a
// metadata envelope must not open as a wrapped key even under the same key.
func TestWrapAndMetadataAreNotInterchangeable(t *testing.T) {
	key := bytes.Repeat([]byte{0x0B}, derivedKeySize)
	nonce, envelope, err := SealMetadata(key, Metadata{Name: "a", Type: "text/plain", Size: 1})
	if err != nil {
		t.Fatalf("seal metadata: %v", err)
	}
	if _, err := UnwrapFileKey(key, nonce, envelope); !errors.Is(err, ErrUnwrap) {
		t.Fatal("a metadata envelope opened as a wrapped file key")
	}
}
