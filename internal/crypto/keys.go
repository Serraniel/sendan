// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package crypto

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Sizes in bytes, per spec §3.
const (
	FileIDSize     = 16
	LinkSecretSize = 32
	FileKeySize    = 32
	OwnerTokenSize = 32
	NonceSize      = 12

	// TagSize is the AES-GCM authentication tag, which every sealed value
	// carries in addition to its plaintext.
	TagSize = 16

	// WrappedFileKeySize is the stored size of a wrapped file key: the key
	// itself plus its tag (spec §6). A value of any other length was not
	// produced by this scheme.
	WrappedFileKeySize = FileKeySize + TagSize

	derivedKeySize = 32
)

// Domain-separation labels, per spec §4. These are the version of the scheme:
// changing what any of them means requires a v2 label, never an edit here.
const (
	labelWrapping = "sendan/v1/kek"
	labelMetadata = "sendan/v1/metadata"
	labelAuth     = "sendan/v1/auth"
)

var (
	// ErrKeyMaterial reports malformed inputs to the key schedule.
	ErrKeyMaterial = errors.New("crypto: invalid key material")

	// ErrUnwrap reports that a wrapped file key could not be recovered.
	//
	// It deliberately does not distinguish a wrong password from a corrupt
	// container: spec §13 invariant 5 requires the two to be indistinguishable
	// to the caller.
	ErrUnwrap = errors.New("crypto: cannot unwrap file key")
)

// Keys are the three keys derived from one upload's key material.
//
// None of these ever leaves the client.
type Keys struct {
	// Wrapping encrypts the file key (spec §6).
	Wrapping []byte
	// Metadata encrypts the metadata envelope (spec §7).
	Metadata []byte
	// AuthToken is presented to the server to authenticate a download
	// (spec §8.1). Unlike the other two it is transmitted, in exchange for
	// the server storing only its hash.
	AuthToken []byte
}

// DeriveKeys derives the key schedule for an upload with no password.
func DeriveKeys(fileID, linkSecret []byte) (*Keys, error) {
	return deriveKeys(fileID, linkSecret, nil)
}

// DeriveKeysWithPassword derives the key schedule for a password-protected
// upload.
//
// The password is stretched with Argon2id and concatenated with the link
// secret before extraction, so the password contributes to the wrapping key
// itself. A link without its password therefore decrypts nothing, which is a
// cryptographic property rather than a server-side policy.
func DeriveKeysWithPassword(fileID, linkSecret []byte, password string, p PasswordParams) (*Keys, error) {
	if err := p.validate(password); err != nil {
		return nil, err
	}
	return deriveKeys(fileID, linkSecret, p.hash(password))
}

func deriveKeys(fileID, linkSecret, passwordHash []byte) (*Keys, error) {
	if len(fileID) != FileIDSize {
		return nil, fmt.Errorf("%w: file id is %d bytes, want %d", ErrKeyMaterial, len(fileID), FileIDSize)
	}
	if len(linkSecret) != LinkSecretSize {
		return nil, fmt.Errorf("%w: link secret is %d bytes, want %d", ErrKeyMaterial, len(linkSecret), LinkSecretSize)
	}

	// IKM = LS || pwHash, with pwHash empty when no password is set (spec §4).
	ikm := make([]byte, 0, len(linkSecret)+len(passwordHash))
	ikm = append(ikm, linkSecret...)
	ikm = append(ikm, passwordHash...)

	// The file identifier is public, which is acceptable for a salt, and it
	// domain-separates uploads without requiring another stored field.
	prk, err := hkdf.Extract(sha256.New, ikm, fileID)
	if err != nil {
		return nil, fmt.Errorf("crypto: hkdf extract: %w", err)
	}

	keys := &Keys{}
	for _, d := range []struct {
		label string
		dst   *[]byte
	}{
		{labelWrapping, &keys.Wrapping},
		{labelMetadata, &keys.Metadata},
		{labelAuth, &keys.AuthToken},
	} {
		k, err := hkdf.Expand(sha256.New, prk, d.label, derivedKeySize)
		if err != nil {
			return nil, fmt.Errorf("crypto: hkdf expand %q: %w", d.label, err)
		}
		*d.dst = k
	}
	return keys, nil
}

// AuthTokenHash returns the value a server stores in order to verify a download
// authentication token (spec §8.1).
//
// The server never holds the token itself, only this hash.
//
// SHA-256 is correct here, and static analysis reports otherwise.
// CodeQL's go/weak-sensitive-data-hashing traces a password into this call -
// truthfully, since a password-protected upload derives AT from a PRK the
// password contributed to - and concludes that a password is being hashed with
// a function too fast for the purpose. Two things make that conclusion wrong:
//
//   - The password is already stretched. DeriveKeysWithPassword runs it through
//     Argon2id (PasswordParams.hash) before it reaches the key schedule, which
//     is the expensive step the rule exists to require.
//   - What is hashed here is not a password. AT is 32 bytes of HKDF-Expand
//     output, uniformly distributed to anyone without the link secret. The
//     speed of a hash only matters when its input can be guessed, and a
//     256-bit key cannot be. Hashing a high-entropy credential so the server
//     can verify without holding it is the standard construction.
//
// The rule is worth keeping enabled: if this project ever did hash a password
// directly, that is precisely the defect nobody would notice by reading. The
// alert is dismissed per instance rather than the query being excluded.
func AuthTokenHash(authToken []byte) []byte {
	sum := sha256.Sum256(authToken)
	return sum[:]
}

// NewFileID returns a random file identifier. Generated server-side.
func NewFileID() ([]byte, error) { return randomBytes(FileIDSize) }

// NewLinkSecret returns a random link secret.
//
// It is 32 bytes rather than 16 because it is the sole credential protecting an
// upload, and Grover's algorithm halves effective symmetric security. See
// docs/design.md §2.4.
func NewLinkSecret() ([]byte, error) { return randomBytes(LinkSecretSize) }

// NewFileKey returns a random file key.
func NewFileKey() ([]byte, error) { return randomBytes(FileKeySize) }

// NewOwnerToken returns a random owner token.
//
// It is independent of the link secret, so an upload can be revoked by someone
// who cannot read it.
func NewOwnerToken() ([]byte, error) { return randomBytes(OwnerTokenSize) }

// OwnerTokenHash returns the value a server stores to verify an owner token.
func OwnerTokenHash(ownerToken []byte) []byte {
	sum := sha256.Sum256(ownerToken)
	return sum[:]
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("crypto: read random bytes: %w", err)
	}
	return b, nil
}
