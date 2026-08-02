// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func fixedFileID() []byte     { return bytes.Repeat([]byte{0x01}, FileIDSize) }
func fixedLinkSecret() []byte { return bytes.Repeat([]byte{0x02}, LinkSecretSize) }

func fixedPasswordParams() PasswordParams {
	return PasswordParams{
		Salt: bytes.Repeat([]byte{0x03}, PasswordSaltSize),
		// Deliberately weak so tests stay fast. Never use these for real.
		MemoryKiB:   64,
		Iterations:  1,
		Parallelism: 1,
	}
}

func TestDeriveKeysIsDeterministic(t *testing.T) {
	a, err := DeriveKeys(fixedFileID(), fixedLinkSecret())
	if err != nil {
		t.Fatalf("first derivation: %v", err)
	}
	b, err := DeriveKeys(fixedFileID(), fixedLinkSecret())
	if err != nil {
		t.Fatalf("second derivation: %v", err)
	}
	if !bytes.Equal(a.Wrapping, b.Wrapping) || !bytes.Equal(a.Metadata, b.Metadata) || !bytes.Equal(a.AuthToken, b.AuthToken) {
		t.Fatal("same inputs produced different keys")
	}
}

// The three keys must be independent. If a label were duplicated or dropped,
// two of them would collide and compromising one would compromise another.
func TestDerivedKeysAreDistinct(t *testing.T) {
	k, err := DeriveKeys(fixedFileID(), fixedLinkSecret())
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	for _, c := range []struct {
		name string
		a, b []byte
	}{
		{"wrapping vs metadata", k.Wrapping, k.Metadata},
		{"wrapping vs auth", k.Wrapping, k.AuthToken},
		{"metadata vs auth", k.Metadata, k.AuthToken},
	} {
		if bytes.Equal(c.a, c.b) {
			t.Errorf("%s: keys are identical, domain separation has failed", c.name)
		}
	}
	for _, c := range []struct {
		name string
		key  []byte
	}{{"wrapping", k.Wrapping}, {"metadata", k.Metadata}, {"auth", k.AuthToken}} {
		if len(c.key) != derivedKeySize {
			t.Errorf("%s key is %d bytes, want %d", c.name, len(c.key), derivedKeySize)
		}
	}
}

func TestDeriveKeysVariesWithEveryInput(t *testing.T) {
	base, err := DeriveKeys(fixedFileID(), fixedLinkSecret())
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	otherID := fixedFileID()
	otherID[0] ^= 0xFF
	byID, err := DeriveKeys(otherID, fixedLinkSecret())
	if err != nil {
		t.Fatalf("derive with other file id: %v", err)
	}
	if bytes.Equal(base.Wrapping, byID.Wrapping) {
		t.Error("file id does not affect the derived keys")
	}

	otherSecret := fixedLinkSecret()
	otherSecret[0] ^= 0xFF
	bySecret, err := DeriveKeys(fixedFileID(), otherSecret)
	if err != nil {
		t.Fatalf("derive with other link secret: %v", err)
	}
	if bytes.Equal(base.Wrapping, bySecret.Wrapping) {
		t.Error("link secret does not affect the derived keys")
	}
}

// A password must change the wrapping key itself. If it did not, the password
// would be server-enforced policy rather than a cryptographic property, which
// is precisely the weakness this scheme exists to avoid.
func TestPasswordChangesTheWrappingKey(t *testing.T) {
	without, err := DeriveKeys(fixedFileID(), fixedLinkSecret())
	if err != nil {
		t.Fatalf("derive without password: %v", err)
	}
	with, err := DeriveKeysWithPassword(fixedFileID(), fixedLinkSecret(), "correct horse", fixedPasswordParams())
	if err != nil {
		t.Fatalf("derive with password: %v", err)
	}
	if bytes.Equal(without.Wrapping, with.Wrapping) {
		t.Fatal("password did not affect the wrapping key")
	}
	if bytes.Equal(without.Metadata, with.Metadata) {
		t.Fatal("password did not affect the metadata key: filenames would leak without it")
	}

	other, err := DeriveKeysWithPassword(fixedFileID(), fixedLinkSecret(), "correct horss", fixedPasswordParams())
	if err != nil {
		t.Fatalf("derive with other password: %v", err)
	}
	if bytes.Equal(with.Wrapping, other.Wrapping) {
		t.Fatal("different passwords produced the same wrapping key")
	}
}

// An empty password denotes a meaningless state: an upload marked
// password-protected that any link holder can open. The browser's Argon2id
// implementation refuses it outright, so both implementations reject it and the
// state cannot arise at all.
func TestEmptyPasswordIsRejected(t *testing.T) {
	if _, err := DeriveKeysWithPassword(fixedFileID(), fixedLinkSecret(), "", fixedPasswordParams()); !errors.Is(err, ErrKeyMaterial) {
		t.Fatalf("got %v, want ErrKeyMaterial", err)
	}
}

func TestDeriveKeysRejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fileID     []byte
		linkSecret []byte
	}{
		{"short file id", make([]byte, FileIDSize-1), fixedLinkSecret()},
		{"long file id", make([]byte, FileIDSize+1), fixedLinkSecret()},
		{"nil file id", nil, fixedLinkSecret()},
		{"short link secret", fixedFileID(), make([]byte, LinkSecretSize-1)},
		{"16 byte link secret", fixedFileID(), make([]byte, 16)},
		{"nil link secret", fixedFileID(), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DeriveKeys(tc.fileID, tc.linkSecret); !errors.Is(err, ErrKeyMaterial) {
				t.Fatalf("got %v, want ErrKeyMaterial", err)
			}
		})
	}
}

func TestDeriveKeysWithPasswordRejectsBadParams(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*PasswordParams)
	}{
		{"short salt", func(p *PasswordParams) { p.Salt = make([]byte, PasswordSaltSize-1) }},
		{"nil salt", func(p *PasswordParams) { p.Salt = nil }},
		{"zero memory", func(p *PasswordParams) { p.MemoryKiB = 0 }},
		{"zero iterations", func(p *PasswordParams) { p.Iterations = 0 }},
		{"zero parallelism", func(p *PasswordParams) { p.Parallelism = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := fixedPasswordParams()
			tc.mutate(&p)
			if _, err := DeriveKeysWithPassword(fixedFileID(), fixedLinkSecret(), "pw", p); !errors.Is(err, ErrKeyMaterial) {
				t.Fatalf("got %v, want ErrKeyMaterial", err)
			}
		})
	}
}

func TestNewPasswordParamsUsesSpecDefaults(t *testing.T) {
	p, err := NewPasswordParams()
	if err != nil {
		t.Fatalf("new params: %v", err)
	}
	if len(p.Salt) != PasswordSaltSize {
		t.Errorf("salt is %d bytes, want %d", len(p.Salt), PasswordSaltSize)
	}
	if p.MemoryKiB != DefaultMemoryKiB || p.Iterations != DefaultIterations || p.Parallelism != DefaultParallelism {
		t.Errorf("got m=%d t=%d p=%d, want m=%d t=%d p=%d",
			p.MemoryKiB, p.Iterations, p.Parallelism,
			DefaultMemoryKiB, DefaultIterations, DefaultParallelism)
	}

	other, err := NewPasswordParams()
	if err != nil {
		t.Fatalf("new params: %v", err)
	}
	if bytes.Equal(p.Salt, other.Salt) {
		t.Fatal("two calls produced the same salt")
	}
}

func TestRandomGeneratorsProduceCorrectSizes(t *testing.T) {
	for _, tc := range []struct {
		name string
		gen  func() ([]byte, error)
		want int
	}{
		{"file id", NewFileID, FileIDSize},
		{"link secret", NewLinkSecret, LinkSecretSize},
		{"file key", NewFileKey, FileKeySize},
		{"owner token", NewOwnerToken, OwnerTokenSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := tc.gen()
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			if len(a) != tc.want {
				t.Fatalf("got %d bytes, want %d", len(a), tc.want)
			}
			b, err := tc.gen()
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			if bytes.Equal(a, b) {
				t.Fatal("two calls returned identical bytes")
			}
		})
	}
}

func TestTokenHashesAreStableAndSized(t *testing.T) {
	token := bytes.Repeat([]byte{0x07}, OwnerTokenSize)
	if got := AuthTokenHash(token); len(got) != 32 || !bytes.Equal(got, AuthTokenHash(token)) {
		t.Error("auth token hash is not stable or not 32 bytes")
	}
	if got := OwnerTokenHash(token); len(got) != 32 || !bytes.Equal(got, OwnerTokenHash(token)) {
		t.Error("owner token hash is not stable or not 32 bytes")
	}
}
