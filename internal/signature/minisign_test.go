// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package signature

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
)

// The fixtures in testdata were produced by an independent implementation of
// minisign, not by this package. A test where both sides are ours would agree
// with itself about a format we had misread.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return b
}

func releaseKey(t *testing.T) *PublicKey {
	t.Helper()
	k, err := ParsePublicKey(string(fixture(t, "release.pub")))
	if err != nil {
		t.Fatalf("parsing the public key: %v", err)
	}
	return k
}

func parse(t *testing.T, sig []byte) *Signature {
	t.Helper()
	s, err := ParseSignature(strings.NewReader(string(sig)))
	if err != nil {
		t.Fatalf("parsing the signature: %v", err)
	}
	return s
}

// Both of minisign's algorithms, because which one a signer produces is the
// signer's choice and a verifier that handles one of them rejects half of the
// valid signatures in the world.
func TestSignaturesFromTheReferenceImplementationVerify(t *testing.T) {
	key := releaseKey(t)
	manifest := fixture(t, "manifest.json")

	for _, tc := range []struct {
		name      string
		file      string
		prehashed bool
	}{
		{"the file itself", "manifest.json.minisig", false},
		{"a digest of the file", "manifest.json.prehashed.minisig", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := parse(t, fixture(t, tc.file))
			if s.Prehashed != tc.prehashed {
				t.Errorf("Prehashed = %v, want %v", s.Prehashed, tc.prehashed)
			}
			if err := key.Verify(manifest, s); err != nil {
				t.Errorf("a genuine signature did not verify: %v", err)
			}
		})
	}
}

// The point of the exercise. A manifest that has been altered is a manifest
// that would tell `sendan verify` to expect the attacker's client.
func TestAlteredContentDoesNotVerify(t *testing.T) {
	key := releaseKey(t)
	s := parse(t, fixture(t, "manifest.json.minisig"))

	altered := append([]byte{}, fixture(t, "manifest.json")...)
	altered[len(altered)-3] ^= 0x01

	if err := key.Verify(altered, s); !errors.Is(err, ErrBadSignature) {
		t.Errorf("altered content gave %v, want ErrBadSignature", err)
	}
}

func TestAnotherKeysSignatureIsRefusedAsSuch(t *testing.T) {
	key := releaseKey(t)
	s := parse(t, fixture(t, "manifest.json.otherkey.minisig"))

	// Distinguishable from a bad signature: it tells the user the release was
	// signed by somebody, just not by whoever this build trusts.
	if err := key.Verify(fixture(t, "manifest.json"), s); !errors.Is(err, ErrWrongKey) {
		t.Errorf("a foreign key gave %v, want ErrWrongKey", err)
	}
}

// The global signature is the whole reason the trusted comment can be trusted.
// Implementations that check only the first signature accept a file whose
// trusted comment says whatever an attacker wants, having just reported that
// the file verified.
func TestARewrittenTrustedCommentDoesNotVerify(t *testing.T) {
	key := releaseKey(t)
	s := parse(t, fixture(t, "manifest.json.minisig"))
	s.TrustedComment = "sendan v9.9.9 client asset manifest"

	if err := key.Verify(fixture(t, "manifest.json"), s); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a rewritten trusted comment gave %v, want ErrBadSignature", err)
	}
}

// The converse, recorded so nobody mistakes the first line for a guarantee: it
// is outside both signatures and anybody can write anything there.
func TestTheUntrustedCommentIsNotCovered(t *testing.T) {
	key := releaseKey(t)
	raw := string(fixture(t, "manifest.json.minisig"))
	lines := strings.Split(raw, "\n")
	lines[0] = "untrusted comment: anything at all"

	s := parse(t, []byte(strings.Join(lines, "\n")))
	if err := key.Verify(fixture(t, "manifest.json"), s); err != nil {
		t.Errorf("the untrusted comment is not covered, so this should verify: %v", err)
	}
}

func TestASignatureWithoutAKeyIsNotAVerification(t *testing.T) {
	if err := releaseKey(t).Verify([]byte("anything"), nil); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a missing signature gave %v, want ErrBadSignature", err)
	}
}

func TestPublicKeysAreReadFromAFileOrFromTheLineInIt(t *testing.T) {
	whole := string(fixture(t, "release.pub"))
	fromFile, err := ParsePublicKey(whole)
	if err != nil {
		t.Fatalf("parsing a whole key file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(whole), "\n")
	fromLine, err := ParsePublicKey(lines[len(lines)-1])
	if err != nil {
		t.Fatalf("parsing a bare key line: %v", err)
	}

	if fromFile.ID != fromLine.ID || !fromFile.Key.Equal(fromLine.Key) {
		t.Error("the same key read two ways gave two keys")
	}
}

func TestUnreadablePublicKeysAreRefused(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"empty", ""},
		{"only a comment", "untrusted comment: minisign public key\n"},
		{"not base64", "!!!!not base64!!!!"},
		{"too short", "RWQ="},
		{"an unknown algorithm", encodeField("XX", ed25519.PublicKeySize)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePublicKey(tc.in); err == nil {
				t.Error("accepted a public key that is not one")
			}
		})
	}
}

func TestUnreadableSignaturesAreRefused(t *testing.T) {
	good := strings.Split(strings.TrimRight(string(mustFixture("manifest.json.minisig")), "\n"), "\n")

	swap := func(line int, with string) string {
		altered := append([]string{}, good...)
		altered[line] = with
		return strings.Join(altered, "\n")
	}

	for _, tc := range []struct{ name, in string }{
		{"empty", ""},
		{"too few lines", "untrusted comment: x\nRWQ=\n"},
		{"signature not base64", swap(1, "!!!!")},
		{"signature the wrong length", swap(1, "RWQ=")},
		// Right length, wrong algorithm, so the algorithm check is what has to
		// reject it. Built rather than written out: a hand-typed constant of the
		// wrong length is rejected by the length check instead, and then this
		// case silently stops testing what it names.
		{"an unknown algorithm", swap(1, encodeField("XX", ed25519.SignatureSize))},
		{"no trusted comment", swap(2, "some other line")},
		{"global signature not base64", swap(3, "!!!!")},
		{"global signature the wrong length", swap(3, "RWQ=")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseSignature(strings.NewReader(tc.in)); err == nil {
				t.Error("accepted a signature file that is not one")
			}
		})
	}
}

// encodeField builds a correctly sized key or signature field carrying the
// given algorithm, so a test about the algorithm fails on the algorithm.
func encodeField(alg string, bodySize int) string {
	raw := append([]byte(alg), make([]byte, idSize+bodySize)...)
	return base64.StdEncoding.EncodeToString(raw)
}

func mustFixture(name string) []byte {
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		panic(err)
	}
	return b
}
