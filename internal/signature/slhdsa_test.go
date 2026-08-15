// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package signature

import (
	"errors"
	"strings"
	"testing"
)

func pqKey(t *testing.T) *PQPublicKey {
	t.Helper()
	k, err := ParsePQPublicKey(string(fixture(t, "release.pqpub")))
	if err != nil {
		t.Fatalf("parsing the post-quantum key: %v", err)
	}
	return k
}

func parsePQ(t *testing.T, name string) *PQSignature {
	t.Helper()
	s, err := ParsePQSignature(strings.NewReader(string(fixture(t, name))))
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return s
}

func TestAPostQuantumSignatureVerifies(t *testing.T) {
	if err := pqKey(t).Verify(fixture(t, "manifest.json"), parsePQ(t, "manifest.json.slhdsa")); err != nil {
		t.Errorf("a genuine signature did not verify: %v", err)
	}
}

func TestAnAlteredManifestFailsThePostQuantumSignature(t *testing.T) {
	altered := append([]byte{}, fixture(t, "manifest.json")...)
	altered[len(altered)-3] ^= 0x01

	err := pqKey(t).Verify(altered, parsePQ(t, "manifest.json.slhdsa"))
	if !errors.Is(err, ErrBadSignature) {
		t.Errorf("altered content gave %v, want ErrBadSignature", err)
	}
}

func TestAnotherPostQuantumKeyIsRefusedAsSuch(t *testing.T) {
	err := pqKey(t).Verify(fixture(t, "manifest.json"), parsePQ(t, "manifest.json.otherkey.slhdsa"))
	if !errors.Is(err, ErrWrongKey) {
		t.Errorf("a foreign key gave %v, want ErrWrongKey", err)
	}
}

// The parameter set is named in the file and checked before anything else. A
// verifier that ignored it would check a signature made under one set against a
// key belonging to another, and report whatever that produced.
func TestASignatureFromAnotherParameterSetIsRefused(t *testing.T) {
	raw := string(fixture(t, "manifest.json.slhdsa"))
	altered := strings.Replace(raw, "algorithm: SLH-DSA-SHA2-128s", "algorithm: SLH-DSA-SHAKE-256f", 1)

	_, err := ParsePQSignature(strings.NewReader(altered))
	if !errors.Is(err, ErrPQAlgorithm) {
		t.Errorf("another parameter set gave %v, want ErrPQAlgorithm", err)
	}
}

func TestAPostQuantumSignatureFileMustSayWhatItIs(t *testing.T) {
	raw := string(fixture(t, "manifest.json.slhdsa"))

	for name, in := range map[string]string{
		"empty":           "",
		"no algorithm":    strings.Replace(raw, "algorithm: SLH-DSA-SHA2-128s\n", "", 1),
		"no signature":    "untrusted comment: x\nalgorithm: SLH-DSA-SHA2-128s\n",
		"not base64":      strings.Replace(raw, "algorithm: SLH-DSA-SHA2-128s", "algorithm: SLH-DSA-SHA2-128s\n!!!!", 1),
		"only a key hint": "untrusted comment: x\nalgorithm: SLH-DSA-SHA2-128s\nAAAAAAAAAAA=\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePQSignature(strings.NewReader(in)); err == nil {
				t.Error("accepted a file that is not a post-quantum signature")
			}
		})
	}
}

// Reached over the network before anything about it is trusted, so a malformed
// one has to be an error rather than a crash. The library panics if asked to
// unmarshal without a parameter set, which is how this was found.
func TestUnusablePostQuantumKeysAreRefusedWithoutPanicking(t *testing.T) {
	for name, in := range map[string]string{
		"empty":      "",
		"not base64": "!!!!not base64!!!!",
		"too short":  "AAAA",
		"too long":   strings.Repeat("A", 4096),
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on a %s key: %v", name, r)
				}
			}()
			if _, err := ParsePQPublicKey(in); err == nil {
				t.Error("accepted a public key that is not one")
			}
		})
	}
}

// A signature of the wrong length must fail rather than crash, for the same
// reason: it arrives from wherever the release is published.
func TestAMalformedPostQuantumSignatureDoesNotPanic(t *testing.T) {
	key := pqKey(t)
	content := fixture(t, "manifest.json")

	for name, sig := range map[string]*PQSignature{
		"nil":       nil,
		"empty":     {Algorithm: "SLH-DSA-SHA2-128s", ID: key.ID, Sig: nil},
		"truncated": {Algorithm: "SLH-DSA-SHA2-128s", ID: key.ID, Sig: make([]byte, 100)},
		"enormous":  {Algorithm: "SLH-DSA-SHA2-128s", ID: key.ID, Sig: make([]byte, 100000)},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on a %s signature: %v", name, r)
				}
			}()
			if err := key.Verify(content, sig); err == nil {
				t.Error("a malformed signature verified")
			}
		})
	}
}

func TestThePostQuantumSignatureSitsBesideTheFile(t *testing.T) {
	const url = "https://example.org/releases/download/v1.0.0/manifest.json"
	if got, want := PQSignatureURL(url), url+".slhdsa"; got != want {
		t.Errorf("PQSignatureURL = %q, want %q", got, want)
	}
}

// The two schemes must not be interchangeable. A build that accepted either
// alone would have the weaker of the two as its actual guarantee.
func TestTheTwoSignatureFormatsAreNotInterchangeable(t *testing.T) {
	if _, err := ParsePQSignature(strings.NewReader(string(fixture(t, "manifest.json.minisig")))); err == nil {
		t.Error("an Ed25519 signature was accepted as a post-quantum one")
	}
	if _, err := ParseSignature(strings.NewReader(string(fixture(t, "manifest.json.slhdsa")))); err == nil {
		t.Error("a post-quantum signature was accepted as an Ed25519 one")
	}
}

// A file this format does not fully describe is refused rather than skimmed.
// Taking the parts it recognises and ignoring the rest would accept a file with
// anything at all in it and call the result verified.
func TestAPostQuantumFileWithExtraLinesIsRefused(t *testing.T) {
	raw := string(fixture(t, "manifest.json.slhdsa"))

	for name, in := range map[string]string{
		"two algorithm lines": strings.Replace(raw,
			"algorithm: SLH-DSA-SHA2-128s",
			"algorithm: SLH-DSA-SHA2-128s\nalgorithm: SLH-DSA-SHA2-128s", 1),
		"two signatures": strings.TrimRight(raw, "\n") + "\nAAAA\n",
		"junk before the signature": strings.Replace(raw,
			"algorithm: SLH-DSA-SHA2-128s",
			"algorithm: SLH-DSA-SHA2-128s\n!!!!", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePQSignature(strings.NewReader(in)); err == nil {
				t.Error("accepted a file with content this format does not describe")
			}
		})
	}
}

// Verify checks the algorithm too, not only the parser. A signature reaching it
// from anywhere else must not be taken on the parser's word.
func TestVerifyChecksTheAlgorithmItself(t *testing.T) {
	key := pqKey(t)
	sig := parsePQ(t, "manifest.json.slhdsa")
	sig.Algorithm = "SLH-DSA-SHAKE-256f"

	if err := key.Verify(fixture(t, "manifest.json"), sig); !errors.Is(err, ErrPQAlgorithm) {
		t.Errorf("got %v, want ErrPQAlgorithm", err)
	}
}
