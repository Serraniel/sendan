// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package signature

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// Post-quantum signatures over the same files the Ed25519 signature covers.
//
// Signing is the one place in this project where post-quantum primitives
// genuinely apply. Encryption here is symmetric and stays out of reach of
// Shor's algorithm; a signature is different, because it has to still mean
// something years after it was made, and Ed25519 does not survive an adversary
// who eventually has a quantum computer and a recorded release.
//
// SLH-DSA rather than ML-DSA: its security rests only on the hash function
// underneath it, with no structured hardness assumption that could turn out to
// be weaker than believed. It is the conservative choice, and the cost of that
// conservatism is a signature of about eight kilobytes and a third of a second
// to produce - neither of which matters for a file signed once per release.
//
// This is in addition to the Ed25519 signature, never instead of it. A forgery
// has to defeat both, and each covers the other's failure: one rests on a
// primitive a quantum computer breaks, the other on a scheme with far less
// deployment behind it.
const (
	// pqAlgorithm identifies the parameter set in the signature file, so a file
	// signed under one set can never be checked against another.
	pqAlgorithm = "SLH-DSA-SHA2-128s"

	pqIDSize = 8
)

// pqParams is the parameter set. SHA2-128s: the small-signature variant, since
// the signature is fetched over the network before anything can be verified.
const pqParams = slhdsa.SHA2_128s

// ErrPQAlgorithm reports a signature made with a scheme this build cannot check.
var ErrPQAlgorithm = errors.New("signature: unsupported post-quantum algorithm")

// PQPublicKey is a post-quantum release signing key.
type PQPublicKey struct {
	ID  [pqIDSize]byte
	Key *slhdsa.PublicKey
}

// PQSignature is a parsed post-quantum signature file.
type PQSignature struct {
	Algorithm string
	ID        [pqIDSize]byte
	Sig       []byte
}

// PQKeyID names a key by its own bytes, so a signature says which key made it
// without anybody having to maintain a registry of identifiers.
func PQKeyID(encoded []byte) [pqIDSize]byte {
	sum := sha256.Sum256(encoded)
	var id [pqIDSize]byte
	copy(id[:], sum[:pqIDSize])
	return id
}

// ParsePQPublicKey reads a public key.
//
// The same shape as the Ed25519 one: a comment line and a base64 line, so the
// two keys look alike wherever they are published and nobody has to learn a
// second format to check a release.
func ParsePQPublicKey(s string) (*PQPublicKey, error) {
	line := lastMeaningfulLine(s)
	if line == "" {
		return nil, errors.New("signature: no post-quantum public key here")
	}

	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return nil, fmt.Errorf("signature: unreadable post-quantum public key: %w", err)
	}

	// The parameter set has to be set before unmarshalling: the encoded form
	// carries only the key material, so the reader supplies the scheme. This
	// build reads one set, which is also what stops a key from another being
	// silently reinterpreted as this one.
	key := slhdsa.PublicKey{ID: pqParams}
	if err := key.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("signature: unusable post-quantum public key: %w", err)
	}
	return &PQPublicKey{ID: PQKeyID(raw), Key: &key}, nil
}

// ParsePQSignature reads a post-quantum signature file.
func ParsePQSignature(r io.Reader) (*PQSignature, error) {
	body, err := io.ReadAll(io.LimitReader(r, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("signature: reading: %w", err)
	}

	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")

	// Every line has to be one of the three this format has. Skimming for the
	// parts it recognises and ignoring the rest would accept a file with
	// anything at all in it, and report the result as a verified signature.
	var algorithm, encoded string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "untrusted comment:"):
		case strings.HasPrefix(line, "algorithm: "):
			if algorithm != "" {
				return nil, errors.New("signature: two algorithm lines")
			}
			algorithm = strings.TrimPrefix(line, "algorithm: ")
		case encoded != "":
			return nil, errors.New("signature: more than one signature in this file")
		default:
			encoded = line
		}
	}

	// Checked before the signature is even decoded. A verifier that ignored
	// this would check a signature from one parameter set against a key from
	// another and report whatever that happened to produce.
	if algorithm != pqAlgorithm {
		return nil, fmt.Errorf("%w: %q, and this build checks %q",
			ErrPQAlgorithm, algorithm, pqAlgorithm)
	}
	if encoded == "" {
		return nil, errors.New("signature: no post-quantum signature in this file")
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("signature: unreadable post-quantum signature: %w", err)
	}
	if len(raw) <= pqIDSize {
		return nil, errors.New("signature: the post-quantum signature is truncated")
	}

	s := &PQSignature{Algorithm: algorithm, Sig: raw[pqIDSize:]}
	copy(s.ID[:], raw[:pqIDSize])
	return s, nil
}

// Verify reports whether content was signed by this key.
func (k *PQPublicKey) Verify(content []byte, s *PQSignature) error {
	if s == nil {
		return ErrBadSignature
	}
	if s.Algorithm != pqAlgorithm {
		return fmt.Errorf("%w: %q", ErrPQAlgorithm, s.Algorithm)
	}
	if subtle.ConstantTimeCompare(k.ID[:], s.ID[:]) != 1 {
		return ErrWrongKey
	}
	if !slhdsa.Verify(k.Key, slhdsa.NewMessage(content), s.Sig, nil) {
		return ErrBadSignature
	}
	return nil
}

// PQSignatureURL is where the post-quantum signature for a file lives.
func PQSignatureURL(url string) string { return url + ".slhdsa" }
