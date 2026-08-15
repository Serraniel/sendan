// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Package signature verifies detached Ed25519 signatures in minisign's format.
//
// The command line client is this project's trust anchor: it is the program
// somebody obtains in order to check everything else, so what it links is part
// of what they are being asked to trust. Verifying a Sigstore bundle properly
// costs 365 further modules and triples the binary, which is a poor trade for a
// tool whose smallness is the argument for auditing it. Ed25519 against the
// standard library is about a hundred lines and no new module tree.
//
// minisign's format rather than an invented one, because a signature only one
// program can check is a signature nobody independent can check. The files this
// package reads are the files `minisign -Vm` reads.
package signature

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// Algorithms, as they appear in the first two bytes of a key or signature.
const (
	algPure      = "Ed" // the signature covers the file itself
	algPrehashed = "ED" // the signature covers BLAKE2b-512 of the file
)

// Sizes of the fixed-width fields.
const (
	algSize = 2
	idSize  = 8
)

var (
	// ErrWrongKey reports a signature by some other key. Kept distinct because
	// it means "this is not ours", which is a different answer to the user than
	// "this does not verify".
	ErrWrongKey = errors.New("signature: signed by a different key")

	// ErrBadSignature reports a signature that does not verify. Deliberately
	// singular: nothing that reaches this is worth telling apart, because every
	// cause has the same consequence.
	ErrBadSignature = errors.New("signature: does not verify")
)

// PublicKey is a minisign public key.
type PublicKey struct {
	ID  [idSize]byte
	Key ed25519.PublicKey
}

// Signature is a parsed detached signature.
type Signature struct {
	// Prehashed reports whether the signature covers a BLAKE2b-512 digest of
	// the file rather than the file itself.
	Prehashed bool
	ID        [idSize]byte
	Sig       []byte

	// TrustedComment is covered by GlobalSig, unlike the comment on the first
	// line of the file, which anybody can rewrite.
	TrustedComment string
	GlobalSig      []byte
}

// ParsePublicKey reads a public key.
//
// Accepts a whole minisign .pub file or the bare base64 line from one, so the
// key compiled into this binary can be the one line rather than a file with a
// comment nobody reads.
func ParsePublicKey(s string) (*PublicKey, error) {
	line := lastMeaningfulLine(s)
	if line == "" {
		return nil, errors.New("signature: no public key here")
	}

	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return nil, fmt.Errorf("signature: unreadable public key: %w", err)
	}
	if len(raw) != algSize+idSize+ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"signature: a public key is %d bytes and this is %d",
			algSize+idSize+ed25519.PublicKeySize, len(raw))
	}
	// A public key carries "Ed" whether or not signatures made with it are
	// prehashed; the signature says which, and that is what is checked below.
	if alg := string(raw[:algSize]); alg != algPure {
		return nil, fmt.Errorf("signature: unsupported public key algorithm %q", alg)
	}

	k := &PublicKey{Key: ed25519.PublicKey(raw[algSize+idSize:])}
	copy(k.ID[:], raw[algSize:algSize+idSize])
	return k, nil
}

// ParseSignature reads a detached signature file.
func ParseSignature(r io.Reader) (*Signature, error) {
	// Callers are responsible for bounding r. `sendan verify` fetches signatures
	// over the network, where the far end decides how much it sends.
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("signature: reading: %w", err)
	}

	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	if len(lines) < 4 {
		return nil, errors.New(
			"signature: truncated; a detached signature is four lines")
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil {
		return nil, fmt.Errorf("signature: unreadable: %w", err)
	}
	if len(raw) != algSize+idSize+ed25519.SignatureSize {
		return nil, fmt.Errorf(
			"signature: a signature is %d bytes and this is %d",
			algSize+idSize+ed25519.SignatureSize, len(raw))
	}

	s := &Signature{Sig: raw[algSize+idSize:]}
	copy(s.ID[:], raw[algSize:algSize+idSize])

	switch alg := string(raw[:algSize]); alg {
	case algPure:
		s.Prehashed = false
	case algPrehashed:
		s.Prehashed = true
	default:
		return nil, fmt.Errorf("signature: unsupported algorithm %q", alg)
	}

	const marker = "trusted comment: "
	if !strings.HasPrefix(lines[2], marker) {
		return nil, errors.New("signature: no trusted comment")
	}
	s.TrustedComment = strings.TrimSuffix(lines[2][len(marker):], "\r")

	if s.GlobalSig, err = base64.StdEncoding.DecodeString(strings.TrimSpace(lines[3])); err != nil {
		return nil, fmt.Errorf("signature: unreadable global signature: %w", err)
	}
	if len(s.GlobalSig) != ed25519.SignatureSize {
		return nil, fmt.Errorf(
			"signature: a global signature is %d bytes and this is %d",
			ed25519.SignatureSize, len(s.GlobalSig))
	}
	return s, nil
}

// Verify reports whether content was signed by this key.
//
// Both signatures are checked. The second one covers the trusted comment, and
// skipping it is the standard way to get this wrong: the comment would then be
// attacker-controlled text that a verifier has just finished calling verified.
func (k *PublicKey) Verify(content []byte, s *Signature) error {
	if s == nil {
		return ErrBadSignature
	}
	if subtle.ConstantTimeCompare(k.ID[:], s.ID[:]) != 1 {
		return ErrWrongKey
	}

	signed := content
	if s.Prehashed {
		sum := blake2b.Sum512(content)
		signed = sum[:]
	}
	if !ed25519.Verify(k.Key, signed, s.Sig) {
		return ErrBadSignature
	}

	// minisign signs the signature bytes followed by the trusted comment, with
	// no separator between them.
	global := append(append([]byte{}, s.Sig...), []byte(s.TrustedComment)...)
	if !ed25519.Verify(k.Key, global, s.GlobalSig) {
		return ErrBadSignature
	}
	return nil
}

// lastMeaningfulLine returns the final non-empty, non-comment line.
func lastMeaningfulLine(s string) string {
	var found string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "untrusted comment:") {
			continue
		}
		found = line
	}
	return found
}
