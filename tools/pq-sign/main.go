// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Command pq-sign makes and checks the post-quantum release signature.
//
// Separate from the command line client on purpose. That binary is what people
// are asked to obtain and trust, and it should be able to *check* a signature
// without carrying the ability to *make* one - a signing key has no business in
// the program whose smallness is the argument for auditing it.
//
// SLH-DSA has no equivalent of minisign, so unlike the Ed25519 signature this
// one has no third-party tool that can produce it. That is the cost of choosing
// the conservative scheme, and it is why this exists.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/circl/sign/slhdsa"

	"github.com/Serraniel/sendan/internal/signature"
)

const usage = `pq-sign — the post-quantum half of a release signature

  pq-sign generate <name>        write <name>.pqkey and <name>.pqpub
  pq-sign sign <key> <file>      write <file>.slhdsa
  pq-sign verify <pub> <file>    check <file>.slhdsa

The private key never leaves the machine that made it. See
docs/workflows/release.md for where this sits in cutting a release.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "pq-sign: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("no command given")
	}

	switch args[0] {
	case "generate":
		if len(args) != 2 {
			return fmt.Errorf("usage: pq-sign generate <name>")
		}
		return generate(args[1])
	case "sign":
		if len(args) != 3 {
			return fmt.Errorf("usage: pq-sign sign <key> <file>")
		}
		return sign(args[1], args[2])
	case "verify":
		if len(args) != 3 {
			return fmt.Errorf("usage: pq-sign verify <pub> <file>")
		}
		return verify(args[1], args[2])
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func generate(name string) error {
	pub, priv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	if err != nil {
		return err
	}

	privBytes, err := priv.MarshalBinary()
	if err != nil {
		return err
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return err
	}

	// Readable only by its owner, and refusing to overwrite: a private key
	// silently replaced is a release nobody can sign and a key nobody can get
	// back.
	//nolint:gosec // G304: the path is the operator's own argument, and naming
	// the key file is what this command is for.
	f, err := os.OpenFile(name+".pqkey", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("writing the private key: %w", err)
	}
	if _, err := fmt.Fprintf(f, "untrusted comment: sendan post-quantum secret key\n%s\n",
		base64.StdEncoding.EncodeToString(privBytes)); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	encoded := base64.StdEncoding.EncodeToString(pubBytes)
	// Readable by anyone: this is a published key, and a release pipeline that
	// has to widen permissions before uploading it is a step to forget.
	//nolint:gosec // G304,G306: the operator's own path, and a public key.
	if err := os.WriteFile(name+".pqpub", []byte(
		"untrusted comment: sendan post-quantum public key\n"+encoded+"\n"), 0o644); err != nil {
		return fmt.Errorf("writing the public key: %w", err)
	}

	fmt.Printf("%s\n", encoded)
	fmt.Fprintf(os.Stderr,
		"\nWrote %s.pqkey and %s.pqpub.\n\n"+
			"The public half above goes in releasePQKey in cmd/sendan-cli/verify.go\n"+
			"and in docs/cli.md. The private half never leaves this machine, and is\n"+
			"not the same key as the Ed25519 one: a release needs both signatures,\n"+
			"and keeping them together would defeat the reason there are two.\n",
		name, name)
	return nil
}

func sign(keyPath, file string) error {
	priv, err := readPrivateKey(keyPath)
	if err != nil {
		return err
	}
	content, err := os.ReadFile(file) //nolint:gosec // the path is the operator's own argument
	if err != nil {
		return fmt.Errorf("reading %s: %w", file, err)
	}

	// Deterministic: signing the same release twice produces the same bytes, so
	// a signature can be reproduced and compared like the binaries it covers.
	sig, err := slhdsa.SignDeterministic(priv, slhdsa.NewMessage(content), nil)
	if err != nil {
		return fmt.Errorf("signing: %w", err)
	}

	pub := priv.PublicKey()
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return err
	}
	id := keyID(pubBytes)

	out := signature.PQSignatureURL(file)
	body := fmt.Sprintf("untrusted comment: sendan post-quantum signature\nalgorithm: %s\n%s\n",
		"SLH-DSA-SHA2-128s",
		base64.StdEncoding.EncodeToString(append(id, sig...)))
	if err := os.WriteFile(out, []byte(body), 0o644); err != nil { //nolint:gosec // a published signature
		return fmt.Errorf("writing %s: %w", out, err)
	}

	fmt.Printf("%s\n", out)
	return nil
}

func verify(pubPath, file string) error {
	raw, err := os.ReadFile(pubPath) //nolint:gosec // the path is the operator's own argument
	if err != nil {
		return fmt.Errorf("reading %s: %w", pubPath, err)
	}
	key, err := signature.ParsePQPublicKey(string(raw))
	if err != nil {
		return err
	}

	content, err := os.ReadFile(file) //nolint:gosec // the path is the operator's own argument
	if err != nil {
		return fmt.Errorf("reading %s: %w", file, err)
	}

	sigPath := signature.PQSignatureURL(file)
	sigFile, err := os.Open(sigPath) //nolint:gosec // derived from the argument above
	if err != nil {
		return fmt.Errorf("reading %s: %w", sigPath, err)
	}
	defer func() { _ = sigFile.Close() }()

	sig, err := signature.ParsePQSignature(sigFile)
	if err != nil {
		return err
	}
	if err := key.Verify(content, sig); err != nil {
		return err
	}

	fmt.Printf("%s: signature verified\n", file)
	return nil
}

func readPrivateKey(path string) (*slhdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the path is the operator's own argument
	if err != nil {
		return nil, fmt.Errorf("reading the private key: %w", err)
	}

	var line string
	for _, l := range strings.Split(string(raw), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "untrusted comment:") {
			continue
		}
		line = l
	}
	if line == "" {
		return nil, fmt.Errorf("no key in %s", path)
	}

	decoded, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return nil, fmt.Errorf("unreadable private key: %w", err)
	}

	priv := slhdsa.PrivateKey{ID: slhdsa.SHA2_128s}
	if err := priv.UnmarshalBinary(decoded); err != nil {
		return nil, fmt.Errorf("unusable private key: %w", err)
	}
	return &priv, nil
}

// keyID mirrors what the verifier computes, so a signature names its key.
func keyID(pubBytes []byte) []byte {
	id := signature.PQKeyID(pubBytes)
	return id[:]
}
