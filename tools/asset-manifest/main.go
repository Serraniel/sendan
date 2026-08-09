// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Command asset-manifest states what the published client hashes to.
//
// For an end-to-end encrypted service the client bundle is the trust boundary:
// the instance only ever holds ciphertext, so what decides whether a file is
// safe is the JavaScript the instance delivered. Verifying an instance
// therefore reduces to verifying what it served, and that is only possible
// against an authoritative statement of what it *should* have served.
//
// This produces that statement. It is published with the release, so it is
// obtainable without asking the instance anything - see docs/design.md §7.1,
// which explains why no endpoint can answer this question.
//
// The manifest is deliberately written outside the directory that is embedded
// and served. An instance serving its own manifest would be attesting to
// itself, which is the circularity the design exists to avoid.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Schema is the manifest format version.
//
// A verifier reading a manifest it does not understand must refuse rather than
// guess, so the number is first and is not optional.
const Schema = 1

// Manifest is the published statement about one build of the client.
type Manifest struct {
	Schema int `json:"schema"`
	// Version and Commit identify the source this was built from.
	Version string `json:"version"`
	Commit  string `json:"commit"`
	// Modified reports a working tree with uncommitted changes.
	//
	// Such a build corresponds to no published revision, so a manifest from one
	// states nothing a verifier can check against the repository. Recorded so
	// that a verifier can refuse it rather than compare against a commit that
	// does not describe these bytes.
	Modified bool `json:"modified"`
	// Assets maps the path a browser requests to the digest of the bytes it
	// should receive. Keys are sorted by encoding/json.
	Assets map[string]string `json:"assets"`
}

func main() {
	dir := flag.String("dir", "internal/webui/dist", "built client to enumerate")
	out := flag.String("out", "internal/webui/manifest.json", "where to write the manifest")
	version := flag.String("version", "", "release version; defaults to git describe")
	commit := flag.String("commit", "", "revision; defaults to git rev-parse HEAD")
	flag.Parse()

	manifest, err := Build(os.DirFS(*dir), *version, *commit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "asset-manifest: %v\n", err)
		os.Exit(1)
	}

	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "asset-manifest: %v\n", err)
		os.Exit(1)
	}
	encoded = append(encoded, '\n')

	// Readable by anyone: this is a published artefact, and a release pipeline
	// that has to widen permissions before uploading it is a step to forget.
	//nolint:gosec // G306: a statement of public digests, deliberately not private.
	if err := os.WriteFile(*out, encoded, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "asset-manifest: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("asset-manifest: %d assets from %s -> %s\n", len(manifest.Assets), *dir, *out)
}

// Build enumerates a built client and digests every file in it.
//
// Everything found is included. There is no filter and no list of what to
// cover, because an asset missing from the manifest is an asset an attacker may
// replace freely - so the set has to come from the build output itself rather
// than from anybody's idea of what the build contains.
func Build(fsys fs.FS, version, commit string) (*Manifest, error) {
	assets := map[string]string{}

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		digest, err := digestOf(fsys, path)
		if err != nil {
			return err
		}
		// The key is what a browser asks for, not where the file sits.
		assets["/"+filepath.ToSlash(path)] = digest
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("enumerating the build: %w", err)
	}
	if len(assets) == 0 {
		// A manifest covering nothing would verify anything. Refusing beats
		// publishing a statement that cannot be violated.
		return nil, fmt.Errorf("no files found: was the client built?")
	}

	if version == "" {
		version = git("describe", "--tags", "--always", "--dirty")
	}
	if commit == "" {
		commit = git("rev-parse", "HEAD")
	}

	return &Manifest{
		Schema:   Schema,
		Version:  version,
		Commit:   commit,
		Modified: git("status", "--porcelain") != "",
		Assets:   assets,
	}, nil
}

// digestOf hashes a file's bytes as they are stored.
//
// Before any transport compression: what a verifier compares is the resource,
// not one encoding of it, and an instance may serve the same bytes gzipped,
// brotli-compressed, or as they are.
func digestOf(fsys fs.FS, path string) (string, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return "", err
	}
	// The subresource integrity spelling, which is what the rest of this
	// project already uses for script hashes.
	return "sha256-" + base64.StdEncoding.EncodeToString(sum.Sum(nil)), nil
}

// git runs a read-only git command and returns its trimmed output, or "".
//
// Absence is not fatal. A build outside a checkout still produces a usable
// manifest, and the release pipeline passes the version and commit explicitly
// rather than relying on what git happens to say.
//
// The command is a literal and every argument at every call site is a literal;
// nothing here comes from input.
//
//nolint:gosec // G204: no part of this command line is caller-supplied.
func git(args ...string) string {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
