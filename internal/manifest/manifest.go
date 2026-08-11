// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Package manifest is the published statement of what a client build contains.
//
// It is one definition used by both halves: tools/asset-manifest writes it with
// a release, and the command line client reads it to check that an instance
// serves that build. Two definitions of a published format would drift, and the
// drift would show up as a verification that fails for no reason anybody could
// find.
package manifest

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
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

// Build enumerates a built client and digests every file in it.
//
// Everything found is included. There is no filter and no list of what to
// cover, because an asset missing from the manifest is an asset an attacker may
// replace freely - so the set has to come from the build output itself rather
// than from anybody's idea of what the build contains.
func Build(fsys fs.FS, version, commit string, modified bool) (*Manifest, error) {
	assets := map[string]string{}

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		digest, err := digestOfFile(fsys, path)
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

	return &Manifest{
		Schema:   Schema,
		Version:  version,
		Commit:   commit,
		Modified: modified,
		Assets:   assets,
	}, nil
}

// DigestOf hashes bytes the way the manifest records them.
//
// Exported because a verifier has to hash what an instance served with exactly
// the function that produced the published value. Two spellings of "the sha256
// of these bytes" would disagree in a way that looks like a modified instance.
//
// Before any transport compression: what a verifier compares is the resource,
// not one encoding of it, and an instance may serve the same bytes gzipped,
// brotli-compressed, or as they are.
func DigestOf(r io.Reader) (string, error) {
	sum := sha256.New()
	if _, err := io.Copy(sum, r); err != nil {
		return "", err
	}
	// The subresource integrity spelling, which is what the rest of this
	// project already uses for script hashes.
	return "sha256-" + base64.StdEncoding.EncodeToString(sum.Sum(nil)), nil
}

// digestOfFile hashes a file's bytes as they are stored.
//
// Before any transport compression: what a verifier compares is the resource,
// not one encoding of it, and an instance may serve the same bytes gzipped,
// brotli-compressed, or as they are.
func digestOfFile(fsys fs.FS, path string) (string, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	return DigestOf(f)
}
