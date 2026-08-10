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
// which explains why no endpoint can answer this question. `sendan verify`
// reads it back.
//
// The manifest is deliberately written outside the directory that is embedded
// and served. An instance serving its own manifest would be attesting to
// itself, which is the circularity the design exists to avoid.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Serraniel/sendan/internal/manifest"
)

func main() {
	dir := flag.String("dir", "internal/webui/dist", "built client to enumerate")
	out := flag.String("out", "internal/webui/manifest.json", "where to write the manifest")
	version := flag.String("version", "", "release version; defaults to git describe")
	commit := flag.String("commit", "", "revision; defaults to git rev-parse HEAD")
	flag.Parse()

	if *version == "" {
		*version = git("describe", "--tags", "--always", "--dirty")
	}
	if *commit == "" {
		*commit = git("rev-parse", "HEAD")
	}

	m, err := manifest.Build(os.DirFS(*dir), *version, *commit, git("status", "--porcelain") != "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "asset-manifest: %v\n", err)
		os.Exit(1)
	}

	encoded, err := json.MarshalIndent(m, "", "  ")
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
	fmt.Printf("asset-manifest: %d assets from %s -> %s\n", len(m.Assets), *dir, *out)
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
