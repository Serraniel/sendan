// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"encoding/json"
	"net/http"
	"runtime/debug"
)

// Build describes what an instance is running.
//
// AGPL §13 obliges an operator of a modified instance to offer its users the
// corresponding source of the version they are actually talking to. Reporting
// the version alone would not do that: a user needs to know where to get it,
// and whether what they would get matches what is running.
type Build struct {
	// Version is the release, or "dev" for a build the release tooling did not
	// stamp.
	Version string `json:"version"`

	// Commit is the revision this binary was built from. Where the release
	// tooling did not stamp one, it is taken from the version control
	// information Go embeds at build time.
	Commit string `json:"commit"`

	// Modified reports that the working tree held uncommitted changes when the
	// binary was built.
	//
	// A modified build has no commit that corresponds to it, so no source link
	// can be exact. Saying so is more useful than a link that appears
	// authoritative and is not.
	Modified bool `json:"modified"`

	// Source is where the corresponding source can be obtained.
	Source string `json:"source"`

	// License names the terms, so a user need not infer them from the source.
	License string `json:"license"`
}

// license is fixed rather than configurable. It describes the terms this code
// is under, which an operator cannot change by setting a variable.
const license = "AGPL-3.0-or-later"

// currentBuild describes the running binary.
func currentBuild(version, commit, source string) Build {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return resolveBuild(version, commit, source, nil)
	}
	return resolveBuild(version, commit, source, info.Settings)
}

// resolveBuild fills in what the linker did not stamp, from the version control
// information Go embeds at build time.
//
// The settings are a parameter rather than read here, because Go embeds no
// vcs.* settings into a test binary. Logic that read them directly could only
// ever be exercised in production: a test asserting the fallback would find
// nothing to fall back to and quietly prove nothing.
func resolveBuild(version, commit, source string, settings []debug.BuildSetting) Build {
	b := Build{Version: version, Commit: commit, Source: source, License: license}

	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			// A stamped commit wins. The linker knows which revision was
			// released; the embedded value describes the tree it was built
			// from, which for a rebuild of an old release is not the same.
			if b.Commit == "" || b.Commit == "unknown" {
				b.Commit = s.Value
			}
		case "vcs.modified":
			if s.Value == "true" {
				b.Modified = true
			}
		}
	}
	return b
}

// handleSource reports what the instance is running.
//
// It is unauthenticated by design. A user deciding whether to trust an instance
// with a file needs this before they have anything to authenticate with, and it
// discloses nothing that is not already public in the source.
func handleSource(b Build) http.HandlerFunc {
	body, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		// Build has no field that can fail to marshal, so this is unreachable
		// without a change to the type. Failing at construction beats serving a
		// compliance endpoint that returns nothing.
		panic("httpapi: encoding the build report: " + err.Error())
	}
	body = append(body, '\n')

	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(body)
	}
}
