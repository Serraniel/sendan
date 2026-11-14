// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Package gomodules answers one question: which modules are linked into a
// shipped binary.
//
// It exists as a package rather than a function in one tool because two things
// now ask it - the licence notices and the SBOM - and they must not be able to
// disagree. An SBOM that names a different set from the notices beside it in
// the same release archive is worse than either alone, because there is then no
// way to tell which is right.
//
// The answer comes from `go list -deps`, which was checked against the record
// the linker itself writes: `go version -m` on both built binaries reports
// exactly these sets. See #313 and #355.
package gomodules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
)

// Module is a dependency of a shipped binary.
type Module struct {
	// Path is the module path, e.g. golang.org/x/crypto.
	Path string
	// Version is the module version, e.g. v0.59.0.
	Version string
	// Dir is where the module is in the local module cache, which is empty
	// when it has not been downloaded.
	Dir string
}

// Main is the module this repository is, which is not a third party to itself
// and is never reported as a dependency.
const Main = "github.com/Serraniel/sendan"

type listedModule struct {
	Path    string
	Version string
	Dir     string
}

type listedPackage struct {
	Module *listedModule
}

// Linked returns the modules reachable from pkgPath, sorted by module path,
// with the main module and the standard library removed. The standard library
// has no module, which is how it is excluded.
//
// No build tags are passed. The image builds the server with -tags embedui,
// and that tag selects between two files in internal/webui, neither of which
// imports anything external - so the tagged and untagged sets are identical,
// and scripts/check-go-notices.sh asserts that whenever the embedded assets are
// present. Running without the tag is what lets this work on a fresh checkout,
// where internal/webui/dist does not exist yet.
func Linked(pkgPath string) ([]Module, error) {
	// pkgPath reaches this from a build script - a literal in tools/go-notices'
	// target table, or the -pkg flag of tools/go-sbom - and the command it
	// builds is otherwise fixed. `go list` reports on packages rather than
	// running them, and nothing here is reachable from the server.
	//nolint:gosec // G204: a package path supplied by the build, not by input.
	command := exec.Command("go", "list", "-deps", "-json", pkgPath)
	command.Stderr = os.Stderr
	out, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("go list %s: %w", pkgPath, err)
	}
	return parse(out)
}

// parse reads the stream of JSON objects `go list -json` emits. Split out so
// the shape handling is testable without running the toolchain.
func parse(out []byte) ([]Module, error) {
	seen := map[string]Module{}
	decoder := json.NewDecoder(bytes.NewReader(out))
	for decoder.More() {
		var listed listedPackage
		if err := decoder.Decode(&listed); err != nil {
			return nil, fmt.Errorf("reading go list output: %w", err)
		}
		if listed.Module == nil || listed.Module.Path == Main {
			continue
		}
		seen[listed.Module.Path] = Module{
			Path:    listed.Module.Path,
			Version: listed.Module.Version,
			Dir:     listed.Module.Dir,
		}
	}

	modules := make([]Module, 0, len(seen))
	for _, found := range seen {
		modules = append(modules, found)
	}
	// Sorted by path, so that two runs produce identical bytes and a diff
	// between them means a dependency moved.
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	return modules, nil
}

// Toolchain is the Go toolchain the project builds with, read from go.mod's
// toolchain directive rather than from the running `go`, because the directive
// is what the release is pinned to and what scripts/check-toolchains.sh holds
// every other reference equal to.
func Toolchain(goMod []byte) (string, error) {
	for line := range bytes.Lines(goMod) {
		fields := bytes.Fields(line)
		if len(fields) == 2 && string(fields[0]) == "toolchain" {
			return string(bytes.TrimPrefix(fields[1], []byte("go"))), nil
		}
	}
	return "", fmt.Errorf("go.mod names no toolchain directive")
}
