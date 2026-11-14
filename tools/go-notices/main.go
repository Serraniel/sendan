// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Generates the third-party notices for the released Go binaries.
//
// # Why this exists
//
// The binaries link modules under MIT, BSD, Apache-2.0 and ISC licences. Every
// one of those requires its notice to travel with the binary that contains the
// code, and nothing produced such a file - so the releases shipped without it.
// See #313.
//
// scripts/third-party-notices.mjs does the same job for the npm packages
// compiled into the web client. This is the Go counterpart, and it exists
// separately because the question "what is linked into this binary" is one only
// the Go toolchain can answer.
//
// # Why one file per binary
//
// The two shipped binaries are not alike. The server links 32 modules; the
// command line client links 4, because it deliberately shares none of the
// server's storage or database code - docs/cli.md says so and this is what
// makes that checkable. Giving the client the server's notices would name 28
// projects whose code is not in it, which is not what a notice file is for.
//
// # Why `go list` runs without the embedui build tag
//
// The image builds the server with -tags embedui, and that tag selects between
// two files in internal/webui, neither of which imports anything external: the
// tagged and untagged module sets are identical, and that equality is asserted
// by scripts/check-go-notices.sh. Running without it matters because the tag
// embeds internal/webui/dist, which is generated and git-ignored - with the tag
// this would not run on a fresh checkout, which is exactly where CI runs it.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// A shipped binary, and the notices file that has to travel with it.
var targets = []struct {
	file    string
	pkg     string
	binary  string
	travels string
}{
	{
		file:    "notices/sendan.txt",
		pkg:     "./cmd/sendan",
		binary:  "sendan server",
		travels: "This file is in the container image at /THIRD-PARTY-NOTICES.txt.",
	},
	{
		file:    "notices/sendan-cli.txt",
		pkg:     "./cmd/sendan-cli",
		binary:  "sendan command line client",
		travels: "This file is published with each release as THIRD-PARTY-NOTICES.txt.",
	},
}

// The main module, which is AGPL-3.0-or-later and is not a third party to
// itself.
const self = "github.com/Serraniel/sendan"

type module struct {
	Path    string
	Version string
	Dir     string
}

type pkg struct {
	Module *module
}

// Names a licence or notice file carries, lowercased. Both spellings of
// "licence", because modules use both.
var licenceNames = []string{
	"license", "license.md", "license.txt", "license-mit", "license.code",
	"licence", "licence.md", "licence.txt",
	"copying", "copying.md", "copying.txt",
	"notice", "notice.md", "notice.txt",
}

func isLicence(name string) bool {
	lowered := strings.ToLower(name)
	for _, candidate := range licenceNames {
		if lowered == candidate {
			return true
		}
	}
	return false
}

// The modules linked into pkg, with the main module and the standard library
// removed. The standard library has no Module, which is how it is excluded.
func modulesFor(pkgPath string) ([]module, error) {
	command := exec.Command("go", "list", "-deps", "-json", pkgPath)
	command.Stderr = os.Stderr
	out, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("go list %s: %w", pkgPath, err)
	}

	seen := map[string]module{}
	decoder := json.NewDecoder(bytes.NewReader(out))
	for decoder.More() {
		var listed pkg
		if err := decoder.Decode(&listed); err != nil {
			return nil, fmt.Errorf("reading go list output: %w", err)
		}
		if listed.Module == nil || listed.Module.Path == self {
			continue
		}
		seen[listed.Module.Path] = *listed.Module
	}

	modules := make([]module, 0, len(seen))
	for _, found := range seen {
		modules = append(modules, found)
	}
	// Sorted by path so that two runs produce identical bytes and a diff
	// between them means a dependency moved.
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	return modules, nil
}

// Every licence and notice file at the module's root, verbatim.
//
// A module with none is an error rather than an omission: a missing notice is
// the precise failure this file exists to prevent, and silently leaving one out
// would make the generator the cause of it.
func noticesIn(found module) ([]string, error) {
	if found.Dir == "" {
		return nil, fmt.Errorf("%s %s is not in the module cache; run `go mod download`",
			found.Path, found.Version)
	}

	entries, err := os.ReadDir(found.Dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", found.Dir, err)
	}

	names := []string{}
	for _, entry := range entries {
		if !entry.IsDir() && isLicence(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)

	if len(names) == 0 {
		return nil, fmt.Errorf("%s %s has no licence file at its root; it cannot be shipped "+
			"without one, so this needs looking at by a person", found.Path, found.Version)
	}

	texts := make([]string, 0, len(names))
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(found.Dir, name))
		if err != nil {
			return nil, fmt.Errorf("reading %s/%s: %w", found.Path, name, err)
		}
		// Normalised line endings only; the text itself is untouched, because
		// reproducing it is the obligation.
		text := strings.ReplaceAll(string(body), "\r\n", "\n")
		texts = append(texts, strings.TrimRight(text, "\n")+"\n")
	}
	return texts, nil
}

const rule = "------------------------------------------------------------------------"

func render(binary, travels string, modules []module) (string, error) {
	var out strings.Builder

	out.WriteString("Third-party notices\n")
	out.WriteString("===================\n\n")
	fmt.Fprintf(&out, "The %s contains code from the projects below.\n", binary)
	out.WriteString("Their licences require these notices to travel with it, so they are\n")
	out.WriteString("shipped beside it rather than only kept in the repository.\n\n")
	out.WriteString(travels)
	out.WriteString("\n\n")
	out.WriteString("Sendan itself is AGPL-3.0-or-later. Its own source is a separate\n")
	out.WriteString("obligation and is not discharged by this file; SECURITY.md and the\n")
	out.WriteString("instance's own source report cover it.\n\n")
	out.WriteString("Generated by tools/go-notices. Do not edit.\n")

	for _, found := range modules {
		texts, err := noticesIn(found)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&out, "\n%s\n%s %s\n%s\n\n", rule, found.Path, found.Version, rule)
		out.WriteString(strings.Join(texts, "\n"))
	}

	return out.String(), nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "go-notices: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if err := os.MkdirAll("notices", 0o755); err != nil {
		return err
	}

	for _, target := range targets {
		modules, err := modulesFor(target.pkg)
		if err != nil {
			return err
		}
		text, err := render(target.binary, target.travels, modules)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target.file, []byte(text), 0o644); err != nil {
			return err
		}
		fmt.Printf("%s: %d modules\n", target.file, len(modules))
	}
	return nil
}
