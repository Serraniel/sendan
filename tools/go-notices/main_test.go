// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Serraniel/sendan/internal/gomodules"
)

func TestIsLicence(t *testing.T) {
	// Both spellings, both cases, and the extensions modules actually use.
	for _, name := range []string{
		"LICENSE", "LICENSE.txt", "LICENSE.md", "license",
		"LICENCE", "LICENCE.txt",
		"COPYING", "COPYING.md",
		"NOTICE", "NOTICE.txt",
		"LICENSE-MIT",
	} {
		if !isLicence(name) {
			t.Errorf("isLicence(%q) = false, want true", name)
		}
	}

	// Things that look close but are not the notice. README is the one that
	// matters: it would add pages of prose to every entry.
	for _, name := range []string{
		"README.md", "go.mod", "licenses.go", "LICENSE.go",
		"THIRD-PARTY", "unlicensed.txt", "",
	} {
		if isLicence(name) {
			t.Errorf("isLicence(%q) = true, want false", name)
		}
	}
}

// A module that is not in the cache must be an error naming the remedy, not an
// entry with an empty licence.
func TestNoticesInRejectsAbsentModule(t *testing.T) {
	_, err := noticesIn(gomodules.Module{Path: "example.com/absent", Version: "v1.0.0", Dir: ""})
	if err == nil {
		t.Fatal("noticesIn with no Dir returned no error")
	}
	if !strings.Contains(err.Error(), "go mod download") {
		t.Errorf("error does not say how to fix it: %v", err)
	}
}

// The case this generator exists to prevent: a module whose notice cannot be
// found must stop the run rather than be quietly left out.
func TestNoticesInRejectsModuleWithoutLicence(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("not a licence"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := noticesIn(gomodules.Module{Path: "example.com/bare", Version: "v1.0.0", Dir: dir})
	if err == nil {
		t.Fatal("noticesIn on a module with no licence file returned no error")
	}
	if !strings.Contains(err.Error(), "example.com/bare") {
		t.Errorf("error does not name the module: %v", err)
	}
}

func TestNoticesInReadsEveryNoticeVerbatim(t *testing.T) {
	dir := t.TempDir()
	// Apache-2.0 section 4(d) requires a NOTICE file's contents to be
	// reproduced too, so both files have to come back - minio-go/v7 and
	// go.yaml.in/yaml/v3 both ship one.
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("LICENSE", "Apache License\nVersion 2.0\n")
	write("NOTICE", "Product (C) 2026 Somebody\n")
	write("README.md", "should not appear")

	texts, err := noticesIn(gomodules.Module{Path: "example.com/both", Version: "v1.0.0", Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(texts) != 2 {
		t.Fatalf("got %d notices, want 2 (LICENSE and NOTICE)", len(texts))
	}

	joined := strings.Join(texts, "")
	for _, want := range []string{"Apache License", "Product (C) 2026 Somebody"} {
		if !strings.Contains(joined, want) {
			t.Errorf("notice text is missing %q", want)
		}
	}
	if strings.Contains(joined, "should not appear") {
		t.Error("the README was included")
	}
}

// CRLF in an upstream licence must not reach the generated file, or the
// committed copy differs by line ending depending on who last regenerated it.
func TestNoticesInNormalisesLineEndings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "LICENSE"), []byte("MIT License\r\nline two\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	texts, err := noticesIn(gomodules.Module{Path: "example.com/crlf", Version: "v1.0.0", Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(texts[0], "\r") {
		t.Errorf("carriage returns survived: %q", texts[0])
	}
	if texts[0] != "MIT License\nline two\n" {
		t.Errorf("got %q", texts[0])
	}
}

func TestRenderNamesEveryModuleAndIsDeterministic(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	for _, dir := range []string{first, second} {
		if err := os.WriteFile(filepath.Join(dir, "LICENSE"), []byte("MIT License\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	modules := []gomodules.Module{
		{Path: "example.com/a", Version: "v1.2.3", Dir: first},
		{Path: "example.com/b", Version: "v0.1.0", Dir: second},
	}

	out, err := render("sendan server", "Shipped at /THIRD-PARTY-NOTICES.txt.", modules)
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"example.com/a v1.2.3",
		"example.com/b v0.1.0",
		"sendan server",
		"Shipped at /THIRD-PARTY-NOTICES.txt.",
		"AGPL-3.0-or-later",
		"Do not edit",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered notices are missing %q", want)
		}
	}

	// Rendered twice so a diff in the committed file means a dependency moved
	// rather than that somebody regenerated it.
	again, err := render("sendan server", "Shipped at /THIRD-PARTY-NOTICES.txt.", modules)
	if err != nil {
		t.Fatal(err)
	}
	if out != again {
		t.Error("two renders of one module set differ")
	}
}
