// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package gomodules

import "testing"

// The shape `go list -deps -json` emits: a stream of objects, not an array.
// Standard library packages carry no Module at all, which is how they are
// excluded; the main module has to be excluded by path.
const listed = `{"ImportPath":"fmt"}
{"ImportPath":"github.com/Serraniel/sendan/internal/thing","Module":{"Path":"github.com/Serraniel/sendan","Version":"","Dir":"/src"}}
{"ImportPath":"golang.org/x/term","Module":{"Path":"golang.org/x/term","Version":"v0.48.0","Dir":"/cache/term"}}
{"ImportPath":"golang.org/x/crypto/hkdf","Module":{"Path":"golang.org/x/crypto","Version":"v0.59.0","Dir":"/cache/crypto"}}
{"ImportPath":"golang.org/x/crypto/sha3","Module":{"Path":"golang.org/x/crypto","Version":"v0.59.0","Dir":"/cache/crypto"}}
`

func TestParse(t *testing.T) {
	modules, err := parse([]byte(listed))
	if err != nil {
		t.Fatal(err)
	}

	// Two packages of golang.org/x/crypto collapse to one module, the standard
	// library is gone, and the main module is gone.
	if len(modules) != 2 {
		t.Fatalf("got %d modules, want 2: %+v", len(modules), modules)
	}

	// Sorted by path, which is what makes the generated files stable.
	if modules[0].Path != "golang.org/x/crypto" || modules[1].Path != "golang.org/x/term" {
		t.Errorf("not sorted by path: %+v", modules)
	}
	if modules[0].Version != "v0.59.0" {
		t.Errorf("version = %q, want v0.59.0", modules[0].Version)
	}
	if modules[0].Dir != "/cache/crypto" {
		t.Errorf("dir = %q, want /cache/crypto", modules[0].Dir)
	}

	for _, found := range modules {
		if found.Path == Main {
			t.Error("the main module is reported as its own dependency")
		}
	}
}

func TestParseRejectsMalformedOutput(t *testing.T) {
	if _, err := parse([]byte(`{"ImportPath":`)); err == nil {
		t.Error("parse accepted truncated JSON")
	}
}

func TestParseEmpty(t *testing.T) {
	modules, err := parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(modules) != 0 {
		t.Errorf("got %d modules from no output", len(modules))
	}
}

func TestToolchain(t *testing.T) {
	goMod := []byte("module example.com/x\n\n// a comment\ngo 1.26.0\n\ntoolchain go1.27.4\n\nrequire (\n\tx v1.0.0\n)\n")
	version, err := Toolchain(goMod)
	if err != nil {
		t.Fatal(err)
	}
	// The directive, not the running toolchain: the release is pinned to this.
	if version != "1.27.4" {
		t.Errorf("got %q, want 1.27.4", version)
	}
}

func TestToolchainWithoutDirective(t *testing.T) {
	if _, err := Toolchain([]byte("module example.com/x\n\ngo 1.26.0\n")); err == nil {
		t.Error("Toolchain accepted a go.mod with no toolchain directive")
	}
}

// `go 1.26.0` must not be mistaken for the toolchain: they are different lines
// and the whole point of reading the directive is that they differ.
func TestToolchainIgnoresTheGoDirective(t *testing.T) {
	if _, err := Toolchain([]byte("go 1.26.0\n")); err == nil {
		t.Error("the go directive was read as a toolchain")
	}
}
