// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Serraniel/sendan/internal/gomodules"
)

func TestCreatedFromSourceDateEpoch(t *testing.T) {
	for epoch, want := range map[string]string{
		"":           "1970-01-01T00:00:00Z",
		"0":          "1970-01-01T00:00:00Z",
		"1763000000": "2025-11-13T02:13:20Z",
	} {
		got, err := created(epoch)
		if err != nil {
			t.Fatalf("created(%q): %v", epoch, err)
		}
		if got != want {
			t.Errorf("created(%q) = %q, want %q", epoch, got, want)
		}
	}
}

// Falling back to "now" would break the release's reproducibility check, and
// would do it intermittently, which is the worst way for it to break.
func TestCreatedRefusesGarbageRatherThanUsingNow(t *testing.T) {
	if _, err := created("yesterday"); err == nil {
		t.Error("created accepted a non-numeric SOURCE_DATE_EPOCH")
	}
}

// SPDX identifiers admit letters, digits, dots and hyphens only.
func TestIdentifierIsValidSPDX(t *testing.T) {
	got := identifier("Package", "golang.org/x/crypto-v0.59.0")
	if got != "SPDXRef-Package-golang.org-x-crypto-v0.59.0" {
		t.Errorf("got %q", got)
	}
	for _, r := range strings.TrimPrefix(got, "SPDXRef-") {
		ok := r == '.' || r == '-' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok {
			t.Errorf("identifier contains %q, which SPDX does not allow", r)
		}
	}
}

func modules() []gomodules.Module {
	return []gomodules.Module{
		{Path: "github.com/cloudflare/circl", Version: "v1.6.5"},
		{Path: "golang.org/x/crypto", Version: "v0.59.0"},
	}
}

func TestBuildNamesEveryComponent(t *testing.T) {
	doc, err := build("sendan", "v0.4.0", "abc123", "1.27.4", "0", modules())
	if err != nil {
		t.Fatal(err)
	}

	if doc.SPDXVersion != "SPDX-2.3" || doc.DataLicense != "CC0-1.0" {
		t.Errorf("wrong document header: %+v", doc)
	}

	// The binary, the standard library, and one per module.
	if len(doc.Packages) != len(modules())+2 {
		t.Fatalf("got %d packages, want %d", len(doc.Packages), len(modules())+2)
	}

	names := map[string]string{}
	for _, p := range doc.Packages {
		names[p.Name] = p.VersionInfo
		if p.LicenseConcluded == "" || p.CopyrightText == "" || p.DownloadLocation == "" {
			t.Errorf("%s omits a field SPDX requires: %+v", p.Name, p)
		}
	}

	// The toolchain is a component: two Gos do not produce the same bytes, and
	// a standard library advisory is fixed by moving it and nothing else.
	if names["go"] != "1.27.4" {
		t.Errorf("the standard library is not named as 1.27.4: %v", names)
	}
	if names["golang.org/x/crypto"] != "v0.59.0" {
		t.Errorf("a module is missing or misversioned: %v", names)
	}

	// Only this project's own licence is asserted; the rest is NOASSERTION,
	// because classifying somebody else's licence text is a judgement.
	for _, p := range doc.Packages {
		if p.Name == "sendan" {
			if p.LicenseDeclared != "AGPL-3.0-or-later" {
				t.Errorf("own licence = %q", p.LicenseDeclared)
			}
			continue
		}
		if p.LicenseDeclared != "NOASSERTION" {
			t.Errorf("%s declares %q; it should not claim to know", p.Name, p.LicenseDeclared)
		}
	}
}

func TestBuildRelationshipsAreComplete(t *testing.T) {
	doc, err := build("sendan", "v0.4.0", "abc123", "1.27.4", "0", modules())
	if err != nil {
		t.Fatal(err)
	}

	root := identifier("Binary", "sendan")
	if len(doc.DocumentDescribes) != 1 || doc.DocumentDescribes[0] != root {
		t.Errorf("documentDescribes = %v", doc.DocumentDescribes)
	}

	// Every package other than the root must hang off it, or a consumer sees
	// components with no stated relationship to what was shipped.
	dependedOn := map[string]bool{}
	describes := false
	for _, r := range doc.Relationships {
		switch r.RelationshipType {
		case "DEPENDS_ON":
			if r.SPDXElementID != root {
				t.Errorf("DEPENDS_ON from %q, not the binary", r.SPDXElementID)
			}
			dependedOn[r.RelatedSPDXElement] = true
		case "DESCRIBES":
			describes = true
		}
	}
	if !describes {
		t.Error("no DESCRIBES relationship from the document")
	}
	for _, p := range doc.Packages {
		if p.SPDXID == root {
			continue
		}
		if !dependedOn[p.SPDXID] {
			t.Errorf("%s is listed but nothing depends on it", p.Name)
		}
	}
}

// The release builds twice and fails if the checksums differ, so this file has
// to come out byte-identical from one input.
func TestBuildIsDeterministic(t *testing.T) {
	first, err := build("sendan", "v0.4.0", "abc123", "1.27.4", "0", modules())
	if err != nil {
		t.Fatal(err)
	}
	second, err := build("sendan", "v0.4.0", "abc123", "1.27.4", "0", modules())
	if err != nil {
		t.Fatal(err)
	}

	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Error("two builds of one input differ")
	}

	// And the namespace is derived, so two releases do not collide.
	other, err := build("sendan", "v0.4.1", "def456", "1.27.4", "0", modules())
	if err != nil {
		t.Fatal(err)
	}
	if other.DocumentNamespace == first.DocumentNamespace {
		t.Error("two different releases share a document namespace")
	}
}
