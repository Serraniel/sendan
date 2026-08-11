// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package manifest

import (
	"encoding/json"
	"io/fs"
	"sort"
	"testing"
	"testing/fstest"
)

func aBuild() fstest.MapFS {
	return fstest.MapFS{
		"index.html":                           {Data: []byte("<!doctype html><title>Sendan</title>")},
		"service-worker.js":                    {Data: []byte("self.addEventListener('fetch', () => {})")},
		"favicon.png":                          {Data: []byte("\x89PNG")},
		"_app/immutable/entry/app.Cd3f.js":     {Data: []byte("export const app = 1;")},
		"_app/immutable/assets/app.9a2b.css":   {Data: []byte("body{}")},
		"_app/immutable/chunks/deep/one.2c.js": {Data: []byte("export const one = 1;")},
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The property the manifest exists for. An asset missing from it is an asset an
// attacker may replace freely, so the set has to come from the build output and
// not from anybody's idea of what the build contains.
func TestEveryFileInTheBuildIsCovered(t *testing.T) {
	build := aBuild()

	manifest, err := Build(build, "v0.4.0", "abc123", false)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// Walked independently of the code under test.
	var want []string
	err = fs.WalkDir(build, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			want = append(want, "/"+path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	sort.Strings(want)

	got := keys(manifest.Assets)
	if len(got) != len(want) {
		t.Fatalf("manifest covers %d files, the build has %d\n got:  %v\n want: %v",
			len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("asset %d is %q, want %q", i, got[i], want[i])
		}
	}
}

// Nothing is filtered. A generator that skipped a category - dotfiles, an
// extension it did not recognise, a directory it thought was internal - would
// leave exactly the assets nobody thought about unprotected.
func TestNothingIsSkipped(t *testing.T) {
	build := fstest.MapFS{
		".well-known/security.txt":  {Data: []byte("Contact: mailto:x@example.org")},
		"robots.txt":                {Data: []byte("User-agent: *")},
		"a file with spaces.js":     {Data: []byte("//")},
		"no-extension":              {Data: []byte("x")},
		"nested/very/deep/thing.js": {Data: []byte("//")},
		"empty.js":                  {Data: []byte("")},
	}

	manifest, err := Build(build, "v1", "c", false)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	for _, want := range []string{
		"/.well-known/security.txt",
		"/robots.txt",
		"/a file with spaces.js",
		"/no-extension",
		"/nested/very/deep/thing.js",
		"/empty.js",
	} {
		if _, ok := manifest.Assets[want]; !ok {
			t.Errorf("%s is not covered", want)
		}
	}
}

// The digest is checked against a value computed elsewhere, not against this
// program's own hashing. A self-consistent wrong format - the wrong alphabet,
// the wrong prefix, the hex of the digest - would round trip here and be
// rejected by every verifier.
func TestTheDigestIsSubresourceIntegritySpelling(t *testing.T) {
	// printf 'hello' | openssl dgst -sha256 -binary | base64
	// The same bytes in hex, for anyone cross-checking by another route:
	// 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	const helloSHA256 = "sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="

	manifest, err := Build(fstest.MapFS{"a.js": {Data: []byte("hello")}}, "v1", "c", false)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := manifest.Assets["/a.js"]; got != helloSHA256 {
		t.Errorf("digest %q, want %q", got, helloSHA256)
	}
}

// Two builds of the same bytes must produce the same manifest, or a verifier
// comparing against a published one has nothing to compare.
func TestTheManifestIsDeterministic(t *testing.T) {
	first, err := Build(aBuild(), "v1", "c", false)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	second, err := Build(aBuild(), "v1", "c", false)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	a, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("two runs disagree:\n%s\n%s", a, b)
	}
}

// A manifest covering nothing would verify anything, so an empty build is a
// refusal rather than a document.
func TestAnEmptyBuildIsRefused(t *testing.T) {
	if _, err := Build(fstest.MapFS{}, "v1", "c", false); err == nil {
		t.Fatal("an empty build produced a manifest")
	}
}

func TestTheSchemaIsStated(t *testing.T) {
	// A verifier reading a manifest it does not understand must refuse rather
	// than guess at the shape.
	manifest, err := Build(aBuild(), "v1", "c", false)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if manifest.Schema != Schema {
		t.Errorf("schema %d, want %d", manifest.Schema, Schema)
	}

	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, field := range []string{`"schema"`, `"version"`, `"commit"`, `"modified"`, `"assets"`} {
		if !containsField(string(encoded), field) {
			t.Errorf("the manifest does not carry %s", field)
		}
	}
}

func containsField(encoded, field string) bool {
	for i := 0; i+len(field) <= len(encoded); i++ {
		if encoded[i:i+len(field)] == field {
			return true
		}
	}
	return false
}
