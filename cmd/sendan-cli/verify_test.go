// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Serraniel/sendan/internal/client"
	"github.com/Serraniel/sendan/internal/signature"
)

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../internal/signature/testdata/" + name)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return b
}

// keyLine is the public key as it is published: one base64 line.
func keyLine(t *testing.T) string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(string(testdata(t, "release.pub"))), "\n")
	return lines[len(lines)-1]
}

func aReleasePage(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".minisig") {
			_, _ = w.Write(testdata(t, "manifest.json.minisig"))
			return
		}
		_, _ = w.Write(testdata(t, "manifest.json"))
	}))
	t.Cleanup(server.Close)
	return server.URL + "/manifest.json"
}

// A key is published as a line of base64 and usually pasted, but somebody who
// saved it to a file should not have to know the difference.
func TestAKeyIsTakenAsALineOrAsAPath(t *testing.T) {
	line := keyLine(t)

	path := filepath.Join(t.TempDir(), "release.pub")
	if err := os.WriteFile(path, testdata(t, "release.pub"), 0o600); err != nil {
		t.Fatal(err)
	}

	fromLine, err := loadKey(line)
	if err != nil {
		t.Fatalf("a pasted key was refused: %v", err)
	}
	fromFile, err := loadKey(path)
	if err != nil {
		t.Fatalf("a key file was refused: %v", err)
	}
	if fromLine.ID != fromFile.ID {
		t.Error("the same key given two ways gave two keys")
	}
}

// Until a release key is compiled in, checking a published manifest cannot mean
// anything - and saying so beats checking against nothing and reporting a pass.
func TestWithoutAKeyAPublishedManifestIsNotChecked(t *testing.T) {
	if releaseKey != "" {
		t.Skip("this build has a release key")
	}

	_, _, err := loadManifest(context.Background(), &client.Client{},
		aReleasePage(t), "", client.Claim{Version: "v0.1.0"})
	if err == nil {
		t.Fatal("checked a published manifest with no key to check it against")
	}
	if !strings.Contains(err.Error(), "--key") {
		t.Errorf("the error does not say what to do about it: %v", err)
	}
}

func TestASignedManifestIsReportedAsSigned(t *testing.T) {
	_, authority, err := loadManifest(context.Background(), &client.Client{},
		aReleasePage(t), keyLine(t), client.Claim{Version: "v0.1.0"})
	if err != nil {
		t.Fatalf("a signed manifest was refused: %v", err)
	}
	if !strings.Contains(authority, "signed by") {
		t.Errorf("authority = %q, want it to say the manifest was signed", authority)
	}
}

// Somebody who built the client themselves is the authority for the manifest
// they produced. The report says so rather than implying a signature.
func TestALocalManifestIsUsedAndSaidToBeUnsigned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, testdata(t, "manifest.json"), 0o600); err != nil {
		t.Fatal(err)
	}

	m, authority, err := loadManifest(context.Background(), &client.Client{},
		path, "", client.Claim{})
	if err != nil {
		t.Fatalf("a local manifest was refused: %v", err)
	}
	if m.Version != "v0.1.0" {
		t.Errorf("version %q, want v0.1.0", m.Version)
	}
	if !strings.Contains(authority, "unsigned") {
		t.Errorf("authority = %q, want it to say the manifest is unsigned", authority)
	}
}

// The signature is what decides, so a bad one has to end the run rather than
// print a warning above a result that then reads as a pass.
func TestABadSignatureStopsTheCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".minisig") {
			_, _ = w.Write(testdata(t, "manifest.json.otherkey.minisig"))
			return
		}
		_, _ = w.Write(testdata(t, "manifest.json"))
	}))
	defer server.Close()

	_, _, err := loadManifest(context.Background(), &client.Client{},
		server.URL+"/manifest.json", keyLine(t), client.Claim{Version: "v0.1.0"})
	if err == nil {
		t.Fatal("carried on with a manifest signed by another key")
	}
}

// An unsigned release is a distinct answer, and the advice that goes with it is
// different: there is nothing to fix by trying again.
func TestAnUnsignedReleaseExplainsWhatToDo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".minisig") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(testdata(t, "manifest.json"))
	}))
	defer server.Close()

	_, _, err := loadManifest(context.Background(), &client.Client{},
		server.URL+"/manifest.json", keyLine(t), client.Claim{Version: "v0.1.0"})
	if !errors.Is(err, client.ErrUnsigned) {
		t.Fatalf("got %v, want ErrUnsigned", err)
	}
	if !strings.Contains(err.Error(), "--manifest") {
		t.Errorf("the error does not offer a way forward: %v", err)
	}
}

// A version the instance made up names no release, which is a failure to carry
// out the check rather than a verdict on the instance.
func TestAnInstanceWithNoReleaseToCompareAgainstSaysSo(t *testing.T) {
	for _, version := range []string{"", "dev"} {
		_, _, err := loadManifest(context.Background(), &client.Client{},
			"", "", client.Claim{Version: version})
		if err == nil {
			t.Errorf("version %q: expected a refusal", version)
		}
	}
}

// The two release keys must be filled in together.
//
// They behave differently when empty, and that asymmetry is the trap: an empty
// releaseKey refuses every published manifest, which is loud, while an empty
// releasePQKey silently skips the post-quantum check. Filling in one and
// forgetting the other yields a build that looks like it enforces both
// signatures and enforces one - which is the failure requiring two was meant to
// prevent, arrived at by an editing mistake rather than an attack.
func TestBothReleaseKeysAreSetOrNeither(t *testing.T) {
	switch {
	case releaseKey == "" && releasePQKey == "":
		// No release has been cut. `sendan verify` says so rather than
		// checking against nothing.
	case releaseKey != "" && releasePQKey != "":
		// Both in force, which is what a published release requires.
	case releaseKey == "":
		t.Fatal("releasePQKey is set but releaseKey is not: a published manifest " +
			"cannot be checked at all, because the classical signature is the one " +
			"that gates the fetch")
	default:
		t.Fatal("releaseKey is set but releasePQKey is not: this build would " +
			"accept a release carrying only the classical signature, and report " +
			"it as verified. Fill in releasePQKey, or clear releaseKey")
	}
}

// And whichever are set must actually parse, so a mistyped key is caught here
// rather than by the first person to run `sendan verify`.
func TestTheCompiledInKeysParse(t *testing.T) {
	if releaseKey != "" {
		if _, err := signature.ParsePublicKey(releaseKey); err != nil {
			t.Errorf("releaseKey does not parse: %v", err)
		}
	}
	if releasePQKey != "" {
		if _, err := signature.ParsePQPublicKey(releasePQKey); err != nil {
			t.Errorf("releasePQKey does not parse: %v", err)
		}
	}
}
