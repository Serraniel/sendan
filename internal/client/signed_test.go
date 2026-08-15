// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Serraniel/sendan/internal/client"
	"github.com/Serraniel/sendan/internal/signature"
)

// The same fixtures the signature package uses, produced by an independent
// implementation of minisign rather than by this project.
func signedFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../signature/testdata/" + name)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return b
}

func releasePublicKey(t *testing.T) *signature.PublicKey {
	t.Helper()
	k, err := signature.ParsePublicKey(string(signedFixture(t, "release.pub")))
	if err != nil {
		t.Fatalf("parsing the release key: %v", err)
	}
	return k
}

// aReleasePageServing answers for a manifest and its detached signature. A nil
// signature means the release was published without one.
func aReleasePageServing(t *testing.T, body, sig []byte) (*client.Client, string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".minisig"):
			if sig == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write(sig)
		default:
			_, _ = w.Write(body)
		}
	}))
	t.Cleanup(server.Close)
	return &client.Client{Origin: server.URL}, server.URL + "/manifest.json"
}

func TestASignedManifestIsAccepted(t *testing.T) {
	c, url := aReleasePageServing(t,
		signedFixture(t, "manifest.json"),
		signedFixture(t, "manifest.json.minisig"))

	m, err := c.FetchSignedManifest(context.Background(), url, releasePublicKey(t))
	if err != nil {
		t.Fatalf("a correctly signed manifest was refused: %v", err)
	}
	if m.Version != "v0.1.0" {
		t.Errorf("version %q, want v0.1.0", m.Version)
	}
}

// The attack this exists to stop: whoever can replace the manifest on the
// release page makes a backdoored instance verify clean.
func TestAManifestAlteredAfterSigningIsRefused(t *testing.T) {
	altered := strings.Replace(string(signedFixture(t, "manifest.json")),
		"sha256-3lQ", "sha256-XXX", 1)

	c, url := aReleasePageServing(t, []byte(altered), signedFixture(t, "manifest.json.minisig"))

	_, err := c.FetchSignedManifest(context.Background(), url, releasePublicKey(t))
	if !errors.Is(err, signature.ErrBadSignature) {
		t.Fatalf("an altered manifest gave %v, want ErrBadSignature", err)
	}
}

func TestAManifestSignedByTheWrongKeyIsRefused(t *testing.T) {
	c, url := aReleasePageServing(t,
		signedFixture(t, "manifest.json"),
		signedFixture(t, "manifest.json.otherkey.minisig"))

	_, err := c.FetchSignedManifest(context.Background(), url, releasePublicKey(t))
	if !errors.Is(err, signature.ErrWrongKey) {
		t.Fatalf("a foreign signature gave %v, want ErrWrongKey", err)
	}
}

// Told apart from a bad signature, because "this release was never signed" and
// "this release is not what it claims" call for different things from the user.
func TestAnUnsignedReleaseIsReportedAsUnsigned(t *testing.T) {
	c, url := aReleasePageServing(t, signedFixture(t, "manifest.json"), nil)

	_, err := c.FetchSignedManifest(context.Background(), url, releasePublicKey(t))
	if !errors.Is(err, client.ErrUnsigned) {
		t.Fatalf("an unsigned release gave %v, want ErrUnsigned", err)
	}
}

func TestAnUnreadableSignatureIsRefused(t *testing.T) {
	c, url := aReleasePageServing(t,
		signedFixture(t, "manifest.json"),
		[]byte("this is not a signature\n"))

	if _, err := c.FetchSignedManifest(context.Background(), url, releasePublicKey(t)); err == nil {
		t.Fatal("accepted a signature file that is not one")
	}
}

// The manifest is fetched before the signature, so a valid signature over a
// truncated body must not pass. Bounding the read is what makes the bytes that
// were verified the same bytes that get parsed.
func TestTheSignatureCoversTheManifestThatIsUsed(t *testing.T) {
	body := signedFixture(t, "manifest.json")
	c, url := aReleasePageServing(t, body, signedFixture(t, "manifest.json.minisig"))

	m, err := c.FetchSignedManifest(context.Background(), url, releasePublicKey(t))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got := m.Assets["/index.html"]; got == "" {
		t.Error("the manifest that was verified is not the manifest that was parsed")
	}
}

func TestTheSignatureSitsBesideTheManifest(t *testing.T) {
	const url = "https://example.org/releases/download/v1.0.0/manifest.json"
	if got, want := client.SignatureURL(url), url+".minisig"; got != want {
		t.Errorf("SignatureURL = %q, want %q", got, want)
	}
}
