// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package client_test

import (
	"bytes"
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

	m, err := c.FetchSignedManifest(context.Background(), url, client.Keys{Ed25519: releasePublicKey(t)})
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

	_, err := c.FetchSignedManifest(context.Background(), url, client.Keys{Ed25519: releasePublicKey(t)})
	if !errors.Is(err, signature.ErrBadSignature) {
		t.Fatalf("an altered manifest gave %v, want ErrBadSignature", err)
	}
}

func TestAManifestSignedByTheWrongKeyIsRefused(t *testing.T) {
	c, url := aReleasePageServing(t,
		signedFixture(t, "manifest.json"),
		signedFixture(t, "manifest.json.otherkey.minisig"))

	_, err := c.FetchSignedManifest(context.Background(), url, client.Keys{Ed25519: releasePublicKey(t)})
	if !errors.Is(err, signature.ErrWrongKey) {
		t.Fatalf("a foreign signature gave %v, want ErrWrongKey", err)
	}
}

// Told apart from a bad signature, because "this release was never signed" and
// "this release is not what it claims" call for different things from the user.
func TestAnUnsignedReleaseIsReportedAsUnsigned(t *testing.T) {
	c, url := aReleasePageServing(t, signedFixture(t, "manifest.json"), nil)

	_, err := c.FetchSignedManifest(context.Background(), url, client.Keys{Ed25519: releasePublicKey(t)})
	if !errors.Is(err, client.ErrUnsigned) {
		t.Fatalf("an unsigned release gave %v, want ErrUnsigned", err)
	}
}

func TestAnUnreadableSignatureIsRefused(t *testing.T) {
	c, url := aReleasePageServing(t,
		signedFixture(t, "manifest.json"),
		[]byte("this is not a signature\n"))

	if _, err := c.FetchSignedManifest(context.Background(), url, client.Keys{Ed25519: releasePublicKey(t)}); err == nil {
		t.Fatal("accepted a signature file that is not one")
	}
}

// The manifest is fetched before the signature, so a valid signature over a
// truncated body must not pass. Bounding the read is what makes the bytes that
// were verified the same bytes that get parsed.
func TestTheSignatureCoversTheManifestThatIsUsed(t *testing.T) {
	body := signedFixture(t, "manifest.json")
	c, url := aReleasePageServing(t, body, signedFixture(t, "manifest.json.minisig"))

	m, err := c.FetchSignedManifest(context.Background(), url, client.Keys{Ed25519: releasePublicKey(t)})
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

func releasePQKey(t *testing.T) *signature.PQPublicKey {
	t.Helper()
	k, err := signature.ParsePQPublicKey(string(signedFixture(t, "release.pqpub")))
	if err != nil {
		t.Fatalf("parsing the post-quantum key: %v", err)
	}
	return k
}

// aReleasePageWithBoth serves a manifest and whichever of its two signatures
// are given. A nil one is a release that does not carry it.
func aReleasePageWithBoth(t *testing.T, body, ed, pq []byte) (*client.Client, string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var out []byte
		switch {
		case strings.HasSuffix(r.URL.Path, ".slhdsa"):
			out = pq
		case strings.HasSuffix(r.URL.Path, ".minisig"):
			out = ed
		default:
			out = body
		}
		if out == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(out)
	}))
	t.Cleanup(server.Close)
	return &client.Client{Origin: server.URL}, server.URL + "/manifest.json"
}

func bothKeys(t *testing.T) client.Keys {
	t.Helper()
	return client.Keys{Ed25519: releasePublicKey(t), PostQuantum: releasePQKey(t)}
}

func TestAManifestWithBothSignaturesIsAccepted(t *testing.T) {
	c, url := aReleasePageWithBoth(t,
		signedFixture(t, "manifest.json"),
		signedFixture(t, "manifest.json.minisig"),
		signedFixture(t, "manifest.json.slhdsa"))

	if _, err := c.FetchSignedManifest(context.Background(), url, bothKeys(t)); err != nil {
		t.Fatalf("a manifest signed with both keys was refused: %v", err)
	}
}

// The point of having two. A release carrying only the classical signature must
// not pass a build that requires both, or the weaker scheme is the real
// guarantee and the second key is decoration.
func TestAReleaseMissingThePostQuantumSignatureIsRefused(t *testing.T) {
	c, url := aReleasePageWithBoth(t,
		signedFixture(t, "manifest.json"),
		signedFixture(t, "manifest.json.minisig"),
		nil)

	_, err := c.FetchSignedManifest(context.Background(), url, bothKeys(t))
	if !errors.Is(err, client.ErrUnsigned) {
		t.Fatalf("a release with only one signature gave %v, want ErrUnsigned", err)
	}
	if !strings.Contains(err.Error(), "both") {
		t.Errorf("the error does not say what is missing: %v", err)
	}
}

// And the converse: a post-quantum signature by a key this build does not trust
// must fail even though the classical one is genuine.
func TestAForeignPostQuantumSignatureIsRefused(t *testing.T) {
	c, url := aReleasePageWithBoth(t,
		signedFixture(t, "manifest.json"),
		signedFixture(t, "manifest.json.minisig"),
		signedFixture(t, "manifest.json.otherkey.slhdsa"))

	_, err := c.FetchSignedManifest(context.Background(), url, bothKeys(t))
	if !errors.Is(err, signature.ErrWrongKey) {
		t.Fatalf("a foreign post-quantum signature gave %v, want ErrWrongKey", err)
	}
}

// A build with no post-quantum key compiled in checks only the classical
// signature, rather than refusing every release because it cannot check
// something it has no key for.
func TestWithoutAPostQuantumKeyOnlyTheClassicalOneIsRequired(t *testing.T) {
	c, url := aReleasePageWithBoth(t,
		signedFixture(t, "manifest.json"),
		signedFixture(t, "manifest.json.minisig"),
		nil)

	if _, err := c.FetchSignedManifest(context.Background(), url,
		client.Keys{Ed25519: releasePublicKey(t)}); err != nil {
		t.Fatalf("a build with no post-quantum key: %v", err)
	}
}

// Removing an upload is authorised by the owner token, which the instance holds
// only as a hash. These are the answers a client must tell apart.
func TestRevokeReportsWhatHappened(t *testing.T) {
	ownerToken := bytes.Repeat([]byte{0x5A}, 32)

	for name, tc := range map[string]struct {
		status  int
		wantErr error
	}{
		"removed":                  {http.StatusNoContent, nil},
		"the token does not match": {http.StatusForbidden, client.ErrNotOwner},
		"no credential accepted":   {http.StatusUnauthorized, client.ErrNotOwner},
		"no such upload":           {http.StatusNotFound, client.ErrNotOwner},
	} {
		t.Run(name, func(t *testing.T) {
			var gotAuth string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				if r.Method != http.MethodDelete {
					t.Errorf("method %s, want DELETE", r.Method)
				}
				w.WriteHeader(tc.status)
			}))
			defer server.Close()

			c := &client.Client{Origin: server.URL}
			err := c.Revoke(context.Background(), "anuploadidentifier0000", ownerToken)

			if tc.wantErr == nil && err != nil {
				t.Fatalf("got %v, want nil", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}

			// The credential belongs in the header, never in the path: a path
			// reaches access logs and browser history.
			if !strings.HasPrefix(gotAuth, "Bearer ") {
				t.Errorf("the owner token was not sent as a bearer credential: %q", gotAuth)
			}
		})
	}
}

func TestRevokeRefusesAnEmptyToken(t *testing.T) {
	c := &client.Client{Origin: "http://example.invalid"}
	if err := c.Revoke(context.Background(), "anuploadidentifier0000", nil); err == nil {
		t.Error("an empty owner token was sent to the instance")
	}
}

func TestATokenIsReadBackAsItIsPrinted(t *testing.T) {
	token := bytes.Repeat([]byte{0x11}, 32)

	decoded, err := client.DecodeToken(client.EncodeToken(token))
	if err != nil {
		t.Fatalf("a token this client printed does not read back: %v", err)
	}
	if !bytes.Equal(decoded, token) {
		t.Error("the token read back is not the token printed")
	}

	for _, bad := range []string{"", "   ", "!!!not base64!!!"} {
		if _, err := client.DecodeToken(bad); err == nil {
			t.Errorf("%q was accepted as an owner token", bad)
		}
	}
}
