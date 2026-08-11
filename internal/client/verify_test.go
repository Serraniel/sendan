// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package client_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Serraniel/sendan/internal/client"
	"github.com/Serraniel/sendan/internal/manifest"
)

// anInstanceServing stands in for an instance, serving a set of assets and a
// source report.
func anInstanceServing(t *testing.T, assets map[string]string, claim client.Claim) *client.Client {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/source" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(claim)
			return
		}
		body, ok := assets[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	return &client.Client{Origin: server.URL}
}

// manifestFor builds the published statement for a set of assets.
func manifestFor(t *testing.T, assets map[string]string) *manifest.Manifest {
	t.Helper()

	files := fstest.MapFS{}
	for path, body := range assets {
		files[strings.TrimPrefix(path, "/")] = &fstest.MapFile{Data: []byte(body)}
	}

	m, err := manifest.Build(files, "v1.0.0", "abc123", false)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	return m
}

var published = map[string]string{
	"/index.html":                  "<!doctype html><title>Sendan</title>",
	"/_app/immutable/entry/app.js": "export const app = 1;",
	"/_app/immutable/chunks/a.js":  "export const a = 1;",
	"/service-worker.js":           "self.addEventListener('fetch', () => {})",
}

func TestAnInstanceServingThePublishedClientPasses(t *testing.T) {
	c := anInstanceServing(t, published, client.Claim{Version: "v1.0.0", Commit: "abc123"})

	v, err := c.Verify(t.Context(), manifestFor(t, published))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !v.OK() {
		t.Errorf("an honest instance failed: %+v", v.Mismatches)
	}
	if v.Checked != len(published) {
		t.Errorf("checked %d assets, the manifest names %d", v.Checked, len(published))
	}
}

// The whole purpose. One byte in one script the browser executes is the
// difference between end-to-end encryption and the appearance of it.
func TestAModifiedAssetIsDetectedAndNamed(t *testing.T) {
	modified := map[string]string{}
	for path, body := range published {
		modified[path] = body
	}
	modified["/_app/immutable/chunks/a.js"] += " "

	c := anInstanceServing(t, modified, client.Claim{Version: "v1.0.0"})

	v, err := c.Verify(t.Context(), manifestFor(t, published))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.OK() {
		t.Fatal("a modified client passed verification")
	}
	if len(v.Mismatches) != 1 {
		t.Fatalf("reported %d mismatches, want 1: %+v", len(v.Mismatches), v.Mismatches)
	}

	bad := v.Mismatches[0]
	if bad.Path != "/_app/immutable/chunks/a.js" {
		t.Errorf("named %q", bad.Path)
	}
	// Both digests, because "it does not match" without them is not something
	// anybody can act on or report.
	if bad.Served == "" || bad.Expected == "" || bad.Served == bad.Expected {
		t.Errorf("the mismatch does not show what differed: %+v", bad)
	}
}

// An asset the instance does not serve at all is a failure, not an absence.
// Verifying only what happens to be there would let anything be removed.
func TestAMissingAssetIsAMismatch(t *testing.T) {
	incomplete := map[string]string{}
	for path, body := range published {
		if path != "/service-worker.js" {
			incomplete[path] = body
		}
	}

	c := anInstanceServing(t, incomplete, client.Claim{Version: "v1.0.0"})

	v, err := c.Verify(t.Context(), manifestFor(t, published))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.OK() {
		t.Fatal("an instance missing an asset passed")
	}
	if v.Mismatches[0].Path != "/service-worker.js" {
		t.Errorf("named %q", v.Mismatches[0].Path)
	}
	if !strings.Contains(v.Mismatches[0].Served, "404") {
		t.Errorf("does not say what happened: %q", v.Mismatches[0].Served)
	}
}

// The instance's own claim decides nothing.
//
// It is read to know which published build to compare against, and an instance
// lying about its version is detected by the digests failing to match what that
// version published - which is the point of not asking it for the manifest.
func TestTheInstancesClaimDoesNotDecideTheResult(t *testing.T) {
	modified := map[string]string{}
	for path, body := range published {
		modified[path] = body
	}
	modified["/index.html"] = "<!doctype html><title>Not Sendan</title>"

	// Claiming to be the very version it is not serving.
	c := anInstanceServing(t, modified, client.Claim{
		Version: "v1.0.0", Commit: "abc123", Modified: false,
	})

	v, err := c.Verify(t.Context(), manifestFor(t, published))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.OK() {
		t.Fatal("an instance that lied about its version passed")
	}
}

// An instance that will not say what it is can still be measured. Refusing to
// check would let one escape by declining to answer.
func TestAnInstanceThatWillNotIdentifyItselfIsStillChecked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/source" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, ok := published[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	c := &client.Client{Origin: server.URL}
	v, err := c.Verify(t.Context(), manifestFor(t, published))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !v.OK() {
		t.Errorf("a silent but honest instance failed: %+v", v.Mismatches)
	}
}

// A manifest covering nothing would verify anything.
func TestAnEmptyManifestIsRefused(t *testing.T) {
	c := anInstanceServing(t, published, client.Claim{})

	if _, err := c.Verify(t.Context(), &manifest.Manifest{Schema: manifest.Schema}); err == nil {
		t.Error("a manifest naming no assets was accepted")
	}
	if _, err := c.Verify(t.Context(), nil); err == nil {
		t.Error("a missing manifest was accepted")
	}
}

// A format this binary does not understand is refused rather than guessed at.
func TestAManifestFromTheFutureIsRefused(t *testing.T) {
	m := manifestFor(t, published)
	m.Schema = manifest.Schema + 1

	c := anInstanceServing(t, published, client.Claim{})
	_, err := c.Verify(t.Context(), m)
	if err == nil {
		t.Fatal("a manifest of an unknown schema was accepted")
	}
	if !strings.Contains(err.Error(), "schema") {
		t.Errorf("%v does not say what is wrong", err)
	}
}

func TestTheReleaseManifestURLNamesTheVersion(t *testing.T) {
	got := client.ReleaseManifestURL("https://github.com/Serraniel/sendan", "v0.5.0")
	want := "https://github.com/Serraniel/sendan/releases/download/v0.5.0/manifest.json"
	if got != want {
		t.Errorf("%q, want %q", got, want)
	}

	// A trailing slash on the source must not double the separator.
	if client.ReleaseManifestURL("https://example.org/fork/", "v1") !=
		"https://example.org/fork/releases/download/v1/manifest.json" {
		t.Errorf("a trailing slash was not handled")
	}
}

// The digest the verifier computes must be the one the generator wrote, or a
// verification fails for a reason nobody can find.
func TestTheVerifierHashesTheSameWayTheManifestDoes(t *testing.T) {
	m := manifestFor(t, published)

	got, err := manifest.DigestOf(strings.NewReader(published["/index.html"]))
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if got != m.Assets["/index.html"] {
		t.Errorf("the verifier computes %s, the manifest recorded %s", got, m.Assets["/index.html"])
	}
}

// A CDN or server that compresses regardless must not read as a compromise.
//
// The digests are over the stored bytes, and asking for them as stored also
// stops Go decompressing on our behalf - it only does that for encodings it
// requested itself. So a response that arrives compressed anyway cannot be
// compared, and saying "this instance is not serving the published client"
// would be the worst possible way to say "something gzipped it".
func TestACompressedResponseIsReportedAsSuchNotAsACompromise(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/source" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, ok := published[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Ignoring Accept-Encoding, the way something in front of an instance
		// might.
		w.Header().Set("Content-Encoding", "gzip")
		var out bytes.Buffer
		gz := gzip.NewWriter(&out)
		_, _ = gz.Write([]byte(body))
		_ = gz.Close()
		_, _ = w.Write(out.Bytes())
	}))
	t.Cleanup(server.Close)

	c := &client.Client{Origin: server.URL}
	v, err := c.Verify(t.Context(), manifestFor(t, published))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.OK() {
		t.Fatal("a response that could not be compared was treated as matching")
	}

	for _, bad := range v.Mismatches {
		if !strings.Contains(bad.Served, "compress") && !strings.Contains(bad.Served, "encoded") {
			t.Errorf("%s reads as a modified asset rather than an encoding problem: %q",
				bad.Path, bad.Served)
		}
	}
}

// The manifest is read from wherever the caller says, and never from the
// instance. These are the two ways it arrives.
func TestAManifestIsReadFromAFileOrAURL(t *testing.T) {
	m := manifestFor(t, published)
	encoded, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	fromFile, err := client.LoadManifest(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if len(fromFile.Assets) != len(m.Assets) || fromFile.Version != m.Version {
		t.Errorf("what was read back is not what was written: %+v", fromFile)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(encoded)
	}))
	t.Cleanup(server.Close)

	c := &client.Client{}
	fromURL, err := c.FetchManifest(t.Context(), server.URL+"/manifest.json")
	if err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	if len(fromURL.Assets) != len(m.Assets) {
		t.Errorf("fetched %d assets, want %d", len(fromURL.Assets), len(m.Assets))
	}
}

// A version with no published manifest is the ordinary case of checking an
// instance running something unreleased, and has to say so rather than fail
// with a status code.
func TestAManifestThatIsNotPublishedSaysSo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	c := &client.Client{}
	_, err := c.FetchManifest(t.Context(), server.URL+"/v9.9.9/manifest.json")
	if err == nil {
		t.Fatal("a missing manifest was accepted")
	}
	if !strings.Contains(err.Error(), "published manifest") {
		t.Errorf("%v does not suggest what is wrong", err)
	}
}

func TestAnUnreadableManifestIsRefused(t *testing.T) {
	if _, err := client.LoadManifest(strings.NewReader("{not json")); err == nil {
		t.Error("unreadable JSON was accepted as a manifest")
	}
}

// The claim is read to choose a manifest, so a failure to read it must be
// distinguishable from an instance that answered.
func TestAClaimThatCannotBeReadIsReported(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>not json</html>"))
	}))
	t.Cleanup(server.Close)

	c := &client.Client{Origin: server.URL}
	if _, err := c.Claim(t.Context()); err == nil {
		t.Error("an unreadable source report was accepted")
	}

	unreachable := &client.Client{Origin: "http://127.0.0.1:1"}
	if _, err := unreachable.Claim(t.Context()); err == nil {
		t.Error("an unreachable instance produced a claim")
	}
}

func TestAClaimIsReadWhenTheInstanceGivesOne(t *testing.T) {
	want := client.Claim{
		Version: "v0.5.0", Commit: "1a2b3c4", Modified: true,
		Source: "https://example.org/fork", License: "AGPL-3.0-or-later",
	}
	c := anInstanceServing(t, published, want)

	got, err := c.Claim(t.Context())
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if got != want {
		t.Errorf("read %+v, want %+v", got, want)
	}
}
