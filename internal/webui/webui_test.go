// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package webui

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func testAssets() fstest.MapFS {
	return fstest.MapFS{
		"index.html":                    {Data: []byte("<!doctype html><title>Sendan</title>")},
		"_app/immutable/entry/app.js":   {Data: []byte("export const app = 1;")},
		"_app/immutable/assets/app.css": {Data: []byte("body{}")},
		"favicon.png":                   {Data: []byte("\x89PNG")},
		"service-worker.js":             {Data: []byte("self.addEventListener('fetch', () => {})")},
	}
}

func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func TestFilesAreServed(t *testing.T) {
	h := Handler(testAssets())

	for _, name := range []string{"/index.html", "/_app/immutable/entry/app.js", "/favicon.png"} {
		rec := get(t, h, name)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", name, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("%s: empty body", name)
		}
	}
}

// A download URL contains an upload identifier, so the set of pages is not
// known at build time. Any path that does not name a file has to receive the
// shell, or every download link would be a 404.
func TestUnknownPathsReceiveTheShell(t *testing.T) {
	h := Handler(testAssets())

	for _, name := range []string{
		"/",
		"/d/AAAAAAAAAAAAAAAAAAAAAA",
		"/d/an-identifier-this-binary-has-never-seen",
		"/some/deep/route",
	} {
		rec := get(t, h, name)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", name, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Sendan") {
			t.Errorf("%s: did not receive the shell: %q", name, rec.Body.String())
		}
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
			t.Errorf("%s: Content-Type %q", name, got)
		}
	}
}

// The shell names the assets of the build that produced it. Caching it would
// serve a document referring to files a later build no longer has, which is a
// blank page nobody can explain.
func TestTheShellIsNotCachedButHashedAssetsAre(t *testing.T) {
	h := Handler(testAssets())

	if got := get(t, h, "/d/anything").Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("the shell has Cache-Control %q, want no-cache", got)
	}
	if got := get(t, h, "/index.html").Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("index.html has Cache-Control %q, want no-cache", got)
	}

	// Hashed names are content-addressed, so a long lifetime is safe and saves
	// a request per asset per visit.
	got := get(t, h, "/_app/immutable/entry/app.js").Header().Get("Cache-Control")
	if !strings.Contains(got, "immutable") {
		t.Errorf("a hashed asset has Cache-Control %q, want an immutable lifetime", got)
	}
}

// The service worker's name never changes, so a long lifetime would pin a
// browser to one version of it for a year. It is the one asset that can outlive
// a deployment while still being the thing that answers requests, and a stale
// one would keep decrypting downloads with code nobody is running any more.
func TestTheServiceWorkerIsNotCached(t *testing.T) {
	h := Handler(testAssets())

	rec := get(t, h, "/service-worker.js")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control %q, want no-cache", got)
	}
	// Served as script rather than as the shell: a worker delivered as
	// text/html is refused by the browser, and the save path would silently
	// fall back to holding whole files in memory.
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "javascript") {
		t.Errorf("Content-Type %q, want a script type", got)
	}
}

// A path that climbs out of the asset tree must not reach the filesystem. The
// identifiers in these URLs come from strangers.
func TestTraversalIsRefused(t *testing.T) {
	h := Handler(testAssets())

	for _, name := range []string{
		"/../../etc/passwd",
		"/_app/../../../etc/passwd",
		"/d/../../../../etc/passwd",
	} {
		rec := get(t, h, name)
		if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "root:") {
			t.Errorf("%s: served something outside the asset tree", name)
		}
	}
}

// A build without the client embedded must say so. A blank 404 would be read as
// a routing fault and sent to the wrong person to investigate.
func TestABuildWithoutTheClientSaysSo(t *testing.T) {
	h := Handler(fstest.MapFS{})

	rec := get(t, h, "/")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not built") {
		t.Errorf("the response does not explain why: %q", rec.Body.String())
	}
}

func TestHeadReceivesNoBody(t *testing.T) {
	h := Handler(testAssets())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/d/anything", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD returned %d bytes of body", rec.Body.Len())
	}
}

// An untagged build embeds nothing, which is what lets go build and go test run
// without a JavaScript toolchain.
func TestAssetsReflectTheBuildTag(t *testing.T) {
	fsys, ok := Assets()
	if ok && fsys == nil {
		t.Fatal("Assets reported success and returned nothing")
	}
	if !ok && fsys != nil {
		t.Fatal("Assets reported failure and returned something")
	}
	t.Logf("client embedded: %v", ok)
}

// What a browser hashes is the text between the tags. Getting the convention
// wrong is self-consistent everywhere except in a browser, so the expected
// values here are written out rather than computed by the code under test.
func TestInlineScriptHashes(t *testing.T) {
	const body = "console.log(1)"
	sum := sha256.Sum256([]byte(body))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"

	fsys := fstest.MapFS{
		"index.html": {Data: []byte(
			`<html><head>` +
				`<script src="/_app/x.js"></script>` +
				`<script>` + body + `</script>` +
				`</head></html>`)},
	}

	got, err := InlineScriptHashes(fsys)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("hashed %d scripts, want 1 - a script with a src is fetched, not inline", len(got))
	}
	if got[0] != want {
		t.Errorf("hash %s, want %s: a browser would reject the script", got[0], want)
	}
}

func TestInlineScriptHashesOnAShellWithoutOne(t *testing.T) {
	got, err := InlineScriptHashes(fstest.MapFS{
		"index.html": {Data: []byte(`<html><head><script src="/a.js"></script></head></html>`)},
	})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("hashed %d scripts, want none", len(got))
	}
}

func TestInlineScriptHashesWithoutAShell(t *testing.T) {
	if _, err := InlineScriptHashes(fstest.MapFS{}); err == nil {
		t.Fatal("hashing a build with no shell reported success")
	}
}

func TestInlineScripts(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want []string
	}{
		{"none", `<html><body>nothing</body></html>`, nil},
		{"one", `<script>a</script>`, []string{"a"}},
		{"src is not inline", `<script src="/a.js"></script>`, nil},
		{"attributes on an inline script", `<script type="module">a</script>`, []string{"a"}},
		{"several", `<script>a</script><script src="/b.js"></script><script>c</script>`, []string{"a", "c"}},
		{"whitespace is part of the body", "<script>\n a \n</script>", []string{"\n a \n"}},
		{"unclosed is ignored", `<script>a`, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := inlineScripts(tc.doc)
			if len(got) != len(tc.want) {
				t.Fatalf("found %d scripts %q, want %d %q", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("script %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
