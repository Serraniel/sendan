// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package webui

import (
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
