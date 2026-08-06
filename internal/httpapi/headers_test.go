// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Serraniel/sendan/internal/webui"
)

// requiredHeaders must appear on every response the instance produces.
var requiredHeaders = map[string]string{
	"Referrer-Policy":              "no-referrer",
	"X-Content-Type-Options":       "nosniff",
	"X-Frame-Options":              "DENY",
	"X-Robots-Tag":                 "noindex, nofollow",
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Cross-Origin-Embedder-Policy": "require-corp",
	"Cross-Origin-Resource-Policy": "same-origin",
}

func testHandler(t *testing.T, base string) http.Handler {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse base URL: %v", err)
	}
	return New(Options{BaseURL: u})
}

// The headers must survive a middleware reshuffle, so this asserts them on
// responses that never reach a handler as well as on ones that do. A 404 from
// the router is still a response to a visitor, and a policy that applies only
// to routes someone remembered to decorate is not a policy.
func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	h := testHandler(t, "https://sendan.example")

	requests := []struct {
		name   string
		method string
		target string
		// wantStatus is zero where the exact code is not the point. The router
		// cleans a traversal path and redirects, and which redirect it uses is
		// an implementation detail that changed between Go 1.25 and 1.26 - 301
		// to 307, so that the method is preserved. Asserting it would make this
		// test fail on a toolchain difference rather than on a dropped header,
		// which is the only thing it is here to detect.
		wantStatus int
	}{
		{"a routed request", http.MethodGet, "/healthz", http.StatusOK},
		{"an unrouted path", http.MethodGet, "/nope", http.StatusNotFound},
		{"the root", http.MethodGet, "/", http.StatusNotFound},
		{"a wrong method on a real route", http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		{"a path that looks like an upload", http.MethodGet, "/api/download/AAAAAAAAAAAAAAAAAAAAAA", http.StatusNotFound},
		{"a traversal attempt", http.MethodGet, "/../../etc/passwd", 0},
	}

	for _, tc := range requests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))

			switch {
			case tc.wantStatus != 0 && rec.Code != tc.wantStatus:
				t.Errorf("status %d, want %d", rec.Code, tc.wantStatus)
			case tc.wantStatus == 0 && rec.Code < 300:
				t.Errorf("status %d, want a redirect or an error", rec.Code)
			}
			for name, want := range requiredHeaders {
				if got := rec.Header().Get(name); got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
			if rec.Header().Get("Content-Security-Policy") == "" {
				t.Error("Content-Security-Policy is missing")
			}
			if rec.Header().Get("Permissions-Policy") == "" {
				t.Error("Permissions-Policy is missing")
			}
		})
	}
}

// Each directive is asserted individually rather than against one long string,
// so that a failure names the directive that changed instead of printing two
// policies to compare by eye.
func TestContentSecurityPolicyDirectives(t *testing.T) {
	rec := httptest.NewRecorder()
	testHandler(t, "https://sendan.example").
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	csp := rec.Header().Get("Content-Security-Policy")

	for _, want := range []string{
		"default-src 'self'",
		"connect-src 'self'",
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors 'none'",
		"worker-src 'self'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("the policy is missing %q:\n%s", want, csp)
		}
	}

	// Removing this breaks Argon2id, and only Argon2id. Uploads without a
	// password would keep working, so the failure would reach users through any
	// test that did not set one.
	if !strings.Contains(csp, "'wasm-unsafe-eval'") {
		t.Errorf("the policy blocks WebAssembly, which password derivation requires:\n%s", csp)
	}

	// 'unsafe-inline' and 'unsafe-eval' would defeat the point of the rest.
	for _, forbidden := range []string{"'unsafe-inline'", "'unsafe-eval'", "*"} {
		if strings.Contains(csp, forbidden) {
			t.Errorf("the policy contains %q, which weakens it to no purpose:\n%s", forbidden, csp)
		}
	}

	// blob: belongs in img-src and media-src, where it renders decrypted
	// content, and nowhere that would make it an injection vector.
	for _, directive := range strings.Split(csp, "; ") {
		name, value, _ := strings.Cut(directive, " ")
		switch name {
		case "script-src", "worker-src", "object-src", "default-src":
			if strings.Contains(value, "blob:") {
				t.Errorf("%s permits blob:, which is an injection vector there: %s", name, directive)
			}
		}
	}
}

// HSTS instructs a browser to refuse plain HTTP for the whole origin, for two
// years. Sending it from an instance served over HTTP would be advice the
// operator cannot act on and, on a shared name, would break their other
// services.
func TestHSTSFollowsTheConfiguredScheme(t *testing.T) {
	tests := []struct {
		base string
		want bool
	}{
		{"https://sendan.example", true},
		{"http://localhost:8080", false},
		{"http://sendan.example", false},
	}

	for _, tc := range tests {
		t.Run(tc.base, func(t *testing.T) {
			rec := httptest.NewRecorder()
			testHandler(t, tc.base).
				ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

			got := rec.Header().Get("Strict-Transport-Security")
			if tc.want && got == "" {
				t.Error("HSTS is missing from an HTTPS instance")
			}
			if !tc.want && got != "" {
				t.Errorf("HSTS = %q on a plain HTTP instance", got)
			}
		})
	}
}

// A forwarded header is written by whatever spoke last. On a deployment without
// a proxy that is the client, so trusting it would let a visitor decide whether
// the instance claims HTTPS.
func TestHSTSIgnoresForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Forwarded", "proto=https")

	rec := httptest.NewRecorder()
	testHandler(t, "http://localhost:8080").ServeHTTP(rec, req)

	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("a forwarded header produced HSTS: %q", got)
	}
}

// A handler that has already written its status has already flushed its
// headers, so anything set afterwards is silently discarded. This asserts the
// middleware runs before the handler rather than around it.
func TestHeadersSurviveAHandlerThatWritesImmediately(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("body"))
	})

	rec := httptest.NewRecorder()
	secureHeaders(true, contentSecurityPolicy, inner).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status %d, want %d", rec.Code, http.StatusTeapot)
	}
	for name, want := range requiredHeaders {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	testHandler(t, "http://localhost:8080").
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "ok\n" {
		t.Errorf("body %q, want %q", got, "ok\n")
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type %q", got)
	}
}

// A nil base URL must not panic and must not claim HTTPS.
func TestNewToleratesAnAbsentBaseURL(t *testing.T) {
	rec := httptest.NewRecorder()
	New(Options{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS = %q without a configured origin", got)
	}
}

// The client's bootstrap is inline and the policy forbids inline scripts, so
// the policy has to carry its hash. Without it a browser refuses to run the
// script and the application never starts - which no test that serves the page
// without executing it can see.
//
// The hash is computed here independently rather than by calling the function
// that produces it. Asking that function what the answer is and then checking
// the answer against itself would pass whatever convention it used: hashing the
// script tags along with the body is self-consistent, and rejected by every
// browser. What a browser hashes is the text between the tags, and that is what
// this reproduces.
//
// The client is supplied rather than embedded, so this runs on an ordinary
// build. A test that needed a JavaScript toolchain would skip wherever one is
// absent, which is most places.
func TestThePolicyCarriesTheHashOfTheServedInlineScript(t *testing.T) {
	const bootstrap = "\n\t__sveltekit = { base: \"\" };\n"

	handler := New(Options{
		BaseURL: mustURL(t, "https://sendan.example"),
		ServeUI: true,
		WebUI: fstest.MapFS{
			"index.html": {Data: []byte(
				`<html><head><script src="/_app/start.js"></script>` +
					`<script>` + bootstrap + `</script></head><body></body></html>`)},
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}

	scripts := servedInlineScripts(rec.Body.String())
	if len(scripts) != 1 {
		t.Fatalf("served %d inline scripts, want 1", len(scripts))
	}

	sum := sha256.Sum256([]byte(scripts[0]))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, want) {
		t.Errorf("the policy does not allow the inline script it served.\nwant %s\nin   %s", want, csp)
	}
	if strings.Contains(csp, "'unsafe-inline'") {
		t.Error("the policy allows every inline script rather than the one it serves")
	}
}

// The real client, when this build has one. The synthetic shell above proves
// the mechanism; this proves the shell SvelteKit actually emits goes through it.
func TestTheRealClientsBootstrapIsAllowed(t *testing.T) {
	assets, ok := webui.Assets()
	if !ok {
		t.Skip("this build embeds no client; the tagged run in continuous integration covers it")
	}

	handler := New(Options{
		BaseURL: mustURL(t, "https://sendan.example"),
		ServeUI: true,
		WebUI:   assets,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	csp := rec.Header().Get("Content-Security-Policy")
	for _, script := range servedInlineScripts(rec.Body.String()) {
		sum := sha256.Sum256([]byte(script))
		want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		if !strings.Contains(csp, want) {
			t.Errorf("the real client's inline script is not allowed.\nwant %s\nin   %s", want, csp)
		}
	}
}

// scriptRE captures a script element's attributes and its body.
//
// Go's regexp has no lookahead, so scripts with a src are filtered out
// afterwards rather than excluded by the pattern.
var scriptRE = regexp.MustCompile(`(?s)<script([^>]*)>(.*?)</script>`)

// servedInlineScripts returns the body of every inline script in a document.
//
// Written here rather than reused from the package under test on purpose: this
// is the independent reading that makes the hash assertion mean something.
func servedInlineScripts(doc string) []string {
	var out []string
	for _, m := range scriptRE.FindAllStringSubmatch(doc, -1) {
		if strings.Contains(m[1], "src=") {
			continue
		}
		out = append(out, m[2])
	}
	return out
}
