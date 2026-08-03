// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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
	secureHeaders(true, inner).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

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
