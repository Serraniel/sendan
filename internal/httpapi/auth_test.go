// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Serraniel/sendan/internal/crypto"
	"github.com/Serraniel/sendan/internal/store"
)

var authToken = bytes.Repeat([]byte{0x11}, 32)

func (h *apiHarness) auth(t *testing.T, id string, header string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/uploads/"+id+"/auth", nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

func bearer(token []byte) string {
	return "Bearer " + base64.RawURLEncoding.EncodeToString(token)
}

func TestAuthAcceptsTheRightToken(t *testing.T) {
	h := newAPIHarness(t)
	h.put(t, &store.Upload{AuthTokenHash: crypto.AuthTokenHash(authToken)})

	rec := h.auth(t, testID, bearer(authToken))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("a 204 carried a body: %q", rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", got)
	}
}

func TestAuthRejectsAWrongToken(t *testing.T) {
	h := newAPIHarness(t)
	h.put(t, &store.Upload{AuthTokenHash: crypto.AuthTokenHash(authToken)})

	rec := h.auth(t, testID, bearer(bytes.Repeat([]byte{0x22}, 32)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer") {
		t.Errorf("WWW-Authenticate %q", got)
	}
}

// A malformed credential is not a wrong one. Charging it against the upload's
// allowance would let anyone lock out the recipient with garbage, without ever
// making a real attempt.
func TestMalformedCredentialsDoNotConsumeAttempts(t *testing.T) {
	// A limiter with a small burst and no refill, so that any consumption by
	// the garbage below exhausts the allowance before the real attempt.
	h := newAPIHarnessWithAttempts(t, 3)
	h.put(t, &store.Upload{AuthTokenHash: crypto.AuthTokenHash(authToken)})

	for _, header := range []string{
		"",
		"Bearer",
		"Bearer ",
		"Basic " + base64.RawURLEncoding.EncodeToString(authToken),
		"Bearer !!!not-base64!!!",
		"Bearer " + strings.Repeat("A", 500),
		base64.RawURLEncoding.EncodeToString(authToken), // no scheme
	} {
		rec := h.auth(t, testID, header)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("header %q: status %d, want 401", header, rec.Code)
		}
	}

	// The allowance is untouched, so the correct token still works.
	if rec := h.auth(t, testID, bearer(authToken)); rec.Code != http.StatusNoContent {
		t.Fatalf("garbage credentials consumed the allowance: status %d", rec.Code)
	}
}

func TestAuthAcceptsAnyBearerCase(t *testing.T) {
	h := newAPIHarness(t)
	h.put(t, &store.Upload{AuthTokenHash: crypto.AuthTokenHash(authToken)})

	for _, scheme := range []string{"Bearer", "bearer", "BEARER", "BeArEr"} {
		header := scheme + " " + base64.RawURLEncoding.EncodeToString(authToken)
		if rec := h.auth(t, testID, header); rec.Code != http.StatusNoContent {
			t.Errorf("scheme %q: status %d, want 204", scheme, rec.Code)
		}
	}
}

// The token derives from the link secret, which the whole scheme keeps out of
// logs by putting it in the URL fragment. Accepting it in a query parameter
// would write it to every access log on the path.
func TestTokenIsNotAcceptedInTheQuery(t *testing.T) {
	h := newAPIHarness(t)
	h.put(t, &store.Upload{AuthTokenHash: crypto.AuthTokenHash(authToken)})

	encoded := base64.RawURLEncoding.EncodeToString(authToken)
	for _, target := range []string{
		"/api/uploads/" + testID + "/auth?token=" + encoded,
		"/api/uploads/" + testID + "/auth?authorization=" + encoded,
		"/api/uploads/" + testID + "/auth?access_token=" + encoded,
	} {
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, target, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401 - a token in the query is honoured", target, rec.Code)
		}
	}
}

func TestAuthThrottlesRepeatedFailures(t *testing.T) {
	h := newAPIHarnessWithAttempts(t, 3)
	h.put(t, &store.Upload{AuthTokenHash: crypto.AuthTokenHash(authToken)})

	wrong := bearer(bytes.Repeat([]byte{0x22}, 32))
	for i := range 3 {
		if rec := h.auth(t, testID, wrong); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i+1, rec.Code)
		}
	}

	rec := h.auth(t, testID, wrong)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Error("Retry-After is missing")
	} else if n, err := strconv.Atoi(got); err != nil || n < 1 {
		t.Errorf("Retry-After = %q, want a positive whole number", got)
	}

	// The correct token is refused too, or the limit would bound nothing.
	if rec := h.auth(t, testID, bearer(authToken)); rec.Code != http.StatusTooManyRequests {
		t.Errorf("a correct token was accepted while throttled: %d", rec.Code)
	}
}

// The per-upload limit is separate from the per-address one, and must apply
// however many addresses the attempts arrive from.
func TestThrottlingFollowsTheUploadNotTheCaller(t *testing.T) {
	h := newAPIHarnessWithAttempts(t, 2)
	h.put(t, &store.Upload{AuthTokenHash: crypto.AuthTokenHash(authToken)})

	wrong := bearer(bytes.Repeat([]byte{0x22}, 32))
	for i, addr := range []string{"203.0.113.1:1", "198.51.100.2:2"} {
		req := httptest.NewRequest(http.MethodPost, "/api/uploads/"+testID+"/auth", nil)
		req.Header.Set("Authorization", wrong)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d from %s: status %d", i+1, addr, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/api/uploads/"+testID+"/auth", nil)
	req.Header.Set("Authorization", wrong)
	req.RemoteAddr = "192.0.2.3:3"
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("a third address got a fresh allowance: status %d", rec.Code)
	}
}

func TestAuthOnUnavailableUploads(t *testing.T) {
	h := newAPIHarness(t)
	for _, id := range []string{testID, "not-an-identifier"} {
		if rec := h.auth(t, id, bearer(authToken)); rec.Code != http.StatusNotFound {
			t.Errorf("%q: status %d, want 404", id, rec.Code)
		}
	}
}

func TestAuthRejectsOtherMethods(t *testing.T) {
	h := newAPIHarness(t)
	h.put(t, &store.Upload{AuthTokenHash: crypto.AuthTokenHash(authToken)})

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/uploads/"+testID+"/auth", nil)
		req.Header.Set("Authorization", bearer(authToken))
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d, want 405", method, rec.Code)
		}
	}
}

func TestAuthCarriesTheSecurityHeaders(t *testing.T) {
	h := newAPIHarness(t)
	h.put(t, &store.Upload{AuthTokenHash: crypto.AuthTokenHash(authToken)})

	rec := h.auth(t, testID, bearer(bytes.Repeat([]byte{0x22}, 32)))
	for name, want := range requiredHeaders {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestBearerToken(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString(authToken)

	tests := []struct {
		header string
		wantOK bool
	}{
		{"Bearer " + encoded, true},
		{"bearer " + encoded, true},
		{"Bearer  " + encoded, true}, // extra space, trimmed
		{"", false},
		{"Bearer", false},
		{"Bearer ", false},
		{"Basic " + encoded, false},
		{encoded, false},
		{"Bearer " + strings.Repeat("A", maxTokenLength+1), false},
		{"Bearer not+base64/at-all==", false},
	}
	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		_, ok := bearerToken(req)
		if ok != tc.wantOK {
			t.Errorf("bearerToken(%q) ok = %v, want %v", tc.header, ok, tc.wantOK)
		}
	}
}
