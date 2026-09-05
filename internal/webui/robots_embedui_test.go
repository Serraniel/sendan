// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

//go:build embedui

package webui

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// A crawler asks for robots.txt before it asks for anything else, and every
// unknown path here answers with the application shell - which is right for a
// download link and wrong for this one. Without the file, the request is
// answered with HTML and a 200, and a crawler that cannot parse it is entitled
// to conclude that nothing is disallowed.
func TestRobotsTxtIsServedAsARobotsFile(t *testing.T) {
	assets, ok := Assets()
	if !ok {
		t.Fatal("the client is not embedded in this binary")
	}

	rec := httptest.NewRecorder()
	Handler(assets).ServeHTTP(rec, httptest.NewRequest("GET", "/robots.txt", nil))

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain; the shell was served instead", got)
	}

	body := rec.Body.String()
	if strings.Contains(body, "<!doctype html") || strings.Contains(body, "<html") {
		t.Fatal("the application shell was served in place of robots.txt")
	}
	// The two lines that carry the meaning. Asserted rather than the whole
	// file, so a comment can be rewritten without failing a test.
	for _, line := range []string{"User-agent: *", "Disallow: /"} {
		if !strings.Contains(body, line) {
			t.Errorf("robots.txt does not contain %q:\n%s", line, body)
		}
	}
}
