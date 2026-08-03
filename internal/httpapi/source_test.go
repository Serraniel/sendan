// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime/debug"
	"strings"
	"testing"
)

// getSource returns the recorder rather than a *http.Response, so no response
// body exists to leak. Reading rec.Result() would create one, and closing it in
// a helper is something the linter cannot see, which makes every caller look
// like a leak.
func getSource(t *testing.T, opts Options) (*httptest.ResponseRecorder, Build) {
	t.Helper()
	rec := httptest.NewRecorder()
	New(opts).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/source", nil))

	var b Build
	if err := json.NewDecoder(rec.Body).Decode(&b); err != nil {
		t.Fatalf("decode the report: %v", err)
	}
	return rec, b
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestSourceReportsTheBuild(t *testing.T) {
	res, b := getSource(t, Options{
		Version:   "1.2.3",
		Commit:    "abc1234",
		SourceURL: mustURL(t, "https://github.com/Serraniel/sendan"),
	})

	if res.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", res.Code)
	}
	if got := res.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type %q", got)
	}
	if b.Version != "1.2.3" {
		t.Errorf("version %q, want 1.2.3", b.Version)
	}
	if b.Commit != "abc1234" {
		t.Errorf("commit %q, want abc1234", b.Commit)
	}
	if b.Source != "https://github.com/Serraniel/sendan" {
		t.Errorf("source %q", b.Source)
	}
	if b.License != "AGPL-3.0-or-later" {
		t.Errorf("license %q, want AGPL-3.0-or-later", b.License)
	}
}

// The whole point of the endpoint is that an operator running modified code can
// point users at the source of what is actually running. A report that always
// named the upstream repository would satisfy AGPL §13 for nobody who modified
// anything, which is the only case the obligation exists for.
func TestSourceReportsTheConfiguredLocation(t *testing.T) {
	_, b := getSource(t, Options{
		Version:   "1.2.3",
		Commit:    "abc1234",
		SourceURL: mustURL(t, "https://git.example.org/ops/sendan-fork"),
	})

	if b.Source != "https://git.example.org/ops/sendan-fork" {
		t.Errorf("source %q, want the configured fork", b.Source)
	}
	if strings.Contains(b.Source, "Serraniel") {
		t.Errorf("the report names upstream on a modified instance: %q", b.Source)
	}
}

// The licence describes the terms this code is under. An operator cannot change
// them by setting a variable, so the report must not offer a way to say
// otherwise.
func TestLicenseIsNotConfigurable(t *testing.T) {
	_, b := getSource(t, Options{SourceURL: mustURL(t, "https://example.org/x")})
	if b.License != "AGPL-3.0-or-later" {
		t.Errorf("license %q", b.License)
	}
}

// vcs fabricates the build settings Go embeds.
//
// A test binary carries none of these - Go does not stamp version control
// information into one - so the settings have to be supplied. An earlier
// version of this test read the real build information and skipped when it
// found nothing, which is to say it always skipped and proved nothing.
func vcs(revision string, modified bool) []debug.BuildSetting {
	m := "false"
	if modified {
		m = "true"
	}
	return []debug.BuildSetting{
		{Key: "-compiler", Value: "gc"},
		{Key: "vcs", Value: "git"},
		{Key: "vcs.revision", Value: revision},
		{Key: "vcs.modified", Value: m},
	}
}

const fullRevision = "e98f80ced3ab68f139a39fb6e62cf90867b28268"

func TestBuildResolution(t *testing.T) {
	tests := []struct {
		name         string
		version      string
		commit       string
		settings     []debug.BuildSetting
		wantCommit   string
		wantModified bool
	}{
		{
			// A binary built with `go build` rather than the release tooling
			// still knows its revision. Reporting "unknown" would understate
			// what the instance can honestly disclose.
			name:    "an unstamped build takes the embedded revision",
			version: "dev", commit: "unknown",
			settings:   vcs(fullRevision, false),
			wantCommit: fullRevision,
		},
		{
			name:    "an empty stamp takes the embedded revision",
			version: "dev", commit: "",
			settings:   vcs(fullRevision, false),
			wantCommit: fullRevision,
		},
		{
			// The linker knows which revision was released. The embedded value
			// describes the tree the binary was built from, which when an old
			// release is rebuilt is a different thing.
			name:    "a stamped commit is not overwritten",
			version: "1.2.3", commit: "deadbeef",
			settings:   vcs(fullRevision, false),
			wantCommit: "deadbeef",
		},
		{
			// No commit corresponds to a dirty tree, so no source link can be
			// exact. Saying so beats a link that looks authoritative.
			name:    "a dirty tree is reported",
			version: "dev", commit: "unknown",
			settings:     vcs(fullRevision, true),
			wantCommit:   fullRevision,
			wantModified: true,
		},
		{
			// A build from an exported archive has no version control
			// information at all. The stamped values must survive.
			name:    "no version control information leaves the stamp alone",
			version: "1.2.3", commit: "deadbeef",
			settings:   nil,
			wantCommit: "deadbeef",
		},
		{
			name:    "a dirty stamped build is still reported as modified",
			version: "1.2.3", commit: "deadbeef",
			settings:     vcs(fullRevision, true),
			wantCommit:   "deadbeef",
			wantModified: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := resolveBuild(tc.version, tc.commit, "https://example.org/x", tc.settings)

			if b.Commit != tc.wantCommit {
				t.Errorf("commit %q, want %q", b.Commit, tc.wantCommit)
			}
			if b.Modified != tc.wantModified {
				t.Errorf("modified %v, want %v", b.Modified, tc.wantModified)
			}
			if b.Version != tc.version {
				t.Errorf("version %q, want %q", b.Version, tc.version)
			}
		})
	}
}

// The production path reads the real build information. It must produce the
// same report the tested logic does for the settings it is given.
func TestCurrentBuildUsesTheRealBuildInformation(t *testing.T) {
	got := currentBuild("1.2.3", "deadbeef", "https://example.org/x")

	if got.Commit != "deadbeef" {
		t.Errorf("commit %q, want the stamped deadbeef", got.Commit)
	}
	if got.Version != "1.2.3" {
		t.Errorf("version %q", got.Version)
	}
	if got.License != "AGPL-3.0-or-later" {
		t.Errorf("license %q", got.License)
	}
}

// A binary built from a dirty tree has no commit that corresponds to it, so no
// source link can be exact. The report says so rather than presenting a link
// that looks authoritative.
func TestModifiedIsReported(t *testing.T) {
	_, b := getSource(t, Options{SourceURL: mustURL(t, "https://example.org/x")})

	// Whether this build is dirty depends on the working tree, so the value is
	// not asserted. What matters is that the field is always present, because a
	// consumer that never sees it cannot warn about it.
	raw := httptest.NewRecorder()
	New(Options{SourceURL: mustURL(t, "https://example.org/x")}).
		ServeHTTP(raw, httptest.NewRequest(http.MethodGet, "/api/source", nil))

	if !strings.Contains(raw.Body.String(), `"modified"`) {
		t.Errorf("the report omits the modified field:\n%s", raw.Body.String())
	}
	_ = b.Modified
}

// The endpoint is a compliance surface, so it must answer before a user has
// anything to authenticate with, and it must carry the same headers as
// everything else.
func TestSourceIsUnauthenticatedAndCarriesSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	New(Options{
		SourceURL: mustURL(t, "https://example.org/x"),
		BaseURL:   mustURL(t, "https://sendan.example"),
	}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/source", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 without credentials", rec.Code)
	}
	for name, want := range requiredHeaders {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// An instance with no configured source reports an empty location rather than
// refusing to answer or inventing one. The operator has misconfigured it; the
// endpoint's job is to say what is true.
func TestSourceToleratesAnAbsentLocation(t *testing.T) {
	res, b := getSource(t, Options{})
	if res.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", res.Code)
	}
	if b.Source != "" {
		t.Errorf("source %q, want empty", b.Source)
	}
}

func TestSourceRejectsOtherMethods(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		New(Options{SourceURL: mustURL(t, "https://example.org/x")}).
			ServeHTTP(rec, httptest.NewRequest(method, "/api/source", nil))

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d, want 405", method, rec.Code)
		}
	}
}
