// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Serraniel/sendan/internal/upload"
)

// getInstance asks an assembled handler what the instance permits.
func getInstance(t *testing.T, opts Options) (*httptest.ResponseRecorder, Instance) {
	t.Helper()
	rec := httptest.NewRecorder()
	New(opts).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/instance", nil))

	var in Instance
	if err := json.NewDecoder(rec.Body).Decode(&in); err != nil {
		t.Fatalf("decode the report: %v", err)
	}
	return rec, in
}

func TestTheInstanceReportsThePolicyItEnforces(t *testing.T) {
	t.Parallel()

	service := upload.New(nil, nil, upload.Policy{
		DefaultTTL:          24 * time.Hour,
		MaxTTL:              7 * 24 * time.Hour,
		AllowInfiniteTTL:    true,
		DefaultMaxDownloads: 3,
		RequireLimit:        true,
	}, nil)

	rec, in := getInstance(t, Options{MaxUploadSize: 1 << 30, Uploads: service})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	want := Instance{
		MaxUploadSize:       1 << 30,
		DefaultTTLSeconds:   86400,
		MaxTTLSeconds:       604800,
		AllowInfiniteTTL:    true,
		RequireLimit:        true,
		DefaultMaxDownloads: 3,
		CompatEnabled:       false,
	}
	if in != want {
		t.Errorf("report = %+v, want %+v", in, want)
	}
}

func TestTheInstanceSaysWhenCompatibilityIsServed(t *testing.T) {
	t.Parallel()

	// The one setting here that changes what protection an upload can have, so
	// it is the one somebody most needs to know before choosing an instance.
	nothing := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	if _, in := getInstance(t, Options{Compat: nothing}); !in.CompatEnabled {
		t.Error("compatEnabled = false with a compatibility handler registered")
	}
	if _, in := getInstance(t, Options{}); in.CompatEnabled {
		t.Error("compatEnabled = true with no compatibility handler")
	}
}

func TestTheInstanceDescribesPolicyAndNotDeployment(t *testing.T) {
	t.Parallel()

	// The boundary this endpoint exists to hold. None of these change what a
	// person may upload, and all of them help somebody attacking the instance
	// more than they help somebody using it.
	//
	// Checked against the encoded bytes rather than the struct, because a field
	// added later would be serialised without anybody revisiting this test.
	rec, _ := getInstance(t, Options{
		MaxUploadSize: 1 << 20,
		Uploads:       upload.New(nil, nil, upload.Policy{DefaultTTL: time.Hour}, nil),
	})

	body := strings.ToLower(rec.Body.String())
	for _, forbidden := range []string{
		"storage", "database", "postgres", "sqlite", "s3", "bucket",
		"masterkey", "master_key", "proxy", "proxies", "ratelimit", "rate_limit",
		"path", "dsn", "endpoint", "region", "secret",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the report mentions %q: %s", forbidden, rec.Body.String())
		}
	}
}

func TestTheInstanceAnswersWithoutAnUploadService(t *testing.T) {
	t.Parallel()

	// A backend-only assembly, and every test that exercises the HTTP surface
	// alone. Reporting zeroes is right here: it means "no answer", which is
	// what the client treats an absent value as.
	rec, in := getInstance(t, Options{MaxUploadSize: 42})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if in.MaxUploadSize != 42 {
		t.Errorf("maxUploadSize = %d, want 42", in.MaxUploadSize)
	}
	if in.DefaultTTLSeconds != 0 || in.MaxTTLSeconds != 0 {
		t.Errorf("retention reported without a service: %+v", in)
	}
}

func TestSecondsRoundsDown(t *testing.T) {
	t.Parallel()

	// Rounding up would report a maximum longer than the instance accepts,
	// producing a request it then refuses - which is the failure this endpoint
	// exists to prevent.
	for _, c := range []struct {
		in   time.Duration
		want int64
	}{
		{0, 0},
		{-time.Hour, 0},
		{time.Second, 1},
		{1500 * time.Millisecond, 1},
		{90 * time.Minute, 5400},
	} {
		if got := seconds(c.in); got != c.want {
			t.Errorf("seconds(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestTheInstanceReportIsCacheableButNotForLong(t *testing.T) {
	t.Parallel()

	rec, _ := getInstance(t, Options{})

	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q", got)
	}
	// A page that cached this for a day would show a limit that no longer
	// applies; one that never cached it would ask on every visit.
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=60" {
		t.Errorf("Cache-Control = %q", got)
	}
}

func TestTheInstanceCarriesAnOperatorsBanner(t *testing.T) {
	t.Parallel()

	_, in := getInstance(t, Options{Banner: "  This is a demonstration.  ", BannerSeverity: "warning"})

	if in.Banner == nil {
		t.Fatal("no banner reported")
	}
	// Trimmed, because a value from configuration usually arrives with the
	// whitespace somebody's shell left on it.
	if in.Banner.Text != "This is a demonstration." {
		t.Errorf("text = %q", in.Banner.Text)
	}
	if in.Banner.Severity != "warning" {
		t.Errorf("severity = %q, want warning", in.Banner.Severity)
	}
}

func TestAnAbsentBannerIsAbsentRatherThanEmpty(t *testing.T) {
	t.Parallel()

	// The client should not have to decide whether to draw an empty bar, and a
	// banner of spaces is not a banner.
	for _, text := range []string{"", "   ", "\t\n"} {
		rec, in := getInstance(t, Options{Banner: text})
		if in.Banner != nil {
			t.Errorf("banner %q reported as %+v", text, in.Banner)
		}
		if strings.Contains(rec.Body.String(), "banner") {
			t.Errorf("the key is present for %q: %s", text, rec.Body.String())
		}
	}
}

func TestAnUnknownBannerSeverityBecomesTheQuietOne(t *testing.T) {
	t.Parallel()

	// Configuration refuses an unknown value at startup, so this is the second
	// line of defence rather than the first. Falling back to the loud one would
	// let a typo shout at every visitor.
	_, in := getInstance(t, Options{Banner: "notice", BannerSeverity: "catastrophe"})

	if in.Banner == nil || in.Banner.Severity != "info" {
		t.Errorf("severity = %+v, want info", in.Banner)
	}
}

func TestTheBannerIsDeliveredAsTextRatherThanMarkup(t *testing.T) {
	t.Parallel()

	// The operator controls this string. It reaches the client as JSON and is
	// rendered as text there; what matters here is that nothing on this side
	// interprets it, so what goes in is what comes out.
	const hostile = `<script>alert(1)</script> & "quoted"`

	_, in := getInstance(t, Options{Banner: hostile})

	if in.Banner == nil || in.Banner.Text != hostile {
		t.Errorf("text = %+v, want it unchanged", in.Banner)
	}
}
