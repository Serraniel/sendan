// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

// env builds a Getenv from a map, so tests never mutate the process
// environment and can run in parallel.
func env(pairs map[string]string) Getenv {
	return func(key string) string { return pairs[key] }
}

func TestDefaultsAreSafe(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatalf("an empty environment must be valid: %v", err)
	}

	// The defaults that matter are the ones that fail closed.
	if cfg.AllowInfiniteTTL {
		t.Error("unlimited retention must be opt-in")
	}
	if cfg.SendCompat {
		t.Error("compatibility endpoints use a weaker password model and must be opt-in")
	}
	if cfg.MaxTTL == 0 {
		t.Error("an unbounded maximum retention must not be the default")
	}
	if cfg.MaxUploadSize <= 0 {
		t.Error("an unbounded upload size must not be the default")
	}

	if cfg.Listen != DefaultListen {
		t.Errorf("listen is %q, want %q", cfg.Listen, DefaultListen)
	}
	if !cfg.ServeUI {
		t.Error("the web client should be served unless disabled")
	}
	if cfg.DefaultTTL != DefaultTTL || cfg.MaxTTL != DefaultMaxTTL {
		t.Errorf("got default %s max %s", cfg.DefaultTTL, cfg.MaxTTL)
	}
}

func TestValuesAreParsed(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		"SENDAN_LISTEN":                "127.0.0.1:9000",
		"SENDAN_BASE_URL":              "https://sendan.example/",
		"SENDAN_SERVE_UI":              "false",
		"SENDAN_SEND_COMPAT":           "true",
		"SENDAN_DEFAULT_TTL":           "2h",
		"SENDAN_MAX_TTL":               "48h",
		"SENDAN_DEFAULT_MAX_DOWNLOADS": "5",
		"SENDAN_MAX_UPLOAD_SIZE":       "500MiB",
		"SENDAN_DATABASE":              "postgres://localhost/sendan",
		"SENDAN_STORAGE":               "s3://bucket",
		"SENDAN_LOG_LEVEL":             "debug",
		"SENDAN_LOG_FORMAT":            "text",
	}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if cfg.Listen != "127.0.0.1:9000" {
		t.Errorf("listen = %q", cfg.Listen)
	}
	// A trailing slash would double up when links are built.
	if cfg.BaseURL.String() != "https://sendan.example" {
		t.Errorf("base url = %q, want the trailing slash trimmed", cfg.BaseURL)
	}
	if cfg.ServeUI || !cfg.SendCompat {
		t.Error("booleans were not applied")
	}
	if cfg.DefaultTTL != 2*time.Hour || cfg.MaxTTL != 48*time.Hour {
		t.Errorf("durations = %s / %s", cfg.DefaultTTL, cfg.MaxTTL)
	}
	if cfg.DefaultMaxDownloads != 5 {
		t.Errorf("max downloads = %d", cfg.DefaultMaxDownloads)
	}
	if cfg.MaxUploadSize != 500<<20 {
		t.Errorf("upload size = %d, want %d", cfg.MaxUploadSize, 500<<20)
	}
	if cfg.LogLevel != slog.LevelDebug || cfg.LogFormat != "text" {
		t.Errorf("logging = %s / %s", cfg.LogLevel, cfg.LogFormat)
	}
}

func TestByteSuffixes(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int64
	}{
		{"1024", 1024},
		{"1KiB", 1 << 10},
		{"10MiB", 10 << 20},
		{"2GiB", 2 << 30},
		{"1TiB", 1 << 40},
	} {
		cfg, err := Load(env(map[string]string{"SENDAN_MAX_UPLOAD_SIZE": tc.raw}))
		if err != nil {
			t.Fatalf("%s: %v", tc.raw, err)
		}
		if cfg.MaxUploadSize != tc.want {
			t.Errorf("%s parsed as %d, want %d", tc.raw, cfg.MaxUploadSize, tc.want)
		}
	}
}

// A server that silently degrades to a weaker setting is worse than one that
// refuses to start, so every malformed value must be an error.
func TestInvalidValuesAreRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"non-boolean", map[string]string{"SENDAN_SERVE_UI": "yes please"}, "SENDAN_SERVE_UI"},
		{"non-duration", map[string]string{"SENDAN_DEFAULT_TTL": "two hours"}, "SENDAN_DEFAULT_TTL"},
		{"negative duration", map[string]string{"SENDAN_MAX_TTL": "-1h"}, "SENDAN_MAX_TTL"},
		{"non-integer", map[string]string{"SENDAN_DEFAULT_MAX_DOWNLOADS": "many"}, "SENDAN_DEFAULT_MAX_DOWNLOADS"},
		{"negative integer", map[string]string{"SENDAN_DEFAULT_MAX_DOWNLOADS": "-1"}, "SENDAN_DEFAULT_MAX_DOWNLOADS"},
		{"bad size suffix", map[string]string{"SENDAN_MAX_UPLOAD_SIZE": "10 gigabytes"}, "SENDAN_MAX_UPLOAD_SIZE"},
		{"zero size", map[string]string{"SENDAN_MAX_UPLOAD_SIZE": "0"}, "SENDAN_MAX_UPLOAD_SIZE"},
		{"relative base url", map[string]string{"SENDAN_BASE_URL": "/sendan"}, "SENDAN_BASE_URL"},
		{"base url without host", map[string]string{"SENDAN_BASE_URL": "https://"}, "SENDAN_BASE_URL"},
		{"unknown log level", map[string]string{"SENDAN_LOG_LEVEL": "chatty"}, "SENDAN_LOG_LEVEL"},
		{"unknown log format", map[string]string{"SENDAN_LOG_FORMAT": "xml"}, "SENDAN_LOG_FORMAT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(env(tc.env))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error does not name the offending variable: %v", err)
			}
		})
	}
}

// Unlimited retention has to be asked for explicitly. Reaching it by leaving a
// value unset would make "no leftovers" an accident rather than a guarantee.
func TestInfiniteRetentionMustBeOptedInto(t *testing.T) {
	for _, key := range []string{"SENDAN_MAX_TTL", "SENDAN_DEFAULT_TTL"} {
		t.Run(key, func(t *testing.T) {
			_, err := Load(env(map[string]string{key: "0"}))
			if err == nil {
				t.Fatal("zero retention must be rejected without SENDAN_ALLOW_INFINITE_TTL")
			}
			if !strings.Contains(err.Error(), "SENDAN_ALLOW_INFINITE_TTL") {
				t.Fatalf("the error should say how to permit it: %v", err)
			}
		})
	}

	cfg, err := Load(env(map[string]string{
		"SENDAN_MAX_TTL":            "0",
		"SENDAN_DEFAULT_TTL":        "0",
		"SENDAN_ALLOW_INFINITE_TTL": "true",
	}))
	if err != nil {
		t.Fatalf("explicit opt-in must be accepted: %v", err)
	}
	if !cfg.AllowInfiniteTTL || cfg.MaxTTL != 0 {
		t.Error("opt-in was not applied")
	}
}

func TestDefaultTTLMayNotExceedMaxTTL(t *testing.T) {
	_, err := Load(env(map[string]string{
		"SENDAN_DEFAULT_TTL": "72h",
		"SENDAN_MAX_TTL":     "24h",
	}))
	if err == nil {
		t.Fatal("a default beyond the maximum must be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// An operator fixing a misconfiguration should not have to restart repeatedly
// to discover the next fault.
func TestAllProblemsAreReportedTogether(t *testing.T) {
	_, err := Load(env(map[string]string{
		"SENDAN_SERVE_UI":        "maybe",
		"SENDAN_DEFAULT_TTL":     "soon",
		"SENDAN_MAX_UPLOAD_SIZE": "-5",
	}))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, key := range []string{"SENDAN_SERVE_UI", "SENDAN_DEFAULT_TTL", "SENDAN_MAX_UPLOAD_SIZE"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error omits %s, so it would surface only on the next run: %v", key, err)
		}
	}
}

func TestWhitespaceIsTolerated(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		"SENDAN_LISTEN":      "  :9999  ",
		"SENDAN_DEFAULT_TTL": " 3h ",
	}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen != ":9999" || cfg.DefaultTTL != 3*time.Hour {
		t.Errorf("whitespace was not trimmed: %q %s", cfg.Listen, cfg.DefaultTTL)
	}
}

// A rate limit with no burst refuses every request, including the first. That
// is indistinguishable from an outage at the point of use, so it is rejected at
// startup where the cause is still visible.
func TestRateLimitRequiresABurst(t *testing.T) {
	_, err := Load(env(map[string]string{
		"SENDAN_RATE_LIMIT": "120",
		"SENDAN_RATE_BURST": "0",
	}))
	if err == nil {
		t.Fatal("a limit with no burst must be rejected")
	}
	if !strings.Contains(err.Error(), "SENDAN_RATE_BURST") {
		t.Fatalf("the error does not name the setting at fault: %v", err)
	}
}

// Disabling the limit entirely is a legitimate choice, and must not be confused
// with the misconfiguration above.
func TestRateLimitMayBeDisabled(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		"SENDAN_RATE_LIMIT": "0",
		"SENDAN_RATE_BURST": "0",
	}))
	if err != nil {
		t.Fatalf("disabling the limit was rejected: %v", err)
	}
	if cfg.RateLimit != 0 {
		t.Errorf("rate limit %d, want 0", cfg.RateLimit)
	}
}

func TestTrustedProxiesDefaultsToNone(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Anything else would mean an out-of-the-box instance reads a header the
	// caller writes, and so has no effective rate limit.
	if cfg.TrustedProxies != 0 {
		t.Errorf("trusted proxies %d, want 0", cfg.TrustedProxies)
	}
	if cfg.RateLimit <= 0 {
		t.Errorf("rate limit %d: an instance is unmetered by default", cfg.RateLimit)
	}
}

// An upload that is never treated as abandoned keeps its partial content for
// ever, which is the leftover the whole project exists to avoid.
func TestIncompleteTTLMustBePositive(t *testing.T) {
	_, err := Load(env(map[string]string{"SENDAN_INCOMPLETE_TTL": "0"}))
	if err == nil {
		t.Fatal("an incomplete TTL of zero must be rejected")
	}
	if !strings.Contains(err.Error(), "SENDAN_INCOMPLETE_TTL") {
		t.Fatalf("the error does not name the setting at fault: %v", err)
	}
}
