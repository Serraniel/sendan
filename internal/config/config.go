// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Package config loads Sendan's configuration from the environment.
//
// Every setting is a SENDAN_ prefixed environment variable, and every default
// is chosen to be safe rather than convenient. Configuration is validated once
// at startup and the process refuses to run if anything is wrong: a server that
// silently degrades to a weaker setting is worse than one that will not start.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Defaults, per docs/design.md §3 and §8.
const (
	DefaultListen        = ":8080"
	DefaultBaseURL       = "http://localhost:8080"
	DefaultTTL           = 24 * time.Hour
	DefaultMaxTTL        = 7 * 24 * time.Hour
	DefaultMaxUploadSize = 1 << 30 // 1 GiB
	DefaultMaxDownloads  = 0       // unlimited unless the uploader sets one
	DefaultDatabase      = "sqlite:data/sendan.db"
	DefaultStorage       = "file:data/blobs"
)

// Config is the validated runtime configuration.
type Config struct {
	// Listen is the address the HTTP server binds to.
	Listen string
	// BaseURL is the externally visible origin, used to build download links.
	BaseURL *url.URL

	// ServeUI serves the embedded web client. Disabling it yields a
	// backend-only instance from the same binary.
	ServeUI bool
	// SendCompat enables the third-party compatibility endpoints.
	//
	// Off by default: uploads made through them use a weaker, server-enforced
	// password model. See docs/design.md §5.
	SendCompat bool

	// DefaultTTL applies when an uploader does not choose one.
	DefaultTTL time.Duration
	// MaxTTL bounds what an uploader may choose. Zero means unbounded, which
	// requires AllowInfiniteTTL.
	MaxTTL time.Duration
	// AllowInfiniteTTL permits uploads that never expire. Off by default.
	AllowInfiniteTTL bool

	// DefaultMaxDownloads applies when an uploader does not choose one. Zero
	// means no download limit.
	DefaultMaxDownloads int
	// MaxUploadSize bounds a single upload, in bytes.
	MaxUploadSize int64

	// Database is a driver-prefixed location, for example
	// "sqlite:data/sendan.db" or "postgres://user@host/db".
	Database string
	// Storage is a driver-prefixed location, for example "file:data/blobs"
	// or "s3://bucket".
	Storage string

	LogLevel  slog.Level
	LogFormat string // "json" or "text"
}

// Getenv reads one environment variable. Taking it as a parameter keeps Load
// testable without mutating the process environment.
type Getenv func(string) string

// Load reads and validates the configuration.
//
// All problems are reported together rather than one per run, so an operator
// fixing a misconfiguration does not have to restart repeatedly to discover the
// next fault.
func Load(getenv Getenv) (*Config, error) {
	l := &loader{getenv: getenv}

	cfg := &Config{
		Listen:     l.str("SENDAN_LISTEN", DefaultListen),
		ServeUI:    l.boolean("SENDAN_SERVE_UI", true),
		SendCompat: l.boolean("SENDAN_SEND_COMPAT", false),

		DefaultTTL:       l.duration("SENDAN_DEFAULT_TTL", DefaultTTL),
		MaxTTL:           l.duration("SENDAN_MAX_TTL", DefaultMaxTTL),
		AllowInfiniteTTL: l.boolean("SENDAN_ALLOW_INFINITE_TTL", false),

		DefaultMaxDownloads: l.integer("SENDAN_DEFAULT_MAX_DOWNLOADS", DefaultMaxDownloads),
		MaxUploadSize:       l.bytes("SENDAN_MAX_UPLOAD_SIZE", DefaultMaxUploadSize),

		Database: l.str("SENDAN_DATABASE", DefaultDatabase),
		Storage:  l.str("SENDAN_STORAGE", DefaultStorage),

		LogLevel:  l.level("SENDAN_LOG_LEVEL", slog.LevelInfo),
		LogFormat: l.enum("SENDAN_LOG_FORMAT", "json", "json", "text"),
	}
	cfg.BaseURL = l.url("SENDAN_BASE_URL", DefaultBaseURL)

	l.validate(cfg)

	if err := errors.Join(l.errs...); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

type loader struct {
	getenv Getenv
	errs   []error
}

func (l *loader) fail(key string, value string, reason string) {
	l.errs = append(l.errs, fmt.Errorf("%s=%q: %s", key, value, reason))
}

func (l *loader) str(key, fallback string) string {
	if v := strings.TrimSpace(l.getenv(key)); v != "" {
		return v
	}
	return fallback
}

func (l *loader) boolean(key string, fallback bool) bool {
	raw := strings.TrimSpace(l.getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		l.fail(key, raw, "expected a boolean, for example true or false")
		return fallback
	}
	return v
}

func (l *loader) integer(key string, fallback int) int {
	raw := strings.TrimSpace(l.getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		l.fail(key, raw, "expected an integer")
		return fallback
	}
	if v < 0 {
		l.fail(key, raw, "must not be negative")
		return fallback
	}
	return v
}

func (l *loader) duration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(l.getenv(key))
	if raw == "" {
		return fallback
	}
	// "0" is meaningful: it requests no expiry, which validate rejects unless
	// SENDAN_ALLOW_INFINITE_TTL is set.
	v, err := time.ParseDuration(raw)
	if err != nil {
		l.fail(key, raw, "expected a duration, for example 24h or 30m")
		return fallback
	}
	if v < 0 {
		l.fail(key, raw, "must not be negative")
		return fallback
	}
	return v
}

// bytes accepts a plain byte count or a binary suffix, so operators can write
// 500MiB rather than counting zeros.
func (l *loader) bytes(key string, fallback int64) int64 {
	raw := strings.TrimSpace(l.getenv(key))
	if raw == "" {
		return fallback
	}

	multiplier := int64(1)
	digits := raw
	for suffix, m := range map[string]int64{
		"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40,
	} {
		if strings.HasSuffix(raw, suffix) {
			multiplier = m
			digits = strings.TrimSpace(strings.TrimSuffix(raw, suffix))
			break
		}
	}

	v, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		l.fail(key, raw, "expected a byte count, optionally suffixed KiB, MiB, GiB or TiB")
		return fallback
	}
	if v <= 0 {
		l.fail(key, raw, "must be positive")
		return fallback
	}
	if v > (1<<62)/multiplier {
		l.fail(key, raw, "is impossibly large")
		return fallback
	}
	return v * multiplier
}

func (l *loader) url(key, fallback string) *url.URL {
	raw := l.str(key, fallback)
	u, err := url.Parse(raw)
	if err != nil {
		l.fail(key, raw, "is not a valid URL")
		return nil
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		l.fail(key, raw, "must be an absolute http or https URL")
		return nil
	}
	if u.Host == "" {
		l.fail(key, raw, "must include a host")
		return nil
	}
	// A trailing slash would double up when links are built.
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u
}

func (l *loader) level(key string, fallback slog.Level) slog.Level {
	raw := strings.TrimSpace(l.getenv(key))
	if raw == "" {
		return fallback
	}
	var v slog.Level
	if err := v.UnmarshalText([]byte(raw)); err != nil {
		l.fail(key, raw, "expected one of debug, info, warn or error")
		return fallback
	}
	return v
}

func (l *loader) enum(key, fallback string, allowed ...string) string {
	raw := strings.TrimSpace(l.getenv(key))
	if raw == "" {
		return fallback
	}
	for _, a := range allowed {
		if raw == a {
			return raw
		}
	}
	l.fail(key, raw, "expected one of "+strings.Join(allowed, ", "))
	return fallback
}

func (l *loader) validate(cfg *Config) {
	if cfg.Listen == "" {
		l.errs = append(l.errs, errors.New("SENDAN_LISTEN must not be empty"))
	}

	// An unlimited retention period has to be asked for explicitly. Defaulting
	// to it, or allowing it to be reached by leaving a value unset, would make
	// "no leftovers" an accident rather than a guarantee.
	if cfg.MaxTTL == 0 && !cfg.AllowInfiniteTTL {
		l.errs = append(l.errs, errors.New(
			"SENDAN_MAX_TTL=0 requests unlimited retention, which requires SENDAN_ALLOW_INFINITE_TTL=true"))
	}
	if cfg.DefaultTTL == 0 && !cfg.AllowInfiniteTTL {
		l.errs = append(l.errs, errors.New(
			"SENDAN_DEFAULT_TTL=0 requests unlimited retention, which requires SENDAN_ALLOW_INFINITE_TTL=true"))
	}
	if cfg.MaxTTL > 0 && cfg.DefaultTTL > cfg.MaxTTL {
		l.errs = append(l.errs, fmt.Errorf(
			"SENDAN_DEFAULT_TTL (%s) exceeds SENDAN_MAX_TTL (%s)", cfg.DefaultTTL, cfg.MaxTTL))
	}
	if cfg.MaxTTL == 0 && cfg.DefaultTTL == 0 && cfg.AllowInfiniteTTL {
		// Permitted, but an operator should know what they have chosen.
		slog.Default().Warn("uploads will never expire by default",
			"SENDAN_DEFAULT_TTL", "0", "SENDAN_ALLOW_INFINITE_TTL", true)
	}
}
