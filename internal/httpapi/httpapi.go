// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Package httpapi serves the Sendan HTTP surface.
//
// Every response passes through one middleware chain, so a route added later
// inherits the security headers rather than having to remember them.
package httpapi

import (
	"log/slog"
	"net/http"
	"net/url"

	"github.com/Serraniel/sendan/internal/ratelimit"
	"github.com/Serraniel/sendan/internal/upload"
)

// Options configures the handler.
type Options struct {
	// BaseURL is the externally visible origin. Its scheme decides whether
	// HSTS is sent, which is why it is taken from configuration rather than
	// from a forwarded header the client could write.
	BaseURL *url.URL

	// SourceURL is where this instance's corresponding source can be obtained.
	// It is the operator's to set, because on a modified instance the upstream
	// repository is the wrong answer.
	SourceURL *url.URL

	// Version and Commit are stamped by the release tooling. Where they are
	// not, the build information Go embeds is used instead.
	Version string
	Commit  string

	// MaxUploadSize bounds a single upload, in bytes. Zero means unbounded.
	MaxUploadSize int64

	// Uploads owns the upload lifecycle. Routes that need it are registered
	// only when it is present, so a handler can never be reached with a nil
	// service.
	Uploads *upload.Service

	// RateLimit is the per-address request limit. A nil limiter disables the
	// check; the caller decides that, so that a configured limit of zero means
	// "no limit" rather than "no service".
	RateLimit *ratelimit.Limiter

	// TrustedProxies is how many reverse proxies stand in front of this
	// instance. Zero, the default, means the peer address is used and
	// X-Forwarded-For is ignored entirely.
	TrustedProxies int

	Log *slog.Logger
}

// New returns the HTTP handler for an instance.
func New(opts Options) http.Handler {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}

	mux := http.NewServeMux()

	// Liveness only: it reports that the process is serving, not that its
	// backends are reachable. A health check that fails when the database
	// blinks would restart a server that was about to recover.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})

	// The source report is what makes the AGPL's network provision effective:
	// without it a user has no way to learn what an instance is running, and
	// the obligation is one nobody can check.
	source := ""
	if opts.SourceURL != nil {
		source = opts.SourceURL.String()
	}
	mux.HandleFunc("GET /api/source", handleSource(
		currentBuild(opts.Version, opts.Commit, source)))

	if opts.Uploads != nil {
		mux.HandleFunc("GET /api/uploads/{id}/metadata", handleMetadata(opts.Uploads))
		mux.HandleFunc("POST /api/uploads/{id}/auth", handleAuth(opts.Uploads))
		mux.HandleFunc("GET /api/uploads/{id}/content", handleContent(opts.Uploads))

		tusHandler, err := newTusHandler(opts)
		if err != nil {
			// Reached only if the protocol handler cannot be constructed, which
			// is a programming error rather than a runtime condition. Failing
			// here beats an instance that starts and cannot accept uploads.
			panic("httpapi: " + err.Error())
		}
		// Registered by method and exact path rather than as a prefix. A
		// catch-all would shadow the sub-resources above, so a POST to
		// .../metadata would reach the protocol handler and be answered with a
		// protocol error instead of "method not allowed".
		//
		// The prefix is stripped because the protocol handler derives the
		// upload identifier from the whole request path, so it must see only
		// the identifier. Its configured base path is used to build the
		// Location header and is separate from what it receives.
		mounted := http.StripPrefix("/api/uploads", tusHandler)
		mux.Handle("POST /api/uploads", mounted)
		mux.Handle("OPTIONS /api/uploads", mounted)
		mux.Handle("HEAD /api/uploads/{id}", mounted)
		mux.Handle("PATCH /api/uploads/{id}", mounted)
		mux.Handle("OPTIONS /api/uploads/{id}", mounted)
	}

	https := opts.BaseURL != nil && opts.BaseURL.Scheme == "https"

	// The limit is outside the header middleware so that a refused request
	// still carries the security headers: a 429 is a response like any other.
	return secureHeaders(https, rateLimit(opts.RateLimit, opts.TrustedProxies, mux))
}
