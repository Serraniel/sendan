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

	https := opts.BaseURL != nil && opts.BaseURL.Scheme == "https"
	return secureHeaders(https, mux)
}
