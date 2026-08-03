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

	https := opts.BaseURL != nil && opts.BaseURL.Scheme == "https"
	return secureHeaders(https, mux)
}
