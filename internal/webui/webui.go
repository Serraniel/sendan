// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Package webui serves the web client from the binary.
//
// The client is a single-page application: a download URL contains an upload
// identifier, so the set of pages is not known at build time and never will be.
// Any path that does not name a file is therefore answered with the shell,
// which routes on the client.
package webui

import (
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// shell is the document every unmatched path receives.
const shell = "index.html"

// Handler serves the client from fsys.
//
// Requests that name a file get the file. Everything else gets the shell, which
// is what makes /d/<identifier> work for an identifier this binary has never
// seen.
func Handler(fsys fs.FS) http.Handler {
	files := http.FileServerFS(fsys)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")

		// Served directly rather than through the file server, which would
		// answer a request for the shell by name with a redirect to the
		// directory. That is correct and pointless: it costs a round trip on
		// the most requested path, and the redirect skips the cache directive
		// chosen below.
		if name == "" || name == "." || name == shell {
			serveShell(w, r, fsys)
			return
		}

		if _, err := fs.Stat(fsys, name); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			serveShell(w, r, fsys)
			return
		}

		// Hashed asset names are content-addressed, so they may be cached
		// indefinitely. The shell must not be: it names the current assets, and
		// a stale one would load assets that no longer exist.
		if strings.HasPrefix(name, "_app/immutable/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

// serveShell answers with the single-page document.
func serveShell(w http.ResponseWriter, r *http.Request, fsys fs.FS) {
	body, err := fs.ReadFile(fsys, shell)
	if err != nil {
		// A build without the client embedded. Saying so beats a blank 404 that
		// an operator would read as a routing fault.
		http.Error(w, "the web client was not built into this binary", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(body)
}
