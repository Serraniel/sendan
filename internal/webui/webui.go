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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io/fs"
	"net/http"
	"path"
	"sort"
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

// InlineScriptHashes returns a Content-Security-Policy source expression for
// every inline script in the shell.
//
// The client's bootstrap is inline: it is the two hundred bytes that tell the
// application where it was served from, and it cannot be a separate file
// because it differs per build. The policy forbids 'unsafe-inline', so without
// its hash a browser refuses to run it and the application never starts - a
// failure invisible to any test that does not execute the page.
//
// Hashing here rather than letting the client emit its own policy keeps one
// authoritative header. Two policies both apply, and the intersection of a
// header without the hash and a meta tag with it still blocks the script.
func InlineScriptHashes(fsys fs.FS) ([]string, error) {
	body, err := fs.ReadFile(fsys, shell)
	if err != nil {
		return nil, err
	}

	var hashes []string
	for _, script := range inlineScripts(string(body)) {
		sum := sha256.Sum256([]byte(script))
		hashes = append(hashes, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
	}
	return hashes, nil
}

// InlineStyleAttrHashes returns a Content-Security-Policy source expression for
// every inline style attribute the client carries.
//
// One exists, and it is not ours: SvelteKit gives every application a route
// announcer - a live region that reads the new page name after a client-side
// navigation - and styles it with a style attribute rather than a class.
// `style-src 'self'` forbids that, so every page load reported a violation
// against our own policy.
//
// Hashed rather than allowed wholesale. 'unsafe-hashes' is needed for a browser
// to consider a hash for a style attribute at all, but it does not permit
// arbitrary ones: only a value matching one of these hashes is applied. A
// second, unexpected style attribute is still refused.
//
// Derived from the built client rather than written down, for the same reason
// the script hashes are: a value pinned here would be correct until the
// framework changed its announcer, and would then fail in a browser rather than
// in a test.
func InlineStyleAttrHashes(fsys fs.FS) ([]string, error) {
	values, err := inlineStyleAttrs(fsys)
	if err != nil {
		return nil, err
	}

	hashes := make([]string, 0, len(values))
	for _, value := range values {
		sum := sha256.Sum256([]byte(value))
		hashes = append(hashes, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
	}
	return hashes, nil
}

// inlineStyleAttrs collects the distinct style attribute values in the client,
// in a stable order.
//
// It reads the shell and the built JavaScript, because a framework emits its
// markup as template text inside a bundle rather than as HTML. Scanning for the
// literal attribute is enough for that: the bundles are generated by this
// project's own build, not fetched from anywhere.
//
// A value that is not really a style attribute costs one unused hash and
// permits nothing, so the scan errs towards finding too much.
func inlineStyleAttrs(fsys fs.FS) ([]string, error) {
	var out []string
	seen := make(map[string]bool)

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (!strings.HasSuffix(path, ".js") && !strings.HasSuffix(path, ".html")) {
			return nil
		}
		body, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		for _, value := range styleAttrValues(string(body)) {
			if !seen[value] {
				seen[value] = true
				out = append(out, value)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Sorted so the header is the same for two builds of the same client, which
	// is what makes a policy comparable between instances.
	sort.Strings(out)
	return out, nil
}

// styleAttrValues returns the value of every `style="..."` in a document.
func styleAttrValues(doc string) []string {
	var out []string
	rest := doc
	for {
		at := strings.Index(rest, `style="`)
		if at < 0 {
			return out
		}
		rest = rest[at+len(`style="`):]

		end := strings.Index(rest, `"`)
		if end < 0 {
			return out
		}
		out = append(out, rest[:end])
		rest = rest[end+1:]
	}
}

// inlineScripts returns the body of every script element that has no src.
//
// Deliberately narrow: it reads the shell this project builds, not arbitrary
// markup. A general HTML parser would invite the assumption that it handles
// hostile input, which it never sees.
func inlineScripts(doc string) []string {
	var out []string
	rest := doc
	for {
		open := strings.Index(rest, "<script")
		if open < 0 {
			return out
		}
		rest = rest[open:]

		gt := strings.Index(rest, ">")
		if gt < 0 {
			return out
		}
		attrs := rest[:gt]
		rest = rest[gt+1:]

		end := strings.Index(rest, "</script>")
		if end < 0 {
			return out
		}
		if !strings.Contains(attrs, "src=") {
			out = append(out, rest[:end])
		}
		rest = rest[end+len("</script>"):]
	}
}
