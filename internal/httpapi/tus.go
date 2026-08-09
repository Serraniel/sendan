// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"fmt"
	"net/http"
	"net/url"

	tus "github.com/tus/tusd/v2/pkg/handler"

	"github.com/Serraniel/sendan/internal/upload"
)

// newTusHandler builds the upload endpoint.
//
// tus is adopted rather than reimplemented. Resumption, offset negotiation and
// the request semantics are a protocol with maintained implementations on both
// sides; what is specific to Sendan is where bytes go and what a completed
// upload becomes, which is the data store.
func newTusHandler(opts Options) (http.Handler, error) {
	store := upload.NewTusStore(opts.Uploads, opts.MaxUploadSize)

	composer := tus.NewStoreComposer()
	composer.UseCore(store)

	// The path the handler is mounted at, which is what it uses to derive an
	// upload identifier from a request and to build the Location header.
	const base = "/api/uploads/"

	h, err := tus.NewUnroutedHandler(tus.Config{
		BasePath:      base,
		StoreComposer: composer,
		MaxSize:       opts.MaxUploadSize,

		// The download endpoint serves content, with a token check first. tus
		// would serve it without one.
		DisableDownload: true,

		// An upload is removed through revocation, which requires the owner
		// token. tus termination would remove it for anyone holding the
		// identifier, which recipients have.
		DisableTermination: true,

		// Concatenation composes an upload from parts, each of which would be a
		// row with its own at-rest key and no lifecycle. Sendan has no use for
		// it and would have to reap the parts.
		DisableConcatenation: true,

		Logger: tusLogger(opts.Log),
	})
	if err != nil {
		return nil, fmt.Errorf("tus handler: %w", err)
	}

	// The middleware writes the protocol version headers and answers OPTIONS,
	// so it wraps every method the endpoint accepts.
	return h.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			h.PostFile(w, r)
		case http.MethodHead:
			h.HeadFile(w, r)
		case http.MethodPatch:
			h.PatchFile(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed",
				"this endpoint accepts POST, HEAD and PATCH")
		}
	})), nil
}

// relativeLocation rewrites an absolute Location header to a path.
//
// The protocol handler builds `scheme://host/path` from the request it can see,
// and the request it can see is the one from the reverse proxy - plain HTTP,
// because this binary does not terminate TLS and `docs/configuration.md` does
// not ask it to. A browser on an HTTPS page is then handed an http:// URL and
// refuses to follow it as mixed content, so every upload fails after creation
// in the deployment the documentation recommends.
//
// Forwarded headers are not consulted instead. They are written by whatever
// spoke last, and this project treats believing them as a security setting
// rather than a default (SENDAN_TRUSTED_PROXIES).
//
// A path is used rather than SENDAN_BASE_URL because it cannot be wrong: the
// tus specification permits a relative Location, and a client resolves it
// against the request it actually made - which is by definition one that
// reached the instance. An absolute URL built from configuration is correct
// only while that configuration is, and wrong in a way that looks like a client
// fault when it is not.
func relativeLocation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&locationRewriter{ResponseWriter: w}, r)
	})
}

type locationRewriter struct {
	http.ResponseWriter
	rewritten bool
}

func (l *locationRewriter) WriteHeader(status int) {
	l.rewrite()
	l.ResponseWriter.WriteHeader(status)
}

func (l *locationRewriter) Write(b []byte) (int, error) {
	// A handler that writes a body without calling WriteHeader implies 200, and
	// the headers are sent at that point too.
	l.rewrite()
	return l.ResponseWriter.Write(b)
}

func (l *locationRewriter) rewrite() {
	if l.rewritten {
		return
	}
	l.rewritten = true

	location := l.Header().Get("Location")
	if location == "" {
		return
	}
	parsed, err := url.Parse(location)
	if err != nil || !parsed.IsAbs() {
		// Already relative, or unparseable and not ours to mangle.
		return
	}
	l.Header().Set("Location", parsed.RequestURI())
}
