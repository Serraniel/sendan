// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"fmt"
	"net/http"

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
