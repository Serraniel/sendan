// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Package compat speaks a third-party file-sharing protocol, so clients written
// for it work against a Sendan instance.
//
// Off unless an operator asks for it. Uploads made through here use that
// protocol's weaker, server-enforced password model: the password changes only
// the key the *server* checks a downloader against, so the server can serve the
// content to anybody regardless of it. Sendan's own model derives part of the
// content key from the password, which no server-side policy can bypass.
//
// The formats are close enough that this is mostly routing rather than a second
// implementation of anything - both use the RFC 8188 content encoding with
// HKDF-SHA256, which is why docs/design.md §5 chose that framing. What differs
// is who holds which key, and that difference is confined to
// [store.CompatUpload] and to this package.
package compat

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/Serraniel/sendan/internal/blob"
	"github.com/Serraniel/sendan/internal/store"
	"github.com/Serraniel/sendan/internal/upload"
)

// compatProtocolVersion is the generation of the third-party protocol this
// speaks. Its clients probe for it and choose their endpoints accordingly.
const compatProtocolVersion = "3.4.28"

// Options configures the compatibility handler.
type Options struct {
	// Store holds the compatibility state. Required.
	Store store.CompatStore

	// Uploads owns the lifecycle: expiry policy, revocation, reaping. A
	// compatibility upload is an ordinary upload, so it is subject to all of
	// it.
	Uploads *upload.Service

	// Metadata is the upload store, for reads the lifecycle service does not
	// cover.
	Metadata store.Store

	// Blobs stores the ciphertext, encrypted at rest exactly as a native
	// upload's is.
	Blobs *blob.Shredder

	// BaseURL is what goes into the download link handed back to a client. It
	// has to be the address a recipient will use, not the one this process can
	// see.
	BaseURL *url.URL

	Log *slog.Logger
}

// Handler serves the compatibility endpoints.
type Handler struct {
	store    store.CompatStore
	uploads  *upload.Service
	metadata store.Store
	blobs    *blob.Shredder
	baseURL  *url.URL
	log      *slog.Logger

	mux *http.ServeMux
}

// New builds the handler.
//
// Every route is registered here rather than in the main API surface, so that
// turning the mode off removes the routes entirely rather than leaving them
// answering with a refusal. An endpoint that exists and says no is still an
// endpoint somebody can probe.
func New(opts Options) *Handler {
	log := opts.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	h := &Handler{
		store:    opts.Store,
		uploads:  opts.Uploads,
		metadata: opts.Metadata,
		blobs:    opts.Blobs,
		baseURL:  opts.BaseURL,
		log:      log,
		mux:      http.NewServeMux(),
	}

	// Probed before anything else, because a client uses it to decide which
	// generation of the protocol to speak. Without it, one falls back to an
	// older API whose endpoints are shaped differently and nothing works -
	// which is exactly what happened the first time a real client was pointed
	// at this.
	h.mux.HandleFunc("GET /__version__", h.handleVersion)

	// The share link a client hands out. Its own clients fetch it to decide
	// whether the upload still exists, so answering must not depend on the web
	// interface being served.
	h.mux.HandleFunc("GET /download/{id}/", h.handleSharePage)

	h.mux.HandleFunc("GET /api/ws", h.handleUpload)
	h.mux.HandleFunc("GET /api/exists/{id}", h.handleExists)
	h.mux.HandleFunc("GET /api/metadata/{id}", h.handleMetadata)
	h.mux.HandleFunc("GET /api/download/token/{id}", h.handleDownloadToken)
	h.mux.HandleFunc("GET /api/download/{id}", h.handleDownload)

	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

// Handles reports whether a path belongs to this protocol.
//
// Used by the main API surface to decide what to delegate, so the two do not
// have to agree on a list of paths in two places.
func (h *Handler) Handles(r *http.Request) bool {
	_, pattern := h.mux.Handler(r)
	return pattern != ""
}

// handleExists answers before any authentication, because a client needs to
// know whether to prompt for a password before it can derive anything.
//
// It discloses only that an upload exists and whether it is protected, which is
// what the protocol requires. The nonce comes with it: this is where a client
// that has never spoken to the server learns what to sign.
func (h *Handler) handleExists(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	c, err := h.store.Compat(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Only for an upload that is actually reachable. Answering for one that has
	// expired or been exhausted would say it exists when it does not.
	if _, err := h.metadata.Get(r.Context(), id, h.uploads.Now()); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	offer(w, c.Nonce)
	writeJSON(w, http.StatusOK, map[string]any{
		"requiresPassword": c.RequiresPassword,
	})
}

// handleMetadata returns the client's own encrypted metadata.
//
// Opaque here: it is in that protocol's format, encrypted with a key derived
// from the secret in the link, which never reaches this server.
func (h *Handler) handleMetadata(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	c, ok := h.authenticate(w, r, id)
	if !ok {
		return
	}

	u, err := h.metadata.Get(r.Context(), id, h.uploads.Now())
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	ttl := int64(0)
	if !u.ExpiresAt.IsZero() {
		ttl = u.ExpiresAt.Sub(h.uploads.Now()).Milliseconds()
		if ttl < 0 {
			ttl = 0
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"metadata": string(c.Metadata),
		"flagged":  false,
		// True when this download would be the last one allowed, so a client
		// can warn before spending it.
		"finalDownload": u.MaxDownloads > 0 && u.DownloadCount+1 >= u.MaxDownloads,
		"ttl":           ttl,
	})
}

// handleVersion identifies which generation of the protocol this speaks.
//
// The version reported is the protocol's, not this project's: it answers "what
// can I say to you", and a client comparing it against Sendan's own version
// would learn nothing it could act on.
func (h *Handler) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version": compatProtocolVersion,
		"commit":  "sendan",
		"source":  "https://github.com/Serraniel/sendan",
	})
}

// handleSharePage answers the link a client hands to a recipient.
//
// This is where a client gets the nonce it signs, which is not obvious: it
// fetches this page rather than the endpoint that reports whether the upload
// exists. Found by reading a real client after it stopped here without ever
// requesting metadata - the page answered, carried no WWW-Authenticate, and the
// client had nothing to sign.
func (h *Handler) handleSharePage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	c, err := h.store.Compat(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if _, err := h.metadata.Get(r.Context(), id, h.uploads.Now()); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	offer(w, c.Nonce)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("This upload was made with a third-party client.\n" +
		"Use that client to download it; the key is in the part of the link after the #.\n"))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
