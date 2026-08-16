// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package compat

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Serraniel/sendan/internal/store"
)

// The protocol fetches content in two steps: an authenticated request for a
// token, then the transfer itself carrying that token as a bearer credential.
// The second request has no nonce to sign, which is why the first exists.

// downloadToken is derived rather than stored.
//
// Keyed by the upload's at-rest key, which the server already holds and never
// sends anywhere, so a token needs no row of its own and is the same on every
// replica. A client cannot forge one: it never sees that key, unlike the
// authentication key it supplied itself.
func downloadToken(atRestKey []byte, id string) string {
	mac := hmac.New(sha256.New, atRestKey)
	mac.Write([]byte("compat/download-token/" + id))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// handleDownloadToken issues the credential the transfer request carries.
//
// Upstream increments the download count here, so a client that asks for a
// token and never transfers still spends one. Sendan counts by bytes actually
// served, and that is left alone deliberately: a download nobody received is
// not a download, and the limit exists to bound what recipients get rather than
// what clients ask for. The count still advances on transfer, so a limit is
// still a limit.
func (h *Handler) handleDownloadToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	if _, ok := h.authenticate(w, r, id); !ok {
		return
	}

	u, err := h.metadata.Get(r.Context(), id, h.uploads.Now())
	if err != nil {
		if errors.Is(err, store.ErrExhausted) {
			http.Error(w, "download limit reached", http.StatusForbidden)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token": downloadToken(u.AtRestKey, id),
	})
}

// handleDownload serves the ciphertext.
//
// What goes out is what the client encrypted: this server holds no key that
// opens it, only the at-rest key that protects it on disk, which is stripped as
// it is read.
func (h *Handler) handleDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	u, err := h.metadata.Get(r.Context(), id, h.uploads.Now())
	if err != nil {
		if errors.Is(err, store.ErrExhausted) {
			http.Error(w, "download limit reached", http.StatusForbidden)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Either credential is accepted, because clients of this protocol differ on
	// which one they send here. Some fetch a token first and present it as a
	// bearer credential; the one this was tested against signs the rotating
	// nonce instead and never asks for a token at all. Both are checked the
	// same way they would be on their own, so accepting both widens which
	// clients work rather than what counts as authenticated.
	if !h.authorizeDownload(w, r, id, u.AtRestKey) {
		return
	}

	content, err := h.blobs.Open(r.Context(), id, u.AtRestKey)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer func() { _ = content.Close() }()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(u.Size, 10))
	w.WriteHeader(http.StatusOK)

	served, err := io.Copy(w, content)
	if err != nil {
		// The client is gone or the transfer broke. Whatever arrived still
		// counts, so the accounting below runs either way.
		h.log.Warn("compatibility download interrupted", "error", err)
	}

	// Recorded after the bytes have gone, because the count is derived from
	// them: this is what makes a download limit apply to this protocol at all.
	if served > 0 {
		if _, err := h.metadata.RecordServed(r.Context(), id, served); err != nil {
			h.log.Error("could not record a compatibility download", "error", err)
		}
	}
}

// authorizeDownload accepts either credential this protocol's clients send.
func (h *Handler) authorizeDownload(w http.ResponseWriter, r *http.Request, id string, atRestKey []byte) bool {
	// The bearer token first: it is derived from a key no client ever sees, so
	// a wrong one teaches nothing about the right one.
	if presented, ok := bearerToken(r.Header.Get("Authorization")); ok {
		if hmac.Equal([]byte(presented), []byte(downloadToken(atRestKey, id))) {
			return true
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}

	// Otherwise the same rotating-nonce signature every other endpoint takes.
	_, ok := h.authenticate(w, r, id)
	return ok
}

// bearerToken reads an Authorization header of the bearer scheme.
func bearerToken(header string) (string, bool) {
	name, value, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(name, "bearer") {
		return "", false
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	return value, true
}
