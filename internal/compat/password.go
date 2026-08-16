// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package compat

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/Serraniel/sendan/internal/store"
)

// The password model this protocol uses is **server-enforced**, and that is a
// weaker guarantee than Sendan's own.
//
// Setting a password replaces the key the server checks a downloader against.
// It does not change the key that decrypts the content: that is derived from
// the secret in the link and is the same with or without a password. So the
// server can serve the content to anybody it likes, password or not, and a
// database that leaks discloses a credential rather than nothing.
//
// Sendan's native model derives part of the key-wrapping key from the password,
// so an instance holding every byte it stores still cannot open a
// password-protected upload. That difference is why an upload made through here
// is marked, and why the interface says so beside it rather than in a footnote.
//
// It is implemented anyway because this is what the protocol's clients speak,
// and a compatibility layer that refused passwords would be one that refused
// most of the files people actually send.

// maxPasswordBody bounds the request. It carries one base64 key.
const maxPasswordBody = 8 << 10

type passwordRequest struct {
	// Auth is the new authentication key, derived by the client from the
	// password. The password itself never arrives.
	Auth string `json:"auth"`

	// OwnerToken is what the uploader was given when the upload was created.
	// Only they may set a password.
	OwnerToken string `json:"owner_token"`
}

// handlePassword sets or replaces an upload's password.
//
// Authorised by the owner token rather than by the download credential: the
// person who may change how a file is protected is the one who uploaded it, not
// somebody who has been given the link.
func (h *Handler) handlePassword(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req passwordRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxPasswordBody)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	authKey, err := decodeB64(req.Auth)
	if err != nil || len(authKey) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	u, err := h.metadata.Get(r.Context(), id, h.uploads.Now())
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Constant time, and against a hash: unlike this protocol's own server,
	// nothing here stores the owner token itself.
	if !hmac.Equal(hashToken(req.OwnerToken), u.OwnerTokenHash) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := h.store.SetCompatPassword(r.Context(), id, authKey); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.log.Info("a compatibility upload was given a password",
		"model", "server-enforced, weaker than native")

	w.WriteHeader(http.StatusOK)
}
