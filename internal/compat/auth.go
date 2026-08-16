// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package compat

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/Serraniel/sendan/internal/store"
)

// scheme is the authorization scheme this protocol uses.
const scheme = "send-v1"

// nonceSize is what the protocol's clients expect to receive and sign over.
const nonceSize = 16

// authenticate checks the Authorization header against the stored nonce.
//
// The protocol works the other way round from Sendan's own. Here the server
// holds the client's key and computes the expected HMAC itself, so possession
// of the stored value is possession of the ability to authenticate. Sendan's
// native model stores a hash and cannot do that, which is the difference
// docs/design.md and SECURITY.md describe and this package exists to speak
// anyway.
//
// A fresh nonce is issued on every success and handed back in WWW-Authenticate,
// so an Authorization header that is captured cannot be replayed. On failure the
// current nonce is returned instead, because the client needs it to try again -
// including the first time, when it has never seen one.
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request, id string) (*store.CompatUpload, bool) {
	c, err := h.store.Compat(r.Context(), id)
	if err != nil {
		// Absent and unauthenticated are the same answer, so probing for which
		// identifiers exist learns nothing.
		http.Error(w, "not found", http.StatusNotFound)
		return nil, false
	}

	presented, ok := presentedAuthenticator(r.Header.Get("Authorization"))
	if !ok || !hmac.Equal(expectedAuthenticator(c.AuthKey, c.Nonce), presented) {
		offer(w, c.Nonce)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}

	// Rotated before the request is served rather than after, so a failure
	// later cannot leave the same nonce usable a second time.
	next := make([]byte, nonceSize)
	if _, err := rand.Read(next); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, false
	}
	if err := h.store.RotateCompatNonce(r.Context(), id, next); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return nil, false
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, false
	}

	offer(w, next)
	c.Nonce = next
	return c, true
}

// expectedAuthenticator is what a client holding the key would send.
func expectedAuthenticator(authKey, nonce []byte) []byte {
	mac := hmac.New(sha256.New, authKey)
	mac.Write(nonce)
	return mac.Sum(nil)
}

// presentedAuthenticator decodes an Authorization header of this scheme.
func presentedAuthenticator(header string) ([]byte, bool) {
	name, value, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(name, scheme) {
		return nil, false
	}
	sig, err := decodeB64(value)
	if err != nil {
		return nil, false
	}
	return sig, true
}

// offer tells the client which nonce to sign next.
func offer(w http.ResponseWriter, nonce []byte) {
	w.Header().Set("WWW-Authenticate", scheme+" "+encodeB64(nonce))
}

// encodeB64 writes the encoding this protocol's clients produce: URL-safe and
// unpadded. Discovered by running one, which rejected standard base64 outright.
func encodeB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// decodeB64 accepts every spelling of base64 this protocol has been seen to
// use.
//
// Its clients encode URL-safe and unpadded, while its original server emitted
// standard base64 with padding, so implementations at both ends are lenient and
// anything strict fails against one of them. Being lenient here costs nothing:
// the value is authenticated by what it is used for, not by how it was spelled.
func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("compat: not base64")
}

// uploadAuthKey reads the key a client sends when it creates an upload.
//
// At upload time the header carries the key itself rather than a signature over
// anything: the client is telling the server what to check future downloads
// against. That is the protocol, and it is why the key ends up stored.
func uploadAuthKey(header string) ([]byte, error) {
	name, value, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(name, scheme) {
		return nil, errors.New("compat: the authorization header is not of this scheme")
	}
	key, err := decodeB64(value)
	if err != nil {
		return nil, errors.New("compat: the authorization key is not base64")
	}
	if len(key) == 0 {
		return nil, errors.New("compat: the authorization key is empty")
	}
	return key, nil
}
