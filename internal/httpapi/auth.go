// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"encoding/base64"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/Serraniel/sendan/internal/store"
	"github.com/Serraniel/sendan/internal/upload"
)

// maxTokenLength bounds what is decoded from the Authorization header. The
// token is 32 bytes, which is 43 characters of unpadded base64url; the margin
// tolerates padding without accepting a header worth decoding at length.
const maxTokenLength = 64

// bearerToken extracts and decodes the download token from a request.
//
// The token travels in a header, never in the path or query. A query parameter
// would be written to every access log between the client and the server, and
// this token is derived from the link secret - the one value the whole scheme
// keeps out of logs by putting it in the URL fragment (spec §10).
func bearerToken(r *http.Request) ([]byte, bool) {
	raw := r.Header.Get("Authorization")
	scheme, value, found := strings.Cut(raw, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return nil, false
	}

	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxTokenLength {
		return nil, false
	}

	token, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, false
	}
	return token, true
}

// handleAuth verifies a download token without serving anything.
//
// It exists so a client can report a wrong password before starting a
// download, rather than discovering it part-way through a transfer, and so it
// can do that without spending one of the upload's downloads.
//
// POST rather than GET: an attempt has an effect, being counted against the
// upload's allowance, and a GET would be prefetched by browsers and link
// previewers that have no business consuming attempts.
func handleAuth(uploads *upload.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		id := r.PathValue("id")
		if !validID(id) {
			writeError(w, http.StatusNotFound, "not_found", "no such upload")
			return
		}

		token, ok := bearerToken(r)
		if !ok {
			// A malformed credential is not a wrong one. Charging it against
			// the upload's allowance would let anyone exhaust it with garbage,
			// locking out the recipient without ever making a real attempt.
			w.Header().Set("WWW-Authenticate", `Bearer realm="sendan"`)
			writeError(w, http.StatusUnauthorized, "unauthorized",
				"a download token is required")
			return
		}

		switch err := uploads.Authenticate(r.Context(), id, token); {
		case err == nil:
			w.WriteHeader(http.StatusNoContent)

		case errors.Is(err, store.ErrNotFound):
			// Existence is already public: the metadata endpoint answers
			// unauthenticated. Hiding it here would cost a recipient with an
			// expired link a clear answer and conceal nothing.
			writeError(w, http.StatusNotFound, "not_found", "no such upload")

		case errors.Is(err, upload.ErrTooManyAttempts):
			retry := uploads.RetryAfter(id)
			if seconds := int(math.Ceil(retry.Seconds())); seconds > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(seconds))
			}
			writeError(w, http.StatusTooManyRequests, "too_many_attempts",
				"too many attempts against this upload; retry later")

		case errors.Is(err, upload.ErrUnauthorized):
			w.Header().Set("WWW-Authenticate", `Bearer realm="sendan"`)
			writeError(w, http.StatusUnauthorized, "unauthorized",
				"the download token is not valid for this upload")

		default:
			writeServerError(w, r, err)
		}
	}
}
