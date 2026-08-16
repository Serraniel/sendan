// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"errors"
	"net/http"

	"github.com/Serraniel/sendan/internal/upload"
)

// handleRevoke removes an upload before it would otherwise expire.
//
// Authorised by the owner token, which the uploader was given once and which
// this server holds only as a hash: possession proves ownership, and an
// operator cannot produce one for an upload they did not make. That is the
// whole of the mechanism, and it is why there is no account to authenticate
// against.
//
// The token travels in the Authorization header rather than the path, for the
// same reason a link secret lives in the fragment: a path reaches access logs,
// proxies and browser history, and a credential that reaches those is one that
// outlives its use.
//
// DELETE, because the effect is exactly that. It is idempotent in the way that
// matters - an upload that is already gone answers the same as one this request
// removed, so a client retrying a request whose response it never saw is not
// told that something went wrong.
func handleRevoke(uploads *upload.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		id := r.PathValue("id")
		if !validID(id) {
			writeError(w, http.StatusNotFound, "not_found", "no such upload")
			return
		}

		token, ok := bearerToken(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="sendan"`)
			writeError(w, http.StatusUnauthorized, "unauthorized",
				"the owner token is required")
			return
		}

		switch err := uploads.Revoke(r.Context(), id, token); {
		case err == nil:
			w.WriteHeader(http.StatusNoContent)

		case errors.Is(err, upload.ErrNotOwner):
			// One answer for a wrong token and for an upload that does not
			// exist. Telling them apart would let somebody map which
			// identifiers are real by asking about each in turn.
			writeError(w, http.StatusForbidden, "forbidden",
				"that owner token does not match this upload")

		default:
			writeError(w, http.StatusInternalServerError, "internal_error",
				"the upload could not be removed")
		}
	}
}
