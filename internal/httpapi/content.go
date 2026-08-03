// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/Serraniel/sendan/internal/logging"
	"github.com/Serraniel/sendan/internal/store"
	"github.com/Serraniel/sendan/internal/upload"
)

// countingWriter records how many bytes reached the client.
//
// The download counter accounts by volume (docs/design.md §4.4), so what
// matters is what was actually written, not what was intended. A transfer the
// client abandons part-way is charged for the part it received.
//
// It deliberately does not implement io.ReaderFrom. Doing so would let io.Copy
// bypass Write and the count would silently be zero.
type countingWriter struct {
	http.ResponseWriter
	written int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.written += int64(n)
	return n, err
}

// handleContent streams an upload's ciphertext.
//
// Serving is delegated to http.ServeContent, which implements conditional and
// range requests correctly. Hand-rolling Range parsing is a well-known source
// of defects - overlapping ranges, suffix ranges, unsatisfiable ranges - and
// none of it is specific to this project.
func handleContent(uploads *upload.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A shared cache holding this would serve content the server never
		// counted, which would make the download limit unenforceable.
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
				"a download token is required")
			return
		}

		content, _, err := uploads.Content(r.Context(), id, token)
		if err != nil {
			writeContentError(w, r, uploads, id, err)
			return
		}
		defer func() { _ = content.Close() }()

		// Set before serving, because ServeContent writes the header. Without
		// an explicit type it would sniff the ciphertext, and a stream of
		// random bytes can be detected as anything.
		w.Header().Set("Content-Type", "application/octet-stream")

		// No filename: the server does not know it. The disposition still
		// stops a browser rendering the response inline.
		w.Header().Set("Content-Disposition", "attachment")

		// An upload's content never changes, so its identifier is a complete
		// validator. This is what makes resumption work: without it a ranged
		// request carrying If-Range fails the comparison, and ServeContent
		// answers with the whole file instead of the range - charging the
		// client for a second download of content they already hold.
		w.Header().Set("ETag", strconv.Quote(id))

		counter := &countingWriter{ResponseWriter: w}
		http.ServeContent(counter, r, "", time.Time{}, content)

		// Accounted after the transfer, from what was written. A request that
		// is refused, conditional, or abandoned is charged accordingly.
		// Recorded against the background context, not the request's: a client
		// that disconnected has already cancelled r.Context(), and accounting
		// for what it received must not be cancelled with it. That would make
		// every abandoned transfer free, which is the bypass this model exists
		// to close.
		if err := uploads.RecordServed(context.WithoutCancel(r.Context()), id, counter.written); err != nil {
			// The bytes have already been served; there is nobody left to tell.
			slog.Default().Error("could not record served bytes",
				logging.FileID([]byte(id)), "bytes", counter.written, "error", err)
		}
	}
}

func writeContentError(w http.ResponseWriter, r *http.Request, uploads *upload.Service, id string, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such upload")
	case errors.Is(err, upload.ErrTooManyAttempts):
		if seconds := int(math.Ceil(uploads.RetryAfter(id).Seconds())); seconds > 0 {
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
