// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Serraniel/sendan/internal/logging"
)

// errorResponse is the shape of every error this API returns.
//
// code is a stable identifier a client may branch on; message is for a person
// reading a log. Neither ever describes server internals: an error message that
// names a table, a path, or a driver tells an attacker about the deployment and
// tells a legitimate user nothing they can act on.
type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	// Encoded before the status is written, so a failure can still become a 500
	// rather than a truncated body under a 200.
	encoded, err := json.Marshal(body)
	if err != nil {
		slog.Default().Error("encoding a response", "error", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":"internal","message":"internal error"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
	_, _ = w.Write([]byte("\n"))
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Code: code, Message: message})
}

// writeServerError reports a fault to the operator and a generic answer to the
// caller.
//
// The error is logged rather than returned, because it may name a backend, a
// query or a path. The caller learns that something failed, which is all they
// can act on.
//
// The route pattern is logged, never r.URL.Path. Two reasons, and both matter:
//
//   - The path carries the upload identifier. Sendan's guarantee is that
//     identifiers never appear in logs verbatim, so that a log which leaks
//     does not become a list of downloadable files. They go through
//     logging.FileID, which records a truncated hash.
//   - The path is caller-controlled. A pattern is a compile-time constant
//     registered by this package, so it cannot be used to forge log entries.
func writeServerError(w http.ResponseWriter, r *http.Request, err error) {
	attrs := []any{"method", r.Method, "route", r.Pattern, "error", err}
	if id := r.PathValue("id"); id != "" {
		attrs = append(attrs, logging.FileID([]byte(id)))
	}
	slog.Default().Error("request failed", attrs...)

	writeError(w, http.StatusInternalServerError, "internal", "internal error")
}
