// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Serraniel/sendan/internal/logging"
)

// unencodable fails to marshal, standing in for a response type that a later
// change makes unencodable.
type unencodable struct{}

func (unencodable) MarshalJSON() ([]byte, error) {
	return nil, errors.New("marshalling the session key at /var/lib/sendan/keys")
}

// Encoding happens before the status is written. Were it written first, a
// failure part-way through would leave a truncated body under a 200, which a
// client would parse as a short but valid response rather than as an error.
func TestWriteJSONFailsAsAnErrorRatherThanATruncatedSuccess(t *testing.T) {
	var logBuf strings.Builder
	slog.SetDefault(logging.New(&logBuf, logging.Options{Format: "json"}))
	t.Cleanup(func() { slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil))) })

	rec := httptest.NewRecorder()
	writeJSON(rec, 200, unencodable{})

	if rec.Code != 500 {
		t.Fatalf("status %d, want 500", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type %q", got)
	}

	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the failure response is not valid JSON: %v\n%s", err, rec.Body.String())
	}
	if body.Code != "internal" {
		t.Errorf("code %q, want internal", body.Code)
	}

	// The encoding error may name paths or key material. It belongs in the log.
	if strings.Contains(rec.Body.String(), "/var/lib/sendan/keys") {
		t.Errorf("the encoding error reached the client:\n%s", rec.Body.String())
	}
	if !strings.Contains(logBuf.String(), "/var/lib/sendan/keys") {
		t.Errorf("the encoding error was not logged:\n%s", logBuf.String())
	}
}

func TestWriteErrorShape(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, 404, "not_found", "no such upload")

	if rec.Code != 404 {
		t.Fatalf("status %d", rec.Code)
	}

	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Code != "not_found" || body.Message != "no such upload" {
		t.Errorf("body %+v", body)
	}
	if !strings.HasSuffix(rec.Body.String(), "\n") {
		t.Error("the response does not end in a newline, which makes it awkward on a terminal")
	}
}
