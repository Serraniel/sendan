// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Serraniel/sendan/internal/crypto"
	"github.com/Serraniel/sendan/internal/logging"
)

// uploadMetadata builds a valid Upload-Metadata header.
//
// Values are base64 of the raw bytes, which is what the protocol specifies and
// what tus decodes for the data store.
func uploadMetadata(extra map[string]string) string {
	id := make([]byte, crypto.FileIDSize)
	if _, err := rand.Read(id); err != nil {
		panic(err)
	}
	fields := map[string]string{
		"fileID":           string(id),
		"wrappedFileKey":   string(bytes.Repeat([]byte{0x01}, crypto.WrappedFileKeySize)),
		"wrapNonce":        string(bytes.Repeat([]byte{0x02}, crypto.NonceSize)),
		"metadataEnvelope": string(bytes.Repeat([]byte{0x03}, 256+crypto.TagSize)),
		"metadataNonce":    string(bytes.Repeat([]byte{0x04}, crypto.NonceSize)),
		"authTokenHash":    string(crypto.AuthTokenHash(authToken)),
		"ownerTokenHash":   string(bytes.Repeat([]byte{0x06}, sha256.Size)),
	}
	for k, v := range extra {
		if v == "" {
			delete(fields, k)
			continue
		}
		fields[k] = v
	}

	parts := make([]string, 0, len(fields))
	for k, v := range fields {
		parts = append(parts, k+" "+base64.StdEncoding.EncodeToString([]byte(v)))
	}
	return strings.Join(parts, ",")
}

// create starts an upload and returns its location and identifier.
func (h *apiHarness) create(t *testing.T, size int, meta string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/uploads", nil)
	req.Header.Set("Tus-Resumable", "1.0.0")
	req.Header.Set("Upload-Length", strconv.Itoa(size))
	if meta != "" {
		req.Header.Set("Upload-Metadata", meta)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	location := rec.Header().Get("Location")
	id := location[strings.LastIndex(location, "/")+1:]
	return rec, id
}

// patch sends a chunk at an offset.
func (h *apiHarness) patch(t *testing.T, id string, offset int, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPatch, "/api/uploads/"+id, bytes.NewReader(body))
	req.Header.Set("Tus-Resumable", "1.0.0")
	req.Header.Set("Content-Type", "application/offset+octet-stream")
	req.Header.Set("Upload-Offset", strconv.Itoa(offset))
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

func (h *apiHarness) head(t *testing.T, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodHead, "/api/uploads/"+id, nil)
	req.Header.Set("Tus-Resumable", "1.0.0")
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

func TestUploadRoundTrip(t *testing.T) {
	h := newAPIHarness(t)
	body := []byte(strings.Repeat("sendan..", 500)) // 4000 bytes

	rec, id := h.create(t, len(body), uploadMetadata(nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d, want 201: %s", rec.Code, rec.Body.String())
	}
	if id == "" {
		t.Fatal("no identifier in the Location header")
	}

	// Not downloadable while it is being written.
	if got, _ := h.get(t, "/api/uploads/"+id+"/metadata"); got.Code != http.StatusNotFound {
		t.Fatalf("an upload in progress is readable: status %d", got.Code)
	}

	// Two chunks, so the resumable path is the one exercised.
	if rec := h.patch(t, id, 0, body[:1500]); rec.Code != http.StatusNoContent {
		t.Fatalf("first chunk: status %d: %s", rec.Code, rec.Body.String())
	}
	if rec := h.patch(t, id, 1500, body[1500:]); rec.Code != http.StatusNoContent {
		t.Fatalf("second chunk: status %d: %s", rec.Code, rec.Body.String())
	}

	// Now it is downloadable, and what comes back is what went in.
	meta, m := h.get(t, "/api/uploads/"+id+"/metadata")
	if meta.Code != http.StatusOK {
		t.Fatalf("metadata after completion: status %d", meta.Code)
	}
	if m.WrappedFileKey != base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, crypto.WrappedFileKeySize)) {
		t.Errorf("the wrapped key did not survive the upload")
	}

	got := h.fetch(t, id, "", nil)
	if got.Code != http.StatusOK {
		t.Fatalf("download: status %d: %s", got.Code, got.Body.String())
	}
	if !bytes.Equal(got.Body.Bytes(), body) {
		t.Errorf("downloaded %d bytes that differ from the %d uploaded", got.Body.Len(), len(body))
	}
}

// A client that lost its connection asks where it stopped, and continues from
// there. This is the whole reason the protocol is used.
func TestUploadResumesFromTheReportedOffset(t *testing.T) {
	h := newAPIHarness(t)
	body := []byte(strings.Repeat("x", 3000))

	_, id := h.create(t, len(body), uploadMetadata(nil))
	if rec := h.patch(t, id, 0, body[:1000]); rec.Code != http.StatusNoContent {
		t.Fatalf("first chunk: %d", rec.Code)
	}

	rec := h.head(t, id)
	if rec.Code != http.StatusOK {
		t.Fatalf("head: status %d", rec.Code)
	}
	offset, err := strconv.Atoi(rec.Header().Get("Upload-Offset"))
	if err != nil {
		t.Fatalf("Upload-Offset %q: %v", rec.Header().Get("Upload-Offset"), err)
	}
	if offset != 1000 {
		t.Fatalf("Upload-Offset is %d after 1000 bytes: a client would resume from the wrong place", offset)
	}

	if rec := h.patch(t, id, offset, body[offset:]); rec.Code != http.StatusNoContent {
		t.Fatalf("resume: status %d: %s", rec.Code, rec.Body.String())
	}

	got := h.fetch(t, id, "", nil)
	if !bytes.Equal(got.Body.Bytes(), body) {
		t.Errorf("a resumed upload produced %d bytes that differ from the %d sent", got.Body.Len(), len(body))
	}
}

// A chunk that does not continue where the stored bytes end would leave a gap
// or an overlap, which decrypts to nothing from that point on.
func TestUploadRefusesAChunkAtTheWrongOffset(t *testing.T) {
	h := newAPIHarness(t)
	_, id := h.create(t, 100, uploadMetadata(nil))

	if rec := h.patch(t, id, 0, []byte("0123456789")); rec.Code != http.StatusNoContent {
		t.Fatalf("first chunk: %d", rec.Code)
	}
	rec := h.patch(t, id, 5, []byte("overlap"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409 for a chunk that does not continue the upload", rec.Code)
	}
}

// Once an upload is complete its identifier is shared with recipients. If it
// were still writable, anyone holding that identifier could replace what the
// recipient receives.
func TestACompletedUploadCannotBeWrittenTo(t *testing.T) {
	h := newAPIHarness(t)
	body := []byte("the original content")

	_, id := h.create(t, len(body), uploadMetadata(nil))
	if rec := h.patch(t, id, 0, body); rec.Code != http.StatusNoContent {
		t.Fatalf("upload: %d", rec.Code)
	}

	for _, offset := range []int{0, len(body)} {
		rec := h.patch(t, id, offset, []byte("replaced"))
		if rec.Code == http.StatusNoContent {
			t.Fatalf("a completed upload accepted a chunk at offset %d", offset)
		}
	}

	got := h.fetch(t, id, "", nil)
	if !bytes.Equal(got.Body.Bytes(), body) {
		t.Errorf("the content of a completed upload changed to %q", got.Body.String())
	}
}

func TestUploadEnforcesTheSizeLimit(t *testing.T) {
	h := newAPIHarnessWithLimit(t, 1024)

	rec, _ := h.create(t, 2048, uploadMetadata(nil))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413 for an upload beyond the limit", rec.Code)
	}

	ok, _ := h.create(t, 1024, uploadMetadata(nil))
	if ok.Code != http.StatusCreated {
		t.Fatalf("an upload at the limit was refused: %d", ok.Code)
	}
}

// A declared length is what makes the limit enforceable before any byte
// arrives. Without it the server would accept content and discover the problem
// afterwards, having already written it.
func TestUploadRequiresADeclaredLength(t *testing.T) {
	h := newAPIHarnessWithLimit(t, 1024)

	req := httptest.NewRequest(http.MethodPost, "/api/uploads", nil)
	req.Header.Set("Tus-Resumable", "1.0.0")
	req.Header.Set("Upload-Defer-Length", "1")
	req.Header.Set("Upload-Metadata", uploadMetadata(nil))
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusCreated {
		t.Fatal("an upload of undeclared length was accepted, so the size limit is unenforceable")
	}
}

// Client-produced values are opaque, but their sizes are not: a wrong length
// means a client that cannot be interoperable and an upload nobody will open.
func TestUploadValidatesTheCryptographicMetadata(t *testing.T) {
	h := newAPIHarness(t)

	tests := map[string]map[string]string{
		"no wrapped key":         {"wrappedFileKey": ""},
		"short wrapped key":      {"wrappedFileKey": "too short"},
		"no wrap nonce":          {"wrapNonce": ""},
		"wrong nonce length":     {"wrapNonce": "0123456789"},
		"no auth token hash":     {"authTokenHash": ""},
		"short auth token hash":  {"authTokenHash": "nope"},
		"no owner token hash":    {"ownerTokenHash": ""},
		"no metadata envelope":   {"metadataEnvelope": ""},
		"unpadded envelope":      {"metadataEnvelope": "not a padded envelope"},
		"negative max downloads": {"maxDownloads": "-1"},
	}
	for name, extra := range tests {
		t.Run(name, func(t *testing.T) {
			rec, _ := h.create(t, 100, uploadMetadata(extra))
			if rec.Code == http.StatusCreated {
				t.Fatalf("accepted: %s", rec.Body.String())
			}
			if rec.Code >= 500 {
				t.Fatalf("a malformed request produced %d, which reports a server fault for a client error", rec.Code)
			}
		})
	}
}

// A password-protected upload must carry all its derivation parameters. A
// partial set would let a client derive with parameters the uploader never
// chose.
func TestUploadRequiresCompleteArgon2Parameters(t *testing.T) {
	h := newAPIHarness(t)

	salt := string(bytes.Repeat([]byte{0x5A}, crypto.PasswordSaltSize))
	rec, _ := h.create(t, 100, uploadMetadata(map[string]string{"passwordSalt": salt}))
	if rec.Code == http.StatusCreated {
		t.Fatal("a password salt was accepted without its Argon2id parameters")
	}

	ok, id := h.create(t, 100, uploadMetadata(map[string]string{
		"passwordSalt":      salt,
		"argon2MemoryKiB":   "65536",
		"argon2Iterations":  "3",
		"argon2Parallelism": "1",
	}))
	if ok.Code != http.StatusCreated {
		t.Fatalf("a complete parameter set was refused: %s", ok.Body.String())
	}

	if rec := h.patch(t, id, 0, bytes.Repeat([]byte("x"), 100)); rec.Code != http.StatusNoContent {
		t.Fatalf("upload: %d", rec.Code)
	}
	_, m := h.get(t, "/api/uploads/"+id+"/metadata")
	if !m.PasswordRequired || m.KDF == nil {
		t.Fatal("the password parameters did not survive the upload")
	}
	if m.KDF.MemoryKiB != 65536 || m.KDF.Iterations != 3 || m.KDF.Parallelism != 1 {
		t.Errorf("parameters %+v", m.KDF)
	}
}

// tus attaches the upload identifier to every record it logs. This project's
// guarantee is that identifiers never appear in logs verbatim, so that a log
// which leaks does not become a list of downloadable files.
func TestTusLoggingDoesNotDiscloseIdentifiers(t *testing.T) {
	var buf bytes.Buffer
	log := logging.New(&buf, logging.Options{Level: slog.LevelDebug, Format: "json"})

	h := newAPIHarnessWithLogger(t, log)
	body := []byte("logged")

	_, id := h.create(t, len(body), uploadMetadata(nil))
	if rec := h.patch(t, id, 0, body); rec.Code != http.StatusNoContent {
		t.Fatalf("upload: %d", rec.Code)
	}
	_ = h.head(t, id)

	if buf.Len() == 0 {
		t.Skip("tus logged nothing, so this proves nothing")
	}
	if strings.Contains(buf.String(), id) {
		t.Errorf("the upload identifier appears in the logs verbatim:\n%s", buf.String())
	}
}

func TestUploadRejectsOtherMethods(t *testing.T) {
	h := newAPIHarness(t)
	_, id := h.create(t, 10, uploadMetadata(nil))

	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/uploads/"+id, nil)
		req.Header.Set("Tus-Resumable", "1.0.0")
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusNoContent || rec.Code == http.StatusOK {
			t.Errorf("%s was accepted with status %d", method, rec.Code)
		}
	}
}

// An upload that was abandoned holds an at-rest key and a partial blob nothing
// will finish, so the reaper collects it along with what it wrote.
func TestAbandonedUploadsAreReapedWithTheirContent(t *testing.T) {
	// Anything unfinished for a nanosecond counts as abandoned, so the reaper
	// can be reached without waiting or rewriting timestamps behind the
	// service's back.
	h := newAPIHarnessWithIncompleteTTL(t, time.Nanosecond)

	_, id := h.create(t, 1000, uploadMetadata(nil))
	if rec := h.patch(t, id, 0, bytes.Repeat([]byte("x"), 400)); rec.Code != http.StatusNoContent {
		t.Fatalf("chunk: %d", rec.Code)
	}
	if n, err := h.blobs.Length(context.Background(), id); err != nil || n != 400 {
		t.Fatalf("the partial upload holds %d bytes, %v", n, err)
	}

	if _, err := h.svc.Reap(context.Background(), 100); err != nil {
		t.Fatalf("reap: %v", err)
	}
	if _, err := h.blobs.Length(context.Background(), id); err == nil {
		t.Error("the partial content of an abandoned upload survived the reaper")
	}
}

// The bridge is what keeps tus's records inside this project's logging
// guarantees, so its own behaviour is worth asserting directly rather than only
// through a request.
func TestTusLoggerBridge(t *testing.T) {
	var buf bytes.Buffer
	to := logging.New(&buf, logging.Options{Level: slog.LevelDebug, Format: "json"})

	l := tusLogger(to)
	l.With("id", "SECRETIDAAAAAAAAAAAAAA").
		WithGroup("request").
		Info("something", "method", "PATCH", "url", "http://x/api/uploads/SECRETIDAAAAAAAAAAAAAA", "path", "/SECRETIDAAAAAAAAAAAAAA")

	out := buf.String()
	if strings.Contains(out, "SECRETIDAAAAAAAAAAAAAA") {
		t.Errorf("the identifier reached the log:\n%s", out)
	}
	if !strings.Contains(out, `"method":"PATCH"`) {
		t.Errorf("an allowed attribute was dropped:\n%s", out)
	}
	if !strings.Contains(out, `"file"`) {
		t.Errorf("the hashed identifier is absent, so a record cannot be correlated:\n%s", out)
	}
}

// A nil logger must not panic. An instance that starts without one should still
// serve, and tus writes records regardless.
func TestTusLoggerToleratesNoLogger(t *testing.T) {
	if l := tusLogger(nil); l == nil {
		t.Fatal("tusLogger returned nil")
	}
}

// streamedBody is a body whose length is not known in advance, which is what a
// browser sends with fetch request streaming (duplex: "half"). httptest sets a
// Content-Length for the readers it recognises, so this hides the type.
type streamedBody struct{ r io.Reader }

func (s streamedBody) Read(p []byte) (int, error) { return s.r.Read(p) }

// patchStreamed sends a chunk whose length the server learns only as it
// arrives.
func (h *apiHarness) patchStreamed(t *testing.T, id string, offset int, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPatch, "/api/uploads/"+id, streamedBody{bytes.NewReader(body)})
	req.ContentLength = -1
	req.Header.Set("Tus-Resumable", "1.0.0")
	req.Header.Set("Content-Type", "application/offset+octet-stream")
	req.Header.Set("Upload-Offset", strconv.Itoa(offset))
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

// A browser with fetch request streaming sends the whole upload as one request
// whose length is not declared on the request itself. That needs no second
// endpoint: it is the same PATCH, with the body arriving as a stream.
//
// This is asserted because nothing else would notice it breaking. The chunked
// path is exercised by every other test; a regression in the streamed one would
// surface only in a browser that supports it.
func TestUploadAcceptsAStreamedBody(t *testing.T) {
	h := newAPIHarness(t)
	body := []byte(strings.Repeat("streamed", 500)) // 4000 bytes

	_, id := h.create(t, len(body), uploadMetadata(nil))

	rec := h.patchStreamed(t, id, 0, body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204: %s", rec.Code, rec.Body.String())
	}

	got := h.fetch(t, id, "", nil)
	if got.Code != http.StatusOK {
		t.Fatalf("download: status %d", got.Code)
	}
	if !bytes.Equal(got.Body.Bytes(), body) {
		t.Errorf("a streamed upload produced %d bytes that differ from the %d sent",
			got.Body.Len(), len(body))
	}
}

// The declared length is what makes the size limit enforceable, and a streamed
// body is the case where the server cannot check the length up front. A client
// that declares a little and streams a lot must not be able to store the lot.
func TestAStreamedBodyCannotExceedTheDeclaredLength(t *testing.T) {
	h := newAPIHarness(t)

	const declared = 10
	_, id := h.create(t, declared, uploadMetadata(nil))

	rec := h.patchStreamed(t, id, 0, bytes.Repeat([]byte("X"), 100))
	if rec.Code == http.StatusNoContent {
		t.Fatal("a body ten times the declared length was accepted in full")
	}

	// Exactly what was declared is stored, and no more.
	got := h.fetch(t, id, "", nil)
	if got.Body.Len() > declared {
		t.Errorf("stored %d bytes against a declared length of %d", got.Body.Len(), declared)
	}
}

// Resumption still works when the resumed chunk is streamed, which is the
// combination a browser produces after a dropped connection.
func TestAStreamedChunkCanResume(t *testing.T) {
	h := newAPIHarness(t)
	body := []byte(strings.Repeat("y", 2000))

	_, id := h.create(t, len(body), uploadMetadata(nil))
	if rec := h.patch(t, id, 0, body[:800]); rec.Code != http.StatusNoContent {
		t.Fatalf("first chunk: %d", rec.Code)
	}
	if rec := h.patchStreamed(t, id, 800, body[800:]); rec.Code != http.StatusNoContent {
		t.Fatalf("streamed resume: status %d: %s", rec.Code, rec.Body.String())
	}

	got := h.fetch(t, id, "", nil)
	if !bytes.Equal(got.Body.Bytes(), body) {
		t.Errorf("a streamed resume produced %d bytes that differ from the %d sent",
			got.Body.Len(), len(body))
	}
}

// The client is registered at the root, so it answers whatever nothing else
// claimed. That is only safe if the API and the health endpoint keep their
// paths - a client that shadowed them would break every request while looking
// like a routing preference.
func TestTheClientDoesNotShadowTheAPI(t *testing.T) {
	h := newAPIHarness(t)
	// The handler is rebuilt with the client enabled. An untagged build embeds
	// nothing, so this exercises the registration rather than the assets.
	handler := New(Options{
		Uploads: h.svc,
		BaseURL: mustURL(t, "https://sendan.example"),
		ServeUI: true,
		Log:     logging.New(io.Discard, logging.Options{Format: "json"}),
	})

	h.putContent(t, testID, 0)

	cases := []struct {
		name   string
		method string
		target string
		reject int
	}{
		{"health", http.MethodGet, "/healthz", http.StatusNotFound},
		{"source", http.MethodGet, "/api/source", http.StatusNotFound},
		{"metadata", http.MethodGet, "/api/uploads/" + testID + "/metadata", http.StatusNotFound},
		{"content", http.MethodGet, "/api/uploads/" + testID + "/content", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, nil)
			if strings.Contains(tc.target, "/content") {
				req.Header.Set("Authorization", bearer(authToken))
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code == tc.reject {
				t.Fatalf("%s was answered by the client rather than its handler", tc.target)
			}
			if strings.Contains(rec.Body.String(), "<!doctype html") {
				t.Errorf("%s received the client shell:\n%s", tc.target, rec.Body.String())
			}
		})
	}
}

// With the client disabled, an instance is backend-only from the same binary.
func TestTheClientIsNotServedWhenDisabled(t *testing.T) {
	h := newAPIHarness(t)
	handler := New(Options{
		Uploads: h.svc,
		BaseURL: mustURL(t, "https://sendan.example"),
		ServeUI: false,
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d with the client disabled, want 404", rec.Code)
	}
}

// The Location a client is given must describe the request the client made,
// not the one this process received.
//
// The binary does not terminate TLS; docs/configuration.md expects a reverse
// proxy to. The protocol handler builds an absolute URL from the connection it
// can see, which is the proxy's plain HTTP one, so a browser on an HTTPS page
// was handed an http:// URL and refused to follow it as mixed content. Every
// upload failed after creation, in the deployment the documentation recommends.
//
// Nothing caught it because every other test reaches the instance directly,
// where the scheme it infers happens to be right.
func TestTheLocationDoesNotDescribeTheConnectionItCannotSee(t *testing.T) {
	h := newAPIHarness(t)

	req := httptest.NewRequest(http.MethodPost, "/api/uploads", nil)
	req.Header.Set("Tus-Resumable", "1.0.0")
	req.Header.Set("Upload-Length", "100")
	req.Header.Set("Upload-Metadata", uploadMetadata(nil))
	// What a TLS-terminating proxy sends: the browser's host, over a plain
	// connection to this process.
	req.Host = "send.example"

	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d, want 201: %s", rec.Code, rec.Body.String())
	}

	location := rec.Header().Get("Location")
	if location == "" {
		t.Fatal("no Location header")
	}
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		t.Errorf("Location %q is absolute; it asserts a scheme this process cannot know", location)
	}
	if !strings.HasPrefix(location, "/api/uploads/") {
		t.Errorf("Location %q does not address the upload endpoint", location)
	}
	// And it still identifies the upload, which is the point of the header.
	if strings.TrimPrefix(location, "/api/uploads/") == "" {
		t.Errorf("Location %q names no upload", location)
	}
}

// A taken identifier is a client-side condition and must say so.
//
// The client generates the identifier (spec §3), so a collision means
// generating another and trying again. A 500 says the instance is broken and
// invites a retry of the same request, which cannot succeed, and puts an error
// in the operator's log for something that is not theirs.
//
// The existing tests assert the refusal at the store, so the status the
// protocol handler produced was never checked and had been 500 since the
// identifier moved to the client.
func TestADuplicateIdentifierIsAConflictAtTheHTTPSurface(t *testing.T) {
	h := newAPIHarness(t)
	meta := uploadMetadata(nil)

	first, _ := h.create(t, 100, meta)
	if first.Code != http.StatusCreated {
		t.Fatalf("first create: status %d, want 201: %s", first.Code, first.Body.String())
	}

	second, _ := h.create(t, 100, meta)
	if second.Code != http.StatusConflict {
		t.Errorf("second create: status %d, want 409 (%s)", second.Code, second.Body.String())
	}
	// And no upload was made: a conflict must not have written anything.
	if location := second.Header().Get("Location"); location != "" {
		t.Errorf("a refused creation named an upload at %q", location)
	}
}
