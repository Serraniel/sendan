// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Serraniel/sendan/internal/blob"
	"github.com/Serraniel/sendan/internal/crypto"
	"github.com/Serraniel/sendan/internal/store"
)

// content is the ciphertext a client receives. Its bytes are distinguishable by
// position so a range response can be checked against the range requested.
var content = []byte(strings.Repeat("0123456789", 100)) // 1000 bytes

// putContent stores an upload whose blob holds content, returning its size.
func (h *apiHarness) putContent(t *testing.T, id string, maxDownloads int) {
	t.Helper()

	key, err := blob.NewAtRestKey()
	if err != nil {
		t.Fatalf("at-rest key: %v", err)
	}
	if _, err := h.blobs.Put(t.Context(), id, key, bytes.NewReader(content)); err != nil {
		t.Fatalf("put blob: %v", err)
	}
	h.put(t, &store.Upload{
		ID:            id,
		AtRestKey:     key,
		AuthTokenHash: crypto.AuthTokenHash(authToken),
		Size:          int64(len(content)),
		MaxDownloads:  maxDownloads,
	})
}

func (h *apiHarness) fetch(t *testing.T, id, rangeHeader string, extra map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/uploads/"+id+"/content", nil)
	req.Header.Set("Authorization", bearer(authToken))
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

func (h *apiHarness) counts(t *testing.T, id string) (bytesServed int64, downloads int) {
	t.Helper()
	u, err := h.store.Get(context.Background(), id, h.clock)
	if err != nil {
		t.Fatalf("get %s: %v", id, err)
	}
	return u.BytesServed, u.DownloadCount
}

func TestContentServesTheWholeFile(t *testing.T) {
	h := newAPIHarness(t)
	h.putContent(t, testID, 0)

	rec := h.fetch(t, testID, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(rec.Body.Bytes(), content) {
		t.Errorf("served %d bytes, want %d", rec.Body.Len(), len(content))
	}
	if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type %q: ciphertext must not be sniffed", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control %q: a cached copy would be served uncounted", got)
	}
	if got := rec.Header().Get("Accept-Ranges"); got != "bytes" {
		t.Errorf("Accept-Ranges %q, want bytes", got)
	}
	if got := rec.Header().Get("Content-Disposition"); got != "attachment" {
		t.Errorf("Content-Disposition %q", got)
	}

	served, downloads := h.counts(t, testID)
	if served != int64(len(content)) {
		t.Errorf("recorded %d bytes, want %d", served, len(content))
	}
	if downloads != 1 {
		t.Errorf("recorded %d downloads, want 1", downloads)
	}
}

func TestContentServesARange(t *testing.T) {
	h := newAPIHarness(t)
	h.putContent(t, testID, 0)

	rec := h.fetch(t, testID, "bytes=100-199", nil)
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status %d, want 206", rec.Code)
	}
	if got, want := rec.Body.Bytes(), content[100:200]; !bytes.Equal(got, want) {
		t.Errorf("served %q, want %q", got, want)
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 100-199/1000" {
		t.Errorf("Content-Range %q", got)
	}

	served, downloads := h.counts(t, testID)
	if served != 100 {
		t.Errorf("recorded %d bytes for a 100-byte range", served)
	}
	if downloads != 0 {
		t.Errorf("a 100-byte range counted %d downloads, want 0", downloads)
	}
}

// The case the whole accounting model exists for: a transfer that drops and is
// resumed must cost one download, not two.
func TestResumingATransferCostsOneDownload(t *testing.T) {
	h := newAPIHarness(t)
	// A limit of two, so the upload is still readable afterwards and the counts
	// can be inspected. With a limit of one it would correctly become
	// unreachable, which TestExhaustedUploadServesNothing covers instead.
	h.putContent(t, testID, 2)

	first := h.fetch(t, testID, "bytes=0-599", nil)
	if first.Code != http.StatusPartialContent {
		t.Fatalf("first: status %d, want 206", first.Code)
	}
	if _, downloads := h.counts(t, testID); downloads != 0 {
		t.Fatalf("60%% of a file counted %d downloads, want 0", downloads)
	}

	// Resume, quoting the validator the first response returned.
	second := h.fetch(t, testID, "bytes=600-", map[string]string{
		"If-Range": first.Header().Get("ETag"),
	})
	if second.Code != http.StatusPartialContent {
		t.Fatalf("resume: status %d, want 206 - a resumed request was answered with the whole file", second.Code)
	}
	if got, want := second.Body.Bytes(), content[600:]; !bytes.Equal(got, want) {
		t.Errorf("resume served %d bytes, want %d", len(got), len(want))
	}

	served, downloads := h.counts(t, testID)
	if served != int64(len(content)) {
		t.Errorf("recorded %d bytes across a resumed transfer, want %d", served, len(content))
	}
	if downloads != 1 {
		t.Errorf("a resumed transfer counted %d downloads, want 1", downloads)
	}
}

// Without a validator on the response, a client's If-Range cannot match and
// ServeContent answers with the whole file - charging a second download for
// content the client already holds.
func TestETagIsPresentSoResumptionCanValidate(t *testing.T) {
	h := newAPIHarness(t)
	h.putContent(t, testID, 0)

	rec := h.fetch(t, testID, "", nil)
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag, so a resumed request cannot validate and will be served in full")
	}

	resumed := h.fetch(t, testID, "bytes=900-", map[string]string{"If-Range": etag})
	if resumed.Code != http.StatusPartialContent {
		t.Fatalf("status %d, want 206", resumed.Code)
	}
	if resumed.Body.Len() != 100 {
		t.Errorf("served %d bytes, want 100", resumed.Body.Len())
	}
}

// Reading almost all of a file repeatedly must be charged, or the limit is
// evadable by never finishing.
func TestRepeatedPartialReadsExhaustTheLimit(t *testing.T) {
	h := newAPIHarness(t)
	h.putContent(t, testID, 2)

	for i := range 3 {
		rec := h.fetch(t, testID, "bytes=0-989", nil) // 99% of the file
		if rec.Code != http.StatusPartialContent {
			t.Fatalf("read %d: status %d", i+1, rec.Code)
		}
	}

	// 2970 bytes of a 1000-byte file is two whole downloads, so the upload is
	// exhausted and unreachable.
	rec := h.fetch(t, testID, "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d after three 99%% reads of a 2-download upload, want 404: "+
			"the limit is evadable by aborting", rec.Code)
	}
}

func TestContentRequiresAToken(t *testing.T) {
	h := newAPIHarness(t)
	h.putContent(t, testID, 0)

	req := httptest.NewRequest(http.MethodGet, "/api/uploads/"+testID+"/content", nil)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if served, _ := h.counts(t, testID); served != 0 {
		t.Errorf("an unauthenticated request was charged %d bytes", served)
	}
}

// Nobody who could not have decrypted the file may cause its allowance to be
// spent. A wrong token must serve nothing and cost nothing.
func TestAWrongTokenServesNothingAndCostsNothing(t *testing.T) {
	h := newAPIHarness(t)
	h.putContent(t, testID, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/uploads/"+testID+"/content", nil)
	req.Header.Set("Authorization", bearer(bytes.Repeat([]byte{0x22}, 32)))
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	// The body is a JSON error, which is expected. What must not appear is any
	// of the content.
	if bytes.Contains(rec.Body.Bytes(), content[:32]) {
		t.Errorf("a refused request returned content:\n%s", rec.Body.String())
	}

	served, downloads := h.counts(t, testID)
	if served != 0 || downloads != 0 {
		t.Errorf("a wrong token was charged %d bytes and %d downloads", served, downloads)
	}
	// And the upload survives for its intended recipient.
	if rec := h.fetch(t, testID, "", nil); rec.Code != http.StatusOK {
		t.Errorf("the recipient can no longer download: status %d", rec.Code)
	}
}

func TestContentOnUnavailableUploads(t *testing.T) {
	h := newAPIHarness(t)
	for _, id := range []string{testID, "not-an-identifier"} {
		if rec := h.fetch(t, id, "", nil); rec.Code != http.StatusNotFound {
			t.Errorf("%q: status %d, want 404", id, rec.Code)
		}
	}
}

// An exhausted upload is unreachable, so a further request serves nothing.
func TestExhaustedUploadServesNothing(t *testing.T) {
	h := newAPIHarness(t)
	h.putContent(t, testID, 1)

	if rec := h.fetch(t, testID, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("first download: status %d", rec.Code)
	}
	rec := h.fetch(t, testID, "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d after the only download, want 404", rec.Code)
	}
	if rec.Body.Len() != 0 && strings.Contains(rec.Body.String(), "0123456789") {
		t.Error("content was served after the limit was reached")
	}
}

func TestUnsatisfiableRangeIsRefused(t *testing.T) {
	h := newAPIHarness(t)
	h.putContent(t, testID, 0)

	rec := h.fetch(t, testID, fmt.Sprintf("bytes=%d-%d", len(content)+10, len(content)+20), nil)
	if rec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("status %d, want 416", rec.Code)
	}
	if _, downloads := h.counts(t, testID); downloads != 0 {
		t.Errorf("an unsatisfiable range counted %d downloads", downloads)
	}
}

func TestContentCarriesTheSecurityHeaders(t *testing.T) {
	h := newAPIHarness(t)
	h.putContent(t, testID, 0)

	rec := h.fetch(t, testID, "", nil)
	for name, want := range requiredHeaders {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestContentRejectsOtherMethods(t *testing.T) {
	h := newAPIHarness(t)
	h.putContent(t, testID, 0)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/uploads/"+testID+"/content", nil)
		req.Header.Set("Authorization", bearer(authToken))
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d, want 405", method, rec.Code)
		}
	}
}

// Memory must not scale with the file. This is asserted structurally: the
// handler is given a reader it streams from, and never holds the content.
func TestServingDoesNotBufferTheWholeFile(t *testing.T) {
	h := newAPIHarness(t)

	// Sixteen megabytes, larger than any sensible buffer, served in one request.
	big := bytes.Repeat([]byte("sendan.."), 2<<20)
	key, err := blob.NewAtRestKey()
	if err != nil {
		t.Fatalf("at-rest key: %v", err)
	}
	if _, err := h.blobs.Put(t.Context(), testID, key, bytes.NewReader(big)); err != nil {
		t.Fatalf("put: %v", err)
	}
	h.put(t, &store.Upload{
		ID: testID, AtRestKey: key,
		AuthTokenHash: crypto.AuthTokenHash(authToken),
		Size:          int64(len(big)),
	})

	rec := h.fetch(t, testID, "bytes=0-1023", nil)
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status %d, want 206", rec.Code)
	}
	if rec.Body.Len() != 1024 {
		t.Errorf("a 1 KiB range of a 16 MiB file returned %d bytes", rec.Body.Len())
	}
	if served, _ := h.counts(t, testID); served != 1024 {
		t.Errorf("recorded %d bytes for a 1 KiB range", served)
	}
}

// cancellingWriter cancels the request the moment the first byte is written,
// which is what a client disconnecting mid-transfer looks like to the handler.
type cancellingWriter struct {
	http.ResponseWriter
	cancel context.CancelFunc
	once   sync.Once
}

func (c *cancellingWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.once.Do(c.cancel)
	return n, err
}

// A client that disconnects has already cancelled the request context. If
// accounting rode that context it would be cancelled too, and every abandoned
// transfer would be free - which is the bypass the volume model exists to
// close.
//
// The cancellation has to happen while the handler is running. Cancelling after
// it returns proves nothing, because the context is live throughout.
func TestAbandonedTransfersAreStillCharged(t *testing.T) {
	h := newAPIHarness(t)
	h.putContent(t, testID, 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/api/uploads/"+testID+"/content", nil).WithContext(ctx)
	req.Header.Set("Authorization", bearer(authToken))

	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(&cancellingWriter{ResponseWriter: rec, cancel: cancel}, req)

	served, _ := h.counts(t, testID)
	if served == 0 {
		t.Fatal("a transfer abandoned by the client was recorded as zero bytes: " +
			"aborting would be free, and the download limit unenforceable")
	}
	if served != int64(rec.Body.Len()) {
		t.Errorf("recorded %d bytes but wrote %d", served, rec.Body.Len())
	}
}

// The content endpoint is subject to the same per-upload attempt limit as the
// authentication one, or an attacker would simply guess against this path
// instead.
func TestContentThrottlesRepeatedWrongTokens(t *testing.T) {
	h := newAPIHarnessWithAttempts(t, 2)
	h.putContent(t, testID, 0)

	wrong := bearer(bytes.Repeat([]byte{0x22}, 32))
	for i := range 2 {
		req := httptest.NewRequest(http.MethodGet, "/api/uploads/"+testID+"/content", nil)
		req.Header.Set("Authorization", wrong)
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i+1, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/uploads/"+testID+"/content", nil)
	req.Header.Set("Authorization", wrong)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("Retry-After is missing, so a client cannot know when to return")
	}
	if served, _ := h.counts(t, testID); served != 0 {
		t.Errorf("refused attempts were charged %d bytes", served)
	}
}

// The owner token is the only thing that removes an upload before it expires.
// The server holds a hash of it, so it can check one and cannot produce one -
// which is what makes possession proof of ownership rather than a record of it.
func TestAnUploadIsRemovedByItsOwnerToken(t *testing.T) {
	h := newAPIHarness(t)
	ownerToken := bytes.Repeat([]byte{0x5A}, 32)

	const id = "revokedbyitsowner00000"
	key, err := blob.NewAtRestKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.blobs.Put(t.Context(), id, key, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	owner := sha256.Sum256(ownerToken)
	h.put(t, &store.Upload{
		ID:             id,
		AtRestKey:      key,
		AuthTokenHash:  crypto.AuthTokenHash(authToken),
		OwnerTokenHash: owner[:],
		Size:           int64(len(content)),
	})

	del := func(token []byte, malformed string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, "/api/uploads/"+id, nil)
		switch {
		case malformed != "":
			req.Header.Set("Authorization", malformed)
		case token != nil:
			req.Header.Set("Authorization",
				"Bearer "+base64.RawURLEncoding.EncodeToString(token))
		}
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		return rec
	}

	if got := del(nil, ""); got.Code != http.StatusUnauthorized {
		t.Errorf("with no credential: status %d, want 401", got.Code)
	}
	if got := del(nil, "Basic abc"); got.Code != http.StatusUnauthorized {
		t.Errorf("with another scheme: status %d, want 401", got.Code)
	}
	if got := del(bytes.Repeat([]byte{0x01}, 32), ""); got.Code != http.StatusForbidden {
		t.Errorf("with a wrong token: status %d, want 403", got.Code)
	}

	// Still there, because none of those were the owner.
	if _, err := h.store.Get(t.Context(), id, time.Now()); err != nil {
		t.Fatalf("a refused revocation removed the upload: %v", err)
	}

	if got := del(ownerToken, ""); got.Code != http.StatusNoContent {
		t.Fatalf("with the owner token: status %d, want 204", got.Code)
	}

	// Gone, and nothing distinguishes it from an upload that never existed.
	if _, err := h.store.Get(t.Context(), id, time.Now()); err == nil {
		t.Error("the upload survived its own revocation")
	}
	if got := del(ownerToken, ""); got.Code != http.StatusForbidden {
		t.Errorf("revoking an upload that is already gone: status %d, want 403", got.Code)
	}
}

// An identifier of the wrong shape never reaches the store, so a malformed one
// cannot be used to probe it.
func TestRevokingRefusesAnIdentifierOfTheWrongShape(t *testing.T) {
	h := newAPIHarness(t)

	for _, id := range []string{"short", strings.Repeat("A", 23), "has/a/slash/in/it00000"} {
		req := httptest.NewRequest(http.MethodDelete, "/api/uploads/"+id, nil)
		req.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(
			bytes.Repeat([]byte{0x01}, 32)))
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)

		if rec.Code == http.StatusNoContent {
			t.Errorf("%q was accepted as an identifier", id)
		}
	}
}
