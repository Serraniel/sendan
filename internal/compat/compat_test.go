// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package compat_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Serraniel/sendan/internal/blob"
	"github.com/Serraniel/sendan/internal/compat"
	"github.com/Serraniel/sendan/internal/store"
	"github.com/Serraniel/sendan/internal/upload"
)

// harness is an instance with the compatibility protocol enabled, over a real
// SQLite database and a real blob store.
type harness struct {
	t      *testing.T
	server *httptest.Server
	store  store.CompatStore
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	dir := t.TempDir()
	metadata, err := store.OpenSQLite(t.Context(), filepath.Join(dir, "sendan.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = metadata.Close() })

	blobs, err := blob.Open(t.Context(), "file:"+filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatalf("blobs: %v", err)
	}

	uploads := upload.New(metadata, blob.NewShredder(blobs), upload.Policy{
		DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour, IncompleteTTL: time.Hour,
	}, slog.New(slog.DiscardHandler))

	h := &harness{t: t, store: metadata}
	h.server = httptest.NewServer(compat.New(compat.Options{
		Store:    metadata,
		Uploads:  uploads,
		Metadata: metadata,
		Blobs:    blob.NewShredder(blobs),
		BaseURL:  mustURL(t, "http://example.test"),
		Log:      slog.New(slog.DiscardHandler),
	}))
	t.Cleanup(h.server.Close)
	return h
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// upload performs the protocol's WebSocket upload and returns the identifier
// and the authentication key it was given.
func (h *harness) upload(content []byte, dlimit int) (string, []byte) {
	h.t.Helper()

	authKey := make([]byte, 32)
	if _, err := rand.Read(authKey); err != nil {
		h.t.Fatal(err)
	}

	wsURL := "ws" + strings.TrimPrefix(h.server.URL, "http") + "/api/ws"
	conn, res, err := websocket.Dial(h.t.Context(), wsURL, nil)
	if err != nil {
		h.t.Fatalf("dial: %v", err)
	}
	if res != nil && res.Body != nil {
		_ = res.Body.Close()
	}
	defer func() { _ = conn.CloseNow() }()

	header, _ := json.Marshal(map[string]any{
		"fileMetadata":  b64([]byte("an envelope in the other format")),
		"authorization": "send-v1 " + b64(authKey),
		"timeLimit":     3600,
		"dlimit":        dlimit,
	})
	if err := conn.Write(h.t.Context(), websocket.MessageText, header); err != nil {
		h.t.Fatalf("header: %v", err)
	}

	_, reply, err := conn.Read(h.t.Context())
	if err != nil {
		h.t.Fatalf("reply: %v", err)
	}
	var created struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(reply, &created); err != nil {
		h.t.Fatalf("reply is not the created upload: %v (%s)", err, reply)
	}

	if err := conn.Write(h.t.Context(), websocket.MessageBinary, content); err != nil {
		h.t.Fatalf("body: %v", err)
	}
	// One zero byte ends the stream.
	if err := conn.Write(h.t.Context(), websocket.MessageBinary, []byte{0x00}); err != nil {
		h.t.Fatalf("terminator: %v", err)
	}

	_, done, err := conn.Read(h.t.Context())
	if err != nil {
		h.t.Fatalf("completion: %v", err)
	}
	if !bytes.Contains(done, []byte(`"ok":true`)) {
		h.t.Fatalf("the upload did not complete: %s", done)
	}
	return created.ID, authKey
}

// nonce reads the value the server wants signed next.
func (h *harness) nonce(id string) []byte {
	h.t.Helper()
	nonce, ok := h.tryNonce(id)
	if !ok {
		h.t.Fatal("the server offered no nonce")
	}
	return nonce
}

// tryNonce is nonce for cases where the upload may already be gone. An upload
// that has expired or run out of downloads answers 404 and offers nothing,
// which is the correct behaviour and not a failure to test around.
func (h *harness) tryNonce(id string) ([]byte, bool) {
	h.t.Helper()
	res, err := http.Get(h.server.URL + "/download/" + id + "/")
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()

	header := res.Header.Get("WWW-Authenticate")
	if res.StatusCode != http.StatusOK || header == "" {
		return nil, false
	}
	return decodeNonce(h.t, header), true
}

// download attempts one transfer and reports the status. An upload that is no
// longer reachable offers no nonce, which counts as refused.
func (h *harness) download(id string, authKey []byte) int {
	h.t.Helper()
	nonce, ok := h.tryNonce(id)
	if !ok {
		return http.StatusNotFound
	}
	res := h.get("/api/download/"+id, sign(authKey, nonce))
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, res.Body)
	return res.StatusCode
}

func decodeNonce(t *testing.T, header string) []byte {
	t.Helper()
	_, value, found := strings.Cut(header, " ")
	if !found {
		t.Fatalf("no nonce in %q", header)
	}
	n, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		t.Fatalf("nonce %q: %v", value, err)
	}
	return n
}

func sign(authKey, nonce []byte) string {
	mac := hmac.New(sha256.New, authKey)
	mac.Write(nonce)
	return "send-v1 " + b64(mac.Sum(nil))
}

func (h *harness) get(path, authorization string) *http.Response {
	h.t.Helper()
	req, err := http.NewRequestWithContext(h.t.Context(), http.MethodGet, h.server.URL+path, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return res
}

// The whole protocol, end to end, without a third-party client involved.
func TestAnUploadCanBeDownloadedAgain(t *testing.T) {
	h := newHarness(t)
	content := bytes.Repeat([]byte("ciphertext"), 5000)

	id, authKey := h.upload(content, 3)

	res := h.get("/api/download/"+id, sign(authKey, h.nonce(id)))
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("download: status %d", res.StatusCode)
	}

	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Error("what came back is not what went in")
	}
}

// The nonce moves on every success, so an Authorization header that is captured
// does not work a second time. This is the whole of the replay protection.
func TestAnAuthenticatorWorksOnlyOnce(t *testing.T) {
	h := newHarness(t)
	id, authKey := h.upload([]byte("ciphertext"), 5)

	authorization := sign(authKey, h.nonce(id))

	first := h.get("/api/metadata/"+id, authorization)
	_ = first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first request: status %d", first.StatusCode)
	}

	second := h.get("/api/metadata/"+id, authorization)
	_ = second.Body.Close()
	if second.StatusCode != http.StatusUnauthorized {
		t.Errorf("the same authenticator worked twice: status %d", second.StatusCode)
	}
}

func TestAWrongSignatureIsRefused(t *testing.T) {
	h := newHarness(t)
	id, _ := h.upload([]byte("ciphertext"), 5)

	wrong := make([]byte, 32)
	res := h.get("/api/metadata/"+id, sign(wrong, h.nonce(id)))
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", res.StatusCode)
	}

	// And the refusal still says which nonce to sign, or a client that has just
	// been told no can never try again.
	if res.Header.Get("WWW-Authenticate") == "" {
		t.Error("a refusal carried no nonce")
	}
}

// A client that omits the limit is expecting the protocol's default of one
// download, not an unlimited upload. Getting this wrong turns a single-use link
// into a permanent one, silently.
func TestAnUploadWithNoStatedLimitIsServedOnce(t *testing.T) {
	h := newHarness(t)
	id, authKey := h.upload([]byte("ciphertext"), 0)

	if status := h.download(id, authKey); status != http.StatusOK {
		t.Fatalf("first download: status %d", status)
	}
	if status := h.download(id, authKey); status == http.StatusOK {
		t.Error("an upload with no stated limit was served twice")
	}
}

func TestTheStatedLimitIsHonoured(t *testing.T) {
	h := newHarness(t)
	id, authKey := h.upload([]byte("ciphertext"), 2)

	for i := 1; i <= 2; i++ {
		if status := h.download(id, authKey); status != http.StatusOK {
			t.Fatalf("download %d: status %d", i, status)
		}
	}
	if status := h.download(id, authKey); status == http.StatusOK {
		t.Error("a third download was served for a limit of two")
	}
}

// Content is never served to somebody who cannot authenticate, whichever
// credential they are missing.
func TestContentIsNotServedWithoutACredential(t *testing.T) {
	h := newHarness(t)
	id, _ := h.upload([]byte("ciphertext"), 5)

	for name, authorization := range map[string]string{
		"none":           "",
		"a bearer token": "Bearer " + b64([]byte("not the token")),
		"another scheme": "Basic " + b64([]byte("user:pass")),
	} {
		t.Run(name, func(t *testing.T) {
			res := h.get("/api/download/"+id, authorization)
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				t.Error("content was served without a credential")
			}
		})
	}
}

// Before authentication a client learns only that the upload is there and
// whether it is protected, which is what it needs to decide whether to prompt.
func TestExistsDisclosesOnlyWhatAClientNeeds(t *testing.T) {
	h := newHarness(t)
	id, _ := h.upload([]byte("ciphertext"), 5)

	res := h.get("/api/exists/"+id, "")
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["requiresPassword"]; !ok {
		t.Error("a client cannot tell whether to prompt for a password")
	}
	for _, leak := range []string{"metadata", "auth", "authKey", "ownerToken", "size"} {
		if _, found := body[leak]; found {
			t.Errorf("the unauthenticated response discloses %q", leak)
		}
	}
}

func TestAnUnknownUploadIsNotFound(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{
		"/api/exists/0123456789abcdef",
		"/api/metadata/0123456789abcdef",
		"/api/download/0123456789abcdef",
		"/download/0123456789abcdef/",
	} {
		res := h.get(path, "")
		_ = res.Body.Close()
		if res.StatusCode == http.StatusOK {
			t.Errorf("%s answered 200 for an upload that does not exist", path)
		}
	}
}

// The version endpoint is what a client uses to decide which generation of the
// protocol to speak, and everything else fails if it is absent.
func TestTheVersionEndpointIdentifiesTheProtocol(t *testing.T) {
	h := newHarness(t)

	res := h.get("/__version__", "")
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}

	var body struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body.Version, "3.") {
		t.Errorf("version %q does not identify the generation clients expect", body.Version)
	}
}

// An upload that never finishes must leave nothing behind: no row, no blob, no
// at-rest key.
func TestAnAbandonedUploadIsDiscarded(t *testing.T) {
	h := newHarness(t)

	wsURL := "ws" + strings.TrimPrefix(h.server.URL, "http") + "/api/ws"
	conn, res, err := websocket.Dial(t.Context(), wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if res != nil && res.Body != nil {
		_ = res.Body.Close()
	}

	authKey := make([]byte, 32)
	header, _ := json.Marshal(map[string]any{
		"fileMetadata":  b64([]byte("envelope")),
		"authorization": "send-v1 " + b64(authKey),
		"timeLimit":     3600,
		"dlimit":        1,
	})
	if err := conn.Write(t.Context(), websocket.MessageText, header); err != nil {
		t.Fatal(err)
	}

	_, reply, err := conn.Read(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(reply, &created); err != nil {
		t.Fatal(err)
	}

	// Some content, then the connection drops without the terminator.
	_ = conn.Write(t.Context(), websocket.MessageBinary, []byte("half a file"))
	_ = conn.CloseNow()

	// The handler cleans up on its own; give it a moment to notice.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := h.store.Compat(context.Background(), created.ID); err != nil {
			return // gone, which is the point
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("an abandoned upload was left behind")
}

// An upload made through this protocol always carries a download limit, so it
// can never be the unbounded kind an instance may refuse. The limit is applied
// here rather than assumed, because that assumption is one function away from
// being false.
func TestACompatUploadIsAlwaysBounded(t *testing.T) {
	h := newHarness(t)

	// No limit asked for, and the protocol's default applies.
	id, authKey := h.upload([]byte("ciphertext"), 0)

	if status := h.download(id, authKey); status != http.StatusOK {
		t.Fatalf("first download: status %d", status)
	}
	if status := h.download(id, authKey); status == http.StatusOK {
		t.Error("an upload with no stated limit was served more than once")
	}
}
