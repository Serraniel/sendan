// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Serraniel/sendan/internal/blob"
	"github.com/Serraniel/sendan/internal/logging"
	"github.com/Serraniel/sendan/internal/store"
	"github.com/Serraniel/sendan/internal/upload"
)

type apiHarness struct {
	handler http.Handler
	store   *store.SQLite
	clock   time.Time
}

// the identifier of a 16-byte value, per spec §10.
const testID = "AAAAAAAAAAAAAAAAAAAAAA"

func newAPIHarness(t *testing.T) *apiHarness {
	t.Helper()
	dir := t.TempDir()

	st, err := store.OpenSQLite(t.Context(), filepath.Join(dir, "sendan.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	fs, err := blob.NewFS(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatalf("open blobs: %v", err)
	}

	// Real time rather than an injected clock: the service's clock is
	// unexported, and adding production API so a test in another package can
	// reach it would be worse than expressing the fixtures relative to now.
	h := &apiHarness{store: st, clock: time.Now().UTC()}
	svc := upload.New(st, blob.NewShredder(fs), upload.Policy{
		DefaultTTL: 24 * time.Hour, MaxTTL: 7 * 24 * time.Hour,
	}, logging.New(io.Discard, logging.Options{Format: "json"}))

	h.handler = New(Options{Uploads: svc, BaseURL: mustURL(t, "https://sendan.example")})
	return h
}

// atRestKey is the value that must never appear in a response: it decrypts the
// blob, so disclosing it would make the ciphertext readable by the server's own
// storage backend, which is the one thing crypto-shredding exists to prevent.
var atRestKey = bytes.Repeat([]byte{0x7E}, blob.AtRestKeySize)

func (h *apiHarness) put(t *testing.T, u *store.Upload) {
	t.Helper()
	if u.ID == "" {
		u.ID = testID
	}
	if u.WrappedFileKey == nil {
		u.WrappedFileKey = bytes.Repeat([]byte{0x01}, 48)
	}
	if u.WrapNonce == nil {
		u.WrapNonce = bytes.Repeat([]byte{0x02}, 12)
	}
	if u.MetadataEnvelope == nil {
		u.MetadataEnvelope = bytes.Repeat([]byte{0x03}, 256)
	}
	if u.MetadataNonce == nil {
		u.MetadataNonce = bytes.Repeat([]byte{0x04}, 12)
	}
	if u.AuthTokenHash == nil {
		u.AuthTokenHash = bytes.Repeat([]byte{0x05}, 32)
	}
	if u.OwnerTokenHash == nil {
		u.OwnerTokenHash = bytes.Repeat([]byte{0x06}, 32)
	}
	if u.AtRestKey == nil {
		u.AtRestKey = atRestKey
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = h.clock
	}
	if u.ExpiresAt.IsZero() {
		u.ExpiresAt = h.clock.Add(time.Hour)
	}
	if err := h.store.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
}

func (h *apiHarness) get(t *testing.T, path string) (*httptest.ResponseRecorder, metadataResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

	var m metadataResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("decode: %v\nbody: %s", err, rec.Body.String())
		}
	}
	return rec, m
}

func TestMetadataReturnsTheCiphertext(t *testing.T) {
	h := newAPIHarness(t)
	h.put(t, &store.Upload{})

	rec, m := h.get(t, "/api/uploads/"+testID+"/metadata")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}

	enc := base64.RawURLEncoding.EncodeToString
	if m.ID != testID {
		t.Errorf("id %q", m.ID)
	}
	if m.WrappedFileKey != enc(bytes.Repeat([]byte{0x01}, 48)) {
		t.Errorf("wrappedFileKey %q", m.WrappedFileKey)
	}
	if m.MetadataEnvelope != enc(bytes.Repeat([]byte{0x03}, 256)) {
		t.Errorf("metadataEnvelope %q", m.MetadataEnvelope)
	}
	if m.PasswordRequired {
		t.Error("passwordRequired is set on an upload without a password")
	}
	if m.KDF != nil {
		t.Errorf("kdf present without a password: %+v", m.KDF)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", got)
	}
}

// The at-rest key decrypts the blob and the token hashes verify credentials.
// None may ever cross this boundary. This asserts on the raw body rather than
// the decoded struct, because a field added to the response type would be
// invisible to a decode into the type it was added to.
func TestMetadataNeverDisclosesServerSecrets(t *testing.T) {
	h := newAPIHarness(t)
	h.put(t, &store.Upload{
		AtRestKey:      atRestKey,
		AuthTokenHash:  bytes.Repeat([]byte{0xA1}, 32),
		OwnerTokenHash: bytes.Repeat([]byte{0xB2}, 32),
		Size:           1234567,
	})

	rec, _ := h.get(t, "/api/uploads/"+testID+"/metadata")
	body := rec.Body.String()

	forbidden := map[string][]byte{
		"the at-rest key":      atRestKey,
		"the auth token hash":  bytes.Repeat([]byte{0xA1}, 32),
		"the owner token hash": bytes.Repeat([]byte{0xB2}, 32),
	}
	for what, secret := range forbidden {
		for encoding, encoded := range map[string]string{
			"base64url": base64.RawURLEncoding.EncodeToString(secret),
			"base64":    base64.StdEncoding.EncodeToString(secret),
			"hex":       hexOf(secret),
		} {
			if strings.Contains(body, encoded) {
				t.Errorf("%s appears in the response as %s:\n%s", what, encoding, body)
			}
		}
	}

	// The server knows the stored ciphertext length. Reporting it would give the
	// file's size to anyone holding an identifier, which is what the metadata
	// envelope's padding exists to prevent.
	if strings.Contains(body, "1234567") {
		t.Errorf("the stored size appears in the response:\n%s", body)
	}
	for _, field := range []string{"atRestKey", "authTokenHash", "ownerTokenHash", "size", "Size"} {
		if strings.Contains(body, field) {
			t.Errorf("the response names %q:\n%s", field, body)
		}
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

// A password-protected upload must publish its derivation parameters: a client
// cannot compute anything without them (spec §9). They disclose only that a
// password exists, because the password hash is combined with the link secret,
// which never reaches the server.
func TestMetadataPublishesKDFParametersWhenAPasswordIsSet(t *testing.T) {
	h := newAPIHarness(t)
	salt := bytes.Repeat([]byte{0x5A}, 16)
	h.put(t, &store.Upload{
		Password: &store.PasswordParams{
			Salt: salt, MemoryKiB: 65536, Iterations: 3, Parallelism: 1,
		},
	})

	_, m := h.get(t, "/api/uploads/"+testID+"/metadata")
	if !m.PasswordRequired {
		t.Fatal("passwordRequired is not set")
	}
	if m.KDF == nil {
		t.Fatal("the derivation parameters are missing, so no client can derive a key")
	}
	if m.KDF.Salt != base64.RawURLEncoding.EncodeToString(salt) {
		t.Errorf("salt %q", m.KDF.Salt)
	}
	if m.KDF.MemoryKiB != 65536 || m.KDF.Iterations != 3 || m.KDF.Parallelism != 1 {
		t.Errorf("parameters %+v", m.KDF)
	}
}

// Reading metadata must not consume the download allowance. A chat client
// generating a link preview, or a recipient checking a filename, would
// otherwise exhaust a limited upload before anyone fetched the content.
func TestMetadataDoesNotClaimADownload(t *testing.T) {
	h := newAPIHarness(t)
	h.put(t, &store.Upload{MaxDownloads: 3})

	for range 5 {
		if rec, _ := h.get(t, "/api/uploads/"+testID+"/metadata"); rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
	}

	u, err := h.store.Get(context.Background(), testID, h.clock)
	if err != nil {
		t.Fatalf("the upload is gone after five metadata reads: %v", err)
	}
	if u.DownloadCount != 0 {
		t.Errorf("download count is %d after five metadata reads, want 0", u.DownloadCount)
	}
}

func TestMetadataReportsRemainingDownloads(t *testing.T) {
	h := newAPIHarness(t)
	h.put(t, &store.Upload{MaxDownloads: 3, DownloadCount: 2})

	_, m := h.get(t, "/api/uploads/"+testID+"/metadata")
	if m.DownloadsRemaining == nil {
		t.Fatal("downloadsRemaining is absent on a limited upload")
	}
	if *m.DownloadsRemaining != 1 {
		t.Errorf("downloadsRemaining %d, want 1", *m.DownloadsRemaining)
	}
}

func TestMetadataOmitsLimitsThatDoNotApply(t *testing.T) {
	h := newAPIHarness(t)
	h.put(t, &store.Upload{MaxDownloads: 0})

	rec, m := h.get(t, "/api/uploads/"+testID+"/metadata")
	if m.DownloadsRemaining != nil {
		t.Errorf("downloadsRemaining %d on an unlimited upload", *m.DownloadsRemaining)
	}
	if strings.Contains(rec.Body.String(), "downloadsRemaining") {
		t.Errorf("the field is present rather than omitted:\n%s", rec.Body.String())
	}
}

// Expired, exhausted, revoked and never-existed must be one answer. Any
// difference reports on an upload the caller is not entitled to know about -
// including confirming that a link which has since expired once existed.
func TestUnavailableUploadsAreIndistinguishable(t *testing.T) {
	const otherID = "BBBBBBBBBBBBBBBBBBBBBB"

	tests := []struct {
		name  string
		setup func(t *testing.T, h *apiHarness)
		path  string
	}{
		{
			name:  "never existed",
			setup: func(*testing.T, *apiHarness) {},
			path:  "/api/uploads/" + testID + "/metadata",
		},
		{
			name: "expired",
			setup: func(t *testing.T, h *apiHarness) {
				h.put(t, &store.Upload{ExpiresAt: h.clock.Add(-time.Hour)})
			},
			path: "/api/uploads/" + testID + "/metadata",
		},
		{
			name: "exhausted",
			setup: func(t *testing.T, h *apiHarness) {
				h.put(t, &store.Upload{MaxDownloads: 2, DownloadCount: 2})
			},
			path: "/api/uploads/" + testID + "/metadata",
		},
		{
			name: "a well-formed identifier that names nothing",
			setup: func(t *testing.T, h *apiHarness) {
				h.put(t, &store.Upload{})
			},
			path: "/api/uploads/" + otherID + "/metadata",
		},
		{
			name:  "a malformed identifier",
			setup: func(*testing.T, *apiHarness) {},
			path:  "/api/uploads/not-an-identifier/metadata",
		},
		{
			name:  "an identifier of the right length that is not base64url",
			setup: func(*testing.T, *apiHarness) {},
			path:  "/api/uploads/!!!!!!!!!!!!!!!!!!!!!!/metadata",
		},
	}

	var bodies []string
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newAPIHarness(t)
			tc.setup(t, h)

			rec, _ := h.get(t, tc.path)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status %d, want 404: %s", rec.Code, rec.Body.String())
			}
			// A cached negative answer could go on reporting an upload as gone.
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control %q on a 404, want no-store", got)
			}
			bodies = append(bodies, rec.Body.String())
		})
	}

	for i, b := range bodies {
		if b != bodies[0] {
			t.Errorf("case %d answers differently from the first:\n%q\n%q", i, b, bodies[0])
		}
	}
}

func TestMetadataRejectsOtherMethods(t *testing.T) {
	h := newAPIHarness(t)
	h.put(t, &store.Upload{})

	for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPut} {
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, httptest.NewRequest(method, "/api/uploads/"+testID+"/metadata", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d, want 405", method, rec.Code)
		}
	}
}

// The route is registered only when the service is present, so an instance
// without one answers 404 rather than reaching a handler with nothing behind it.
func TestMetadataRouteIsAbsentWithoutAService(t *testing.T) {
	rec := httptest.NewRecorder()
	New(Options{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/uploads/"+testID+"/metadata", nil))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", rec.Code)
	}
}

func TestMetadataCarriesTheSecurityHeaders(t *testing.T) {
	h := newAPIHarness(t)
	h.put(t, &store.Upload{})

	rec, _ := h.get(t, "/api/uploads/"+testID+"/metadata")
	for name, want := range requiredHeaders {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestValidID(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{testID, true},
		{"", false},
		{"short", false},
		{strings.Repeat("A", 21), false},
		{strings.Repeat("A", 23), false},
		{"!!!!!!!!!!!!!!!!!!!!!!", false},
		{"AAAAAAAAAAAAAAAAAAAA==", false},  // padded base64 is not the encoding
		{"AAAAAAAAAAAAAAAAAAAA+/", false},  // standard alphabet, not URL-safe
		{strings.Repeat("A", 4096), false}, // rejected on length, before decoding
	}
	for _, tc := range tests {
		if got := validID(tc.id); got != tc.want {
			t.Errorf("validID(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
}

// failingStore fails every read, standing in for a database that has gone away.
type failingStore struct {
	store.Store
}

func (failingStore) Get(context.Context, string, time.Time) (*store.Upload, error) {
	return nil, errors.New("connection refused: postgres://sendan:hunter2@db.internal:5432")
}

// A backend failure must not become a 404, which would tell a caller their link
// is dead when it is not, and must not put the backend's error in the response:
// that error names hosts, credentials and drivers.
func TestBackendFailureIsNotReportedAsMissing(t *testing.T) {
	var logBuf bytes.Buffer
	slog.SetDefault(logging.New(&logBuf, logging.Options{Format: "json"}))
	t.Cleanup(func() { slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil))) })

	svc := upload.New(failingStore{}, nil, upload.Policy{DefaultTTL: time.Hour},
		logging.New(io.Discard, logging.Options{Format: "json"}))
	handler := New(Options{Uploads: svc})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/uploads/"+testID+"/metadata", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	for _, leak := range []string{"postgres", "hunter2", "db.internal", "5432", "connection refused"} {
		if strings.Contains(body, leak) {
			t.Errorf("the response discloses %q from the backend error:\n%s", leak, body)
		}
	}

	// The operator still needs the detail, so it goes to the log instead.
	if !strings.Contains(logBuf.String(), "connection refused") {
		t.Errorf("the fault was not logged, so an operator would not see it:\n%s", logBuf.String())
	}

	// The request path carries the upload identifier. Logging it verbatim would
	// turn a leaked log into a list of downloadable files, which is the
	// guarantee internal/logging exists to keep.
	if strings.Contains(logBuf.String(), testID) {
		t.Errorf("the upload identifier was logged verbatim:\n%s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), `"route"`) {
		t.Errorf("the route pattern was not logged, so an operator cannot tell what failed:\n%s", logBuf.String())
	}
}

// A caller-controlled path in a log entry lets a caller forge log entries. The
// route pattern is a constant registered by this package, so a request cannot
// influence it - asserted here with a path built to break a line-oriented log.
func TestRequestPathCannotForgeLogEntries(t *testing.T) {
	var logBuf bytes.Buffer
	slog.SetDefault(logging.New(&logBuf, logging.Options{Format: "text"}))
	t.Cleanup(func() { slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil))) })

	svc := upload.New(failingStore{}, nil, upload.Policy{DefaultTTL: time.Hour},
		logging.New(io.Discard, logging.Options{Format: "json"}))
	handler := New(Options{Uploads: svc})

	// A 22-character identifier that is also an attempt at a second log line.
	forged := "AAAA\nlevel=INFO msg=ok"
	req := httptest.NewRequest(http.MethodGet, "/api/uploads/x/metadata", nil)
	req.SetPathValue("id", forged)
	req.URL.Path = "/api/uploads/" + forged + "/metadata"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if strings.Contains(logBuf.String(), "level=INFO msg=ok\n") {
		t.Errorf("a request forged a log entry:\n%s", logBuf.String())
	}
}

// An exhausted upload is unreachable through the handler, because liveness is
// evaluated on read and store.Get refuses it. The clamp therefore guards a
// state the invariant already prevents - which is exactly why it is tested
// here, directly: defensive code that no test exercises is code that will be
// wrong on the day the invariant it defends stops holding.
//
// A negative count published to a client would render as "-1 downloads
// remaining", which reads as a bug in the client rather than in the server.
func TestDownloadsRemainingNeverGoesNegative(t *testing.T) {
	res := newMetadataResponse(&upload.PublicMetadata{
		ID:            testID,
		MaxDownloads:  3,
		DownloadCount: 5,
	})

	if res.DownloadsRemaining == nil {
		t.Fatal("downloadsRemaining is absent on a limited upload")
	}
	if *res.DownloadsRemaining != 0 {
		t.Errorf("downloadsRemaining %d, want 0", *res.DownloadsRemaining)
	}
}
