// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package client_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/Serraniel/sendan/internal/client"
)

// answering serves one canned response to everything.
func answering(t *testing.T, status int, contentType, body string) *client.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return &client.Client{Origin: server.URL}
}

// What a person reads when something goes wrong.
//
// The API answers in JSON and the protocol handler in plain text, and a client
// that assumed either would show nothing for half of what can go wrong.
func TestARefusalIsReportedWithWhateverExplanationItCarried(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
		wants       string
	}{
		{"json from the API", 413, "application/json",
			`{"code":"too_large","message":"larger than this instance accepts"}`,
			"larger than this instance accepts"},
		{"text from the protocol handler", 400, "text/plain",
			"ERR_SIZE_REQUIRED: the total upload length must be declared up front",
			"must be declared up front"},
		{"nothing at all", 429, "", "", "429"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := answering(t, tc.status, tc.contentType, tc.body)

			_, err := c.Send(t.Context(), bytes.NewReader([]byte("x")), "a.bin", "", 1,
				client.UploadOptions{})
			if err == nil {
				t.Fatal("a refusal was accepted")
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("%v does not carry %q", err, tc.wants)
			}

			var apiErr *client.APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("%v is not an APIError", err)
			}
			if apiErr.Status != tc.status {
				t.Errorf("status %d, want %d", apiErr.Status, tc.status)
			}
		})
	}
}

func TestAnEmptyRefusalStillSaysWhatHappened(t *testing.T) {
	err := &client.APIError{Status: 502}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("%v does not name the status", err)
	}
}

// Invariant 3, at the client: truncated, reordered or modified ciphertext never
// yields plaintext. What the caller does with the bytes already written is its
// own problem - the command line writes to a temporary name for exactly this -
// but the call must fail.
func TestATamperedStreamFailsRatherThanYieldingAFile(t *testing.T) {
	c := anInstance(t)
	plaintext := filled(200_000)

	up, err := c.Send(t.Context(), bytes.NewReader(plaintext), "a.bin", "",
		int64(len(plaintext)), client.UploadOptions{})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	published, err := c.Describe(t.Context(), up.Link.ID())
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	opened, err := client.Open(up.Link, published, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	// The instance's own ciphertext, damaged on the way through.
	damaging := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get(c.Origin + r.URL.Path) //nolint:gosec,noctx // test proxy
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()

		body, _ := io.ReadAll(resp.Body)
		if len(body) > 200 {
			// A record removed: what remains is well formed and decrypts for a
			// while, so bytes reach the writer before the failure is detected.
			body = append(body[:21:21], body[21+65536:]...)
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	}))
	t.Cleanup(damaging.Close)

	var got bytes.Buffer
	through := &client.Client{Origin: damaging.URL}
	err = through.Fetch(t.Context(), up.Link.ID(), opened, &got)
	if err == nil {
		t.Fatal("a damaged stream produced a file")
	}
	if int64(got.Len()) == opened.File.Size {
		t.Error("the whole file came back from a stream that was damaged")
	}
}

// The envelope is authenticated and states the size, so content that does not
// match it means the instance served something other than what was sealed.
func TestContentThatDisagreesWithTheEnvelopeIsRefused(t *testing.T) {
	c := anInstance(t)
	plaintext := filled(5000)

	up, err := c.Send(t.Context(), bytes.NewReader(plaintext), "a.bin", "",
		int64(len(plaintext)), client.UploadOptions{})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	published, err := c.Describe(t.Context(), up.Link.ID())
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	opened, err := client.Open(up.Link, published, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	// Serving a *different* upload's content under this identifier: it decrypts
	// to nothing useful, which is what the size check is the last line against.
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(empty.Close)

	through := &client.Client{Origin: empty.URL}
	if err := through.Fetch(t.Context(), up.Link.ID(), opened, io.Discard); err == nil {
		t.Error("an empty body satisfied a request for a 5000 byte file")
	}
}

func TestAnUnreadableDescriptionIsReportedAsSuch(t *testing.T) {
	c := answering(t, http.StatusOK, "application/json", "{not json")

	if _, err := c.Describe(t.Context(), "AAAAAAAAAAAAAAAAAAAAAA"); err == nil {
		t.Error("unreadable JSON was accepted")
	}
}

// passwordRequired without parameters is an upload nobody could ever open, so
// it is refused rather than producing keys from defaults that never sealed it.
func TestAProtectedUploadWithoutParametersIsRefused(t *testing.T) {
	c := answering(t, http.StatusOK, "application/json", `{
		"id":"AAAAAAAAAAAAAAAAAAAAAA",
		"wrappedFileKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"wrapNonce":"AAAAAAAAAAAAAAAA",
		"metadataEnvelope":"AAAAAAAAAAAAAAAA",
		"metadataNonce":"AAAAAAAAAAAAAAAA",
		"passwordRequired":true
	}`)

	if _, err := c.Describe(t.Context(), "AAAAAAAAAAAAAAAAAAAAAA"); err == nil {
		t.Error("an upload that says it needs a password but gives no parameters was accepted")
	}
}

func TestAValueThatIsNotBase64UrlIsRefused(t *testing.T) {
	c := answering(t, http.StatusOK, "application/json",
		`{"id":"x","wrappedFileKey":"not base64!","wrapNonce":"AAAA",
		  "metadataEnvelope":"AAAA","metadataNonce":"AAAA","passwordRequired":false}`)

	if _, err := c.Describe(t.Context(), "AAAAAAAAAAAAAAAAAAAAAA"); err == nil {
		t.Error("a value that is not base64url was accepted")
	}
}

// An instance that cannot be reached is not an instance that refused, and the
// difference is what tells somebody whether to check their network or the link.
func TestAnUnreachableInstanceIsReportedAsUnreachable(t *testing.T) {
	// A port nothing is listening on.
	c := &client.Client{Origin: "http://127.0.0.1:1"}

	_, err := c.Describe(t.Context(), "AAAAAAAAAAAAAAAAAAAAAA")
	if err == nil {
		t.Fatal("an unreachable instance was accepted")
	}
	if errors.Is(err, client.ErrUnavailable) {
		t.Error("an unreachable instance was reported as an unavailable upload")
	}
}

// A source that fails part way through must not leave an upload behind.
//
// The unmeasurable path encodes before it declares, so a read failure happens
// before anything has been created - which is the good order for this to fail
// in, and is worth pinning because reordering it would leave incomplete rows
// for the reaper.
func TestASourceThatFailsLeavesNothingBehind(t *testing.T) {
	c := anInstance(t)

	failing := io.MultiReader(
		bytes.NewReader(filled(50_000)),
		iotest.ErrReader(errors.New("the disk went away")),
	)

	_, err := c.Send(t.Context(), failing, "doomed.bin", "", -1, client.UploadOptions{})
	if err == nil {
		t.Fatal("a source that failed produced an upload")
	}
	if !strings.Contains(err.Error(), "the disk went away") {
		t.Errorf("%v does not say what actually went wrong", err)
	}
}

// The same for a measurable source, where encoding happens as it is sent and so
// the failure arrives with the upload already created.
func TestAMeasurableSourceThatFailsIsReported(t *testing.T) {
	c := anInstance(t)

	failing := io.MultiReader(
		bytes.NewReader(filled(1000)),
		iotest.ErrReader(errors.New("read error")),
	)

	// Declares more than the reader will yield.
	if _, err := c.Send(t.Context(), failing, "doomed.bin", "", 50_000,
		client.UploadOptions{}); err == nil {
		t.Fatal("a source that failed produced an upload")
	}
}
