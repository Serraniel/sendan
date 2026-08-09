// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package client_test

import (
	"bytes"
	"errors"
	"io"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Serraniel/sendan/internal/blob"
	"github.com/Serraniel/sendan/internal/client"
	"github.com/Serraniel/sendan/internal/crypto"
	"github.com/Serraniel/sendan/internal/httpapi"
	"github.com/Serraniel/sendan/internal/logging"
	"github.com/Serraniel/sendan/internal/store"
	"github.com/Serraniel/sendan/internal/upload"
)

// anInstance starts the real server, in process.
//
// Not a fake. The client's whole job is to satisfy an instance, and a double
// would only ever assert what this package already believes - which is how a
// client that no server accepts passes its own tests.
func anInstance(t *testing.T) *client.Client {
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

	svc := upload.New(st, blob.NewShredder(fs), upload.Policy{
		DefaultTTL: 24 * time.Hour, MaxTTL: 7 * 24 * time.Hour,
	}, logging.New(io.Discard, logging.Options{Format: "json"}))

	base, err := url.Parse("http://sendan.example")
	if err != nil {
		t.Fatalf("base url: %v", err)
	}
	server := httptest.NewServer(httpapi.New(httpapi.Options{Uploads: svc, BaseURL: base}))
	t.Cleanup(server.Close)

	return &client.Client{Origin: server.URL}
}

func filled(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*31 + 7) % 256)
	}
	return b
}

// The round trip, against the real server, with nothing carried between the two
// halves but the link.
func TestSendAndFetch(t *testing.T) {
	c := anInstance(t)
	plaintext := filled(300_000)

	up, err := c.Send(t.Context(), bytes.NewReader(plaintext),
		"report.pdf", "application/pdf", int64(len(plaintext)), client.UploadOptions{})
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	// From here, only the link.
	link, err := client.ParseLink(up.Link.String())
	if err != nil {
		t.Fatalf("parse link: %v", err)
	}

	published, err := c.Describe(t.Context(), link.ID())
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if published.PasswordRequired {
		t.Error("an upload with no password says one is required")
	}

	opened, err := client.Open(link, published, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if opened.File.Name != "report.pdf" || opened.File.Type != "application/pdf" {
		t.Errorf("envelope says %q / %q", opened.File.Name, opened.File.Type)
	}
	if opened.File.Size != int64(len(plaintext)) {
		t.Errorf("envelope says %d bytes, sent %d", opened.File.Size, len(plaintext))
	}

	var got bytes.Buffer
	if err := c.Fetch(t.Context(), link.ID(), opened, &got); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(got.Bytes(), plaintext) {
		t.Errorf("received %d bytes, sent %d, and they differ", got.Len(), len(plaintext))
	}
}

// A source that cannot be measured without reading it.
//
// The instance refuses a deferred length, so this is the path that encodes
// before it declares. What it must not do is get the length wrong, which would
// leave an upload that never completes.
func TestSendFromSomethingUnmeasurable(t *testing.T) {
	c := anInstance(t)
	plaintext := filled(200_000)

	// A reader with no Len and no Stat, which is what a pipe is.
	source := io.MultiReader(bytes.NewReader(plaintext))

	up, err := c.Send(t.Context(), source, "piped.bin", "", -1, client.UploadOptions{})
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

	// The envelope must state the plaintext length, which nothing measured in
	// advance.
	if opened.File.Size != int64(len(plaintext)) {
		t.Errorf("envelope says %d bytes, sent %d", opened.File.Size, len(plaintext))
	}
	// And a media type, since a pipe carries none.
	if opened.File.Type != "application/octet-stream" {
		t.Errorf("media type %q, want a usable default", opened.File.Type)
	}

	var got bytes.Buffer
	if err := c.Fetch(t.Context(), up.Link.ID(), opened, &got); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(got.Bytes(), plaintext) {
		t.Error("what came back is not what was piped in")
	}
}

func TestSendAnEmptyFile(t *testing.T) {
	c := anInstance(t)

	up, err := c.Send(t.Context(), bytes.NewReader(nil), "empty.bin", "", 0, client.UploadOptions{})
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

	var got bytes.Buffer
	if err := c.Fetch(t.Context(), up.Link.ID(), opened, &got); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got.Len() != 0 {
		t.Errorf("an empty file came back as %d bytes", got.Len())
	}
}

// The password contributes to the key, so a wrong one produces a key that does
// not fit - checked here, not by the instance.
func TestAPasswordIsCheckedWithoutAskingTheInstance(t *testing.T) {
	c := anInstance(t)
	plaintext := filled(2000)

	up, err := c.Send(t.Context(), bytes.NewReader(plaintext), "secret.txt", "text/plain",
		int64(len(plaintext)), client.UploadOptions{Password: "correct horse"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	published, err := c.Describe(t.Context(), up.Link.ID())
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if !published.PasswordRequired || published.KDF == nil {
		t.Fatal("the instance did not report that a password is required")
	}

	for _, wrong := range []string{"wrong horse", ""} {
		if _, err := client.Open(up.Link, published, wrong); !errors.Is(err, client.ErrPassword) {
			t.Errorf("password %q: %v, want ErrPassword", wrong, err)
		}
	}

	opened, err := client.Open(up.Link, published, "correct horse")
	if err != nil {
		t.Fatalf("open with the right password: %v", err)
	}
	var got bytes.Buffer
	if err := c.Fetch(t.Context(), up.Link.ID(), opened, &got); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(got.Bytes(), plaintext) {
		t.Error("the file did not survive the round trip")
	}
}

// Without a password there is nothing to have got wrong, so the same failure
// means something else. Reporting "wrong password" for an upload that has none
// would send somebody looking for one that does not exist.
func TestADamagedLinkIsNotReportedAsAWrongPassword(t *testing.T) {
	c := anInstance(t)

	up, err := c.Send(t.Context(), bytes.NewReader(filled(100)), "a.bin", "", 100,
		client.UploadOptions{})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	published, err := c.Describe(t.Context(), up.Link.ID())
	if err != nil {
		t.Fatalf("describe: %v", err)
	}

	other, err := crypto.NewLinkSecret()
	if err != nil {
		t.Fatalf("link secret: %v", err)
	}
	wrong := client.Link{Origin: up.Link.Origin, FileID: up.Link.FileID, LinkSecret: other}

	if _, err := client.Open(wrong, published, ""); !errors.Is(err, client.ErrDamaged) {
		t.Errorf("%v, want ErrDamaged", err)
	}
}

// The instance answers 404 for expired, exhausted, revoked and unknown alike,
// and a client must not guess between them.
func TestAnUnknownUploadIsUnavailable(t *testing.T) {
	c := anInstance(t)

	_, err := c.Describe(t.Context(), "AAAAAAAAAAAAAAAAAAAAAA")
	if !errors.Is(err, client.ErrUnavailable) {
		t.Errorf("%v, want ErrUnavailable", err)
	}
	if err != nil && !strings.Contains(err.Error(), "may have") {
		t.Errorf("the message picks a reason: %q", err)
	}
}

func TestAnExhaustedUploadIsUnavailable(t *testing.T) {
	c := anInstance(t)
	plaintext := filled(1000)

	up, err := c.Send(t.Context(), bytes.NewReader(plaintext), "once.bin", "",
		int64(len(plaintext)), client.UploadOptions{MaxDownloads: 1})
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
	if err := c.Fetch(t.Context(), up.Link.ID(), opened, io.Discard); err != nil {
		t.Fatalf("first fetch: %v", err)
	}

	if _, err := c.Describe(t.Context(), up.Link.ID()); !errors.Is(err, client.ErrUnavailable) {
		t.Errorf("after the only download: %v, want ErrUnavailable", err)
	}
}

// The link is the whole credential, so it must carry nothing the instance ever
// sees and everything a recipient needs.
func TestTheLinkCarriesTheSecretOnlyInTheFragment(t *testing.T) {
	c := anInstance(t)

	up, err := c.Send(t.Context(), bytes.NewReader(filled(10)), "a.bin", "", 10,
		client.UploadOptions{})
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	raw := up.Link.String()
	hash := strings.Index(raw, "#")
	if hash < 0 {
		t.Fatalf("no fragment in %q", raw)
	}
	transmitted := raw[:hash]

	secret := client.EncodeToken(up.Link.LinkSecret)
	if strings.Contains(transmitted, secret) {
		t.Error("the secret appears in the part a browser sends")
	}
	// Nor any substantial run of it.
	for i := 0; i+12 <= len(secret); i++ {
		if strings.Contains(transmitted, secret[i:i+12]) {
			t.Errorf("part of the secret appears in the transmitted portion at %d", i)
		}
	}
}
