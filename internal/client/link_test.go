// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package client_test

import (
	"strings"
	"testing"

	"github.com/Serraniel/sendan/internal/client"
	"github.com/Serraniel/sendan/internal/crypto"
)

func aLink(t *testing.T) client.Link {
	t.Helper()
	id, err := crypto.NewFileID()
	if err != nil {
		t.Fatalf("file id: %v", err)
	}
	secret, err := crypto.NewLinkSecret()
	if err != nil {
		t.Fatalf("link secret: %v", err)
	}
	return client.Link{Origin: "https://send.example", FileID: id, LinkSecret: secret}
}

func TestALinkRoundTrips(t *testing.T) {
	want := aLink(t)

	got, err := client.ParseLink(want.String())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Origin != want.Origin {
		t.Errorf("origin %q, want %q", got.Origin, want.Origin)
	}
	if string(got.FileID) != string(want.FileID) {
		t.Error("the identifier did not survive")
	}
	if string(got.LinkSecret) != string(want.LinkSecret) {
		t.Error("the secret did not survive")
	}
}

// Spec §10 fixes these lengths. A person comparing what they pasted against
// what they were given counts characters, and a 22/43 split is the check.
func TestALinkIs22CharactersOfIdentifierAnd43OfSecret(t *testing.T) {
	raw := aLink(t).String()

	hash := strings.Index(raw, "#")
	if hash < 0 {
		t.Fatalf("no fragment in %q", raw)
	}
	id := raw[strings.LastIndex(raw[:hash], "/")+1 : hash]
	fragment := raw[hash+1:]

	if len(id) != 22 {
		t.Errorf("identifier is %d characters, want 22", len(id))
	}
	if len(fragment) != 43 {
		t.Errorf("secret is %d characters, want 43", len(fragment))
	}
}

// The failure the whole interface is built around: a link that lost its
// fragment is still a well-formed URL to a real page, and what it lost cannot
// be recovered by anybody. Parsing it as though it were whole would derive keys
// from nothing and report the file as corrupt, which sends the person holding
// it to look in the wrong place.
func TestALinkThatLostItsFragmentSaysSo(t *testing.T) {
	raw := aLink(t).String()
	hash := strings.Index(raw, "#")

	for _, damaged := range []string{
		raw[:hash],       // the fragment gone
		raw[:hash+1],     // copied up to and including the separator
		raw[:len(raw)-5], // the tail clipped
	} {
		_, err := client.ParseLink(damaged)
		if err == nil {
			t.Errorf("%q was accepted", damaged)
			continue
		}
		if damaged == raw[:hash] || damaged == raw[:hash+1] {
			if !strings.Contains(err.Error(), "cannot be recovered") {
				t.Errorf("%q: %v, want it to say the key cannot be recovered", damaged, err)
			}
		}
	}
}

func TestALinkWithADamagedIdentifierIsRefused(t *testing.T) {
	raw := aLink(t).String()
	hash := strings.Index(raw, "#")

	if _, err := client.ParseLink(raw[:hash-3] + raw[hash:]); err == nil {
		t.Error("a truncated identifier was accepted")
	}
}

func TestWhatIsNotALinkIsRefused(t *testing.T) {
	secret := aLink(t)
	for _, raw := range []string{
		"",
		"not a url",
		"https://send.example/",
		"https://send.example/d/",
		"ftp://send.example/d/AAAAAAAAAAAAAAAAAAAAAA#" + strings.Repeat("A", 43),
		// A path that is not a download URL, however well formed the rest is.
		strings.Replace(secret.String(), "/d/", "/upload/", 1),
	} {
		if _, err := client.ParseLink(raw); err == nil {
			t.Errorf("%q was accepted", raw)
		}
	}
}

// Somebody pasting a link out of a message may bring whitespace with it, and
// that is not damage.
func TestSurroundingWhitespaceIsNotDamage(t *testing.T) {
	want := aLink(t)

	got, err := client.ParseLink("  " + want.String() + "\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if string(got.LinkSecret) != string(want.LinkSecret) {
		t.Error("the secret did not survive")
	}
}

func TestTheOriginIsTakenFromTheLink(t *testing.T) {
	// A recipient's client must talk to the instance the link names, not to one
	// it was configured with.
	for _, origin := range []string{
		"https://files.example.org",
		"http://localhost:8080",
		"https://send.example:8443",
	} {
		l := aLink(t)
		l.Origin = origin

		got, err := client.ParseLink(l.String())
		if err != nil {
			t.Fatalf("%s: %v", origin, err)
		}
		if got.Origin != origin {
			t.Errorf("origin %q, want %q", got.Origin, origin)
		}
	}
}

func TestATrailingSlashDoesNotDoubleTheSeparator(t *testing.T) {
	l := aLink(t)
	withSlash := l
	withSlash.Origin = l.Origin + "/"

	if withSlash.String() != l.String() {
		t.Errorf("%q != %q", withSlash.String(), l.String())
	}
}
