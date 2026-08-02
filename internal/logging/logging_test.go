// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package logging

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// The promise that an expired upload leaves nothing behind is void if its
// identifier survives in a log. These tests exist so that a change which starts
// writing one down fails rather than passes quietly.

func TestIDIsNeverLoggedVerbatim(t *testing.T) {
	raw := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}

	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			log := New(&buf, Options{Level: slog.LevelDebug, Format: format})
			log.Info("upload expired", FileID(raw))

			out := buf.String()
			for _, forbidden := range []string{
				hex.EncodeToString(raw),
				strings.ToUpper(hex.EncodeToString(raw)),
				string(raw),
			} {
				if strings.Contains(out, forbidden) {
					t.Fatalf("log line discloses the identifier: %s", out)
				}
			}
			if !strings.Contains(out, "file=") && !strings.Contains(out, `"file"`) {
				t.Fatalf("expected a redacted file attribute, got: %s", out)
			}
		})
	}
}

// Redaction is only useful if it still correlates. Two lines about the same
// upload must be linkable, or an operator cannot debug anything.
func TestIDIsStableAndCorrelatable(t *testing.T) {
	a := ID([]byte("file-one"))
	b := ID([]byte("file-two"))

	if a.String() != ID([]byte("file-one")).String() {
		t.Fatal("the same identifier redacted to two different values")
	}
	if a.String() == b.String() {
		t.Fatal("two different identifiers redacted to the same value")
	}
	if len(a.String()) != redactedPrefixLen {
		t.Fatalf("redacted form is %d characters, want %d", len(a.String()), redactedPrefixLen)
	}
}

func TestEmptyIDIsReported(t *testing.T) {
	if got := ID(nil).String(); got != "none" {
		t.Fatalf("got %q, want %q", got, "none")
	}
}

// Formatting is a far easier mistake than a bad log call: fmt.Sprintf("%s", id)
// bypasses slog entirely. The String method closes that path.
func TestIDDoesNotDiscloseThroughFmt(t *testing.T) {
	raw := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	id := ID(raw)

	for _, s := range []string{
		// staticcheck suggests String() here, which would defeat the test:
		// the point is that the %s path a careless caller would reach for is
		// also safe.
		fmt.Sprintf("%s", id), //nolint:staticcheck // exercising the fmt path deliberately
		fmt.Sprintf("%v", id),
		fmt.Sprint(id),
		"prefix " + id.String(),
	} {
		if strings.Contains(s, hex.EncodeToString(raw)) {
			t.Fatalf("fmt disclosed the identifier: %s", s)
		}
	}
}

func TestSecretIsNeverDisclosed(t *testing.T) {
	raw := []byte("correct horse battery staple")
	secret := Secret(raw)

	var buf bytes.Buffer
	log := New(&buf, Options{Level: slog.LevelDebug, Format: "json"})
	log.Info("deriving", slog.Any("password", secret))

	out := buf.String()
	if strings.Contains(out, string(raw)) || strings.Contains(out, hex.EncodeToString(raw)) {
		t.Fatalf("log line discloses the secret: %s", out)
	}
	if !strings.Contains(out, "[redacted]") {
		t.Fatalf("expected a redaction marker, got: %s", out)
	}

	// Unlike an ID, a secret must not be correlatable: two uses of the same
	// secret must be indistinguishable from two different ones.
	if Secret([]byte("a")).String() != Secret([]byte("b")).String() {
		t.Fatal("secrets are distinguishable from one another")
	}
}

func TestLevelIsRespected(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, Options{Level: slog.LevelWarn, Format: "json"})
	log.Debug("should not appear")
	log.Info("should not appear")
	log.Warn("should appear")

	if strings.Contains(buf.String(), "should not appear") {
		t.Fatalf("a level below the threshold was emitted: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "should appear") {
		t.Fatalf("a level at the threshold was suppressed: %s", buf.String())
	}
}
