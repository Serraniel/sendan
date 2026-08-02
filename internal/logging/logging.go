// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Package logging configures structured logging and makes it difficult to log
// a value that must never be written down.
//
// Sendan promises that an expired upload leaves nothing behind. That promise is
// void if identifiers survive in an access log, so this package provides types
// that redact themselves when logged, rather than relying on every call site to
// remember. See docs/design.md §3 and issue #26.
package logging

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
)

// redactedPrefixLen is how much of a hash is kept. Eight hex characters are
// enough to correlate lines within one request and far too few to enumerate.
const redactedPrefixLen = 8

// ID is a value that must never appear in logs verbatim: a file identifier, an
// owner token, a link secret.
//
// It implements [slog.LogValuer], so passing one to a logger emits a truncated
// hash rather than the value. Logging the raw bytes then requires deliberately
// converting away from this type, which is the point.
type ID []byte

// LogValue implements [slog.LogValuer].
func (id ID) LogValue() slog.Value {
	if len(id) == 0 {
		return slog.StringValue("none")
	}
	sum := sha256.Sum256(id)
	return slog.StringValue(hex.EncodeToString(sum[:])[:redactedPrefixLen])
}

// String prevents an ID from disclosing itself through fmt verbs or string
// concatenation, which is a far easier mistake to make than a bad log call.
func (id ID) String() string {
	return id.LogValue().String()
}

// Secret is a value that must never be written down at all, not even as a
// correlatable hash: a password, a wrapping key, a decrypted file key.
//
// Unlike [ID] it is not correlatable by design, because correlating two uses of
// the same secret is itself a disclosure.
type Secret []byte

// LogValue implements [slog.LogValuer].
func (Secret) LogValue() slog.Value { return slog.StringValue("[redacted]") }

// String prevents disclosure through fmt verbs.
func (Secret) String() string { return "[redacted]" }

// Options configure the logger.
type Options struct {
	Level  slog.Level
	Format string // "json" or "text"
}

// New returns a logger writing to w.
func New(w io.Writer, opts Options) *slog.Logger {
	handlerOpts := &slog.HandlerOptions{Level: opts.Level}

	var handler slog.Handler
	if opts.Format == "text" {
		handler = slog.NewTextHandler(w, handlerOpts)
	} else {
		handler = slog.NewJSONHandler(w, handlerOpts)
	}
	return slog.New(handler)
}

// FileID returns a log-safe attribute for a file identifier.
//
// Prefer this to writing the key by hand, so that every correlatable identifier
// in the logs uses one consistent name.
func FileID(id []byte) slog.Attr { return slog.Any("file", ID(id)) }
