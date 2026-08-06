// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"context"
	"log/slog"

	xslog "golang.org/x/exp/slog"

	"github.com/Serraniel/sendan/internal/logging"
)

// tusIDKey is the attribute tus attaches to every record about an upload,
// verbatim: `c.log = c.log.With("id", id)`. It is replaced with a truncated
// hash, because a log that leaks must not become a list of downloadable files.
const tusIDKey = "id"

// tusSafeAttrs is what may be forwarded from tus's own records.
//
// This is an allowlist rather than a list of keys to drop, and the difference
// matters. Blocking known-bad keys was tried first and leaked three times: the
// identifier travels as "id", again inside "path", and again inside the "url"
// of the Location header. Each was found only because a test looked for it.
//
// With an allowlist, an attribute a future version of tus adds is dropped
// rather than published. The cost is that a genuinely useful new field is
// silently lost until someone adds it here, which is the right way round for a
// project whose guarantee is that identifiers never reach a log.
var tusSafeAttrs = map[string]bool{
	"method":       true,
	"status":       true,
	"size":         true,
	"bytesWritten": true,
	"offset":       true,
	"requestId":    true,
	"error":        true,
}

// tusLogger returns the logger tus should use.
//
// tus takes a *golang.org/x/exp/slog.Logger rather than the standard library's,
// so its records cannot simply be handed to ours. Bridging them is not merely
// cosmetic: without it, tus writes to its own default handler, ignoring the
// configured format and level, and writes upload identifiers in full.
func tusLogger(to *slog.Logger) *xslog.Logger {
	if to == nil {
		to = slog.Default()
	}
	return xslog.New(&redactingHandler{to: to})
}

// redactingHandler forwards records to a standard library logger, replacing any
// upload identifier with a truncated hash on the way.
type redactingHandler struct {
	to    *slog.Logger
	attrs []slog.Attr
	group string
}

func (h *redactingHandler) Enabled(ctx context.Context, level xslog.Level) bool {
	return h.to.Enabled(ctx, slog.Level(level))
}

func (h *redactingHandler) Handle(ctx context.Context, r xslog.Record) error {
	attrs := make([]slog.Attr, 0, r.NumAttrs()+len(h.attrs))
	attrs = append(attrs, h.attrs...)
	r.Attrs(func(a xslog.Attr) bool {
		if converted, ok := convert(a); ok {
			attrs = append(attrs, converted)
		}
		return true
	})

	// The message is tus's own and carries no caller-supplied text; the
	// identifier travels as an attribute, which is what is redacted above.
	h.to.LogAttrs(ctx, slog.Level(r.Level), r.Message, attrs...)
	return nil
}

func (h *redactingHandler) WithAttrs(as []xslog.Attr) xslog.Handler {
	next := &redactingHandler{to: h.to, group: h.group}
	next.attrs = append(next.attrs, h.attrs...)
	for _, a := range as {
		if converted, ok := convert(a); ok {
			next.attrs = append(next.attrs, converted)
		}
	}
	return next
}

func (h *redactingHandler) WithGroup(name string) xslog.Handler {
	return &redactingHandler{to: h.to, attrs: h.attrs, group: name}
}

// convert maps one attribute across, reporting whether it may be forwarded.
func convert(a xslog.Attr) (slog.Attr, bool) {
	if a.Key == tusIDKey {
		return logging.FileID([]byte(a.Value.String())), true
	}
	if !tusSafeAttrs[a.Key] {
		return slog.Attr{}, false
	}
	return slog.Any(a.Key, a.Value.Any()), true
}
