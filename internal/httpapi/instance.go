// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"encoding/json"
	"net/http"
	"time"
)

// Instance is what an instance says about the rules it enforces.
//
// Everything here is policy: what an upload may ask for and what it will be
// refused. None of it describes the deployment, and that boundary is the
// interesting part of this type rather than an implementation detail.
//
// # What is deliberately absent
//
// Which storage backend is in use, which database, whether at-rest keys are
// wrapped under a master key, how many proxies stand in front, and what the
// rate limits are. None of it changes what a person may upload, and all of it
// helps somebody attacking the instance more than it helps somebody using it.
//
// # What this is worth
//
// An instance can state whatever it likes here; nothing binds it to the truth.
// It is a convenience, not a guarantee, and the interface says so. The
// properties that do not depend on the instance being honest are the
// cryptographic ones - the key is derived and used in the browser, whatever
// this endpoint claims.
type Instance struct {
	// MaxUploadSize is the largest single upload, in bytes. Zero means the
	// instance sets no limit of its own.
	//
	// Also advertised as Tus-Max-Size on the upload endpoint, which is where
	// the client reads it during a transfer. Repeated here so that everything
	// a person is shown before choosing a file comes from one answer.
	MaxUploadSize int64 `json:"maxUploadSize"`

	// DefaultTTLSeconds is how long an upload lives when the uploader does not
	// choose, and MaxTTLSeconds is the longest they may choose.
	DefaultTTLSeconds int64 `json:"defaultTtlSeconds"`
	MaxTTLSeconds     int64 `json:"maxTtlSeconds"`

	// AllowInfiniteTTL is whether an upload may be asked to never expire.
	AllowInfiniteTTL bool `json:"allowInfiniteTtl"`

	// RequireLimit is whether every upload must carry either a deadline or a
	// download limit. It can only bind where unlimited retention is allowed,
	// since otherwise every upload already has a deadline.
	RequireLimit bool `json:"requireLimit"`

	// DefaultMaxDownloads is the download limit applied when the uploader does
	// not choose one. Zero means no limit.
	DefaultMaxDownloads int `json:"defaultMaxDownloads"`

	// CompatEnabled reports whether the third-party compatibility endpoints are
	// served.
	//
	// Published because it is the one setting that changes what protection an
	// upload can have: through those endpoints the instance checks the password
	// rather than the password contributing to the key. Somebody choosing an
	// instance is entitled to know that before they use it, not after.
	CompatEnabled bool `json:"compatEnabled"`
}

// handleInstance reports the policy an instance enforces.
func handleInstance(in Instance) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		// Short, not never: the answer changes only when an operator changes
		// configuration and restarts, but a page that caches it for a day would
		// show a limit that no longer applies.
		w.Header().Set("Cache-Control", "public, max-age=60")

		if err := json.NewEncoder(w).Encode(in); err != nil {
			// The header is already written, so there is nothing useful to say
			// to the client. Nothing here is secret and nothing is identifying,
			// so there is nothing to redact either.
			return
		}
	}
}

// describeInstance builds the report from the options an instance was given.
func describeInstance(opts Options) Instance {
	in := Instance{
		MaxUploadSize: opts.MaxUploadSize,
		CompatEnabled: opts.Compat != nil,
	}

	// A service is absent in a backend-only assembly and in tests that exercise
	// the HTTP surface alone. Reporting zeroes there would be describing a
	// policy nobody set, so the retention fields stay at their zero values and
	// mean the same thing they mean everywhere else: no answer.
	if opts.Uploads == nil {
		return in
	}

	policy := opts.Uploads.Policy()
	in.DefaultTTLSeconds = seconds(policy.DefaultTTL)
	in.MaxTTLSeconds = seconds(policy.MaxTTL)
	in.AllowInfiniteTTL = policy.AllowInfiniteTTL
	in.RequireLimit = policy.RequireLimit
	in.DefaultMaxDownloads = policy.DefaultMaxDownloads
	return in
}

// seconds converts a duration for the wire, rounding down.
//
// Rounding down rather than to nearest: a maximum reported as longer than it is
// produces a request the instance then refuses, which is the failure this
// endpoint exists to prevent.
func seconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64(d / time.Second)
}
