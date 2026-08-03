// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/Serraniel/sendan/internal/ratelimit"
)

// rateLimit applies a per-address limit to every request it wraps.
//
// End-to-end encryption precludes inspecting content, so abuse controls have to
// be structural (docs/design.md §8). This is the outermost of them: without it,
// an unauthenticated caller can drive one database read per request at no cost
// to themselves.
//
// A nil limiter disables the check rather than rejecting everything, so that
// setting the limit to zero means "no limit" rather than "no service".
func rateLimit(limiter *ratelimit.Limiter, trustedProxies int, next http.Handler) http.Handler {
	if limiter == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Liveness is exempt. A container or orchestrator polls it on a fixed
		// schedule from a fixed address, and a health check that starts failing
		// because the limit was reached would restart a server that is working.
		// It reads nothing and touches no backend, so it costs nothing to serve.
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		key := clientAddr(r, trustedProxies)
		if limiter.Allow(key) {
			next.ServeHTTP(w, r)
			return
		}

		retry := limiter.Retry(key)
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(retry)))

		// no-store: a cached 429 would go on refusing a caller whose budget has
		// since recovered.
		w.Header().Set("Cache-Control", "no-store")
		writeError(w, http.StatusTooManyRequests, "rate_limited",
			"too many requests; retry later")
	})
}

// retryAfterSeconds renders a wait for the Retry-After header, which is
// expressed in whole seconds.
//
// It rounds up and reports at least one, because rounding a 400ms wait down to
// zero would invite an immediate retry that is certain to be refused.
func retryAfterSeconds(d time.Duration) int {
	if d <= 0 {
		return 1
	}
	return max(int(math.Ceil(d.Seconds())), 1)
}
