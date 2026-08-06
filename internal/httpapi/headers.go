// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"net/http"
	"strings"
)

// contentSecurityPolicy is the policy served with every response.
//
// The client decrypts files in the browser, so the policy's purpose is not only
// to prevent script injection but to ensure that an injected script has nowhere
// to send what it steals. connect-src 'self' is the load-bearing directive: a
// file key that cannot leave the origin is a file key an attacker cannot use.
//
//   - 'wasm-unsafe-eval' is required, not optional. Argon2id has no WebCrypto
//     equivalent, so password derivation runs in WebAssembly, and instantiating
//     a module counts as evaluation. Without it, password-protected uploads and
//     downloads fail while everything else keeps working - a failure narrow
//     enough to survive a smoke test and reach users.
//   - base-uri 'none' stops an injected <base> element rewriting where relative
//     API requests go.
//   - frame-ancestors 'none' prevents an attacker framing the client and
//     reading a link fragment through clickjacking.
//   - blob: is permitted for images and media because decrypted content is
//     rendered from object URLs. It is deliberately absent from script-src and
//     worker-src, where it would be an injection vector rather than a feature.
const contentSecurityPolicy = "default-src 'self'; " +
	scriptSrcPlaceholder + "; " +
	"style-src 'self'; " +
	"img-src 'self' blob:; " +
	"media-src 'self' blob:; " +
	"font-src 'self'; " +
	"connect-src 'self'; " +
	"worker-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"form-action 'none'; " +
	"frame-ancestors 'none'"

// scriptSrcPlaceholder is the script-src directive before the shell's inline
// bootstrap is accounted for.
//
// The client's entry point is inline and differs per build, so its hash cannot
// be written here. It is added at construction from the shell that is actually
// embedded, which is the only value that can be correct for a given binary.
const scriptSrcPlaceholder = "script-src 'self' 'wasm-unsafe-eval'"

// withScriptHashes returns the policy with additional script sources allowed.
func withScriptHashes(policy string, hashes []string) string {
	if len(hashes) == 0 {
		return policy
	}
	return strings.Replace(policy, scriptSrcPlaceholder,
		scriptSrcPlaceholder+" "+strings.Join(hashes, " "), 1)
}

// permissionsPolicy denies every feature the client has no use for. Sendan
// reads no sensors and captures no media, so the correct answer to all of them
// is the empty allowlist.
const permissionsPolicy = "accelerometer=(), ambient-light-sensor=(), autoplay=(), " +
	"camera=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), " +
	"gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), " +
	"picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), " +
	"serial=(), usb=(), xr-spatial-tracking=()"

// hstsMaxAge is two years, the value the preload list requires. Sendan does not
// ask to be preloaded and does not claim subdomains: both affect names the
// instance may not own, and are the operator's decision at their proxy.
const hstsMaxAge = "max-age=63072000"

// secureHeaders writes the security headers on every response.
//
// It wraps rather than decorates individual routes so that a handler added
// later cannot be forgotten. Headers are set before the wrapped handler runs,
// because WriteHeader flushes them: setting them afterwards would silently do
// nothing for any handler that has already written.
func secureHeaders(https bool, policy string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		// The link secret lives in the URL fragment. Browsers do not send
		// fragments in a referrer, but a referrer still discloses which
		// instance and which upload identifier a user came from, and any future
		// page that puts the secret in the path or query would leak it outright.
		// no-referrer removes the question.
		h.Set("Referrer-Policy", "no-referrer")

		h.Set("Content-Security-Policy", policy)
		h.Set("Permissions-Policy", permissionsPolicy)

		// Ciphertext must never be sniffed into a type the browser will execute
		// or render. Every response says what it is and is taken at its word.
		h.Set("X-Content-Type-Options", "nosniff")

		// frame-ancestors covers this for current browsers; the header covers
		// the ones that do not implement it.
		h.Set("X-Frame-Options", "DENY")

		// A download link is a capability. Indexing one would publish it.
		h.Set("X-Robots-Tag", "noindex, nofollow")

		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")

		// HSTS is sent only when the instance is served over HTTPS, taken from
		// the configured external origin rather than from a forwarded header.
		// X-Forwarded-Proto is written by whatever spoke last, which on a
		// misconfigured deployment is the client.
		if https {
			h.Set("Strict-Transport-Security", hstsMaxAge)
		}

		next.ServeHTTP(w, r)
	})
}
