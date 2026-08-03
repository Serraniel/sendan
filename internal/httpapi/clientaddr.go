// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"net"
	"net/http"
	"strings"
)

// ipv6BucketBits is the prefix length a rate limit key uses for IPv6.
//
// A single residential IPv6 allocation is commonly a /64, and often a /56 or
// /48. Keying a limit on the full 128-bit address would let one subscriber
// present billions of distinct addresses and never meet a limit at all, which
// is not a limit. Keying on the /64 charges the allocation rather than the
// address.
//
// The cost is that clients sharing a /64 share a bucket. That is the intended
// trade: a limit that can be evaded is worth nothing, whereas a limit that is
// occasionally shared is merely stricter than necessary.
const ipv6BucketBits = 64

// clientAddr returns the rate limiting key for a request.
//
// trustedProxies is how many reverse proxies stand in front of this instance.
// Zero means none, and is the default.
//
// With N trusted proxies the client is the Nth entry from the right of
// X-Forwarded-For. Each proxy appends the address it observed, so the rightmost
// entry was written by the nearest proxy and cannot be influenced by the
// caller. Entries a caller forges can only pad the left, where they are not
// read.
//
// Misconfiguring N too high, or too low, degrades toward charging several
// clients to one bucket - stricter than intended, never weaker. The dangerous
// misconfiguration is the opposite one: claiming a proxy that does not exist,
// which hands the caller a header nothing overwrites and therefore lets them
// choose their own bucket. That is why the default is zero and why the
// documentation says so plainly.
func clientAddr(r *http.Request, trustedProxies int) string {
	direct := hostOnly(r.RemoteAddr)
	if trustedProxies <= 0 {
		return bucketKey(direct)
	}

	entries := forwardedFor(r)
	i := len(entries) - trustedProxies
	if i < 0 || i >= len(entries) {
		// Fewer hops than configured: the header is absent or shorter than
		// expected. Falling back to the peer charges everyone behind the proxy
		// to one bucket, which is wrong but not exploitable.
		return bucketKey(direct)
	}
	return bucketKey(entries[i])
}

// forwardedFor splits X-Forwarded-For into trimmed entries, across repeated
// header lines as well as comma-separated values, since a header may legally
// appear more than once.
func forwardedFor(r *http.Request) []string {
	var entries []string
	for _, line := range r.Header.Values("X-Forwarded-For") {
		for _, raw := range strings.Split(line, ",") {
			if v := strings.TrimSpace(raw); v != "" {
				entries = append(entries, v)
			}
		}
	}
	return entries
}

// hostOnly strips a port from an address, tolerating an address without one.
func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return strings.TrimSpace(addr)
}

// bucketKey normalises an address into the key a limit is charged against.
//
// An unparseable value is returned as itself rather than discarded. A forwarded
// entry may be an obfuscated identifier or a hostname, and charging it as an
// opaque string still limits it; the limiter evicts idle keys, so an adversary
// choosing junk keys costs memory only while they keep using them.
func bucketKey(addr string) string {
	addr = hostOnly(addr)

	ip := net.ParseIP(addr)
	if ip == nil {
		return addr
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(ipv6BucketBits, 128)).String() + "/64"
}
