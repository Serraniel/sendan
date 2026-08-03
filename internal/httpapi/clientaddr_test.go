// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func requestFrom(remote string, forwarded ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/source", nil)
	r.RemoteAddr = remote
	for _, v := range forwarded {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func TestClientAddr(t *testing.T) {
	tests := []struct {
		name      string
		remote    string
		forwarded []string
		proxies   int
		want      string
	}{
		{
			name:   "no proxy uses the peer address",
			remote: "203.0.113.7:44321", proxies: 0,
			want: "203.0.113.7",
		},
		{
			// The decisive case. With no proxy configured the header is not
			// read at all, so a caller cannot choose their own bucket.
			name:   "no proxy ignores a forged header",
			remote: "203.0.113.7:44321", forwarded: []string{"1.2.3.4"}, proxies: 0,
			want: "203.0.113.7",
		},
		{
			name:   "one proxy takes the rightmost entry",
			remote: "10.0.0.1:8080", forwarded: []string{"198.51.100.9"}, proxies: 1,
			want: "198.51.100.9",
		},
		{
			// A caller prepending entries pads the left. The rightmost was
			// written by the proxy from the socket it accepted, so it is the
			// one value the caller cannot influence.
			name:      "one proxy ignores entries the caller prepended",
			remote:    "10.0.0.1:8080",
			forwarded: []string{"1.2.3.4, 5.6.7.8, 198.51.100.9"}, proxies: 1,
			want: "198.51.100.9",
		},
		{
			name:      "two proxies take the second entry from the right",
			remote:    "10.0.0.1:8080",
			forwarded: []string{"1.2.3.4, 198.51.100.9, 10.0.0.2"}, proxies: 2,
			want: "198.51.100.9",
		},
		{
			name:      "entries split across repeated header lines",
			remote:    "10.0.0.1:8080",
			forwarded: []string{"1.2.3.4", "198.51.100.9"}, proxies: 1,
			want: "198.51.100.9",
		},
		{
			// Misconfigured too high: everyone behind the proxy shares one
			// bucket. Stricter than intended, and not exploitable.
			name:   "more proxies configured than entries falls back to the peer",
			remote: "10.0.0.1:8080", forwarded: []string{"198.51.100.9"}, proxies: 3,
			want: "10.0.0.1",
		},
		{
			name:   "a proxy configured but no header falls back to the peer",
			remote: "10.0.0.1:8080", proxies: 1,
			want: "10.0.0.1",
		},
		{
			name:   "whitespace around entries is ignored",
			remote: "10.0.0.1:8080", forwarded: []string{"  198.51.100.9  "}, proxies: 1,
			want: "198.51.100.9",
		},
		{
			name:   "empty entries are discarded",
			remote: "10.0.0.1:8080", forwarded: []string{"1.2.3.4, , 198.51.100.9"}, proxies: 1,
			want: "198.51.100.9",
		},
		{
			name:   "an address without a port",
			remote: "203.0.113.7", proxies: 0,
			want: "203.0.113.7",
		},
		{
			name:   "an IPv4-mapped IPv6 address is charged as IPv4",
			remote: "[::ffff:203.0.113.7]:1234", proxies: 0,
			want: "203.0.113.7",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := clientAddr(requestFrom(tc.remote, tc.forwarded...), tc.proxies)
			if got != tc.want {
				t.Errorf("clientAddr = %q, want %q", got, tc.want)
			}
		})
	}
}

// A residential IPv6 allocation is commonly a /64 or larger. Keying on the full
// address would let one subscriber present billions of distinct addresses and
// never meet a limit, which is the same as having no limit.
func TestIPv6IsChargedPerAllocationNotPerAddress(t *testing.T) {
	within := []string{
		"[2001:db8:1:2::1]:1234",
		"[2001:db8:1:2::2]:1234",
		"[2001:db8:1:2:ffff:ffff:ffff:ffff]:1234",
	}

	first := clientAddr(requestFrom(within[0]), 0)
	for _, addr := range within[1:] {
		if got := clientAddr(requestFrom(addr), 0); got != first {
			t.Errorf("%s keys to %q, want %q - the limit is evadable within a /64", addr, got, first)
		}
	}

	// A different /64 must be a different bucket, or the limit would be shared
	// across unrelated networks.
	other := clientAddr(requestFrom("[2001:db8:1:3::1]:1234"), 0)
	if other == first {
		t.Errorf("a different /64 shares the bucket %q", first)
	}
}

// A forwarded entry need not be an address: RFC 7239 permits obfuscated
// identifiers, and a misbehaving proxy may write anything. Charging it as an
// opaque key still limits it, which is better than discarding it and charging
// nothing.
func TestUnparseableForwardedValueStillKeysSomething(t *testing.T) {
	got := clientAddr(requestFrom("10.0.0.1:8080", "_hidden"), 1)
	if got == "" {
		t.Fatal("an unparseable entry produced an empty key, so it would be unlimited")
	}
	if got != "_hidden" {
		t.Errorf("key %q, want the entry itself", got)
	}
}
