// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Serraniel/sendan/internal/ratelimit"
)

func limitedHandler(t *testing.T, rate float64, burst, proxies int) http.Handler {
	t.Helper()
	return New(Options{
		BaseURL:        mustURL(t, "https://sendan.example"),
		SourceURL:      mustURL(t, "https://example.org/src"),
		RateLimit:      ratelimit.New(ratelimit.Config{Rate: rate, Burst: burst}),
		TrustedProxies: proxies,
	})
}

func callFrom(t *testing.T, h http.Handler, remote string, forwarded ...string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, requestFrom(remote, forwarded...))
	return rec
}

func TestRateLimitRefusesOnceTheBurstIsSpent(t *testing.T) {
	// A rate of zero refills nothing, so the burst is the whole budget and the
	// test does not depend on how long it takes to run.
	h := limitedHandler(t, 0, 3, 0)

	for i := range 3 {
		if rec := callFrom(t, h, "203.0.113.7:1000"); rec.Code != http.StatusOK {
			t.Fatalf("request %d: status %d, want 200", i+1, rec.Code)
		}
	}

	rec := callFrom(t, h, "203.0.113.7:1000")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Error("Retry-After is missing, so a client cannot know when to return")
	} else if n, err := strconv.Atoi(got); err != nil || n < 1 {
		t.Errorf("Retry-After = %q, want a positive whole number of seconds", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control %q on a 429, want no-store", got)
	}
}

// A limit that is global rather than per-address turns one abusive client into
// an outage for everyone else, which is a denial of service delivered by the
// defence.
func TestRateLimitIsPerAddress(t *testing.T) {
	h := limitedHandler(t, 0, 2, 0)

	for range 2 {
		if rec := callFrom(t, h, "203.0.113.7:1000"); rec.Code != http.StatusOK {
			t.Fatal("the first client was refused within its budget")
		}
	}
	if rec := callFrom(t, h, "203.0.113.7:1000"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the first client was not limited: %d", rec.Code)
	}

	if rec := callFrom(t, h, "198.51.100.4:1000"); rec.Code != http.StatusOK {
		t.Fatalf("a second client was refused because of the first: %d", rec.Code)
	}
}

// The header is only read when a proxy is configured. Were it read regardless,
// a caller could pick a fresh bucket per request and never meet the limit.
func TestForwardedHeaderCannotBypassTheLimit(t *testing.T) {
	h := limitedHandler(t, 0, 2, 0)

	for range 2 {
		if rec := callFrom(t, h, "203.0.113.7:1000", "1.1.1.1"); rec.Code != http.StatusOK {
			t.Fatal("refused within budget")
		}
	}

	for i, forged := range []string{"2.2.2.2", "3.3.3.3", "4.4.4.4"} {
		rec := callFrom(t, h, "203.0.113.7:1000", forged)
		if rec.Code != http.StatusTooManyRequests {
			t.Errorf("attempt %d with X-Forwarded-For: %s got %d, want 429 - the limit is evadable",
				i+1, forged, rec.Code)
		}
	}
}

// With a proxy configured the limit must follow the forwarded client, or every
// client behind the proxy shares one budget and a single user can exhaust it
// for all of them.
func TestWithAProxyTheLimitFollowsTheForwardedClient(t *testing.T) {
	h := limitedHandler(t, 0, 2, 1)

	for range 2 {
		if rec := callFrom(t, h, "10.0.0.1:8080", "198.51.100.9"); rec.Code != http.StatusOK {
			t.Fatal("refused within budget")
		}
	}
	if rec := callFrom(t, h, "10.0.0.1:8080", "198.51.100.9"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the forwarded client was not limited: %d", rec.Code)
	}

	// A different client through the same proxy has its own budget.
	if rec := callFrom(t, h, "10.0.0.1:8080", "198.51.100.10"); rec.Code != http.StatusOK {
		t.Fatalf("a second client behind the proxy was refused: %d", rec.Code)
	}
}

// A health check polls on a schedule from a fixed address. If it could be
// limited, reaching the limit would make the instance look unhealthy and get it
// restarted - the defence causing the outage it exists to prevent.
func TestHealthzIsNotRateLimited(t *testing.T) {
	h := limitedHandler(t, 0, 1, 0)

	if rec := callFrom(t, h, "203.0.113.7:1000"); rec.Code != http.StatusOK {
		t.Fatal("the budget was already spent")
	}
	if rec := callFrom(t, h, "203.0.113.7:1000"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the budget was not spent: %d", rec.Code)
	}

	for i := range 5 {
		rec := httptest.NewRecorder()
		req := requestFrom("203.0.113.7:1000")
		req.URL.Path = "/healthz"
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("health check %d refused with %d", i+1, rec.Code)
		}
	}
}

// A refused request is still a response, so it must carry the same headers as
// any other. A 429 without them would be the one reply an attacker can reliably
// provoke.
func TestRefusedRequestsCarryTheSecurityHeaders(t *testing.T) {
	h := limitedHandler(t, 0, 1, 0)
	_ = callFrom(t, h, "203.0.113.7:1000")

	rec := callFrom(t, h, "203.0.113.7:1000")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", rec.Code)
	}
	for name, want := range requiredHeaders {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// A nil limiter means the operator set no limit. That must serve every request,
// not refuse every request: the two failure directions look identical in
// configuration and could not be more different in effect.
func TestNoLimiterServesEverything(t *testing.T) {
	h := New(Options{SourceURL: mustURL(t, "https://example.org/src")})
	for i := range 20 {
		if rec := callFrom(t, h, "203.0.113.7:1000"); rec.Code != http.StatusOK {
			t.Fatalf("request %d refused with %d when no limit is configured", i+1, rec.Code)
		}
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want int
	}{
		{0, 1},
		{-time.Second, 1},
		{time.Millisecond, 1},
		// Rounded up: a client told to wait 1 second when 1.2 remain would
		// return early and be refused again.
		{1200 * time.Millisecond, 2},
		{2 * time.Second, 2},
		{2500 * time.Millisecond, 3},
	}
	for _, tc := range tests {
		if got := retryAfterSeconds(tc.d); got != tc.want {
			t.Errorf("retryAfterSeconds(%s) = %d, want %d", tc.d, got, tc.want)
		}
	}
}

// The budget must actually replenish, or a client that met the limit once would
// be refused for as long as the process runs.
func TestBudgetRecovers(t *testing.T) {
	h := limitedHandler(t, 100, 1, 0) // 100 per second refills in 10ms

	if rec := callFrom(t, h, "203.0.113.7:1000"); rec.Code != http.StatusOK {
		t.Fatal("the first request was refused")
	}
	if rec := callFrom(t, h, "203.0.113.7:1000"); rec.Code != http.StatusTooManyRequests {
		t.Fatal("the budget was not spent")
	}

	deadline := time.After(5 * time.Second)
	for {
		if rec := callFrom(t, h, "203.0.113.7:1000"); rec.Code == http.StatusOK {
			return
		}
		select {
		case <-deadline:
			t.Fatal("the budget never recovered")
		case <-time.After(2 * time.Millisecond):
		}
	}
}
