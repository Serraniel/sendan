// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// clock returns a limiter with controllable time, so the tests never sleep.
func withClock(cfg Config) (*Limiter, func(time.Duration)) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	l := New(cfg)
	l.now = func() time.Time { return now }
	return l, func(d time.Duration) { now = now.Add(d) }
}

func TestBurstIsAllowedThenRefused(t *testing.T) {
	l, _ := withClock(Config{Rate: 1, Burst: 3})

	for i := range 3 {
		if !l.Allow("client") {
			t.Fatalf("event %d within the burst was refused", i+1)
		}
	}
	if l.Allow("client") {
		t.Fatal("an event beyond the burst was allowed")
	}
}

func TestTokensRefillOverTime(t *testing.T) {
	l, advance := withClock(Config{Rate: 2, Burst: 2})

	for i := range 2 {
		if !l.Allow("client") {
			t.Fatalf("burst event %d was refused", i+1)
		}
	}
	if l.Allow("client") {
		t.Fatal("the bucket was not empty")
	}

	advance(500 * time.Millisecond) // one token at 2/s
	if !l.Allow("client") {
		t.Fatal("a refilled token was refused")
	}
	if l.Allow("client") {
		t.Fatal("more than the refilled amount was allowed")
	}
}

func TestRefillIsCappedAtTheBurst(t *testing.T) {
	l, advance := withClock(Config{Rate: 1, Burst: 2})

	for i := range 2 {
		if !l.Allow("client") {
			t.Fatalf("burst event %d was refused", i+1)
		}
	}
	advance(time.Hour) // far more than enough to refill

	for i := range 2 {
		if !l.Allow("client") {
			t.Fatalf("refilled burst event %d was refused", i+1)
		}
	}
	if l.Allow("client") {
		t.Fatal("idling accumulated more than one burst, which would let a patient attacker bank credit")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l, _ := withClock(Config{Rate: 1, Burst: 1})

	if !l.Allow("first") {
		t.Fatal("the first key was refused")
	}
	if l.Allow("first") {
		t.Fatal("the first key exceeded its burst")
	}
	if !l.Allow("second") {
		t.Fatal("one key exhausting its bucket blocked another")
	}
}

// A partial charge would let a caller be billed for work it was not permitted
// to do.
func TestAllowNIsAllOrNothing(t *testing.T) {
	l, _ := withClock(Config{Rate: 1, Burst: 5})

	if l.AllowN("client", 6) {
		t.Fatal("a request larger than the burst was allowed")
	}
	if !l.AllowN("client", 5) {
		t.Fatal("a request exactly at the burst was refused")
	}
	if l.Allow("client") {
		t.Fatal("the refused request consumed tokens anyway")
	}
}

func TestZeroBurstRefusesEverything(t *testing.T) {
	l, _ := withClock(Config{Rate: 100, Burst: 0})
	if l.Allow("client") {
		t.Fatal("a zero burst allowed an event")
	}
}

func TestRetryReportsWhenAnEventBecomesPossible(t *testing.T) {
	l, advance := withClock(Config{Rate: 1, Burst: 1})

	if d := l.Retry("unseen"); d != 0 {
		t.Fatalf("an unseen key must be immediately allowed, got %s", d)
	}
	if !l.Allow("client") {
		t.Fatal("the first event was refused")
	}

	d := l.Retry("client")
	if d <= 0 || d > time.Second {
		t.Fatalf("retry after = %s, want just under a second", d)
	}

	// Retry must not consume a token, or asking when to retry would push the
	// answer further away.
	if again := l.Retry("client"); again > d {
		t.Fatalf("asking twice moved the answer from %s to %s", d, again)
	}

	advance(time.Second)
	if d := l.Retry("client"); d != 0 {
		t.Fatalf("after waiting, retry after = %s, want 0", d)
	}
}

// The key is often a client address, which an adversary chooses. Without
// eviction, cycling through addresses would grow the map without bound.
func TestIdleBucketsAreEvicted(t *testing.T) {
	l, advance := withClock(Config{Rate: 1, Burst: 1, Idle: time.Minute})

	for i := range 100 {
		l.Allow(fmt.Sprintf("client-%d", i))
	}
	if l.Len() != 100 {
		t.Fatalf("holding %d buckets, want 100", l.Len())
	}

	advance(30 * time.Second)
	l.Allow("client-0") // keep one alive
	advance(45 * time.Second)

	removed := l.Sweep()
	if removed != 99 {
		t.Fatalf("swept %d buckets, want 99", removed)
	}
	if l.Len() != 1 {
		t.Fatalf("holding %d buckets after the sweep, want 1", l.Len())
	}
	// Eviction must not grant credit: a fresh bucket is full, and an idle
	// bucket was full anyway, so the two are indistinguishable.
	if !l.Allow("client-50") {
		t.Fatal("an evicted key was not treated as new")
	}
}

func TestForgetDiscardsState(t *testing.T) {
	l, _ := withClock(Config{Rate: 1, Burst: 1})
	if !l.Allow("client") {
		t.Fatal("the first event was refused")
	}
	if l.Allow("client") {
		t.Fatal("the burst was exceeded")
	}
	l.Forget("client")
	if !l.Allow("client") {
		t.Fatal("state survived Forget")
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	l := New(Config{Rate: 1000, Burst: 1000})

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				l.Allow(fmt.Sprintf("client-%d", i%5))
				l.Retry("client-0")
				l.Sweep()
			}
		}()
	}
	wg.Wait()

	// The limiter must still behave correctly afterwards, not merely have
	// survived. A corrupted bucket map would show up here.
	if l.Len() == 0 || l.Len() > 5 {
		t.Fatalf("holding %d buckets after concurrent use, want between 1 and 5", l.Len())
	}
	if !l.Allow("fresh-key") {
		t.Fatal("the limiter stopped accepting new keys after concurrent use")
	}
}

// The total allowed under sustained pressure must track the configured rate,
// not the number of requests attempted.
func TestSustainedRateIsEnforced(t *testing.T) {
	l, advance := withClock(Config{Rate: 10, Burst: 10})

	allowed := 0
	for range 100 { // ten seconds in 100ms steps
		for range 5 { // more requests than the rate permits
			if l.Allow("client") {
				allowed++
			}
		}
		advance(100 * time.Millisecond)
	}

	// Ten seconds at ten per second, plus the initial burst.
	const want = 110
	if allowed < want-2 || allowed > want+2 {
		t.Fatalf("allowed %d events over ten seconds, want about %d", allowed, want)
	}
}
