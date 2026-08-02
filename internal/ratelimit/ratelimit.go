// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Package ratelimit provides the structural abuse controls Sendan relies on.
//
// End-to-end encryption means the server cannot inspect what it stores, so
// nothing here reasons about content. Every control is structural: how often an
// address may act, and how often a password may be guessed against one upload.
//
// Everything is in-process and memory bounded. An external store would be a
// second thing to deploy, a second thing to compromise, and a place where
// upload identifiers would accumulate outside the deletion guarantee.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// Limiter is a token bucket keyed by an arbitrary string.
//
// Buckets are created on demand and evicted once idle, so the memory a limiter
// occupies is proportional to recent activity rather than to everything it has
// ever seen. That matters because the key is often a client address, which an
// adversary chooses.
type Limiter struct {
	rate  float64 // tokens per second
	burst float64
	idle  time.Duration

	now func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	seen   time.Time
}

// Config describes a limit.
type Config struct {
	// Rate is the sustained number of permitted events per second.
	Rate float64
	// Burst is how many may arrive at once.
	Burst int
	// Idle is how long an unused bucket is retained. A bucket that has been
	// idle for longer is indistinguishable from a new one, so discarding it
	// frees memory without weakening the limit.
	Idle time.Duration
}

// New returns a Limiter.
func New(cfg Config) *Limiter {
	if cfg.Idle <= 0 {
		cfg.Idle = 10 * time.Minute
	}
	return &Limiter{
		rate:    cfg.Rate,
		burst:   float64(cfg.Burst),
		idle:    cfg.Idle,
		now:     time.Now,
		buckets: make(map[string]*bucket),
	}
}

// Allow reports whether one event may proceed under key, consuming a token if
// so.
func (l *Limiter) Allow(key string) bool {
	return l.AllowN(key, 1)
}

// AllowN reports whether n events may proceed under key.
//
// Either all n tokens are consumed or none are, so a caller cannot be charged
// for work it was not permitted to do.
func (l *Limiter) AllowN(key string, n float64) bool {
	if l.burst <= 0 {
		return false
	}

	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, seen: now}
		l.buckets[key] = b
	} else {
		elapsed := now.Sub(b.seen).Seconds()
		if elapsed > 0 {
			b.tokens = math.Min(l.burst, b.tokens+elapsed*l.rate)
		}
		b.seen = now
	}

	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

// Retry reports how long a caller should wait before one event under key would
// be permitted. It does not consume a token.
//
// This exists so a rejected request can carry a Retry-After header rather than
// inviting the caller to retry immediately in a loop.
func (l *Limiter) Retry(key string) time.Duration {
	if l.rate <= 0 {
		return l.idle
	}

	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		return 0
	}
	tokens := math.Min(l.burst, b.tokens+now.Sub(b.seen).Seconds()*l.rate)
	if tokens >= 1 {
		return 0
	}
	return time.Duration((1 - tokens) / l.rate * float64(time.Second))
}

// Forget discards the bucket for a key.
//
// Used when an upload is deleted, so that its password-attempt state does not
// outlive the upload it protected.
func (l *Limiter) Forget(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}

// Sweep discards buckets that have been idle longer than the configured
// duration, returning how many were removed.
//
// A bucket idle for longer than the refill period is already full, so removing
// it is indistinguishable from keeping it. Without this, an adversary cycling
// through addresses would grow the map without bound.
func (l *Limiter) Sweep() int {
	cutoff := l.now().Add(-l.idle)

	l.mu.Lock()
	defer l.mu.Unlock()

	removed := 0
	for key, b := range l.buckets {
		if b.seen.Before(cutoff) {
			delete(l.buckets, key)
			removed++
		}
	}
	return removed
}

// Len reports how many buckets are currently held.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
