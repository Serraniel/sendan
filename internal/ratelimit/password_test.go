// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package ratelimit

import (
	"testing"
	"time"
)

func withPasswordClock(cfg Config) (*PasswordAttempts, func(time.Duration)) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	p := NewPasswordAttemptsWith(cfg)
	p.limiter.now = func() time.Time { return now }
	return p, func(d time.Duration) { now = now.Add(d) }
}

func TestPasswordDefaultsAreStrict(t *testing.T) {
	p := NewPasswordAttempts()

	// A handful of mistyped attempts must not lock anyone out.
	for i := range DefaultPasswordBurst {
		if !p.Allow("upload") {
			t.Fatalf("attempt %d was refused; honest retries must be tolerated", i+1)
		}
	}
	if p.Allow("upload") {
		t.Fatal("attempts beyond the burst were allowed")
	}

	// The sustained rate has to be slow enough that online guessing is
	// hopeless. One per minute means under 1500 attempts a day.
	perDay := DefaultPasswordRate * 60 * 60 * 24
	if perDay > 2000 {
		t.Fatalf("the sustained rate permits %.0f attempts a day, which is too many", perDay)
	}
}

// An adversary controls which address a request comes from, so the limit must
// be keyed by upload or it places no bound on the total attack.
func TestAttemptsAreBoundedPerUpload(t *testing.T) {
	p, _ := withPasswordClock(Config{Rate: DefaultPasswordRate, Burst: 3, Idle: time.Hour})

	for range 3 {
		if !p.Allow("target") {
			t.Fatal("an attempt within the burst was refused")
		}
	}
	// Regardless of who is asking, this upload has had its allowance.
	if p.Allow("target") {
		t.Fatal("the per-upload bound was exceeded")
	}
	// A different upload is unaffected.
	if !p.Allow("other") {
		t.Fatal("one upload's exhausted allowance blocked another")
	}
}

func TestAttemptsRecoverSlowly(t *testing.T) {
	p, advance := withPasswordClock(Config{Rate: 1.0 / 60.0, Burst: 2, Idle: time.Hour})

	for i := range 2 {
		if !p.Allow("upload") {
			t.Fatalf("burst attempt %d was refused", i+1)
		}
	}
	if p.Allow("upload") {
		t.Fatal("the burst was exceeded")
	}

	advance(30 * time.Second)
	if p.Allow("upload") {
		t.Fatal("recovery was faster than the configured rate")
	}

	advance(31 * time.Second)
	if !p.Allow("upload") {
		t.Fatal("an attempt was still refused after the refill period")
	}
}

func TestRetryTellsTheClientWhenToReturn(t *testing.T) {
	p, _ := withPasswordClock(Config{Rate: 1.0 / 60.0, Burst: 1, Idle: time.Hour})
	if !p.Allow("upload") {
		t.Fatal("the first attempt was refused")
	}
	d := p.Retry("upload")
	if d <= 0 || d > time.Minute {
		t.Fatalf("retry after = %s, want just under a minute", d)
	}
}

// Attempt state keyed by upload identifier is state about an upload, and a
// deleted upload must leave nothing behind — including in memory.
func TestForgetClearsStateWhenAnUploadIsDeleted(t *testing.T) {
	p, _ := withPasswordClock(Config{Rate: DefaultPasswordRate, Burst: 1, Idle: time.Hour})

	if !p.Allow("upload") {
		t.Fatal("the first attempt was refused")
	}
	if p.Allow("upload") {
		t.Fatal("the burst was exceeded")
	}
	if p.Len() != 1 {
		t.Fatalf("holding %d entries, want 1", p.Len())
	}

	p.Forget("upload")
	if p.Len() != 0 {
		t.Fatalf("holding %d entries after Forget, want 0", p.Len())
	}
}

func TestIdleAttemptStateIsSwept(t *testing.T) {
	p, advance := withPasswordClock(Config{Rate: DefaultPasswordRate, Burst: 1, Idle: time.Minute})
	p.Allow("upload")
	advance(2 * time.Minute)
	if removed := p.Sweep(); removed != 1 {
		t.Fatalf("swept %d entries, want 1", removed)
	}
}
