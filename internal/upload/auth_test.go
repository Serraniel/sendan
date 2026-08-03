// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package upload

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/Serraniel/sendan/internal/crypto"
	"github.com/Serraniel/sendan/internal/ratelimit"
	"github.com/Serraniel/sendan/internal/store"
)

// authFixture stores an upload whose token is known, and returns it.
func authFixture(t *testing.T, h *harness, id string) []byte {
	t.Helper()
	token := bytes.Repeat([]byte{0x11}, 32)
	h.putWith(t, id, "content", h.clock.Add(time.Hour), 0, func(u *store.Upload) {
		u.AuthTokenHash = crypto.AuthTokenHash(token)
	})
	return token
}

func TestAuthenticateAcceptsTheRightToken(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	const id = "AUTHOKAAAAAAAAAAAAAAAA"
	token := authFixture(t, h, id)

	if err := h.svc.Authenticate(t.Context(), id, token); err != nil {
		t.Fatalf("the correct token was refused: %v", err)
	}
}

func TestAuthenticateRejectsAWrongToken(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	const id = "AUTHBADAAAAAAAAAAAAAAA"
	authFixture(t, h, id)

	tests := map[string][]byte{
		"a different token": bytes.Repeat([]byte{0x22}, 32),
		"an empty token":    {},
		"a truncated token": bytes.Repeat([]byte{0x11}, 16),
		"a longer token":    bytes.Repeat([]byte{0x11}, 33),
	}
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			if err := h.svc.Authenticate(t.Context(), id, token); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("got %v, want ErrUnauthorized", err)
			}
		})
	}
}

// Checking a password is not using the file. An upload whose allowance could be
// spent by attempts would be destroyed by anyone able to reach it, without ever
// producing a valid token.
func TestAuthenticateDoesNotClaimADownload(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	const id = "AUTHNOCLAIMAAAAAAAAAAA"

	token := bytes.Repeat([]byte{0x11}, 32)
	h.putWith(t, id, "content", h.clock.Add(time.Hour), 3, func(u *store.Upload) {
		u.AuthTokenHash = crypto.AuthTokenHash(token)
	})

	for range 3 {
		if err := h.svc.Authenticate(t.Context(), id, token); err != nil {
			t.Fatalf("authenticate: %v", err)
		}
	}

	u, err := h.store.Get(t.Context(), id, h.clock)
	if err != nil {
		t.Fatalf("the upload is gone after three authentications: %v", err)
	}
	if u.DownloadCount != 0 {
		t.Errorf("download count %d after three authentications, want 0", u.DownloadCount)
	}
}

// The limit is keyed by upload, so it bounds how hard one file may be attacked
// no matter how many addresses the attempts come from.
func TestAuthenticateLimitsAttemptsPerUpload(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	attempts := ratelimit.NewPasswordAttemptsWith(ratelimit.Config{
		Rate: 0, Burst: 3, Idle: time.Hour,
	})
	h.svc = h.svc.WithPasswordAttempts(attempts)

	const id = "AUTHLIMITAAAAAAAAAAAAA"
	authFixture(t, h, id)
	wrong := bytes.Repeat([]byte{0x22}, 32)

	for i := range 3 {
		if err := h.svc.Authenticate(t.Context(), id, wrong); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("attempt %d: got %v, want ErrUnauthorized", i+1, err)
		}
	}

	if err := h.svc.Authenticate(t.Context(), id, wrong); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("got %v, want ErrTooManyAttempts", err)
	}
	if d := h.svc.RetryAfter(id); d <= 0 {
		t.Errorf("RetryAfter = %s, want a positive wait so a client knows when to return", d)
	}
}

// Once throttled, a correct token must be refused too. Otherwise the limit
// bounds nothing: an attacker's winning guess would be accepted at the moment
// the allowance ran out.
func TestThrottlingAppliesToACorrectTokenAsWell(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	attempts := ratelimit.NewPasswordAttemptsWith(ratelimit.Config{
		Rate: 0, Burst: 2, Idle: time.Hour,
	})
	h.svc = h.svc.WithPasswordAttempts(attempts)

	const id = "AUTHTHROTTLEAAAAAAAAAA"
	token := authFixture(t, h, id)
	wrong := bytes.Repeat([]byte{0x22}, 32)

	for range 2 {
		_ = h.svc.Authenticate(t.Context(), id, wrong)
	}
	if err := h.svc.Authenticate(t.Context(), id, token); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("a correct token was accepted while throttled: %v", err)
	}
}

// A recipient who mistypes a password several times and then gets it right has
// proved they are entitled to the file. Leaving them throttled afterwards would
// penalise the person the upload is for.
func TestASuccessfulAttemptClearsTheRecord(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	attempts := ratelimit.NewPasswordAttemptsWith(ratelimit.Config{
		Rate: 0, Burst: 3, Idle: time.Hour,
	})
	h.svc = h.svc.WithPasswordAttempts(attempts)

	const id = "AUTHRESETAAAAAAAAAAAAA"
	token := authFixture(t, h, id)
	wrong := bytes.Repeat([]byte{0x22}, 32)

	for range 2 {
		_ = h.svc.Authenticate(t.Context(), id, wrong)
	}
	if err := h.svc.Authenticate(t.Context(), id, token); err != nil {
		t.Fatalf("the correct token was refused with budget remaining: %v", err)
	}

	// The budget is back: three more failures are needed to throttle again.
	for i := range 3 {
		if err := h.svc.Authenticate(t.Context(), id, wrong); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("attempt %d after a success: got %v, want ErrUnauthorized", i+1, err)
		}
	}
}

// The limit is charged whatever the outcome. Charging only for failures would
// leave the budget untouched by a correctly guessed token, which is the one
// case worth bounding.
func TestASuccessConsumesFromTheAllowance(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	attempts := ratelimit.NewPasswordAttemptsWith(ratelimit.Config{
		Rate: 0, Burst: 2, Idle: time.Hour,
	})
	h.svc = h.svc.WithPasswordAttempts(attempts)

	const id = "AUTHCHARGEAAAAAAAAAAAA"
	token := authFixture(t, h, id)

	// One success, which resets the bucket, then the bucket is spent again.
	if err := h.svc.Authenticate(t.Context(), id, token); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if attempts.Len() != 0 {
		t.Fatalf("a successful attempt left %d buckets, want 0", attempts.Len())
	}
}

// Liveness is evaluated on read, so a dead upload cannot be authenticated
// against - and must not consume an attempt on the way to being refused.
func TestAuthenticateRefusesDeadUploads(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	attempts := ratelimit.NewPasswordAttemptsWith(ratelimit.Config{
		Rate: 0, Burst: 1, Idle: time.Hour,
	})
	h.svc = h.svc.WithPasswordAttempts(attempts)

	const id = "AUTHDEADAAAAAAAAAAAAAA"
	token := bytes.Repeat([]byte{0x11}, 32)
	h.putWith(t, id, "content", h.clock.Add(-time.Hour), 0, func(u *store.Upload) {
		u.AuthTokenHash = crypto.AuthTokenHash(token)
	})

	if err := h.svc.Authenticate(t.Context(), id, token); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
	if attempts.Len() != 0 {
		t.Errorf("a dead upload consumed an attempt: %d buckets", attempts.Len())
	}
}

func TestAuthenticateOnAnUnknownUpload(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	err := h.svc.Authenticate(t.Context(), "AUTHNONEAAAAAAAAAAAAAA", bytes.Repeat([]byte{0x11}, 32))
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

// A service without a limiter must still authenticate. The limiter is optional
// wiring, not a precondition.
func TestAuthenticateWorksWithoutALimiter(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	const id = "AUTHNOLIMITAAAAAAAAAAA"
	token := authFixture(t, h, id)

	if h.svc.attempts != nil {
		t.Fatal("the fixture already has a limiter, so this proves nothing")
	}
	if err := h.svc.Authenticate(t.Context(), id, token); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if d := h.svc.RetryAfter(id); d != 0 {
		t.Errorf("RetryAfter = %s without a limiter, want 0", d)
	}
}
