// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package ratelimit

import "time"

// Default password attempt limits.
//
// Generous enough that someone mistyping a password several times is not
// locked out, tight enough that guessing at scale is not possible online.
const (
	DefaultPasswordBurst = 5
	DefaultPasswordRate  = 1.0 / 60.0 // one attempt per minute, sustained
	DefaultPasswordIdle  = time.Hour
)

// PasswordAttempts limits password guesses against a single upload.
//
// # Why this is keyed by upload rather than by address
//
// An adversary controls which address a request comes from and can rotate
// through many, so a per-address limit alone places no bound on the total
// guesses one upload receives. Keying by upload bounds the whole attack
// regardless of where it originates.
//
// # Why a per-address limit is still needed alongside it
//
// Keying only by upload means one adversary can exhaust the allowance and lock
// out the intended recipient. The two limits answer different questions —
// "how hard may this file be attacked" and "how much may this client do" — and
// neither substitutes for the other.
//
// # What this does not defend
//
// An attacker holding both the link secret and a copy of the database can
// derive and test candidate passwords offline, where no server-side limit
// applies. This bounds the online case, which is the one available to someone
// who has only the link.
type PasswordAttempts struct {
	limiter *Limiter
}

// NewPasswordAttempts returns a limiter with the default policy.
func NewPasswordAttempts() *PasswordAttempts {
	return NewPasswordAttemptsWith(Config{
		Rate:  DefaultPasswordRate,
		Burst: DefaultPasswordBurst,
		Idle:  DefaultPasswordIdle,
	})
}

// NewPasswordAttemptsWith returns a limiter with an explicit policy.
func NewPasswordAttemptsWith(cfg Config) *PasswordAttempts {
	return &PasswordAttempts{limiter: New(cfg)}
}

// Allow reports whether another password attempt may be made against an upload.
//
// Call this before verifying the token, not after. Verifying first and counting
// only failures would let an attacker with a valid password consume no
// allowance while probing, and would make the limit depend on the outcome it is
// meant to constrain.
func (p *PasswordAttempts) Allow(uploadID string) bool {
	return p.limiter.Allow(uploadID)
}

// Retry reports how long before another attempt against an upload is permitted.
func (p *PasswordAttempts) Retry(uploadID string) time.Duration {
	return p.limiter.Retry(uploadID)
}

// Forget discards the attempt state for an upload.
//
// Deletion must call this. Attempt state keyed by upload identifier is state
// about an upload, and the project's guarantee is that a deleted upload leaves
// nothing behind — including in memory.
func (p *PasswordAttempts) Forget(uploadID string) {
	p.limiter.Forget(uploadID)
}

// Sweep discards idle attempt state, returning how many entries were removed.
func (p *PasswordAttempts) Sweep() int { return p.limiter.Sweep() }

// Len reports how many uploads currently have attempt state.
func (p *PasswordAttempts) Len() int { return p.limiter.Len() }
