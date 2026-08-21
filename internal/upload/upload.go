// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Package upload owns the lifecycle of an upload: creating it, revoking it, and
// removing it once it is dead.
//
// It is the only place that knows both the metadata store and the blob store,
// and therefore the only place that can guarantee the two stay consistent.
package upload

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Serraniel/sendan/internal/blob"
	"github.com/Serraniel/sendan/internal/logging"
	"github.com/Serraniel/sendan/internal/ratelimit"
	"github.com/Serraniel/sendan/internal/store"
)

var (
	// ErrTTLTooLong reports a requested lifetime beyond what the instance
	// permits.
	ErrTTLTooLong = errors.New("upload: requested lifetime exceeds the maximum")

	// ErrInfiniteTTLNotAllowed reports a request for an upload that never
	// expires on an instance that does not permit it.
	ErrInfiniteTTLNotAllowed = errors.New("upload: unlimited retention is not enabled")

	// ErrNotOwner reports a revocation attempt without the owner token.
	ErrNotOwner = errors.New("upload: not the owner")
)

// Policy is the retention policy an instance enforces, taken from
// configuration.
type Policy struct {
	DefaultTTL          time.Duration
	MaxTTL              time.Duration
	AllowInfiniteTTL    bool
	DefaultMaxDownloads int

	// RequireLimit refuses an upload that would have neither a deadline nor a
	// download limit.
	//
	// The two bounds are independent and either alone is enough: a file that
	// expires on Friday may be fetched any number of times until then, and a
	// file with three downloads and no deadline is gone once they are spent.
	// What this refuses is an upload with neither, which is a file that stays
	// until somebody remembers to remove it - and the reason this project
	// deletes anything at all is that nobody remembers.
	//
	// It can only bind when AllowInfiniteTTL is set, since otherwise every
	// upload already has a deadline.
	RequireLimit bool

	// IncompleteTTL is how long an upload may remain unfinished before the
	// reaper treats it as abandoned. Zero selects DefaultIncompleteTTL.
	//
	// It is measured from creation rather than from the last chunk, so it also
	// bounds how long a single upload may take. A day is generous for any size
	// an instance accepts by default, and the alternative - tracking activity -
	// would add a column written on every chunk to answer a question the reaper
	// asks once every few minutes.
	IncompleteTTL time.Duration
}

// Service ties the metadata store and the blob store together.
type Service struct {
	store  store.Store
	blobs  *blob.Shredder
	policy Policy
	log    *slog.Logger

	// attempts is optional. When present, deletion clears an upload's
	// password-attempt state, so that state about a deleted upload does not
	// outlive it in memory.
	attempts *ratelimit.PasswordAttempts

	// now is injectable so tests can control expiry without sleeping.
	now func() time.Time
}

// New returns a Service.
func New(s store.Store, blobs *blob.Shredder, policy Policy, log *slog.Logger) *Service {
	return &Service{store: s, blobs: blobs, policy: policy, log: log, now: time.Now}
}

// Policy returns the retention policy this service enforces.
//
// Read-only and by value, so a caller can describe the policy without being
// able to change it. The HTTP layer publishes some of it, because a person
// deciding whether to use an instance should not have to discover its rules by
// being refused.
func (s *Service) Policy() Policy { return s.policy }

// WithPasswordAttempts attaches a password attempt limiter whose state is
// cleared when an upload is deleted.
func (s *Service) WithPasswordAttempts(a *ratelimit.PasswordAttempts) *Service {
	s.attempts = a
	return s
}

// Now is the service's clock.
//
// Exported so anything sharing this lifecycle uses the same one. Tests inject a
// clock to reach expiry without sleeping, and a caller that reads the wall
// clock directly would quietly opt out of that.
func (s *Service) Now() time.Time { return s.now() }

// ErrUnbounded reports an upload that would never expire and could be
// downloaded any number of times.
var ErrUnbounded = errors.New(
	"upload: an upload needs either a deadline or a download limit; " +
		"this instance does not accept one with neither")

// EnsureBounded refuses an upload that has neither bound.
//
// Called after both have been resolved, because either one alone satisfies it
// and neither path knows the other's answer until then.
func (s *Service) EnsureBounded(expires time.Time, maxDownloads int) error {
	if !s.policy.RequireLimit {
		return nil
	}
	if expires.IsZero() && maxDownloads <= 0 {
		return ErrUnbounded
	}
	return nil
}

// ResolveExpiry turns a requested lifetime into a deadline, applying the
// instance policy.
//
// A zero request means "use the default". A negative request means "never
// expire", which requires the instance to permit it. An excessive request is
// rejected rather than silently clamped: an uploader who asked for a week and
// received a day would believe their file outlives what it does.
func (s *Service) ResolveExpiry(requested time.Duration) (time.Time, error) {
	switch {
	case requested < 0:
		if !s.policy.AllowInfiniteTTL {
			return time.Time{}, ErrInfiniteTTLNotAllowed
		}
		return time.Time{}, nil

	case requested == 0:
		if s.policy.DefaultTTL == 0 {
			if !s.policy.AllowInfiniteTTL {
				return time.Time{}, ErrInfiniteTTLNotAllowed
			}
			return time.Time{}, nil
		}
		return s.now().Add(s.policy.DefaultTTL), nil

	default:
		if s.policy.MaxTTL > 0 && requested > s.policy.MaxTTL {
			return time.Time{}, fmt.Errorf("%w: %s exceeds %s",
				ErrTTLTooLong, requested, s.policy.MaxTTL)
		}
		return s.now().Add(requested), nil
	}
}

// Revoke deletes an upload on presentation of its owner token.
//
// The token is compared in constant time against the stored hash. An upload
// that does not exist and a wrong token both yield ErrNotOwner, so a caller
// cannot use revocation to discover which identifiers exist.
func (s *Service) Revoke(ctx context.Context, id string, ownerToken []byte) error {
	u, err := s.store.Get(ctx, id, s.now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotOwner
		}
		return err
	}

	sum := sha256.Sum256(ownerToken)
	if subtle.ConstantTimeCompare(sum[:], u.OwnerTokenHash) != 1 {
		return ErrNotOwner
	}
	if err := s.Delete(ctx, id); err != nil {
		return err
	}
	// A revocation is a deliberate act, so it should not leave the row
	// recoverable from the write-ahead log until the next reaper pass.
	if err := s.store.Checkpoint(ctx); err != nil {
		s.log.Error("could not checkpoint after revocation", "error", err)
	}
	return nil
}

// Delete removes an upload entirely.
//
// The database row is removed first, and this ordering is deliberate. The row
// holds the blob's at-rest key, so once it is gone the blob is unreadable
// ciphertext even if removing it then fails or the process dies. Deleting the
// blob first would leave the opposite: a row still able to decrypt content that
// may or may not still exist.
//
// A crash between the two therefore leaves an orphan that discloses nothing,
// which is the failure mode worth having.
func (s *Service) Delete(ctx context.Context, id string) error {
	if err := s.store.Delete(ctx, id); err != nil {
		return fmt.Errorf("upload: delete metadata: %w", err)
	}
	// Attempt state is keyed by upload identifier, so it is state about the
	// upload. Leaving it behind would keep a record of a deleted upload in
	// memory, which the deletion guarantee does not permit.
	if s.attempts != nil {
		s.attempts.Forget(id)
	}
	if err := s.blobs.Delete(ctx, id); err != nil {
		// The content is already unrecoverable, so this is a housekeeping
		// failure rather than a disclosure. Report it and carry on.
		s.log.Error("blob left behind after metadata deletion",
			logging.FileID([]byte(id)), "error", err)
		return fmt.Errorf("upload: delete blob: %w", err)
	}
	return nil
}

// Reap removes up to limit uploads that have expired or exhausted their
// download allowance, returning how many were removed.
//
// It is safe to call concurrently with downloads: an upload the reaper has not
// reached yet is already unreachable, because liveness is evaluated on read.
func (s *Service) Reap(ctx context.Context, limit int) (int, error) {
	// An upload still being written after this long is abandoned: nothing will
	// finish it, and it holds an at-rest key and a partial blob.
	abandoned := s.now().Add(-s.incompleteTTL())
	ids, err := s.store.ListDead(ctx, s.now(), abandoned, limit)
	if err != nil {
		return 0, fmt.Errorf("upload: list dead: %w", err)
	}

	removed := 0
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		if err := s.Delete(ctx, id); err != nil {
			// One failure must not strand the rest of the batch.
			s.log.Error("could not reap upload", logging.FileID([]byte(id)), "error", err)
			continue
		}
		removed++
	}
	if removed > 0 {
		// Retire the write-ahead log so the removed rows do not survive on disk
		// in pages it still holds. Without this the metadata of a deleted
		// upload, including the at-rest key that makes its blob readable,
		// remains recoverable from the log file.
		if err := s.store.Checkpoint(ctx); err != nil {
			s.log.Error("could not checkpoint after reaping", "error", err)
		}
		s.log.Info("reaped expired uploads", "count", removed)
	}
	return removed, nil
}

// RunReaper sweeps on a ticker until ctx is cancelled.
//
// This is a backstop, not the mechanism. Expiry is enforced on every read, so a
// stalled or slow reaper delays the reclaiming of disk space but never makes a
// dead upload reachable.
func (s *Service) RunReaper(ctx context.Context, interval time.Duration, batch int) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.log.Info("reaper started", "interval", interval.String(), "batch", batch)
	for {
		select {
		case <-ctx.Done():
			s.log.Info("reaper stopped")
			return
		case <-ticker.C:
			// Keep sweeping while batches come back full, so a backlog is
			// cleared rather than trickled away one batch per tick.
			for {
				n, err := s.Reap(ctx, batch)
				if err != nil {
					if !errors.Is(err, context.Canceled) {
						s.log.Error("reaper pass failed", "error", err)
					}
					break
				}
				if n < batch {
					break
				}
			}
		}
	}
}

// DefaultIncompleteTTL is how long an upload may remain unfinished before it is
// treated as abandoned.
const DefaultIncompleteTTL = 24 * time.Hour

func (s *Service) incompleteTTL() time.Duration {
	if s.policy.IncompleteTTL > 0 {
		return s.policy.IncompleteTTL
	}
	return DefaultIncompleteTTL
}
