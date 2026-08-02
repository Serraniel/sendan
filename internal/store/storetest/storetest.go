// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Package storetest is the conformance suite every [store.Store] must pass.
//
// It exists so that backends are held to one definition of correct behaviour
// rather than each carrying its own hand-written tests. A second backend that
// merely "has tests" is a second set of assumptions; a second backend that
// passes this suite behaves the same way as the first.
//
// Only the [store.Store] interface is used here. Anything that depends on how a
// particular backend stores its rows belongs in that backend's own tests.
package storetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Serraniel/sendan/internal/store"
)

// Factory returns a fresh, empty store for one test.
type Factory func(t *testing.T) store.Store

// Run executes the conformance suite.
func Run(t *testing.T, newStore Factory) {
	t.Helper()

	for name, fn := range map[string]func(*testing.T, Factory){
		"CreateAndGet":                  testCreateAndGet,
		"CreateRejectsDuplicates":       testCreateRejectsDuplicates,
		"CreateRejectsIncomplete":       testCreateRejectsIncomplete,
		"PasswordParametersRoundTrip":   testPasswordParametersRoundTrip,
		"NoPasswordMeansNoParameters":   testNoPasswordMeansNoParameters,
		"ExpiredIsUnreachable":          testExpiredIsUnreachable,
		"NoDeadlineNeverExpires":        testNoDeadlineNeverExpires,
		"DownloadLimitEnforced":         testDownloadLimitEnforced,
		"UnlimitedDownloads":            testUnlimitedDownloads,
		"ConcurrentClaimsRespectLimit":  testConcurrentClaimsRespectLimit,
		"DeleteIsHardAndIdempotent":     testDeleteIsHardAndIdempotent,
		"ListDeadFindsExpired":          testListDeadFindsExpired,
		"ListDeadFindsExhausted":        testListDeadFindsExhausted,
		"ListDeadRespectsLimit":         testListDeadRespectsLimit,
		"CheckpointIsSafeToCallAnyTime": testCheckpointIsSafeToCallAnyTime,
		"LargeValuesRoundTrip":          testLargeValuesRoundTrip,
	} {
		t.Run(name, func(t *testing.T) { fn(t, newStore) })
	}
}

// NewID returns a valid random upload identifier.
func NewID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Sample returns a complete, valid upload.
func Sample(t *testing.T, id string) *store.Upload {
	t.Helper()
	return &store.Upload{
		ID:               id,
		WrappedFileKey:   bytes.Repeat([]byte{0x01}, 48),
		WrapNonce:        bytes.Repeat([]byte{0x02}, 12),
		MetadataEnvelope: bytes.Repeat([]byte{0x03}, 256),
		MetadataNonce:    bytes.Repeat([]byte{0x04}, 12),
		AuthTokenHash:    bytes.Repeat([]byte{0x05}, 32),
		OwnerTokenHash:   bytes.Repeat([]byte{0x06}, 32),
		AtRestKey:        bytes.Repeat([]byte{0x07}, 32),
		Size:             1024,
		CreatedAt:        time.Now().UTC().Truncate(time.Second),
	}
}

func testCreateAndGet(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := t.Context()
	now := time.Now()

	want := Sample(t, NewID(t))
	want.ExpiresAt = now.Add(time.Hour).UTC().Truncate(time.Second)
	want.MaxDownloads = 3

	if err := s.Create(ctx, want); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.Get(ctx, want.ID, now)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	for _, f := range []struct {
		name string
		got  []byte
		want []byte
	}{
		{"wrapped file key", got.WrappedFileKey, want.WrappedFileKey},
		{"wrap nonce", got.WrapNonce, want.WrapNonce},
		{"metadata envelope", got.MetadataEnvelope, want.MetadataEnvelope},
		{"metadata nonce", got.MetadataNonce, want.MetadataNonce},
		{"auth token hash", got.AuthTokenHash, want.AuthTokenHash},
		{"owner token hash", got.OwnerTokenHash, want.OwnerTokenHash},
		{"at-rest key", got.AtRestKey, want.AtRestKey},
	} {
		if !bytes.Equal(f.got, f.want) {
			t.Errorf("%s changed in storage", f.name)
		}
	}
	if got.Size != want.Size || got.MaxDownloads != want.MaxDownloads {
		t.Errorf("size or limit changed: %d/%d", got.Size, got.MaxDownloads)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("expiry = %s, want %s", got.ExpiresAt, want.ExpiresAt)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("created = %s, want %s", got.CreatedAt, want.CreatedAt)
	}
}

func testCreateRejectsDuplicates(t *testing.T, newStore Factory) {
	s := newStore(t)
	u := Sample(t, NewID(t))
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Create(t.Context(), u); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("got %v, want ErrConflict", err)
	}
}

func testCreateRejectsIncomplete(t *testing.T, newStore Factory) {
	s := newStore(t)
	for name, mutate := range map[string]func(*store.Upload){
		"no identifier":    func(u *store.Upload) { u.ID = "" },
		"no wrapped key":   func(u *store.Upload) { u.WrappedFileKey = nil },
		"no wrap nonce":    func(u *store.Upload) { u.WrapNonce = nil },
		"no metadata":      func(u *store.Upload) { u.MetadataEnvelope = nil },
		"no auth hash":     func(u *store.Upload) { u.AuthTokenHash = nil },
		"no owner hash":    func(u *store.Upload) { u.OwnerTokenHash = nil },
		"no at-rest key":   func(u *store.Upload) { u.AtRestKey = nil },
		"negative size":    func(u *store.Upload) { u.Size = -1 },
		"negative limit":   func(u *store.Upload) { u.MaxDownloads = -1 },
		"no creation time": func(u *store.Upload) { u.CreatedAt = time.Time{} },
		"partial password": func(u *store.Upload) { u.Password = &store.PasswordParams{Salt: []byte{1}} },
	} {
		t.Run(name, func(t *testing.T) {
			u := Sample(t, NewID(t))
			mutate(u)
			if err := s.Create(t.Context(), u); !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}

func testPasswordParametersRoundTrip(t *testing.T, newStore Factory) {
	s := newStore(t)
	u := Sample(t, NewID(t))
	u.Password = &store.PasswordParams{
		Salt: bytes.Repeat([]byte{0x08}, 16), MemoryKiB: 65536, Iterations: 3, Parallelism: 1,
	}
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.Get(t.Context(), u.ID, time.Now())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Password == nil {
		t.Fatal("password parameters were lost")
	}
	if !bytes.Equal(got.Password.Salt, u.Password.Salt) ||
		got.Password.MemoryKiB != 65536 || got.Password.Iterations != 3 || got.Password.Parallelism != 1 {
		t.Fatalf("password parameters changed: %+v", got.Password)
	}
}

func testNoPasswordMeansNoParameters(t *testing.T, newStore Factory) {
	s := newStore(t)
	u := Sample(t, NewID(t))
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.Get(t.Context(), u.ID, time.Now())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Password != nil {
		t.Fatalf("password parameters appeared from nowhere: %+v", got.Password)
	}
}

// Lazy expiry: a dead upload is unreachable even before the reaper runs.
func testExpiredIsUnreachable(t *testing.T, newStore Factory) {
	s := newStore(t)
	now := time.Now()
	u := Sample(t, NewID(t))
	u.ExpiresAt = now.Add(-time.Second)
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := s.Get(t.Context(), u.ID, now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("get: got %v, want ErrNotFound", err)
	}
	if _, err := s.ClaimDownload(t.Context(), u.ID, now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("claim: got %v, want ErrNotFound", err)
	}
}

func testNoDeadlineNeverExpires(t *testing.T, newStore Factory) {
	s := newStore(t)
	u := Sample(t, NewID(t))
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
	far := time.Now().Add(100 * 365 * 24 * time.Hour)
	if _, err := s.Get(t.Context(), u.ID, far); err != nil {
		t.Fatalf("an upload with no deadline expired: %v", err)
	}
	dead, err := s.ListDead(t.Context(), far, 10)
	if err != nil {
		t.Fatalf("list dead: %v", err)
	}
	if len(dead) != 0 {
		t.Fatalf("the reaper would remove an upload that never expires: %v", dead)
	}
}

func testDownloadLimitEnforced(t *testing.T, newStore Factory) {
	s := newStore(t)
	now := time.Now()
	u := Sample(t, NewID(t))
	u.MaxDownloads = 2
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}

	for i := 1; i <= 2; i++ {
		got, err := s.ClaimDownload(t.Context(), u.ID, now)
		if err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
		if got.DownloadCount != i {
			t.Fatalf("claim %d recorded count %d", i, got.DownloadCount)
		}
	}
	if _, err := s.ClaimDownload(t.Context(), u.ID, now); !errors.Is(err, store.ErrExhausted) {
		t.Fatalf("third claim: got %v, want ErrExhausted", err)
	}
	if _, err := s.Get(t.Context(), u.ID, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an exhausted upload is still reachable: %v", err)
	}
}

func testUnlimitedDownloads(t *testing.T, newStore Factory) {
	s := newStore(t)
	now := time.Now()
	u := Sample(t, NewID(t))
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
	for i := range 20 {
		if _, err := s.ClaimDownload(t.Context(), u.ID, now); err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
	}
}

// Exceeding a download limit under concurrency is a security defect, not a
// cosmetic one: the uploader chose the limit and the file must not be readable
// more times than that.
func testConcurrentClaimsRespectLimit(t *testing.T, newStore Factory) {
	s := newStore(t)
	now := time.Now()

	const limit = 5
	const racers = 40

	u := Sample(t, NewID(t))
	u.MaxDownloads = limit
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
		other     []error
	)
	start := make(chan struct{})

	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.ClaimDownload(context.Background(), u.ID, now)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, store.ErrExhausted), errors.Is(err, store.ErrNotFound):
			default:
				other = append(other, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	for _, err := range other {
		t.Errorf("unexpected error: %v", err)
	}
	// Never more than the limit. Fewer is acceptable under contention, since a
	// losing writer may fail rather than corrupt; more is never acceptable.
	if succeeded > limit {
		t.Fatalf("%d concurrent claims succeeded, which exceeds the limit of %d", succeeded, limit)
	}
}

func testDeleteIsHardAndIdempotent(t *testing.T, newStore Factory) {
	s := newStore(t)
	u := Sample(t, NewID(t))
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
	for range 3 {
		if err := s.Delete(t.Context(), u.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
	}
	if _, err := s.Get(t.Context(), u.ID, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
	// Deleting removes the row, so the identifier is free again.
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("the identifier was not released by deletion: %v", err)
	}
}

func testListDeadFindsExpired(t *testing.T, newStore Factory) {
	s := newStore(t)
	now := time.Now()

	dead := Sample(t, NewID(t))
	dead.ExpiresAt = now.Add(-time.Hour)
	live := Sample(t, NewID(t))
	live.ExpiresAt = now.Add(time.Hour)

	for _, u := range []*store.Upload{dead, live} {
		if err := s.Create(t.Context(), u); err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	ids, err := s.ListDead(t.Context(), now, 10)
	if err != nil {
		t.Fatalf("list dead: %v", err)
	}
	if len(ids) != 1 || ids[0] != dead.ID {
		t.Fatalf("got %v, want only the expired upload", ids)
	}
}

func testListDeadFindsExhausted(t *testing.T, newStore Factory) {
	s := newStore(t)
	now := time.Now()
	u := Sample(t, NewID(t))
	u.MaxDownloads = 1
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.ClaimDownload(t.Context(), u.ID, now); err != nil {
		t.Fatalf("claim: %v", err)
	}
	ids, err := s.ListDead(t.Context(), now, 10)
	if err != nil {
		t.Fatalf("list dead: %v", err)
	}
	if len(ids) != 1 || ids[0] != u.ID {
		t.Fatalf("got %v, want the exhausted upload", ids)
	}
}

func testListDeadRespectsLimit(t *testing.T, newStore Factory) {
	s := newStore(t)
	now := time.Now()
	for range 3 {
		u := Sample(t, NewID(t))
		u.ExpiresAt = now.Add(-time.Hour)
		if err := s.Create(t.Context(), u); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	ids, err := s.ListDead(t.Context(), now, 2)
	if err != nil {
		t.Fatalf("list dead: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("got %d identifiers, want 2", len(ids))
	}
	none, err := s.ListDead(t.Context(), now, 0)
	if err != nil || none != nil {
		t.Fatalf("a limit of zero returned %v, %v", none, err)
	}
}

func testCheckpointIsSafeToCallAnyTime(t *testing.T, newStore Factory) {
	s := newStore(t)
	if err := s.Checkpoint(t.Context()); err != nil {
		t.Fatalf("checkpoint on an empty store: %v", err)
	}
	u := Sample(t, NewID(t))
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Delete(t.Context(), u.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.Checkpoint(t.Context()); err != nil {
		t.Fatalf("checkpoint after a deletion: %v", err)
	}
	if err := s.Checkpoint(t.Context()); err != nil {
		t.Fatalf("checkpoint twice: %v", err)
	}
}

// Metadata envelopes are padded and wrapped keys are fixed size, but nothing
// bounds them at the storage layer, so a backend must not silently truncate.
func testLargeValuesRoundTrip(t *testing.T, newStore Factory) {
	s := newStore(t)
	u := Sample(t, NewID(t))
	u.MetadataEnvelope = bytes.Repeat([]byte{0xAB}, 64*1024)
	u.Size = 1 << 40

	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.Get(t.Context(), u.ID, time.Now())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got.MetadataEnvelope, u.MetadataEnvelope) {
		t.Fatalf("a %d byte envelope came back as %d bytes",
			len(u.MetadataEnvelope), len(got.MetadataEnvelope))
	}
	if got.Size != u.Size {
		t.Fatalf("size %d came back as %d", u.Size, got.Size)
	}
}
