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
		"CreateAndGet":                     testCreateAndGet,
		"CreateRejectsDuplicates":          testCreateRejectsDuplicates,
		"CreateRejectsIncomplete":          testCreateRejectsIncomplete,
		"PasswordParametersRoundTrip":      testPasswordParametersRoundTrip,
		"NoPasswordMeansNoParameters":      testNoPasswordMeansNoParameters,
		"ExpiredIsUnreachable":             testExpiredIsUnreachable,
		"NoDeadlineNeverExpires":           testNoDeadlineNeverExpires,
		"DownloadLimitEnforced":            testDownloadLimitEnforced,
		"UnlimitedDownloads":               testUnlimitedDownloads,
		"PartialTransfersChargedByVolume":  testPartialTransfersAreChargedByVolume,
		"RepeatedNearCompleteReadsCharged": testRepeatedNearCompleteReadsAreCharged,
		"ConcurrentServedBytesNotLost":     testConcurrentServedBytesAreNotLost,
		"DeleteIsHardAndIdempotent":        testDeleteIsHardAndIdempotent,
		"ListDeadFindsExpired":             testListDeadFindsExpired,
		"ListDeadFindsExhausted":           testListDeadFindsExhausted,
		"ListDeadRespectsLimit":            testListDeadRespectsLimit,
		"CheckpointIsSafeToCallAnyTime":    testCheckpointIsSafeToCallAnyTime,
		"LargeValuesRoundTrip":             testLargeValuesRoundTrip,
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
	// Recording bytes still succeeds on a row the reaper has not reached. A
	// transfer may have been in flight when the deadline passed, and those
	// bytes were served whatever the clock says. Liveness is enforced by Get,
	// which is what refuses to start a transfer.
	if _, err := s.RecordServed(t.Context(), u.ID, 1); err != nil {
		t.Errorf("record served on an expired row: %v", err)
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

	// A whole file's worth of bytes is one download, so serving the size twice
	// reaches the limit.
	for i := 1; i <= 2; i++ {
		got, err := s.RecordServed(t.Context(), u.ID, u.Size)
		if err != nil {
			t.Fatalf("serve %d: %v", i, err)
		}
		if got.DownloadCount != i {
			t.Fatalf("after serving %d files' worth the count is %d, want %d", i, got.DownloadCount, i)
		}
	}
	if _, err := s.Get(t.Context(), u.ID, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an exhausted upload is still reachable: %v", err)
	}
}

// A transfer that stops partway is charged for what it consumed, and resuming
// it costs nothing further. Counting requests would charge two for one file;
// counting only completions would let an attacker read almost all of a file
// repeatedly without ever being counted.
func testPartialTransfersAreChargedByVolume(t *testing.T, newStore Factory) {
	s := newStore(t)
	now := time.Now()
	u := Sample(t, NewID(t))
	u.MaxDownloads = 1
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Nine tenths of the file, then the rest: one download in total.
	got, err := s.RecordServed(t.Context(), u.ID, u.Size*9/10)
	if err != nil {
		t.Fatalf("partial: %v", err)
	}
	if got.DownloadCount != 0 {
		t.Fatalf("a partial transfer counted %d downloads, want 0", got.DownloadCount)
	}
	if _, err := s.Get(t.Context(), u.ID, now); err != nil {
		t.Fatalf("the upload became unreachable after a partial transfer: %v", err)
	}

	got, err = s.RecordServed(t.Context(), u.ID, u.Size-u.Size*9/10)
	if err != nil {
		t.Fatalf("remainder: %v", err)
	}
	if got.DownloadCount != 1 {
		t.Fatalf("resuming to completion counted %d downloads, want 1", got.DownloadCount)
	}
	if _, err := s.Get(t.Context(), u.ID, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the upload survived its only download: %v", err)
	}
}

// Reading almost all of a file repeatedly must be charged. This is the case
// that rules out counting completions.
func testRepeatedNearCompleteReadsAreCharged(t *testing.T, newStore Factory) {
	s := newStore(t)
	u := Sample(t, NewID(t))
	u.MaxDownloads = 2
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Three reads of 99%, none of them ever finishing.
	ninetyNine := u.Size * 99 / 100
	var last *store.Upload
	for i := range 3 {
		got, err := s.RecordServed(t.Context(), u.ID, ninetyNine)
		if err != nil {
			t.Fatalf("read %d: %v", i+1, err)
		}
		last = got
	}
	if last.DownloadCount < 2 {
		t.Fatalf("three reads of 99%% counted %d downloads; the limit is evadable by aborting", last.DownloadCount)
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
		if _, err := s.RecordServed(t.Context(), u.ID, u.Size); err != nil {
			t.Fatalf("serve %d: %v", i, err)
		}
	}
	if _, err := s.Get(t.Context(), u.ID, now); err != nil {
		t.Fatalf("an upload with no limit became unreachable: %v", err)
	}
}

// Losing a concurrent write is a security defect, not a cosmetic one: bytes
// that were served but not recorded are downloads the uploader's limit never
// sees.
//
// This replaces a test of atomic claiming. The invariant changed with the
// accounting model, but the lesson did not: accumulation and the derived count
// must be one operation, or concurrent transfers overwrite each other's totals.
func testConcurrentServedBytesAreNotLost(t *testing.T, newStore Factory) {
	s := newStore(t)

	const racers = 40
	const each = 64

	u := Sample(t, NewID(t))
	// No limit, so every writer proceeds and the total is the only thing under
	// test. A limit would let the row vanish mid-run and mask a lost update.
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		other []error
	)
	start := make(chan struct{})

	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := s.RecordServed(context.Background(), u.ID, each); err != nil {
				mu.Lock()
				other = append(other, err)
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	for _, err := range other {
		t.Errorf("unexpected error: %v", err)
	}

	got, err := s.Get(t.Context(), u.ID, time.Now())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if want := int64(racers * each); got.BytesServed != want {
		t.Fatalf("recorded %d bytes after %d concurrent writers, want %d: writes were lost",
			got.BytesServed, racers, want)
	}
	if want := int64(racers*each) / u.Size; got.DownloadCount != int(want) {
		t.Fatalf("download count %d, want %d", got.DownloadCount, want)
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
	if _, err := s.RecordServed(t.Context(), u.ID, u.Size); err != nil {
		t.Fatalf("serve: %v", err)
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
