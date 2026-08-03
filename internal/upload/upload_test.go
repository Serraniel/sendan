// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package upload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Serraniel/sendan/internal/blob"
	"github.com/Serraniel/sendan/internal/logging"
	"github.com/Serraniel/sendan/internal/ratelimit"
	"github.com/Serraniel/sendan/internal/store"
)

type harness struct {
	svc       *Service
	store     *store.SQLite
	blobs     *blob.Shredder
	blobRoot  string
	logBuffer *bytes.Buffer
	clock     time.Time
}

func newHarness(t *testing.T, policy Policy) *harness {
	t.Helper()
	dir := t.TempDir()

	st, err := store.OpenSQLite(t.Context(), filepath.Join(dir, "sendan.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	blobRoot := filepath.Join(dir, "blobs")
	fsStore, err := blob.NewFS(blobRoot)
	if err != nil {
		t.Fatalf("open blobs: %v", err)
	}
	shredder := blob.NewShredder(fsStore)

	var buf bytes.Buffer
	log := logging.New(&buf, logging.Options{Level: slog.LevelDebug, Format: "json"})

	h := &harness{
		store: st, blobs: shredder, blobRoot: blobRoot,
		logBuffer: &buf, clock: time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC),
	}
	h.svc = New(st, shredder, policy, log)
	h.svc.now = func() time.Time { return h.clock }
	return h
}

// put stores an upload with content, returning the identifier and owner token.
func (h *harness) put(t *testing.T, id, content string, expiresAt time.Time, maxDownloads int) []byte {
	t.Helper()
	atRest, err := blob.NewAtRestKey()
	if err != nil {
		t.Fatalf("at-rest key: %v", err)
	}
	if _, err := h.blobs.Put(t.Context(), id, atRest, strings.NewReader(content)); err != nil {
		t.Fatalf("put blob: %v", err)
	}

	ownerToken := bytes.Repeat([]byte{0xAB}, 32)
	sum := sha256.Sum256(ownerToken)

	u := &store.Upload{
		ID:               id,
		WrappedFileKey:   bytes.Repeat([]byte{0x01}, 48),
		WrapNonce:        bytes.Repeat([]byte{0x02}, 12),
		MetadataEnvelope: bytes.Repeat([]byte{0x03}, 256),
		MetadataNonce:    bytes.Repeat([]byte{0x04}, 12),
		AuthTokenHash:    bytes.Repeat([]byte{0x05}, 32),
		OwnerTokenHash:   sum[:],
		AtRestKey:        atRest,
		Size:             int64(len(content)),
		CreatedAt:        h.clock,
		ExpiresAt:        expiresAt,
		MaxDownloads:     maxDownloads,
	}
	if err := h.store.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
	return ownerToken
}

// blobsOnDisk counts the files under the blob root.
//
// This, not a store read, is what tells us the reaper ran. Liveness is
// evaluated on read, so store.Get reports a dead upload as ErrNotFound the
// moment it expires, whether or not anything has reaped it. Only the reaper
// removes the file.
func (h *harness) blobsOnDisk(t *testing.T) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(h.blobRoot, func(path string, d fs.DirEntry, err error) error {
		// The reaper deletes while this walks, so an entry can vanish between
		// being listed and being visited. That is the state we are waiting for,
		// not a failure - but only below the root. A missing root would make
		// every count zero and turn the wait into a false pass.
		if errors.Is(err, fs.ErrNotExist) && path != h.blobRoot {
			return nil
		}
		if err != nil {
			return err
		}
		if !d.IsDir() {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the blob root: %v", err)
	}
	return n
}

// waitForBlobs blocks until the blob root holds want files, failing if it does
// not reach that state. It waits for the effect rather than for a duration:
// sleeping and hoping made these tests cover a different set of paths on
// roughly half their runs.
func (h *harness) waitForBlobs(t *testing.T, want int) {
	t.Helper()
	h.waitForBlobsWithin(t, want, 5*time.Second)
}

func (h *harness) waitForBlobsWithin(t *testing.T, want int, within time.Duration) {
	t.Helper()
	deadline := time.After(within)
	for {
		got := h.blobsOnDisk(t)
		if got == want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("the blob root holds %d files, want %d", got, want)
		case <-time.After(time.Millisecond):
		}
	}
}

// putWith stores an upload and lets a test adjust the row before it is written,
// for fields the common helper does not take.
func (h *harness) putWith(t *testing.T, id, content string, expiresAt time.Time,
	maxDownloads int, adjust func(*store.Upload),
) {
	t.Helper()
	atRest, err := blob.NewAtRestKey()
	if err != nil {
		t.Fatalf("at-rest key: %v", err)
	}
	if _, err := h.blobs.Put(t.Context(), id, atRest, strings.NewReader(content)); err != nil {
		t.Fatalf("put blob: %v", err)
	}

	sum := sha256.Sum256(bytes.Repeat([]byte{0xAB}, 32))
	u := &store.Upload{
		ID:               id,
		WrappedFileKey:   bytes.Repeat([]byte{0x01}, 48),
		WrapNonce:        bytes.Repeat([]byte{0x02}, 12),
		MetadataEnvelope: bytes.Repeat([]byte{0x03}, 256),
		MetadataNonce:    bytes.Repeat([]byte{0x04}, 12),
		AuthTokenHash:    bytes.Repeat([]byte{0x05}, 32),
		OwnerTokenHash:   sum[:],
		AtRestKey:        atRest,
		Size:             int64(len(content)),
		CreatedAt:        h.clock,
		ExpiresAt:        expiresAt,
		MaxDownloads:     maxDownloads,
	}
	if adjust != nil {
		adjust(u)
	}
	if err := h.store.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
}

func defaultPolicy() Policy {
	return Policy{DefaultTTL: 24 * time.Hour, MaxTTL: 7 * 24 * time.Hour}
}

func TestResolveExpiry(t *testing.T) {
	h := newHarness(t, defaultPolicy())

	got, err := h.svc.ResolveExpiry(0)
	if err != nil {
		t.Fatalf("default: %v", err)
	}
	if !got.Equal(h.clock.Add(24 * time.Hour)) {
		t.Errorf("default expiry = %s", got)
	}

	got, err = h.svc.ResolveExpiry(2 * time.Hour)
	if err != nil {
		t.Fatalf("explicit: %v", err)
	}
	if !got.Equal(h.clock.Add(2 * time.Hour)) {
		t.Errorf("explicit expiry = %s", got)
	}
}

// An uploader who asks for a week and silently receives a day would believe
// their file outlives what it does, so an excessive request is an error.
func TestExcessiveTTLIsRejectedNotClamped(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	if _, err := h.svc.ResolveExpiry(30 * 24 * time.Hour); !errors.Is(err, ErrTTLTooLong) {
		t.Fatalf("got %v, want ErrTTLTooLong", err)
	}
}

func TestInfiniteRetentionRequiresOptIn(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	if _, err := h.svc.ResolveExpiry(-1); !errors.Is(err, ErrInfiniteTTLNotAllowed) {
		t.Fatalf("got %v, want ErrInfiniteTTLNotAllowed", err)
	}

	permissive := newHarness(t, Policy{AllowInfiniteTTL: true})
	got, err := permissive.svc.ResolveExpiry(-1)
	if err != nil {
		t.Fatalf("opted in: %v", err)
	}
	if !got.IsZero() {
		t.Fatalf("expected no deadline, got %s", got)
	}
}

func TestRevokeRequiresTheOwnerToken(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	id := "REVOKEMEAAAAAAAAAAAAAA"
	owner := h.put(t, id, "secret", h.clock.Add(time.Hour), 0)

	if err := h.svc.Revoke(t.Context(), id, []byte("wrong token")); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("wrong token: got %v, want ErrNotOwner", err)
	}
	if _, err := h.store.Get(t.Context(), id, h.clock); err != nil {
		t.Fatalf("a failed revocation deleted the upload: %v", err)
	}

	if err := h.svc.Revoke(t.Context(), id, owner); err != nil {
		t.Fatalf("correct token: %v", err)
	}
	if _, err := h.store.Get(t.Context(), id, h.clock); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the upload survived revocation: %v", err)
	}
}

// Revocation must not become an oracle for which identifiers exist.
func TestRevokingAnUnknownUploadLooksLikeAWrongToken(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	err := h.svc.Revoke(t.Context(), "NEVEREXISTEDAAAAAAAAAA", []byte("anything"))
	if !errors.Is(err, ErrNotOwner) {
		t.Fatalf("got %v, want ErrNotOwner", err)
	}
}

func TestReapRemovesExpiredAndExhaustedUploads(t *testing.T) {
	h := newHarness(t, defaultPolicy())

	live := "LIVEAAAAAAAAAAAAAAAAAA"
	expired := "EXPIREDAAAAAAAAAAAAAAA"
	exhausted := "EXHAUSTEDAAAAAAAAAAAAA"

	h.put(t, live, "still here", h.clock.Add(time.Hour), 0)
	h.put(t, expired, "gone", h.clock.Add(-time.Second), 0)
	h.put(t, exhausted, "gone", h.clock.Add(time.Hour), 1)
	// "gone" is four bytes, so serving four is one whole download and exhausts
	// a limit of one.
	if _, err := h.store.RecordServed(t.Context(), exhausted, int64(len("gone"))); err != nil {
		t.Fatalf("record served: %v", err)
	}

	n, err := h.svc.Reap(t.Context(), 100)
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	if n != 2 {
		t.Fatalf("reaped %d uploads, want 2", n)
	}
	if _, err := h.store.Get(t.Context(), live, h.clock); err != nil {
		t.Fatalf("the reaper removed a live upload: %v", err)
	}
}

func TestReapRespectsTheBatchLimit(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	for _, id := range []string{"D1AAAAAAAAAAAAAAAAAAAA", "D2AAAAAAAAAAAAAAAAAAAA", "D3AAAAAAAAAAAAAAAAAAAA"} {
		h.put(t, id, "x", h.clock.Add(-time.Hour), 0)
	}
	n, err := h.svc.Reap(t.Context(), 2)
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	if n != 2 {
		t.Fatalf("reaped %d, want 2", n)
	}
}

// The row holds the blob's at-rest key, so removing it first means a crash
// between the two leaves an orphan that discloses nothing.
func TestDeleteRemovesMetadataBeforeTheBlob(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	id := "ORDERAAAAAAAAAAAAAAAAA"
	h.put(t, id, "content", h.clock.Add(time.Hour), 0)

	// A blob store that always fails simulates a crash after the row is gone.
	failing := New(h.store, blob.NewShredder(failingStore{}), defaultPolicy(),
		logging.New(io.Discard, logging.Options{Format: "json"}))
	failing.now = h.svc.now

	if err := failing.Delete(t.Context(), id); err == nil {
		t.Fatal("expected the blob failure to be reported")
	}
	// The row must be gone regardless: that is what destroys the content.
	if _, err := h.store.Get(t.Context(), id, h.clock); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the metadata survived a failed blob deletion: %v", err)
	}
}

// This is the guarantee the project is built around: once an upload is gone,
// nothing about it remains anywhere.
func TestNothingSurvivesReaping(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	const id = "LEAVENOTRACEAAAAAAAAAA"
	const content = "the quick brown fox jumps over the lazy dog"

	h.put(t, id, content, h.clock.Add(time.Hour), 0)

	// Advance past the deadline and reap.
	h.clock = h.clock.Add(2 * time.Hour)
	if _, err := h.svc.Reap(t.Context(), 100); err != nil {
		t.Fatalf("reap: %v", err)
	}

	t.Run("no metadata row", func(t *testing.T) {
		if _, err := h.store.Get(t.Context(), id, h.clock); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}
	})

	t.Run("no blob", func(t *testing.T) {
		if _, err := h.blobs.Open(t.Context(), id, bytes.Repeat([]byte{0}, blob.AtRestKeySize)); err == nil {
			t.Fatal("the blob is still readable")
		}
	})

	t.Run("no file on disk", func(t *testing.T) {
		err := filepath.WalkDir(h.blobRoot, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				t.Errorf("residual file: %s", path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
	})

	t.Run("no identifier in the logs", func(t *testing.T) {
		if strings.Contains(h.logBuffer.String(), id) {
			t.Fatalf("the identifier survives in the logs:\n%s", h.logBuffer.String())
		}
	})

	t.Run("no content anywhere on disk", func(t *testing.T) {
		err := filepath.WalkDir(filepath.Dir(h.blobRoot), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err //nolint:nilerr // directories are skipped, errors propagate
			}
			data, readErr := readAll(path)
			if readErr != nil {
				return nil //nolint:nilerr // unreadable files are not evidence
			}
			if bytes.Contains(data, []byte(content)) {
				t.Errorf("plaintext content found in %s", path)
			}
			if bytes.Contains(data, []byte(id)) {
				t.Errorf("identifier found in %s", path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
	})
}

func TestReaperLoopStopsOnCancellation(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	h.put(t, "LOOPAAAAAAAAAAAAAAAAAA", "x", h.clock.Add(-time.Hour), 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.svc.RunReaper(ctx, 5*time.Millisecond, 10)
		close(done)
	}()

	// The blob, not the store read, is the evidence that the loop ran.
	h.waitForBlobs(t, 0)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the reaper did not stop when cancelled")
	}

	if _, err := h.store.Get(context.Background(), "LOOPAAAAAAAAAAAAAAAAAA", h.clock); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the reaper loop did not remove the dead upload: %v", err)
	}
}

type failingStore struct{}

func (failingStore) Put(context.Context, string, io.Reader) (int64, error) {
	return 0, errors.New("blob store unavailable")
}

func (failingStore) Open(context.Context, string) (io.ReadSeekCloser, error) {
	return nil, errors.New("blob store unavailable")
}

func (failingStore) Delete(context.Context, string) error {
	return errors.New("blob store unavailable")
}

func readAll(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // walking a temporary directory in a test
}

// Attempt state is keyed by upload identifier, so it is state about the upload.
// A deleted upload must leave nothing behind, including in memory.
func TestDeleteClearsPasswordAttemptState(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	attempts := ratelimit.NewPasswordAttempts()
	h.svc = h.svc.WithPasswordAttempts(attempts)

	const id = "ATTEMPTSAAAAAAAAAAAAAA"
	h.put(t, id, "content", h.clock.Add(time.Hour), 0)

	if !attempts.Allow(id) {
		t.Fatal("the first attempt was refused")
	}
	if attempts.Len() != 1 {
		t.Fatalf("holding %d entries, want 1", attempts.Len())
	}

	if err := h.svc.Delete(t.Context(), id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if attempts.Len() != 0 {
		t.Fatalf("attempt state for a deleted upload survives: %d entries", attempts.Len())
	}
}

// checkpointFailure fails to retire the write-ahead log.
type checkpointFailure struct{ store.Store }

func (checkpointFailure) Checkpoint(context.Context) error {
	return errors.New("checkpoint unavailable")
}

// A failed checkpoint means reclaimable data stays in the write-ahead log,
// which is worth an error in the log. The uploads themselves are already gone,
// so the sweep must report them as removed rather than fail.
//
// This branch was previously covered on roughly one run in twelve, by a
// checkpoint that happened to fail under a cancelled context. Coverage by
// accident is not coverage.
func TestReapReportsRemovalsWhenTheCheckpointFails(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	h.put(t, "CKPTAAAAAAAAAAAAAAAAAA", "x", h.clock.Add(-time.Hour), 0)

	var buf bytes.Buffer
	svc := New(checkpointFailure{h.store}, h.blobs, defaultPolicy(),
		logging.New(&buf, logging.Options{Level: slog.LevelDebug, Format: "json"}))
	svc.now = h.svc.now

	n, err := svc.Reap(t.Context(), 10)
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	if n != 1 {
		t.Fatalf("reaped %d, want 1", n)
	}
	if !strings.Contains(buf.String(), "could not checkpoint after reaping") {
		t.Fatalf("the checkpoint failure was not reported:\n%s", buf.String())
	}
	if got := h.blobsOnDisk(t); got != 0 {
		t.Fatalf("the blob root holds %d files after reaping, want 0", got)
	}
}

// sweepSignal reports each sweep the reaper performs, so a test can tell how
// much work one tick did rather than only what had happened by some deadline.
type sweepSignal struct {
	store.Store
	sweeps chan struct{}
}

func (s *sweepSignal) ListDead(ctx context.Context, now time.Time, limit int) ([]string, error) {
	select {
	case s.sweeps <- struct{}{}:
	default:
	}
	return s.Store.ListDead(ctx, now, limit)
}

// A backlog larger than one batch must be cleared within a single tick rather
// than trickled away at one batch per tick.
//
// The tick interval is long and the assertion window short, so the whole
// backlog has to go on the first tick. With a short interval this test passed
// against a reaper that swept once per tick, because the extra ticks arrived
// before the deadline: it measured the ticker, not the drain loop.
func TestReaperLoopDrainsABacklogLargerThanOneBatch(t *testing.T) {
	h := newHarness(t, defaultPolicy())

	ids := []string{
		"BL1AAAAAAAAAAAAAAAAAAA", "BL2AAAAAAAAAAAAAAAAAAA", "BL3AAAAAAAAAAAAAAAAAAA",
		"BL4AAAAAAAAAAAAAAAAAAA", "BL5AAAAAAAAAAAAAAAAAAA",
	}
	for _, id := range ids {
		h.put(t, id, "x", h.clock.Add(-time.Hour), 0)
	}

	const tick = 2 * time.Second
	signal := &sweepSignal{Store: h.store, sweeps: make(chan struct{}, 1)}
	svc := New(signal, h.blobs, defaultPolicy(),
		logging.New(io.Discard, logging.Options{Format: "json"}))
	svc.now = h.svc.now

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		// A batch of two against five dead uploads forces the drain loop.
		svc.RunReaper(ctx, tick, 2)
		close(done)
	}()

	select {
	case <-signal.sweeps:
	case <-time.After(tick + 5*time.Second):
		t.Fatal("the reaper never swept")
	}

	// Well inside the tick, so anything still here means the loop is waiting
	// for the next one instead of draining.
	h.waitForBlobsWithin(t, 0, tick/4)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the reaper did not stop when cancelled")
	}
}

// A reaper whose store fails must log and keep running rather than exit,
// otherwise one transient error stops all reclamation until a restart.
func TestReaperSurvivesAFailingBlobStore(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	h.put(t, "FAILAAAAAAAAAAAAAAAAAA", "x", h.clock.Add(-time.Hour), 0)

	failing := New(h.store, blob.NewShredder(failingStore{}), defaultPolicy(),
		logging.New(io.Discard, logging.Options{Format: "json"}))
	failing.now = h.svc.now

	// Delete fails at the blob step, but the row is already gone, so a second
	// pass finds nothing and reports zero rather than looping forever.
	if _, err := failing.Reap(t.Context(), 10); err != nil {
		t.Fatalf("reap: %v", err)
	}
	n, err := failing.Reap(t.Context(), 10)
	if err != nil {
		t.Fatalf("second reap: %v", err)
	}
	if n != 0 {
		t.Fatalf("second reap removed %d, want 0", n)
	}
}
