// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newStore(t *testing.T) *SQLite {
	t.Helper()
	s, err := OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "sendan.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func sample(id string) *Upload {
	return &Upload{
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

func TestCreateAndGet(t *testing.T) {
	s := newStore(t)
	now := time.Now()

	want := sample("AAAABBBBCCCCDDDDEEEEFF")
	want.ExpiresAt = now.Add(time.Hour).UTC().Truncate(time.Second)
	want.MaxDownloads = 3
	want.Password = &PasswordParams{
		Salt: bytes.Repeat([]byte{0x08}, 16), MemoryKiB: 65536, Iterations: 3, Parallelism: 1,
	}

	if err := s.Create(t.Context(), want); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.Get(t.Context(), want.ID, now)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	if got.ID != want.ID || !bytes.Equal(got.WrappedFileKey, want.WrappedFileKey) ||
		!bytes.Equal(got.MetadataEnvelope, want.MetadataEnvelope) ||
		!bytes.Equal(got.AtRestKey, want.AtRestKey) ||
		got.Size != want.Size || got.MaxDownloads != want.MaxDownloads {
		t.Fatalf("round trip changed the upload\n got %+v\nwant %+v", got, want)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("expiry = %s, want %s", got.ExpiresAt, want.ExpiresAt)
	}
	if got.Password == nil || !bytes.Equal(got.Password.Salt, want.Password.Salt) ||
		got.Password.MemoryKiB != 65536 || got.Password.Iterations != 3 || got.Password.Parallelism != 1 {
		t.Errorf("password parameters = %+v", got.Password)
	}
}

func TestUploadWithoutPasswordHasNoParameters(t *testing.T) {
	s := newStore(t)
	u := sample("NOPASSWORDAAAAAAAAAAAA")
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

func TestCreateRejectsDuplicates(t *testing.T) {
	s := newStore(t)
	u := sample("DUPLICATEAAAAAAAAAAAAA")
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Create(t.Context(), u); !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v, want ErrConflict", err)
	}
}

// An upload past its deadline must be unreachable even when the reaper has not
// run, which is what makes lazy expiry a guarantee rather than an optimisation.
func TestExpiredUploadIsUnreachableBeforeReaping(t *testing.T) {
	s := newStore(t)
	now := time.Now()

	u := sample("EXPIREDAAAAAAAAAAAAAAA")
	u.ExpiresAt = now.Add(-time.Second)
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := s.Get(t.Context(), u.ID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get: got %v, want ErrNotFound", err)
	}
	if _, err := s.ClaimDownload(t.Context(), u.ID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("claim: got %v, want ErrNotFound", err)
	}

	// The row is still present until the reaper removes it, which is exactly
	// why lazy expiry has to exist.
	dead, err := s.ListDead(t.Context(), now, 10)
	if err != nil {
		t.Fatalf("list dead: %v", err)
	}
	if len(dead) != 1 || dead[0] != u.ID {
		t.Fatalf("reaper would not find the expired upload: %v", dead)
	}
}

func TestUploadWithoutExpiryNeverExpires(t *testing.T) {
	s := newStore(t)
	u := sample("FOREVERAAAAAAAAAAAAAAA")
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

func TestDownloadLimitIsEnforced(t *testing.T) {
	s := newStore(t)
	now := time.Now()
	u := sample("LIMITEDAAAAAAAAAAAAAAA")
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
	if _, err := s.ClaimDownload(t.Context(), u.ID, now); !errors.Is(err, ErrExhausted) {
		t.Fatalf("third claim: got %v, want ErrExhausted", err)
	}
	if _, err := s.Get(t.Context(), u.ID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an exhausted upload is still reachable: %v", err)
	}
}

func TestUnlimitedDownloadsAreNotCapped(t *testing.T) {
	s := newStore(t)
	now := time.Now()
	u := sample("UNLIMITEDAAAAAAAAAAAAA")
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
	for i := range 20 {
		if _, err := s.ClaimDownload(t.Context(), u.ID, now); err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
	}
}

// The issue calls a concurrent over-limit download a security defect rather
// than a cosmetic one, so this asserts the claim is genuinely atomic: with a
// limit of N and many simultaneous requests, exactly N may succeed.
//
// Each goroutine uses its own store handle, and therefore its own connection.
// Racing through a single handle would prove nothing: the pool is capped at one
// connection, so it serialises every statement and a read-then-write
// implementation would pass. Real concurrency is what makes this test able to
// fail.
func TestConcurrentClaimsNeverExceedTheLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "race.db")
	s, err := OpenSQLite(t.Context(), path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()
	now := time.Now()

	const limit = 5
	const racers = 24

	u := sample("RACEAAAAAAAAAAAAAAAAAA")
	u.MaxDownloads = limit
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}

	handles := make([]*SQLite, racers)
	for i := range handles {
		h, err := OpenSQLite(t.Context(), path)
		if err != nil {
			t.Fatalf("open handle %d: %v", i, err)
		}
		handles[i] = h
		defer func() { _ = h.Close() }()
	}

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
		other     []error
	)
	start := make(chan struct{})

	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := handles[i].ClaimDownload(context.Background(), u.ID, now)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrExhausted), errors.Is(err, ErrNotFound):
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
	if succeeded != limit {
		t.Fatalf("%d of %d concurrent claims succeeded, want exactly %d", succeeded, racers, limit)
	}

	final, err := s.ClaimDownload(t.Context(), u.ID, now)
	if !errors.Is(err, ErrExhausted) {
		t.Fatalf("after the race: got %v (%+v), want ErrExhausted", err, final)
	}
}

func TestDeleteIsHardAndIdempotent(t *testing.T) {
	s := newStore(t)
	u := sample("DELETEMEAAAAAAAAAAAAAA")
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
	for range 3 {
		if err := s.Delete(t.Context(), u.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
	}
	if _, err := s.Get(t.Context(), u.ID, time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}

	// Deletion must remove the row, not mark it. A tombstone would keep the
	// at-rest key alive and make the no-leftovers guarantee false.
	var count int
	if err := s.db.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM uploads WHERE id = ?`, u.ID).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("%d rows survive deletion", count)
	}
}

// The schema must make a tombstone impossible, not merely unused.
func TestSchemaHasNoSoftDeleteColumns(t *testing.T) {
	s := newStore(t)
	rows, err := s.db.QueryContext(t.Context(), `SELECT name FROM pragma_table_info('uploads')`)
	if err != nil {
		t.Fatalf("table info: %v", err)
	}
	defer func() { _ = rows.Close() }()

	forbidden := []string{"deleted", "removed", "tombstone", "archived", "is_active", "state"}
	var columns []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		columns = append(columns, name)
		for _, bad := range forbidden {
			if strings.Contains(strings.ToLower(name), bad) {
				t.Errorf("column %q looks like a soft delete; deletion must remove the row", name)
			}
		}
	}
	if len(columns) == 0 {
		t.Fatal("the uploads table has no columns")
	}
}

// Nothing may retain an upload identifier after deletion.
func TestNoTableRetainsIdentifiersAfterDeletion(t *testing.T) {
	s := newStore(t)
	u := sample("RESIDUEAAAAAAAAAAAAAAA")
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Delete(t.Context(), u.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	rows, err := s.db.QueryContext(t.Context(),
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatalf("tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		tables = append(tables, name)
	}
	_ = rows.Close()

	// Dump every table and look for the identifier anywhere in it.
	for _, table := range tables {
		//nolint:gosec // table names come from sqlite_master, never from input
		dump, err := s.db.QueryContext(t.Context(), `SELECT * FROM "`+table+`"`)
		if err != nil {
			t.Fatalf("dump %s: %v", table, err)
		}
		cols, _ := dump.Columns()
		for dump.Next() {
			cells := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range cells {
				ptrs[i] = &cells[i]
			}
			if err := dump.Scan(ptrs...); err != nil {
				t.Fatalf("scan %s: %v", table, err)
			}
			for i, c := range cells {
				if str, ok := c.(string); ok && strings.Contains(str, u.ID) {
					t.Errorf("table %s column %s retains the identifier after deletion", table, cols[i])
				}
			}
		}
		_ = dump.Close()
	}
}

func TestListDeadRespectsLimit(t *testing.T) {
	s := newStore(t)
	now := time.Now()
	for _, id := range []string{"DEAD1AAAAAAAAAAAAAAAAA", "DEAD2AAAAAAAAAAAAAAAAA", "DEAD3AAAAAAAAAAAAAAAAA"} {
		u := sample(id)
		u.ExpiresAt = now.Add(-time.Hour)
		if err := s.Create(t.Context(), u); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	dead, err := s.ListDead(t.Context(), now, 2)
	if err != nil {
		t.Fatalf("list dead: %v", err)
	}
	if len(dead) != 2 {
		t.Fatalf("got %d identifiers, want 2", len(dead))
	}
	if none, err := s.ListDead(t.Context(), now, 0); err != nil || none != nil {
		t.Fatalf("a limit of zero returned %v, %v", none, err)
	}
}

func TestListDeadFindsExhaustedUploads(t *testing.T) {
	s := newStore(t)
	now := time.Now()
	u := sample("EXHAUSTEDAAAAAAAAAAAAA")
	u.MaxDownloads = 1
	if err := s.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.ClaimDownload(t.Context(), u.ID, now); err != nil {
		t.Fatalf("claim: %v", err)
	}
	dead, err := s.ListDead(t.Context(), now, 10)
	if err != nil {
		t.Fatalf("list dead: %v", err)
	}
	if len(dead) != 1 || dead[0] != u.ID {
		t.Fatalf("the reaper would not collect an exhausted upload: %v", dead)
	}
}

func TestCreateRejectsIncompleteUploads(t *testing.T) {
	s := newStore(t)
	for _, tc := range []struct {
		name   string
		mutate func(*Upload)
	}{
		{"no identifier", func(u *Upload) { u.ID = "" }},
		{"no wrapped key", func(u *Upload) { u.WrappedFileKey = nil }},
		{"no wrap nonce", func(u *Upload) { u.WrapNonce = nil }},
		{"no metadata envelope", func(u *Upload) { u.MetadataEnvelope = nil }},
		{"no auth token hash", func(u *Upload) { u.AuthTokenHash = nil }},
		{"no owner token hash", func(u *Upload) { u.OwnerTokenHash = nil }},
		{"no at-rest key", func(u *Upload) { u.AtRestKey = nil }},
		{"negative size", func(u *Upload) { u.Size = -1 }},
		{"negative download limit", func(u *Upload) { u.MaxDownloads = -1 }},
		{"no creation time", func(u *Upload) { u.CreatedAt = time.Time{} }},
		{"partial password parameters", func(u *Upload) {
			u.Password = &PasswordParams{Salt: []byte{1}, MemoryKiB: 0, Iterations: 3, Parallelism: 1}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := sample("VALIDATEAAAAAAAAAAAAAA")
			tc.mutate(u)
			if err := s.Create(t.Context(), u); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}

// Reopening must not reapply migrations or lose data.
func TestMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sendan.db")

	first, err := OpenSQLite(t.Context(), path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	u := sample("PERSISTAAAAAAAAAAAAAAA")
	if err := first.Create(t.Context(), u); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second, err := OpenSQLite(t.Context(), path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = second.Close() }()

	if _, err := second.Get(t.Context(), u.ID, time.Now()); err != nil {
		t.Fatalf("the upload did not survive a reopen: %v", err)
	}
	var applied int
	if err := second.db.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if applied != 1 {
		t.Fatalf("%d migrations recorded after two opens, want 1", applied)
	}
}
