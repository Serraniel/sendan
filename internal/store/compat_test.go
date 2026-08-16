// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package store_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Serraniel/sendan/internal/store"
)

// aCompatUpload is what the compatibility protocol stores: an upload row with
// no envelope of this project's own, plus the weaker credential beside it.
func aCompatUpload(t *testing.T, id string) (*store.Upload, *store.CompatUpload) {
	t.Helper()
	return &store.Upload{
			ID:             id,
			AuthTokenHash:  bytes.Repeat([]byte{1}, 32),
			OwnerTokenHash: bytes.Repeat([]byte{2}, 32),
			AtRestKey:      masterKey(t),
			CreatedAt:      time.Now().UTC().Truncate(time.Second),
			ExpiresAt:      time.Now().UTC().Add(time.Hour).Truncate(time.Second),
			MaxDownloads:   1,
		}, &store.CompatUpload{
			ID:       id,
			AuthKey:  bytes.Repeat([]byte{3}, 32),
			Nonce:    bytes.Repeat([]byte{4}, 16),
			Metadata: []byte("an envelope in the other protocol's format"),
		}
}

func compatStore(t *testing.T) (store.Store, store.CompatStore) {
	t.Helper()
	s := sqliteAt(t, filepath.Join(t.TempDir(), "sendan.db"))
	c, ok := s.(store.CompatStore)
	if !ok {
		t.Fatal("SQLite does not implement CompatStore")
	}
	return s, c
}

func TestACompatUploadIsStoredAndReadBack(t *testing.T) {
	s, c := compatStore(t)
	u, compat := aCompatUpload(t, "compatstoredandread000")

	if err := c.CreateCompat(t.Context(), u, compat); err != nil {
		t.Fatalf("create: %v", err)
	}

	// The upload row is an ordinary one, so everything that acts on uploads
	// acts on this.
	if err := s.Complete(t.Context(), u.ID, time.Now()); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if _, err := s.Get(t.Context(), u.ID, time.Now()); err != nil {
		t.Fatalf("the upload row is not readable: %v", err)
	}

	got, err := c.Compat(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("read compat: %v", err)
	}
	if !bytes.Equal(got.AuthKey, compat.AuthKey) || !bytes.Equal(got.Nonce, compat.Nonce) {
		t.Error("the compatibility row did not come back as it went in")
	}
	if !bytes.Equal(got.Metadata, compat.Metadata) {
		t.Error("the metadata did not come back as it went in")
	}
}

// The property the separate table must not cost us. Deleting an upload destroys
// its at-rest key, and it has to destroy the weaker credential too — a
// compatibility row outliving its upload is a stored HMAC key for content
// nobody can reach, which is a leak with no purpose.
func TestDeletingAnUploadDestroysItsCompatRow(t *testing.T) {
	s, c := compatStore(t)
	u, compat := aCompatUpload(t, "compatcascadedelete000")

	if err := c.CreateCompat(t.Context(), u, compat); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Compat(t.Context(), u.ID); err != nil {
		t.Fatalf("the compatibility row should exist first: %v", err)
	}

	if err := s.Delete(t.Context(), u.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := c.Compat(t.Context(), u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after deleting the upload, its compatibility row gave %v, want ErrNotFound", err)
	}
}

// Reaping is deletion, so an expired compatibility upload must leave nothing
// behind either. This is the path that runs unattended.
func TestReapingRemovesTheCompatRowToo(t *testing.T) {
	s, c := compatStore(t)
	u, compat := aCompatUpload(t, "compatreapedaway00000x")
	u.ExpiresAt = time.Now().UTC().Add(-time.Hour)

	if err := c.CreateCompat(t.Context(), u, compat); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(t.Context(), u.ID, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	dead, err := s.ListDead(t.Context(), time.Now(), time.Now().Add(-24*time.Hour), 10)
	if err != nil {
		t.Fatalf("list dead: %v", err)
	}
	if len(dead) == 0 {
		t.Fatal("an expired compatibility upload was not listed as dead")
	}
	for _, id := range dead {
		if err := s.Delete(t.Context(), id); err != nil {
			t.Fatalf("delete %s: %v", id, err)
		}
	}

	if _, err := c.Compat(t.Context(), u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after reaping, the compatibility row gave %v, want ErrNotFound", err)
	}
}

// A captured Authorization header must not work twice, which rests entirely on
// the nonce moving.
func TestTheNonceRotates(t *testing.T) {
	_, c := compatStore(t)
	u, compat := aCompatUpload(t, "compatnoncerotation00x")

	if err := c.CreateCompat(t.Context(), u, compat); err != nil {
		t.Fatal(err)
	}

	next := bytes.Repeat([]byte{9}, 16)
	if err := c.RotateCompatNonce(t.Context(), u.ID, next); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	got, err := c.Compat(t.Context(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Nonce, next) {
		t.Error("the nonce did not change")
	}

	if err := c.RotateCompatNonce(t.Context(), "compatnoncemissing000x", next); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("rotating an absent upload gave %v, want ErrNotFound", err)
	}
	if err := c.RotateCompatNonce(t.Context(), u.ID, nil); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("an empty nonce gave %v, want ErrInvalid", err)
	}
}

// Neither row may exist without the other: an upload nobody can authenticate,
// or a credential for content that does not exist.
func TestBothRowsAreWrittenOrNeither(t *testing.T) {
	s, c := compatStore(t)
	u, compat := aCompatUpload(t, "compatatomicwrite0000x")
	compat.AuthKey = nil // refused before anything is written

	if err := c.CreateCompat(t.Context(), u, compat); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
	if _, err := s.Pending(t.Context(), u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a rejected compatibility upload left an upload row behind: %v", err)
	}
}

// A compatibility upload has no envelope in this project's format, and one
// carrying a piece of it is a row no reader can interpret.
func TestACompatUploadCarriesNoNativeEnvelope(t *testing.T) {
	_, c := compatStore(t)
	u, compat := aCompatUpload(t, "compatnoenvelope00000x")
	u.MetadataEnvelope = []byte("this belongs to the other format")

	if err := c.CreateCompat(t.Context(), u, compat); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("got %v, want ErrInvalid", err)
	}
}

// And the converse: a native upload keeps all four envelope columns, so nothing
// can create one that is half in each format. Validation refuses it before the
// database is asked; the CHECK constraint added by the migration is the second
// line, for anything that reaches the table another way.
func TestANativeUploadStillRequiresItsEnvelope(t *testing.T) {
	s, _ := compatStore(t)

	u := anUpload(t, "nativehalfenvelope000x", masterKey(t))
	u.MetadataNonce = nil

	if err := s.Create(t.Context(), u); err == nil {
		t.Error("a native upload was created with part of its envelope missing")
	}
}

// The compatibility protocol streams a file without declaring its length, so
// the size is not known when the row is created. It has to be recorded before
// the upload is reachable, because the download count is derived as bytes
// served divided by size: a row left at zero serves without ever counting a
// download, and the limit silently does not apply.
func TestTheSizeIsRecordedWhenTheUploadFinishes(t *testing.T) {
	s, c := compatStore(t)
	u, compat := aCompatUpload(t, "compatfinishsize00000x")
	u.Size = 0
	// Room for more than one, so the upload stays reachable and the count can
	// be read rather than inferred from it having become unreachable.
	u.MaxDownloads = 3

	if err := c.CreateCompat(t.Context(), u, compat); err != nil {
		t.Fatal(err)
	}

	const size = 4096
	if err := c.FinishCompat(t.Context(), u.ID, size, time.Now()); err != nil {
		t.Fatalf("finish: %v", err)
	}

	got, err := s.Get(t.Context(), u.ID, time.Now())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Size != size {
		t.Errorf("size %d, want %d", got.Size, size)
	}
	if got.CompletedAt.IsZero() {
		t.Error("the upload was not marked complete")
	}

	// And the derived download count now advances, which is what makes a
	// download limit mean anything.
	if _, err := s.RecordServed(t.Context(), u.ID, size); err != nil {
		t.Fatalf("record served: %v", err)
	}
	after, err := s.Get(t.Context(), u.ID, time.Now())
	if err != nil {
		t.Fatalf("get after serving: %v", err)
	}
	if after.DownloadCount != 1 {
		t.Errorf("download count %d after serving the whole file, want 1", after.DownloadCount)
	}
}

func TestFinishingAnAbsentOrFinishedUploadIsRefused(t *testing.T) {
	_, c := compatStore(t)
	u, compat := aCompatUpload(t, "compatfinishtwice0000x")

	if err := c.CreateCompat(t.Context(), u, compat); err != nil {
		t.Fatal(err)
	}
	if err := c.FinishCompat(t.Context(), u.ID, 10, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Twice would let a second upload claim a different size for content that
	// is already being served.
	if err := c.FinishCompat(t.Context(), u.ID, 20, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("finishing twice gave %v, want ErrNotFound", err)
	}
	if err := c.FinishCompat(t.Context(), "compatfinishmissing00x", 10, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("finishing an absent upload gave %v, want ErrNotFound", err)
	}
	if err := c.FinishCompat(t.Context(), u.ID, -1, time.Now()); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("a negative size gave %v, want ErrInvalid", err)
	}
}
