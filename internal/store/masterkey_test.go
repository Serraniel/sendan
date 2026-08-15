// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package store_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Serraniel/sendan/internal/store"
)

func masterKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, store.MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

// sqliteAt opens a store on a file, so a second open sees what the first wrote.
func sqliteAt(t *testing.T, path string) store.Store {
	t.Helper()
	s, err := store.OpenSQLite(t.Context(), path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// created makes an upload and marks it complete, because Get only returns
// uploads that finished - an incomplete one is reached through Pending.
func created(t *testing.T, s store.Store, id string, atRest []byte) {
	t.Helper()
	if err := s.Create(t.Context(), anUpload(t, id, atRest)); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Complete(t.Context(), id, time.Now()); err != nil {
		t.Fatalf("complete: %v", err)
	}
}

func anUpload(t *testing.T, id string, atRest []byte) *store.Upload {
	t.Helper()
	return &store.Upload{
		ID:               id,
		AuthTokenHash:    bytes.Repeat([]byte{1}, 32),
		OwnerTokenHash:   bytes.Repeat([]byte{2}, 32),
		AtRestKey:        atRest,
		WrappedFileKey:   bytes.Repeat([]byte{3}, 48),
		WrapNonce:        bytes.Repeat([]byte{4}, 12),
		MetadataEnvelope: []byte("envelope"),
		MetadataNonce:    bytes.Repeat([]byte{5}, 12),
		CreatedAt:        time.Now().UTC().Truncate(time.Second),
		ExpiresAt:        time.Now().UTC().Add(time.Hour).Truncate(time.Second),
		MaxDownloads:     1,
	}
}

// The whole point: what reaches the database must not be the key that opens the
// blob, and what comes back out must be.
func TestTheStoredKeyIsNotTheKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sendan.db")
	plain := sqliteAt(t, path)

	wrapped, err := store.WithMasterKey(plain, masterKey(t))
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	atRest := masterKey(t) // any 32 random bytes
	const id = "wrappedatrestkey000000"
	created(t, wrapped, id, atRest)

	// Through the wrapping, the key comes back as it went in.
	got, err := wrapped.Get(t.Context(), id, time.Now())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got.AtRestKey, atRest) {
		t.Fatal("the key that came back is not the key that went in")
	}

	// Underneath it, the stored bytes are not the key. This is what a leaked
	// backup would contain.
	stored, err := plain.Get(t.Context(), id, time.Now())
	if err != nil {
		t.Fatalf("get underneath: %v", err)
	}
	if bytes.Equal(stored.AtRestKey, atRest) {
		t.Fatal("the at-rest key was stored in the clear")
	}
	if bytes.Contains(stored.AtRestKey, atRest) {
		t.Fatal("the at-rest key appears inside what was stored")
	}
}

// A cold copy of the database, opened with the wrong key, must yield nothing
// usable rather than something subtly wrong.
func TestAnotherMasterKeyDoesNotOpenIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sendan.db")
	plain := sqliteAt(t, path)

	wrapped, err := store.WithMasterKey(plain, masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	const id = "wrongmasterkey00000000"
	created(t, wrapped, id, masterKey(t))

	other, err := store.WithMasterKey(plain, masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Get(t.Context(), id, time.Now()); !errors.Is(err, store.ErrWrongMasterKey) {
		t.Fatalf("a foreign master key gave %v, want ErrWrongMasterKey", err)
	}
}

// Turning the feature on must not strand what is already stored. Those rows
// stay readable until a rotation wraps them.
func TestUploadsWrittenBeforeWrappingStillOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sendan.db")
	plain := sqliteAt(t, path)

	atRest := masterKey(t)
	const id = "writtenbeforewrapping0"
	created(t, plain, id, atRest)

	wrapped, err := store.WithMasterKey(plain, masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	got, err := wrapped.Get(t.Context(), id, time.Now())
	if err != nil {
		t.Fatalf("an upload written before wrapping was enabled: %v", err)
	}
	if !bytes.Equal(got.AtRestKey, atRest) {
		t.Error("an unwrapped row did not come back unchanged")
	}
}

// One raw key in 256 begins with the version marker. Reading the marker rather
// than the length would fail on those and only those.
func TestARawKeyBeginningWithTheVersionMarkerIsNotMisread(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sendan.db")
	plain := sqliteAt(t, path)

	atRest := masterKey(t)
	atRest[0] = 1 // the wrapped-format marker

	const id = "markerlookalike0000000"
	created(t, plain, id, atRest)

	wrapped, err := store.WithMasterKey(plain, masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	got, err := wrapped.Get(t.Context(), id, time.Now())
	if err != nil {
		t.Fatalf("a raw key starting with the marker byte: %v", err)
	}
	if !bytes.Equal(got.AtRestKey, atRest) {
		t.Error("a raw key starting with the marker byte was mangled")
	}
}

// Every path that returns an upload has to unwrap, not just the obvious one. A
// download reads through RecordServed, and an upload in progress through
// Pending; either returning a wrapped key would encrypt or decrypt with the
// wrong one.
func TestEveryReadPathUnwraps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sendan.db")
	plain := sqliteAt(t, path)

	wrapped, err := store.WithMasterKey(plain, masterKey(t))
	if err != nil {
		t.Fatal(err)
	}

	atRest := masterKey(t)
	const id = "everyreadpath000000000"

	u := anUpload(t, id, atRest)
	if err := wrapped.Create(t.Context(), u); err != nil {
		t.Fatal(err)
	}

	// Pending, before the upload is complete.
	got, err := wrapped.Pending(t.Context(), id)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if !bytes.Equal(got.AtRestKey, atRest) {
		t.Error("Pending returned a key that is not the at-rest key")
	}

	if err := wrapped.Complete(t.Context(), id, time.Now()); err != nil {
		t.Fatal(err)
	}

	served, err := wrapped.RecordServed(t.Context(), id, 10)
	if err != nil {
		t.Fatalf("record served: %v", err)
	}
	if !bytes.Equal(served.AtRestKey, atRest) {
		t.Error("RecordServed returned a key that is not the at-rest key")
	}
}

// Create must not alter the caller's upload: the same key is about to encrypt
// the blob, and handing back a wrapped one would encrypt with something the
// database cannot produce again.
func TestCreateLeavesTheCallersKeyAlone(t *testing.T) {
	plain := sqliteAt(t, filepath.Join(t.TempDir(), "sendan.db"))
	wrapped, err := store.WithMasterKey(plain, masterKey(t))
	if err != nil {
		t.Fatal(err)
	}

	atRest := masterKey(t)
	original := bytes.Clone(atRest)

	u := anUpload(t, "callerskeyintact000000", atRest)
	if err := wrapped.Create(t.Context(), u); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(u.AtRestKey, original) {
		t.Error("Create changed the key the caller is about to encrypt with")
	}
}

func TestMasterKeysAreReadInTheFormsPeopleHaveThem(t *testing.T) {
	key := masterKey(t)

	for name, text := range map[string]string{
		"hex":             hex.EncodeToString(key),
		"hex with spaces": "  " + hex.EncodeToString(key) + "\n",
		"base64":          base64.StdEncoding.EncodeToString(key),
		"base64 unpadded": base64.RawStdEncoding.EncodeToString(key),
		"base64url":       base64.URLEncoding.EncodeToString(key),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := store.ParseMasterKey(text)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !bytes.Equal(got, key) {
				t.Error("the key read back is not the key written")
			}
		})
	}
}

func TestKeysOfTheWrongSizeAreRefused(t *testing.T) {
	for name, text := range map[string]string{
		"empty":     "",
		"too short": hex.EncodeToString(make([]byte, 16)),
		"too long":  hex.EncodeToString(make([]byte, 64)),
		"not a key": "this is not a key at all",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.ParseMasterKey(text); err == nil {
				t.Error("accepted something that is not a master key")
			}
		})
	}

	if _, err := store.WithMasterKey(nil, make([]byte, 16)); !errors.Is(err, store.ErrMasterKeySize) {
		t.Error("a short master key was accepted")
	}
}

func TestAGeneratedKeyIsUsable(t *testing.T) {
	text, err := store.NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := store.ParseMasterKey(text)
	if err != nil {
		t.Fatalf("a generated key does not parse: %v", err)
	}
	if len(key) != store.MasterKeySize {
		t.Errorf("generated %d bytes, want %d", len(key), store.MasterKeySize)
	}

	// Twice, because a generator that returns a constant passes every other
	// test here.
	again, err := store.NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if again == text {
		t.Error("two generated keys are identical")
	}
}

// Rotation, which the feature is not usable without: a key that cannot be
// changed is a key that cannot be responded to when it leaks.
func TestRotationRewrapsEveryUpload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sendan.db")
	plain := sqliteAt(t, path)

	first, second := masterKey(t), masterKey(t)

	wrapped, err := store.WithMasterKey(plain, first)
	if err != nil {
		t.Fatal(err)
	}

	keys := map[string][]byte{}
	for _, id := range []string{"rotationupload0000001x", "rotationupload0000002x"} {
		keys[id] = masterKey(t)
		created(t, wrapped, id, keys[id])
	}

	rewrap, err := store.Rewrap(first, second)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := plain.(store.Rekeyer).Rekey(t.Context(), rewrap)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if changed != len(keys) {
		t.Errorf("rotated %d uploads, want %d", changed, len(keys))
	}

	// The new key opens everything.
	under, err := store.WithMasterKey(plain, second)
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range keys {
		got, err := under.Get(t.Context(), id, time.Now())
		if err != nil {
			t.Fatalf("after rotation, %s: %v", id, err)
		}
		if !bytes.Equal(got.AtRestKey, want) {
			t.Errorf("after rotation, %s came back with a different key", id)
		}
	}

	// And the old one opens nothing, which is what makes rotation a response to
	// a leak rather than a second key that also works.
	stale, err := store.WithMasterKey(plain, first)
	if err != nil {
		t.Fatal(err)
	}
	for id := range keys {
		if _, err := stale.Get(t.Context(), id, time.Now()); !errors.Is(err, store.ErrWrongMasterKey) {
			t.Errorf("the previous master key still opens %s", id)
		}
	}
}

// Turning wrapping on for a database that has none, and off again. Both are
// rotations with one side missing.
func TestWrappingCanBeTurnedOnAndOff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sendan.db")
	plain := sqliteAt(t, path)

	atRest := masterKey(t)
	const id = "onandoffagain000000000"
	created(t, plain, id, atRest)

	key := masterKey(t)

	on, err := store.Rewrap(nil, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.(store.Rekeyer).Rekey(t.Context(), on); err != nil {
		t.Fatalf("turning wrapping on: %v", err)
	}

	// Now the plain store sees something that is not the key.
	stored, err := plain.Get(t.Context(), id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(stored.AtRestKey, atRest) {
		t.Fatal("turning wrapping on left the key in the clear")
	}

	off, err := store.Rewrap(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.(store.Rekeyer).Rekey(t.Context(), off); err != nil {
		t.Fatalf("turning wrapping off: %v", err)
	}

	back, err := plain.Get(t.Context(), id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.AtRestKey, atRest) {
		t.Error("turning wrapping off did not restore the original key")
	}
}

// A rotation that cannot open what it finds must change nothing. Half a
// rotation is a database no single key can read.
func TestARotationWithTheWrongKeyChangesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sendan.db")
	plain := sqliteAt(t, path)

	inForce, wrong := masterKey(t), masterKey(t)
	wrapped, err := store.WithMasterKey(plain, inForce)
	if err != nil {
		t.Fatal(err)
	}

	atRest := masterKey(t)
	const id = "wrongkeyrotation000000"
	created(t, wrapped, id, atRest)

	before, err := plain.Get(t.Context(), id, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	rewrap, err := store.Rewrap(wrong, masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.(store.Rekeyer).Rekey(t.Context(), rewrap); err == nil {
		t.Fatal("a rotation with the wrong key reported success")
	}

	after, err := plain.Get(t.Context(), id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before.AtRestKey, after.AtRestKey) {
		t.Error("a failed rotation changed what was stored")
	}

	// And the database still opens with the key it was written under.
	got, err := wrapped.Get(t.Context(), id, time.Now())
	if err != nil {
		t.Fatalf("after a failed rotation: %v", err)
	}
	if !bytes.Equal(got.AtRestKey, atRest) {
		t.Error("a failed rotation left the database unreadable")
	}
}

func TestARotationNeedsAtLeastOneKey(t *testing.T) {
	if _, err := store.Rewrap(nil, nil); err == nil {
		t.Error("a rotation from nothing to nothing was accepted")
	}
}

// Belt and braces on the promise this feature makes: the bytes on disk must not
// contain the at-rest key anywhere.
func TestTheKeyIsNotInTheDatabaseFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sendan.db")
	plain := sqliteAt(t, path)

	wrapped, err := store.WithMasterKey(plain, masterKey(t))
	if err != nil {
		t.Fatal(err)
	}

	atRest := masterKey(t)
	created(t, wrapped, "notinthefile0000000000", atRest)
	if err := plain.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, atRest) {
		t.Error("the at-rest key is present in the database file")
	}
}
