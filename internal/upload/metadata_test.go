// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package upload

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/Serraniel/sendan/internal/store"
)

func TestMetadataReturnsWhatAClientNeeds(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	const id = "METAAAAAAAAAAAAAAAAAAA"
	h.put(t, id, "content", h.clock.Add(time.Hour), 5)

	m, err := h.svc.Metadata(t.Context(), id)
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}

	if m.ID != id {
		t.Errorf("id %q, want %q", m.ID, id)
	}
	if !bytes.Equal(m.WrappedFileKey, bytes.Repeat([]byte{0x01}, 48)) {
		t.Errorf("wrapped file key %x", m.WrappedFileKey)
	}
	if !bytes.Equal(m.MetadataEnvelope, bytes.Repeat([]byte{0x03}, 256)) {
		t.Errorf("metadata envelope %x", m.MetadataEnvelope)
	}
	if m.MaxDownloads != 5 {
		t.Errorf("max downloads %d, want 5", m.MaxDownloads)
	}
	if m.Password != nil {
		t.Errorf("password parameters present on an upload without one: %+v", m.Password)
	}
}

// PublicMetadata exists so that the at-rest key cannot reach a serialisation
// layer. This asserts the type has no field capable of carrying it, which is
// the property the design depends on - a test that read a field would only
// prove the current mapping, not that the field is absent.
func TestPublicMetadataCannotCarryTheAtRestKey(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	const id = "SECRETAAAAAAAAAAAAAAAA"
	h.put(t, id, "content", h.clock.Add(time.Hour), 0)

	stored, err := h.store.Get(t.Context(), id, h.clock)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(stored.AtRestKey) == 0 {
		t.Fatal("the fixture has no at-rest key, so this test would pass vacuously")
	}

	m, err := h.svc.Metadata(t.Context(), id)
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}

	for _, field := range [][]byte{
		m.WrappedFileKey, m.WrapNonce, m.MetadataEnvelope, m.MetadataNonce,
	} {
		if bytes.Contains(field, stored.AtRestKey) {
			t.Errorf("the at-rest key appears in a published field: %x", field)
		}
	}
}

func TestMetadataPassesThroughPasswordParameters(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	const id = "PWPARAMSAAAAAAAAAAAAAA"

	salt := bytes.Repeat([]byte{0x5A}, 16)
	h.putWith(t, id, "content", h.clock.Add(time.Hour), 0, func(u *store.Upload) {
		u.Password = &store.PasswordParams{
			Salt: salt, MemoryKiB: 65536, Iterations: 3, Parallelism: 1,
		}
	})

	m, err := h.svc.Metadata(t.Context(), id)
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	if m.Password == nil {
		t.Fatal("the parameters are missing, so no client could derive a key")
	}
	if !bytes.Equal(m.Password.Salt, salt) {
		t.Errorf("salt %x", m.Password.Salt)
	}
	if m.Password.MemoryKiB != 65536 || m.Password.Iterations != 3 || m.Password.Parallelism != 1 {
		t.Errorf("parameters %+v", m.Password)
	}
}

// Liveness is evaluated on read, so an upload past its deadline or its
// allowance is already unreachable whether or not the reaper has run.
func TestMetadataRefusesDeadUploads(t *testing.T) {
	tests := []struct {
		name         string
		expiresAt    func(now time.Time) time.Time
		maxDownloads int
		downloads    int
	}{
		{
			name:      "expired",
			expiresAt: func(now time.Time) time.Time { return now.Add(-time.Hour) },
		},
		{
			name:         "exhausted",
			expiresAt:    func(now time.Time) time.Time { return now.Add(time.Hour) },
			maxDownloads: 2, downloads: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, defaultPolicy())
			const id = "DEADAAAAAAAAAAAAAAAAAA"
			h.putWith(t, id, "content", tc.expiresAt(h.clock), tc.maxDownloads,
				func(u *store.Upload) { u.DownloadCount = tc.downloads })

			if _, err := h.svc.Metadata(t.Context(), id); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("got %v, want ErrNotFound", err)
			}
		})
	}
}

func TestMetadataOnAnUnknownUpload(t *testing.T) {
	h := newHarness(t, defaultPolicy())
	if _, err := h.svc.Metadata(t.Context(), "NOSUCHAAAAAAAAAAAAAAAA"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}
