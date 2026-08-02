// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package crypto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The key schedule is fully determined by the specification, so Go acts as the
// reference producer and the TypeScript implementation must reproduce these
// values exactly.
//
// The Argon2id cases matter most. WebCrypto has no Argon2, so the browser uses
// hash-wasm while Go uses golang.org/x/crypto/argon2 — two entirely separate
// implementations, with parameters that are easy to interpret differently
// (memory in KiB against bytes, iterations against lanes). Nothing but these
// vectors would catch a mismatch.
type keyScheduleVectors struct {
	Description string             `json:"description"`
	Spec        string             `json:"spec"`
	Generator   string             `json:"generator"`
	Cases       []keyScheduleCase  `json:"cases"`
	Argon2      []argon2VectorCase `json:"argon2id"`
}

type keyScheduleCase struct {
	Name          string `json:"name"`
	FileIDHex     string `json:"fileIdHex"`
	LinkSecretHex string `json:"linkSecretHex"`
	Password      string `json:"password,omitempty"`
	SaltHex       string `json:"saltHex,omitempty"`
	MemoryKiB     uint32 `json:"memoryKiB,omitempty"`
	Iterations    uint32 `json:"iterations,omitempty"`
	Parallelism   uint8  `json:"parallelism,omitempty"`
	WrappingHex   string `json:"wrappingHex"`
	MetadataHex   string `json:"metadataHex"`
	AuthTokenHex  string `json:"authTokenHex"`
}

type argon2VectorCase struct {
	Name        string `json:"name"`
	Password    string `json:"password"`
	SaltHex     string `json:"saltHex"`
	MemoryKiB   uint32 `json:"memoryKiB"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	HashHex     string `json:"hashHex"`
}

func buildKeyScheduleVectors(t *testing.T) keyScheduleVectors {
	t.Helper()

	fileID := make([]byte, FileIDSize)
	for i := range fileID {
		fileID[i] = byte(i)
	}
	linkSecret := make([]byte, LinkSecretSize)
	for i := range linkSecret {
		linkSecret[i] = byte(0xFF - i)
	}
	salt := make([]byte, PasswordSaltSize)
	for i := range salt {
		salt[i] = byte(0x40 + i)
	}

	// Deliberately cheap parameters so the fixture regenerates quickly, plus
	// one case at the specification defaults so those are exercised too.
	fast := PasswordParams{Salt: salt, MemoryKiB: 64, Iterations: 1, Parallelism: 1}
	defaults := PasswordParams{
		Salt: salt, MemoryKiB: DefaultMemoryKiB,
		Iterations: DefaultIterations, Parallelism: DefaultParallelism,
	}

	v := keyScheduleVectors{
		Description: "Reference output of the spec section 4 key schedule and Argon2id, produced by the Go implementation.",
		Spec:        "docs/spec/wire-format-v1.md section 4",
		Generator:   "go test ./internal/crypto/ -run TestVectorsKeySchedule -update-vectors",
	}

	add := func(name string, password string, p *PasswordParams) {
		var keys *Keys
		var err error
		c := keyScheduleCase{
			Name:          name,
			FileIDHex:     hex.EncodeToString(fileID),
			LinkSecretHex: hex.EncodeToString(linkSecret),
		}
		if p == nil {
			keys, err = DeriveKeys(fileID, linkSecret)
		} else {
			keys, err = DeriveKeysWithPassword(fileID, linkSecret, password, *p)
			c.Password = password
			c.SaltHex = hex.EncodeToString(p.Salt)
			c.MemoryKiB = p.MemoryKiB
			c.Iterations = p.Iterations
			c.Parallelism = p.Parallelism
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		c.WrappingHex = hex.EncodeToString(keys.Wrapping)
		c.MetadataHex = hex.EncodeToString(keys.Metadata)
		c.AuthTokenHex = hex.EncodeToString(keys.AuthToken)
		v.Cases = append(v.Cases, c)
	}

	add("no password", "", nil)
	add("ascii password", "correct horse battery staple", &fast)
	add("unicode password", "パスワード🔐", &fast)
	add("single character password", "x", &fast)
	add("long password", repeatString("a", 1024), &fast)
	add("specification default parameters", "correct horse battery staple", &defaults)

	for _, a := range []struct {
		name string
		pw   string
		p    PasswordParams
	}{
		{"ascii, cheap parameters", "password", fast},
		{"unicode, cheap parameters", "パスワード🔐", fast},
		{"ascii, specification defaults", "password", defaults},
	} {
		v.Argon2 = append(v.Argon2, argon2VectorCase{
			Name:        a.name,
			Password:    a.pw,
			SaltHex:     hex.EncodeToString(a.p.Salt),
			MemoryKiB:   a.p.MemoryKiB,
			Iterations:  a.p.Iterations,
			Parallelism: a.p.Parallelism,
			HashHex:     hex.EncodeToString(a.p.hash(a.pw)),
		})
	}
	return v
}

func repeatString(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for range n {
		out = append(out, s...)
	}
	return string(out)
}

// TestVectorsKeySchedule pins the derived keys. A change here means every
// existing link stops opening, so it requires a new specification version
// rather than a refreshed fixture.
func TestVectorsKeySchedule(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "vectors", "key-schedule.json")
	generated := buildKeyScheduleVectors(t)

	if *updateVectors {
		out, err := json.MarshalIndent(generated, "", "  ")
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil { //nolint:gosec // fixture, not a secret
			t.Fatalf("write vectors: %v", err)
		}
		t.Logf("regenerated %d key schedule and %d argon2id cases", len(generated.Cases), len(generated.Argon2))
		return
	}

	raw, err := os.ReadFile(path) //nolint:gosec // fixed test fixture path
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var committed keyScheduleVectors
	if err := json.Unmarshal(raw, &committed); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	if len(committed.Cases) != len(generated.Cases) {
		t.Fatalf("committed has %d cases, generated %d", len(committed.Cases), len(generated.Cases))
	}
	for i, want := range committed.Cases {
		got := generated.Cases[i]
		t.Run(want.Name, func(t *testing.T) {
			if got.WrappingHex != want.WrappingHex {
				t.Errorf("wrapping key changed\n  got  %s\n  want %s", got.WrappingHex, want.WrappingHex)
			}
			if got.MetadataHex != want.MetadataHex {
				t.Errorf("metadata key changed\n  got  %s\n  want %s", got.MetadataHex, want.MetadataHex)
			}
			if got.AuthTokenHex != want.AuthTokenHex {
				t.Errorf("auth token changed\n  got  %s\n  want %s", got.AuthTokenHex, want.AuthTokenHex)
			}
		})
	}

	if len(committed.Argon2) != len(generated.Argon2) {
		t.Fatalf("committed has %d argon2id cases, generated %d", len(committed.Argon2), len(generated.Argon2))
	}
	for i, want := range committed.Argon2 {
		got := generated.Argon2[i]
		t.Run("argon2id/"+want.Name, func(t *testing.T) {
			if got.HashHex != want.HashHex {
				t.Errorf("hash changed\n  got  %s\n  want %s", got.HashHex, want.HashHex)
			}
		})
	}
}
