// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package httpapi

import (
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/Serraniel/sendan/internal/store"
	"github.com/Serraniel/sendan/internal/upload"
)

// idLength is the encoded length of a 16-byte file identifier (spec §10).
const idLength = 22

// kdfParams are the Argon2id parameters a client needs before it can derive
// anything. Publishing them discloses only that a password exists: without the
// link secret, which never reaches the server, they permit no offline attack,
// because the password hash is only ever combined with that secret (spec §4).
type kdfParams struct {
	Salt        string `json:"salt"`
	MemoryKiB   uint32 `json:"memoryKiB"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}

// metadataResponse is what a client receives before downloading.
//
// Every byte here is ciphertext or a public derivation parameter. Notably
// absent is the size: the server knows the stored ciphertext length, and
// reporting it would disclose a file's size to anyone holding an identifier,
// undoing the padding the metadata envelope applies for exactly that reason
// (spec §7).
type metadataResponse struct {
	ID               string `json:"id"`
	WrappedFileKey   string `json:"wrappedFileKey"`
	WrapNonce        string `json:"wrapNonce"`
	MetadataEnvelope string `json:"metadataEnvelope"`
	MetadataNonce    string `json:"metadataNonce"`

	PasswordRequired bool       `json:"passwordRequired"`
	KDF              *kdfParams `json:"kdf,omitempty"`

	// ExpiresAt is omitted when the upload never expires, rather than sent as a
	// zero time that a client would have to know to interpret.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	// DownloadsRemaining is omitted when there is no limit.
	DownloadsRemaining *int `json:"downloadsRemaining,omitempty"`
}

func newMetadataResponse(m *upload.PublicMetadata) metadataResponse {
	enc := base64.RawURLEncoding.EncodeToString

	res := metadataResponse{
		ID:               m.ID,
		WrappedFileKey:   enc(m.WrappedFileKey),
		WrapNonce:        enc(m.WrapNonce),
		MetadataEnvelope: enc(m.MetadataEnvelope),
		MetadataNonce:    enc(m.MetadataNonce),
		PasswordRequired: m.Password != nil,
	}

	if m.Password != nil {
		res.KDF = &kdfParams{
			Salt:        enc(m.Password.Salt),
			MemoryKiB:   m.Password.MemoryKiB,
			Iterations:  m.Password.Iterations,
			Parallelism: m.Password.Parallelism,
		}
	}
	if !m.ExpiresAt.IsZero() {
		at := m.ExpiresAt.UTC()
		res.ExpiresAt = &at
	}
	if m.MaxDownloads > 0 {
		remaining := max(m.MaxDownloads-m.DownloadCount, 0)
		res.DownloadsRemaining = &remaining
	}
	return res
}

// handleMetadata serves the encrypted metadata for an upload.
//
// It is unauthenticated, and must be. The download token derives from the same
// key schedule as everything else, so producing one requires the password
// (spec §4) - while this endpoint is where a client learns whether a password
// is needed and which parameters to derive it with. Requiring the token would
// make the response unobtainable by precisely the clients that need it.
//
// Nothing is disclosed by that. Both the wrapped key and the envelope are
// AES-256-GCM ciphertext under keys derived from the link secret, which never
// reaches the server, and the identifier is 16 random bytes, so the response
// cannot be reached by enumeration.
func handleMetadata(uploads *upload.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set before any branch, so every answer carries it. no-store rather
		// than a short max-age: a shared cache holding a success would serve a
		// stale download count, and one holding a 404 could go on reporting an
		// upload as gone after it exists.
		w.Header().Set("Cache-Control", "no-store")

		id := r.PathValue("id")

		// A malformed identifier cannot name an upload, so it gets the same
		// answer as one that does not exist. Distinguishing them would tell a
		// caller only that they typed something impossible.
		if !validID(id) {
			writeError(w, http.StatusNotFound, "not_found", "no such upload")
			return
		}

		m, err := uploads.Metadata(r.Context(), id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// Expired, exhausted, revoked and never-existed are one answer.
				// Any difference between them would report on an upload the
				// caller is not entitled to know about.
				writeError(w, http.StatusNotFound, "not_found", "no such upload")
				return
			}
			writeServerError(w, r, err)
			return
		}

		writeJSON(w, http.StatusOK, newMetadataResponse(m))
	}
}

// validID reports whether id could be a file identifier: 22 characters of
// unpadded base64url, which is a 16-byte value (spec §10).
//
// The length test is redundant for correctness - 22 is the only encoded length
// that decodes to 16 bytes, so the byte-length check below already rejects
// everything else. It is kept as a bound on work: without it, any path segment
// the router accepts would be base64-decoded before being rejected.
func validID(id string) bool {
	if len(id) != idLength {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(id)
	return err == nil && len(raw) == 16
}
