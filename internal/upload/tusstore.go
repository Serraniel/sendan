// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package upload

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	tus "github.com/tus/tusd/v2/pkg/handler"

	"github.com/Serraniel/sendan/internal/blob"
	"github.com/Serraniel/sendan/internal/crypto"
	"github.com/Serraniel/sendan/internal/logging"
	"github.com/Serraniel/sendan/internal/store"
)

// Metadata keys a client sends when creating an upload.
//
// tus decodes the base64 in Upload-Metadata for us, so the values arrive as
// raw bytes rather than encoded ones. Encoding them again would be a second
// representation to keep consistent between two implementations for no gain.
//
// values they name are client-produced ciphertext the server cannot read.
//
//nolint:gosec // G101: these are metadata field names, not credentials. The
const (
	metaFileID           = "fileID"
	metaWrappedFileKey   = "wrappedFileKey"
	metaWrapNonce        = "wrapNonce"
	metaEnvelope         = "metadataEnvelope"
	metaEnvelopeNonce    = "metadataNonce"
	metaAuthTokenHash    = "authTokenHash"
	metaOwnerTokenHash   = "ownerTokenHash"
	metaPasswordSalt     = "passwordSalt"
	metaArgon2Memory     = "argon2MemoryKiB"
	metaArgon2Iterations = "argon2Iterations"
	metaArgon2Parallel   = "argon2Parallelism"
	metaTTLSeconds       = "ttlSeconds"
	metaMaxDownloads     = "maxDownloads"
)

// ErrUploadTooLarge reports an upload beyond what the instance accepts.
var ErrUploadTooLarge = errors.New("upload: larger than this instance accepts")

// TusStore adapts the upload lifecycle to the tus protocol.
//
// The protocol is adopted rather than reimplemented: resumption, offset
// negotiation and the request semantics are tusd's, and this type supplies only
// what is specific to Sendan - where bytes go, how they are encrypted, and what
// a completed upload becomes.
type TusStore struct {
	svc *Service
	// maxSize bounds a single upload. Zero means unbounded.
	maxSize int64
}

var _ tus.DataStore = (*TusStore)(nil)

// NewTusStore returns a tus data store backed by the upload service.
func NewTusStore(svc *Service, maxSize int64) *TusStore {
	return &TusStore{svc: svc, maxSize: maxSize}
}

// NewUpload creates the row an upload accumulates into.
//
// The row exists before any byte arrives, because chunks are encrypted with its
// at-rest key as they are written. It is created incomplete, so it is
// unreachable until the upload finishes.
func (t *TusStore) NewUpload(ctx context.Context, info tus.FileInfo) (tus.Upload, error) {
	// A deferred length would mean accepting bytes without knowing whether the
	// result will exceed the limit, which is a limit in name only.
	if info.SizeIsDeferred {
		return nil, tus.NewError("ERR_SIZE_REQUIRED",
			"the total upload length must be declared up front", 400)
	}
	if t.maxSize > 0 && info.Size > t.maxSize {
		return nil, tus.NewError("ERR_TOO_LARGE",
			fmt.Sprintf("upload of %d bytes exceeds the limit of %d", info.Size, t.maxSize), 413)
	}
	if info.Size < 0 {
		return nil, tus.NewError("ERR_INVALID_LENGTH", "the upload length must not be negative", 400)
	}

	u, err := t.newRow(info)
	if err != nil {
		return nil, err
	}
	if err := t.svc.store.Create(ctx, u); err != nil {
		// A taken identifier is the client's to resolve, not a fault here. The
		// client generates it (spec §3), so a collision means generating
		// another and trying again - which a 500 does not say, and which a
		// retry of the same request cannot achieve. It would also put an
		// error in the operator's log for something that is not theirs.
		if errors.Is(err, store.ErrConflict) {
			return nil, tus.NewError("ERR_UPLOAD_EXISTS",
				"an upload with this identifier already exists", http.StatusConflict)
		}
		return nil, fmt.Errorf("upload: create: %w", err)
	}

	info.ID = u.ID
	info.Offset = 0
	return &tusUpload{store: t, id: u.ID, info: info}, nil
}

// newRow builds the store row from the metadata a client supplied.
//
// Every cryptographic value is produced by the client and opaque here, but
// their sizes are not: a wrapped key of the wrong length, or a token hash that
// is not a SHA-256 digest, means a client that cannot possibly be interoperable
// and an upload nobody will ever open. Rejecting it at creation is better than
// storing it and discovering the problem at download.
func (t *TusStore) newRow(info tus.FileInfo) (*store.Upload, error) {
	atRest, err := blob.NewAtRestKey()
	if err != nil {
		return nil, fmt.Errorf("upload: at-rest key: %w", err)
	}

	m := newMetadata(info.MetaData)
	u := &store.Upload{
		ID:               m.fileID(),
		WrappedFileKey:   m.bytes(metaWrappedFileKey, crypto.WrappedFileKeySize),
		WrapNonce:        m.bytes(metaWrapNonce, crypto.NonceSize),
		MetadataEnvelope: m.blob(metaEnvelope),
		MetadataNonce:    m.bytes(metaEnvelopeNonce, crypto.NonceSize),
		AuthTokenHash:    m.bytes(metaAuthTokenHash, sha256.Size),
		OwnerTokenHash:   m.bytes(metaOwnerTokenHash, sha256.Size),
		AtRestKey:        atRest,
		Size:             info.Size,
		CreatedAt:        t.svc.now(),
		MaxDownloads:     m.integer(metaMaxDownloads, t.svc.policy.DefaultMaxDownloads),
	}

	if salt, ok := info.MetaData[metaPasswordSalt]; ok && salt != "" {
		u.Password = &store.PasswordParams{
			Salt: m.bytes(metaPasswordSalt, crypto.PasswordSaltSize),
			// Bounded before conversion. A plain cast would truncate rather
			// than refuse - a parallelism of 300 would be stored as 44 - and
			// the client would derive with parameters the uploader never chose,
			// producing a file that cannot be opened.
			MemoryKiB:   m.uint32Value(metaArgon2Memory),
			Iterations:  m.uint32Value(metaArgon2Iterations),
			Parallelism: m.uint8Value(metaArgon2Parallel),
		}
		if u.Password.MemoryKiB == 0 || u.Password.Iterations == 0 || u.Password.Parallelism == 0 {
			m.fail("the Argon2id parameters must all be present and non-zero when a password salt is given")
		}
	}

	// The uploader's requested lifetime is subject to the instance policy, and
	// an excessive request is rejected rather than clamped: an uploader who
	// asked for a week and silently received a day would believe their file
	// outlives what it does.
	expires, err := t.svc.ResolveExpiry(time.Duration(m.integer64(metaTTLSeconds, 0)) * time.Second)
	if err != nil {
		return nil, tus.NewError("ERR_RETENTION", err.Error(), 400)
	}
	u.ExpiresAt = expires

	if err := m.err(); err != nil {
		return nil, err
	}
	return u, nil
}

// GetUpload returns an upload that is still being written.
//
// A completed upload is not writable. Without that, anyone holding an
// identifier could append past the end of a finished upload and replace what
// its recipient receives - and identifiers become known to recipients as soon
// as a link is shared.
func (t *TusStore) GetUpload(ctx context.Context, id string) (tus.Upload, error) {
	u, err := t.svc.store.Pending(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, tus.ErrNotFound
		}
		return nil, fmt.Errorf("upload: get pending: %w", err)
	}

	offset, err := t.svc.blobs.Length(ctx, id)
	if err != nil && !errors.Is(err, blob.ErrNotFound) {
		return nil, fmt.Errorf("upload: length: %w", err)
	}

	return &tusUpload{
		store: t,
		id:    id,
		info: tus.FileInfo{
			ID:     id,
			Size:   u.Size,
			Offset: offset,
		},
		atRestKey: u.AtRestKey,
	}, nil
}

// tusUpload is one upload in progress.
type tusUpload struct {
	store     *TusStore
	id        string
	info      tus.FileInfo
	atRestKey []byte
}

var _ tus.Upload = (*tusUpload)(nil)

func (u *tusUpload) GetInfo(context.Context) (tus.FileInfo, error) { return u.info, nil }

// WriteChunk encrypts the chunk at its offset and appends it.
func (u *tusUpload) WriteChunk(ctx context.Context, offset int64, src io.Reader) (int64, error) {
	key, err := u.key(ctx)
	if err != nil {
		return 0, err
	}

	n, err := u.store.svc.blobs.WriteChunk(ctx, u.id, key, offset, src)
	u.info.Offset = offset + n
	if err != nil {
		if errors.Is(err, blob.ErrOffset) {
			// tus answers a mismatched offset with 409, and a client's correct
			// response is to ask for the current one rather than retry.
			return n, tus.ErrMismatchOffset
		}
		return n, fmt.Errorf("upload: write chunk: %w", err)
	}
	return n, nil
}

// GetReader is required by the protocol for reading back an in-progress upload.
//
// Sendan does not offer it: what a half-written upload decrypts to is not what
// the uploader sent, and the finished content is served by the download
// endpoint, which verifies a token first.
func (u *tusUpload) GetReader(context.Context) (io.ReadCloser, error) {
	return nil, tus.NewError("ERR_NOT_READABLE",
		"an upload in progress cannot be read back", 403)
}

// FinishUpload promotes the partial blob and makes the row reachable.
//
// The blob is finished first. A crash between the two leaves a complete blob
// belonging to a row still marked incomplete, which the reaper removes; the
// reverse would publish a row whose content was never finished.
func (u *tusUpload) FinishUpload(ctx context.Context) error {
	if err := u.store.svc.blobs.Finish(ctx, u.id); err != nil {
		return fmt.Errorf("upload: finish blob: %w", err)
	}
	if err := u.store.svc.store.Complete(ctx, u.id, u.store.svc.now()); err != nil {
		return fmt.Errorf("upload: complete: %w", err)
	}
	u.store.svc.log.Info("upload completed", logging.FileID([]byte(u.id)), "size", u.info.Size)
	return nil
}

// key returns the at-rest key, loading it when this handle came from creation
// rather than from a resumed request.
func (u *tusUpload) key(ctx context.Context) ([]byte, error) {
	if u.atRestKey != nil {
		return u.atRestKey, nil
	}
	row, err := u.store.svc.store.Pending(ctx, u.id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, tus.ErrNotFound
		}
		return nil, fmt.Errorf("upload: get pending: %w", err)
	}
	u.atRestKey = row.AtRestKey
	return u.atRestKey, nil
}

// metadata reads the values a client supplied, collecting every fault rather
// than reporting the first, so a client fixing its request sees all of them.
//
// Faults are held beside the values rather than in them. Writing into the map
// tus handed over would mutate the client's own metadata, and a second read of
// the same map would inherit the first read's complaints.
type metadata struct {
	values tus.MetaData
	faults []string
}

func newMetadata(values tus.MetaData) *metadata { return &metadata{values: values} }

func (m *metadata) bytes(key string, want int) []byte {
	v, ok := m.values[key]
	if !ok {
		m.fail(key + " is required")
		return nil
	}
	if len(v) != want {
		m.fail(fmt.Sprintf("%s is %d bytes, want %d", key, len(v), want))
		return nil
	}
	return []byte(v)
}

// blob reads a value whose length is not fixed, but is still bounded: the
// metadata envelope is padded to a multiple of 256 bytes and carries a tag
// (spec §7), and a value that is not is not one this scheme produced.
func (m *metadata) blob(key string) []byte {
	v, ok := m.values[key]
	if !ok {
		m.fail(key + " is required")
		return nil
	}
	const block = 256
	const maxEnvelope = 64 * 1024
	switch {
	case len(v) <= crypto.TagSize || (len(v)-crypto.TagSize)%block != 0:
		m.fail(fmt.Sprintf("%s is %d bytes, which is not a padded envelope with its tag", key, len(v)))
	case len(v) > maxEnvelope:
		m.fail(key + " is implausibly large")
	}
	return []byte(v)
}

// uint32Value and uint8Value read a value that must fit a narrower type,
// refusing anything larger rather than truncating it. A parallelism of 300
// stored as 44 would make a client derive with parameters the uploader never
// chose, producing a file nobody can open.
//
// The bound and the conversion are in one function deliberately. Doing the
// check in a helper and converting at the call site is equivalent for a reader
// and opaque to a static analyser, which then cannot tell a guarded conversion
// from an unguarded one - and neither can a reviewer relying on it.
func (m *metadata) uint32Value(key string) uint32 {
	v := m.integer64(key, 0)
	if v < 0 || v > math.MaxUint32 {
		m.fail(fmt.Sprintf("%s is %d, which exceeds the maximum of %d", key, v, int64(math.MaxUint32)))
		return 0
	}
	return uint32(v)
}

func (m *metadata) uint8Value(key string) uint8 {
	v := m.integer64(key, 0)
	if v < 0 || v > math.MaxUint8 {
		m.fail(fmt.Sprintf("%s is %d, which exceeds the maximum of %d", key, v, math.MaxUint8))
		return 0
	}
	return uint8(v)
}

// integer reads a count that must fit an int, which is 32 bits on some
// platforms. Without the bound a large value would wrap rather than be
// refused, and a download limit would become something the uploader never set.
func (m *metadata) integer(key string, fallback int) int {
	v := m.integer64(key, int64(fallback))
	if v < 0 || v > math.MaxInt32 {
		m.fail(fmt.Sprintf("%s is %d, which exceeds the maximum of %d", key, v, math.MaxInt32))
		return fallback
	}
	return int(v)
}

func (m *metadata) integer64(key string, fallback int64) int64 {
	v, ok := m.values[key]
	if !ok || v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		m.fail(key + " must be a non-negative integer")
		return fallback
	}
	return n
}

// fileID reads the identifier the client generated.
//
// The client generates it because it is the salt in the key schedule (spec §3),
// so every key an upload has depends on it and none can exist before it does.
// The server therefore validates rather than produces it.
//
// What it can validate is the length, the alphabet, and that the value is not a
// single byte repeated. That last case is not a weak generator but an absent
// one - an uninitialised buffer, or a stub returning zeroes. Nothing further is
// possible: sixteen bytes cannot be distinguished from good randomness, and
// spec §13.1 records why a server cannot judge key strength at all.
//
// A duplicate is refused by the store, which reports a conflict.
func (m *metadata) fileID() string {
	raw := m.bytes(metaFileID, crypto.FileIDSize)
	if raw == nil {
		return ""
	}
	if allOneByte(raw) {
		m.fail(metaFileID + " is a single repeated byte, which is an absent generator rather than a weak one")
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// allOneByte reports whether every byte of b is the same.
//
// The case worth catching is an uninitialised buffer or a stub returning
// zeroes. It is not a test of randomness and must not be read as one.
func allOneByte(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b[1:] {
		if c != b[0] {
			return false
		}
	}
	return true
}

func (m *metadata) fail(reason string) { m.faults = append(m.faults, reason) }

func (m *metadata) err() error {
	if len(m.faults) == 0 {
		return nil
	}
	return tus.NewError("ERR_INVALID_METADATA", strings.Join(m.faults, "; "), 400)
}
