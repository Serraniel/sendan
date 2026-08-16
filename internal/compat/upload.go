// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package compat

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/Serraniel/sendan/internal/blob"
	"github.com/Serraniel/sendan/internal/store"
)

// The upload is a WebSocket because that protocol made it one. A client sends a
// single JSON header, receives the link it will share, then streams the
// ciphertext as binary frames and ends with a frame containing one zero byte.
//
// Nothing about the content is interpreted here. The frames are ciphertext the
// client produced with a key this server never sees, and they are written to
// the blob store encrypted again at rest, exactly as a native upload is.

// idBytes and ownerBytes match what the protocol's clients expect to parse:
// hexadecimal identifiers of a length their own routing accepts.
const (
	idBytes    = 8
	ownerBytes = 10
)

// endOfFile is the frame that terminates the stream: a single zero byte.
const endOfFile = 0x00

// maxHeaderBytes bounds the opening JSON message. It carries metadata a client
// chose, so its size is not this server's to assume.
const maxHeaderBytes = 1 << 20

// uploadHeader is the opening message.
type uploadHeader struct {
	// FileMetadata is the client's encrypted metadata, base64 in that
	// protocol's own encoding. Opaque here.
	FileMetadata string `json:"fileMetadata"`

	// Authorization carries the client's authentication *key*, not a signature:
	// it is telling the server what to check future downloads against.
	Authorization string `json:"authorization"`

	// TimeLimit is seconds. DLimit is a download count.
	TimeLimit int64 `json:"timeLimit"`
	DLimit    int   `json:"dlimit"`
}

// handleUpload runs one upload from start to finish.
func (h *Handler) handleUpload(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// The protocol's own clients are not browsers and send no Origin;
		// browsers reaching this would be same-origin. Checking is left to the
		// surrounding middleware, which already applies to every request.
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	defer func() { _ = conn.CloseNow() }()

	// An upload has no useful upper bound in time, and the read deadline that
	// matters is the one on the request context.
	conn.SetReadLimit(-1)

	if err := h.runUpload(r.Context(), conn); err != nil {
		h.log.Warn("compatibility upload failed", "error", err)
		return
	}
	_ = conn.Close(websocket.StatusNormalClosure, "")
}

func (h *Handler) runUpload(ctx context.Context, conn *websocket.Conn) error {
	header, err := readHeader(ctx, conn)
	if err != nil {
		sendError(ctx, conn, http.StatusBadRequest)
		return err
	}

	authKey, err := uploadAuthKey(header.Authorization)
	if err != nil {
		sendError(ctx, conn, http.StatusBadRequest)
		return err
	}
	if header.FileMetadata == "" {
		sendError(ctx, conn, http.StatusBadRequest)
		return errors.New("compat: no metadata")
	}

	// The instance's policy decides, not the client's request. A client asking
	// for longer than the operator allows is refused rather than quietly given
	// what it asked for.
	expires, err := h.uploads.ResolveExpiry(time.Duration(header.TimeLimit) * time.Second)
	if err != nil {
		sendError(ctx, conn, http.StatusBadRequest)
		return err
	}

	id, err := randomHex(idBytes)
	if err != nil {
		sendError(ctx, conn, http.StatusInternalServerError)
		return err
	}
	ownerToken, err := randomHex(ownerBytes)
	if err != nil {
		sendError(ctx, conn, http.StatusInternalServerError)
		return err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		sendError(ctx, conn, http.StatusInternalServerError)
		return err
	}
	atRestKey, err := blob.NewAtRestKey()
	if err != nil {
		sendError(ctx, conn, http.StatusInternalServerError)
		return err
	}

	now := h.uploads.Now()
	u := &store.Upload{
		ID: id,
		// The owner token is stored hashed even though this protocol's own
		// server keeps it in the clear. Nothing here needs the original, and a
		// stored credential that need not be recoverable should not be.
		OwnerTokenHash: hashToken(ownerToken),
		// No native authenticator exists for this upload; the compatibility row
		// holds the credential instead. The column is not nullable, so it
		// carries a value that authenticates nothing.
		AuthTokenHash: hashToken("compat/" + id),
		AtRestKey:     atRestKey,
		CreatedAt:     now,
		ExpiresAt:     expires,
		MaxDownloads:  downloadLimit(header.DLimit),
	}
	// Bounded by construction today, since downloadLimit never returns zero.
	// Checked anyway: the rule belongs at every entry point rather than resting
	// on what one function currently happens to return.
	if err := h.uploads.EnsureBounded(u.ExpiresAt, u.MaxDownloads); err != nil {
		sendError(ctx, conn, http.StatusBadRequest)
		return err
	}

	c := &store.CompatUpload{
		ID:       id,
		AuthKey:  authKey,
		Nonce:    nonce,
		Metadata: []byte(header.FileMetadata),
	}

	if err := h.store.CreateCompat(ctx, u, c); err != nil {
		sendError(ctx, conn, http.StatusInternalServerError)
		return err
	}

	// The link goes out before a single byte arrives, which is what the
	// protocol specifies: its clients show the recipient's link while the
	// upload is still running.
	if err := sendJSON(ctx, conn, map[string]any{
		"url":        h.downloadURL(id),
		"ownerToken": ownerToken,
		"id":         id,
	}); err != nil {
		return h.abandon(ctx, id, err)
	}

	size, err := h.receive(ctx, conn, id, atRestKey)
	if err != nil {
		sendError(ctx, conn, http.StatusInternalServerError)
		return h.abandon(ctx, id, err)
	}

	if err := h.blobs.Finish(ctx, id); err != nil {
		sendError(ctx, conn, http.StatusInternalServerError)
		return h.abandon(ctx, id, err)
	}

	// Size and completion together. Until this runs the upload is unreachable,
	// so nothing can be served that is only partly written.
	if err := h.store.FinishCompat(ctx, id, size, h.uploads.Now()); err != nil {
		sendError(ctx, conn, http.StatusInternalServerError)
		return h.abandon(ctx, id, err)
	}

	return sendJSON(ctx, conn, map[string]any{"ok": true})
}

// receive streams frames into the blob store until the end-of-file frame.
func (h *Handler) receive(ctx context.Context, conn *websocket.Conn, id string, key []byte) (int64, error) {
	var offset int64
	for {
		typ, frame, err := conn.Read(ctx)
		if err != nil {
			return offset, fmt.Errorf("compat: reading the upload: %w", err)
		}
		if typ != websocket.MessageBinary {
			return offset, errors.New("compat: a text frame in the middle of an upload")
		}

		// One zero byte ends the stream. Any other single byte is content.
		if len(frame) == 1 && frame[0] == endOfFile {
			return offset, nil
		}

		n, err := h.blobs.WriteChunk(ctx, id, key, offset, newByteReader(frame))
		if err != nil {
			return offset, fmt.Errorf("compat: storing the upload: %w", err)
		}
		offset += n
	}
}

// abandon removes an upload that will never be finished.
//
// Reaping would collect it eventually, but an upload whose client has already
// gone is not worth keeping until then: it holds an at-rest key and a partial
// blob, which is exactly the leftover this project promises not to keep.
func (h *Handler) abandon(ctx context.Context, id string, cause error) error {
	// A fresh context: the request's is usually already cancelled by whatever
	// caused this, and cleanup that depends on the failure not having happened
	// is cleanup that never runs.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	if err := h.uploads.Delete(cleanup, id); err != nil {
		h.log.Error("could not discard an abandoned compatibility upload", "error", err)
	}
	return cause
}

func (h *Handler) downloadURL(id string) string {
	base := *h.baseURL
	base.Path = "/download/" + id + "/"
	return base.String()
}

// downloadLimit is how many times an upload may be served.
//
// The protocol default is one, not unlimited, and a client that does not ask
// for a limit expects that one. Treating an absent value as "no limit" turns a
// single-use upload into a permanent one - which is what happened here first,
// and was caught by downloading the same link twice.
func downloadLimit(requested int) int {
	if requested > 0 {
		return requested
	}
	return 1
}

func readHeader(ctx context.Context, conn *websocket.Conn) (*uploadHeader, error) {
	typ, frame, err := conn.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("compat: reading the header: %w", err)
	}
	if typ != websocket.MessageText {
		return nil, errors.New("compat: the opening message is not text")
	}
	if len(frame) > maxHeaderBytes {
		return nil, errors.New("compat: the opening message is too large")
	}

	var header uploadHeader
	if err := json.Unmarshal(frame, &header); err != nil {
		return nil, fmt.Errorf("compat: unreadable header: %w", err)
	}
	return &header, nil
}

func sendJSON(ctx context.Context, conn *websocket.Conn, body any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, encoded)
}

// sendError reports a status the protocol's clients recognise, then leaves the
// connection to be closed by the caller.
func sendError(ctx context.Context, conn *websocket.Conn, status int) {
	_ = sendJSON(ctx, conn, map[string]any{"error": status})
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("compat: random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// newByteReader avoids pulling in bytes.NewReader's whole surface for one call.
func newByteReader(b []byte) io.Reader { return &sliceReader{b: b} }

type sliceReader struct{ b []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
