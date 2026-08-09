// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package client

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/Serraniel/sendan/internal/crypto"
)

// UploadOptions is what the sender chose. The zero value asks for the
// instance's defaults.
type UploadOptions struct {
	// Password contributes to the key, so the instance cannot open the file
	// without it. Empty means none.
	Password string
	// TTLSeconds is the requested lifetime. Zero selects the instance default.
	TTLSeconds int64
	// MaxDownloads is the download limit. Zero means no limit.
	MaxDownloads int64
}

// Upload is what an upload produced.
//
// These values exist only here. The link opens the file and the owner token
// removes it; the instance holds neither and can reissue neither.
type Upload struct {
	Link       Link
	OwnerToken []byte
}

// Send encrypts what r yields and uploads it.
//
// size is the plaintext length where it is known, and negative where it is not
// - a pipe, which cannot be measured without being read. The instance refuses a
// deferred length, so an unmeasurable source has to be encoded before it can be
// declared; see spoolCiphertext for what that costs and why it costs only that.
//
// The order below is fixed by the key schedule: the identifier is the salt, so
// nothing else can be computed before it exists (spec §3). Do not reorder it.
func (c *Client) Send(ctx context.Context, r io.Reader, name, mediaType string, size int64, opts UploadOptions) (*Upload, error) {
	fileID, err := crypto.NewFileID()
	if err != nil {
		return nil, err
	}
	linkSecret, err := crypto.NewLinkSecret()
	if err != nil {
		return nil, err
	}
	fileKey, err := crypto.NewFileKey()
	if err != nil {
		return nil, err
	}
	ownerToken, err := crypto.NewOwnerToken()
	if err != nil {
		return nil, err
	}

	var keys *crypto.Keys
	var params crypto.PasswordParams
	if opts.Password == "" {
		keys, err = crypto.DeriveKeys(fileID, linkSecret)
	} else {
		params, err = crypto.NewPasswordParams()
		if err != nil {
			return nil, err
		}
		keys, err = crypto.DeriveKeysWithPassword(fileID, linkSecret, opts.Password, params)
	}
	if err != nil {
		return nil, err
	}

	// The body is prepared before the upload is created, because creating it
	// requires the declared length and an unmeasurable source has none until it
	// has been encoded.
	body, length, plaintext, cleanup, err := c.encodedBody(r, fileKey, size)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	wrapNonce, wrapped, err := crypto.WrapFileKey(keys.Wrapping, fileKey)
	if err != nil {
		return nil, err
	}
	if mediaType == "" {
		// A recipient still has to be given something a save dialog will accept.
		mediaType = "application/octet-stream"
	}
	metaNonce, envelope, err := crypto.SealMetadata(keys.Metadata, crypto.Metadata{
		Name: name,
		Type: mediaType,
		Size: plaintext,
	})
	if err != nil {
		return nil, err
	}

	metadata := map[string][]byte{
		"fileID":           fileID,
		"wrappedFileKey":   wrapped,
		"wrapNonce":        wrapNonce,
		"metadataEnvelope": envelope,
		"metadataNonce":    metaNonce,
		"authTokenHash":    crypto.AuthTokenHash(keys.AuthToken),
		"ownerTokenHash":   crypto.OwnerTokenHash(ownerToken),
		"ttlSeconds":       []byte(strconv.FormatInt(opts.TTLSeconds, 10)),
		"maxDownloads":     []byte(strconv.FormatInt(opts.MaxDownloads, 10)),
	}
	if opts.Password != "" {
		// Necessarily public: a recipient cannot derive anything without them,
		// and they disclose only that a password exists (spec §9).
		metadata["passwordSalt"] = params.Salt
		metadata["argon2MemoryKiB"] = []byte(strconv.FormatUint(uint64(params.MemoryKiB), 10))
		metadata["argon2Iterations"] = []byte(strconv.FormatUint(uint64(params.Iterations), 10))
		metadata["argon2Parallelism"] = []byte(strconv.FormatUint(uint64(params.Parallelism), 10))
	}

	location, err := c.createUpload(ctx, length, metadata)
	if err != nil {
		return nil, err
	}
	if err := c.sendBody(ctx, location, 0, length, body); err != nil {
		return nil, err
	}

	return &Upload{
		Link:       Link{Origin: c.Origin, FileID: fileID, LinkSecret: linkSecret},
		OwnerToken: ownerToken,
	}, nil
}

// encodedBody returns the ciphertext to send and how long it is.
//
// A measurable source is encoded as it is sent: the length follows from the
// plaintext length, so nothing has to be produced in advance.
func (c *Client) encodedBody(r io.Reader, fileKey []byte, size int64) (io.Reader, int64, int64, func(), error) {
	if size < 0 {
		return spoolCiphertext(r, fileKey)
	}

	length, err := crypto.EncodedContentLength(size)
	if err != nil {
		return nil, 0, 0, func() {}, err
	}

	pr, pw := io.Pipe()
	go func() {
		e, err := crypto.NewEncryptor(pw, fileKey)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(e, r); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		// Close writes the final record, which is what tells a reader the
		// stream was not truncated.
		if err := e.Close(); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()
	return pr, length, size, func() { _ = pr.Close() }, nil
}

// spoolCiphertext encodes a source that cannot be measured, to a temporary file.
//
// The instance refuses a deferred length (docs/api.md), so a pipe has to be
// encoded before it can be declared. What is spooled is **ciphertext**: the
// plaintext is never written anywhere, so an interrupted upload leaves nothing
// on disk that anybody could read. The file is removed as soon as it is opened,
// so it has no name for the whole time it holds anything.
func spoolCiphertext(r io.Reader, fileKey []byte) (io.Reader, int64, int64, func(), error) {
	tmp, err := os.CreateTemp("", "sendan-*")
	if err != nil {
		return nil, 0, 0, func() {}, fmt.Errorf("client: spooling the upload: %w", err)
	}
	// Unlinked immediately. It stays readable through the open descriptor and
	// is reclaimed when that closes, including if this process is killed.
	_ = os.Remove(tmp.Name())
	cleanup := func() { _ = tmp.Close() }

	e, err := crypto.NewEncryptor(tmp, fileKey)
	if err != nil {
		cleanup()
		return nil, 0, 0, func() {}, err
	}
	// io.Copy reports what it wrote into the encoder, which is the plaintext
	// length exactly. Recovering it from the encoded length instead would mean
	// a second calculation to keep in step with the first.
	plaintext, err := io.Copy(e, r)
	if err != nil {
		cleanup()
		return nil, 0, 0, func() {}, fmt.Errorf("client: reading the input: %w", err)
	}
	if err := e.Close(); err != nil {
		cleanup()
		return nil, 0, 0, func() {}, err
	}

	length, err := tmp.Seek(0, io.SeekCurrent)
	if err != nil {
		cleanup()
		return nil, 0, 0, func() {}, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, 0, 0, func() {}, err
	}
	return tmp, length, plaintext, cleanup, nil
}
