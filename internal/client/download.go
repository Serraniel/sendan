// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Serraniel/sendan/internal/crypto"
)

// ErrUnavailable reports an upload the instance will not serve.
//
// One error for expired, exhausted, revoked, unknown and still-being-written,
// because the instance answers 404 for all of them and is right to: saying
// which applies would confirm to a stranger that an upload existed. A caller
// must not guess between them either.
var ErrUnavailable = errors.New(
	"this upload is no longer available: it may have expired, reached its download limit, " +
		"been deleted by the sender, or never have existed")

// ErrPassword reports a file that did not open.
//
// A wrong password and a corrupt container are indistinguishable by
// construction (spec §13 invariant 5); distinguishing them would let anyone
// holding the ciphertext confirm a guessed password offline. Which error a
// caller sees turns on whether the instance said a password was required, never
// on the failure.
var ErrPassword = errors.New("that password did not open the file")

// ErrDamaged reports a link or stored file that cannot be opened, where no
// password is involved and so there is nothing to have got wrong.
var ErrDamaged = errors.New("this link or the stored file is damaged")

// Published is what an instance says about an upload before anything is
// decrypted.
type Published struct {
	PasswordRequired bool
	KDF              *crypto.PasswordParams
	ExpiresAt        *time.Time
	DownloadsLeft    *int64

	wrappedFileKey   []byte
	wrapNonce        []byte
	metadataEnvelope []byte
	metadataNonce    []byte
}

type publishedJSON struct {
	WrappedFileKey   b64 `json:"wrappedFileKey"`
	WrapNonce        b64 `json:"wrapNonce"`
	MetadataEnvelope b64 `json:"metadataEnvelope"`
	MetadataNonce    b64 `json:"metadataNonce"`
	PasswordRequired bool
	KDF              *struct {
		Salt        b64 `json:"salt"`
		MemoryKiB   uint32
		Iterations  uint32
		Parallelism uint8
	} `json:"kdf"`
	ExpiresAt          *time.Time `json:"expiresAt"`
	DownloadsRemaining *int64     `json:"downloadsRemaining"`
}

// b64 decodes the wire format's unpadded base64url (spec §1).
type b64 []byte

func (v *b64) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	raw, err := encoding.DecodeString(text)
	if err != nil {
		return fmt.Errorf("not base64url: %w", err)
	}
	*v = raw
	return nil
}

// Describe reads what the instance publishes about an upload.
//
// Unauthenticated by necessity: producing a token requires the password, and
// this is where a client learns whether there is one. Nothing is disclosed by
// that - every value is ciphertext under a key the instance does not hold - and
// reading it does not consume a download.
func (c *Client) Describe(ctx context.Context, id string) (*Published, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.url("/api/uploads/"+id+"/metadata"), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http().Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: reaching the instance: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrUnavailable
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{Status: resp.StatusCode, Message: describe(resp)}
	}

	var raw publishedJSON
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("client: the instance sent something unreadable: %w", err)
	}

	p := &Published{
		PasswordRequired: raw.PasswordRequired,
		ExpiresAt:        raw.ExpiresAt,
		DownloadsLeft:    raw.DownloadsRemaining,
		wrappedFileKey:   raw.WrappedFileKey,
		wrapNonce:        raw.WrapNonce,
		metadataEnvelope: raw.MetadataEnvelope,
		metadataNonce:    raw.MetadataNonce,
	}
	if raw.PasswordRequired {
		// Required when a password is set: without them no key can be derived,
		// so an upload missing them is one nobody could ever open.
		if raw.KDF == nil {
			return nil, fmt.Errorf("client: the instance says a password is needed but gave no parameters")
		}
		p.KDF = &crypto.PasswordParams{
			Salt:        raw.KDF.Salt,
			MemoryKiB:   raw.KDF.MemoryKiB,
			Iterations:  raw.KDF.Iterations,
			Parallelism: raw.KDF.Parallelism,
		}
	}
	return p, nil
}

// Opened is an upload whose keys have been recovered.
type Opened struct {
	File    crypto.Metadata
	fileKey []byte
	keys    *crypto.Keys
}

// Open recovers the keys and reads what the file is.
//
// Nothing here touches the network. Succeeding proves the link, and the
// password where there is one, are right: the wrapped key is authenticated, so
// a wrong key cannot open it. That is why a password is checked here rather
// than by asking the instance - a check the instance performed would be one it
// could lie about, and one that spent an attempt allowance.
func Open(link Link, p *Published, password string) (*Opened, error) {
	var keys *crypto.Keys
	var err error
	if p.KDF == nil {
		keys, err = crypto.DeriveKeys(link.FileID, link.LinkSecret)
	} else {
		keys, err = crypto.DeriveKeysWithPassword(link.FileID, link.LinkSecret, password, *p.KDF)
	}
	if err != nil {
		// The schedule refuses an empty password outright (spec §4), which is
		// the ordinary case of somebody pressing return at a prompt.
		if p.PasswordRequired {
			return nil, ErrPassword
		}
		return nil, ErrDamaged
	}

	fileKey, err := crypto.UnwrapFileKey(keys.Wrapping, p.wrapNonce, p.wrappedFileKey)
	if err != nil {
		if p.PasswordRequired {
			return nil, ErrPassword
		}
		return nil, ErrDamaged
	}

	file, err := crypto.OpenMetadata(keys.Metadata, p.metadataNonce, p.metadataEnvelope)
	if err != nil {
		// The wrapped key opened, so the keys are right and the envelope is
		// not. Saying so is safe precisely because the key already worked.
		return nil, fmt.Errorf("client: the file's description is damaged")
	}

	return &Opened{File: file, fileKey: fileKey, keys: keys}, nil
}

// Fetch writes the decrypted file to w.
//
// Decryption is streamed, so a truncated, reordered or modified stream fails
// rather than yielding partial plaintext (spec §13 invariant 3). The caller is
// responsible for not keeping what a failure produced: bytes reach w before the
// end of the stream is known to be sound, which is inherent to streaming and is
// why the command line writes to a temporary name and renames on success.
func (c *Client) Fetch(ctx context.Context, id string, o *Opened, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/api/uploads/"+id+"/content"), nil)
	if err != nil {
		return err
	}
	// Never in the query: the token derives from the link secret, which this
	// scheme keeps out of logs by putting it in a fragment, and a query
	// parameter would write it to every access log in between.
	req.Header.Set("Authorization", "Bearer "+encoding.EncodeToString(o.keys.AuthToken))

	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("client: reaching the instance: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusNotFound,
		// The token derives from the same schedule that just unwrapped the key,
		// so it cannot be wrong here: a 401 means the upload changed underneath.
		resp.StatusCode == http.StatusUnauthorized:
		return ErrUnavailable
	case resp.StatusCode != http.StatusOK:
		return &APIError{Status: resp.StatusCode, Message: describe(resp)}
	}

	d, err := crypto.NewDecryptor(resp.Body, o.fileKey)
	if err != nil {
		return err
	}
	written, err := io.Copy(w, d)
	if err != nil {
		return fmt.Errorf("client: the file failed its integrity check: %w", err)
	}
	// The envelope is authenticated and states the size, so a disagreement
	// means the instance served something other than what was sealed.
	if written != o.File.Size {
		return fmt.Errorf("client: received %d bytes, the file's description says %d",
			written, o.File.Size)
	}
	return nil
}
