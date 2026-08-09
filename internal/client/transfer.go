// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// tusVersion is the protocol this speaks. See docs/api.md.
const tusVersion = "1.0.0"

// Client talks to one instance.
type Client struct {
	// Origin is the instance, without a trailing slash.
	Origin string
	// HTTP is the transport. A nil value uses http.DefaultClient, which is what
	// the command line wants and what a test replaces.
	HTTP *http.Client
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) url(path string) string {
	return strings.TrimRight(c.Origin, "/") + path
}

// APIError is a response the API did not promise.
//
// The status is separate from the message because it is what a caller branches
// on; the message is server-supplied text shown to a person and never parsed.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("the instance answered %d", e.Status)
	}
	return fmt.Sprintf("the instance answered %d: %s", e.Status, e.Message)
}

// describe reads whatever explanation a failed response carries.
//
// The API answers in JSON and the protocol handler in plain text, and a client
// that assumed either would show nothing for half of what can go wrong.
func describe(resp *http.Response) string {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return ""
	}
	text := strings.TrimSpace(string(body))
	if text == "" {
		return ""
	}

	var parsed struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &parsed) == nil && parsed.Message != "" {
		return parsed.Message
	}
	if len(text) > 200 {
		text = text[:200]
	}
	return text
}

// encodeMetadata renders Upload-Metadata.
//
// The format is `key base64(value)`, comma-separated. That base64 is the
// protocol's own - padded, standard alphabet - not the base64url the wire
// format uses elsewhere, because the server decodes this header before Sendan
// sees it.
//
// Keys are emitted in a fixed order so two runs produce identical requests,
// which makes a difference between them mean something.
func encodeMetadata(values map[string][]byte) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+" "+base64.StdEncoding.EncodeToString(values[k]))
	}
	return strings.Join(parts, ",")
}

// createUpload reserves an upload and returns the URL that identifies it.
//
// The Location may be relative - the instance answers with a path, because it
// cannot know the scheme a client reached it by (docs/api.md) - so it is
// resolved against the request that was made.
func (c *Client) createUpload(ctx context.Context, length int64, metadata map[string][]byte) (string, error) {
	endpoint := c.url("/api/uploads")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Tus-Resumable", tusVersion)
	req.Header.Set("Upload-Length", strconv.FormatInt(length, 10))
	req.Header.Set("Upload-Metadata", encodeMetadata(metadata))

	resp, err := c.http().Do(req)
	if err != nil {
		return "", fmt.Errorf("client: reaching %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return "", &APIError{Status: resp.StatusCode, Message: describe(resp)}
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("client: the instance created an upload without saying where")
	}
	base, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	rel, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("client: the instance gave an unusable location %q", location)
	}
	return base.ResolveReference(rel).String(), nil
}

// sendBody writes the whole encoding at an offset in one request.
//
// One request rather than several: this is not a browser, so there is no reason
// to slice a body that can be sent as a stream. The declared length is set
// explicitly, which is what lets the instance enforce its size limit.
func (c *Client) sendBody(ctx context.Context, location string, offset, length int64, body io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, location, body)
	if err != nil {
		return err
	}
	req.Header.Set("Tus-Resumable", tusVersion)
	req.Header.Set("Content-Type", "application/offset+octet-stream")
	req.Header.Set("Upload-Offset", strconv.FormatInt(offset, 10))
	req.ContentLength = length

	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("client: sending the upload: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		return &APIError{Status: resp.StatusCode, Message: describe(resp)}
	}

	// The instance decides what it stored. A disagreement here means the
	// encoding and the declared length have diverged, which would otherwise
	// surface as an upload that never completes and a link that never resolves.
	reported := resp.Header.Get("Upload-Offset")
	stored, err := strconv.ParseInt(reported, 10, 64)
	if err != nil {
		return fmt.Errorf("client: the instance reported the offset as %q", reported)
	}
	if stored != offset+length {
		return fmt.Errorf("client: sent %d bytes from %d but the instance holds %d",
			length, offset, stored)
	}
	return nil
}
