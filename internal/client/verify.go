// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/Serraniel/sendan/internal/manifest"
)

// Claim is what an instance says about itself, from /api/source.
//
// A claim and not a fact. The instance compiles and serves this, so a modified
// one can return anything; it is read to know which published build to compare
// against, and the comparison is what decides.
type Claim struct {
	Version  string `json:"version"`
	Commit   string `json:"commit"`
	Modified bool   `json:"modified"`
	Source   string `json:"source"`
	License  string `json:"license"`
}

// Mismatch is one asset that is not what was published.
type Mismatch struct {
	Path string
	// Expected is the digest the manifest gives. Served is what arrived, or a
	// description of why nothing did.
	Expected string
	Served   string
}

// Verification is the result of checking an instance against a manifest.
type Verification struct {
	Instance   string
	Claim      Claim
	Manifest   *manifest.Manifest
	Checked    int
	Mismatches []Mismatch
}

// OK reports whether every asset matched.
func (v *Verification) OK() bool { return len(v.Mismatches) == 0 }

// Claim reads what an instance says it is running.
func (c *Client) Claim(ctx context.Context) (Claim, error) {
	var claim Claim

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/api/source"), nil)
	if err != nil {
		return claim, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http().Do(req)
	if err != nil {
		return claim, fmt.Errorf("client: reaching the instance: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return claim, &APIError{Status: resp.StatusCode, Message: describe(resp)}
	}
	if err := json.NewDecoder(resp.Body).Decode(&claim); err != nil {
		return claim, fmt.Errorf("client: the instance's source report is unreadable: %w", err)
	}
	return claim, nil
}

// Verify fetches every asset the manifest names and compares what was served.
//
// The manifest comes from the caller, never from the instance: an instance
// serving the statement it is measured against would be attesting to itself,
// which is the circularity docs/design.md §7.1 exists to avoid.
//
// Digests are over the bytes as they arrive, before any transport decoding, so
// what is compared is the resource rather than one encoding of it.
func (c *Client) Verify(ctx context.Context, m *manifest.Manifest) (*Verification, error) {
	if m == nil || len(m.Assets) == 0 {
		// A manifest covering nothing would verify anything.
		return nil, fmt.Errorf("client: the manifest names no assets")
	}
	if m.Schema != manifest.Schema {
		// Refusing beats guessing at a format this binary does not know.
		return nil, fmt.Errorf(
			"client: this manifest is schema %d and this client understands %d",
			m.Schema, manifest.Schema)
	}

	claim, err := c.Claim(ctx)
	if err != nil {
		// Not fatal. The comparison is what decides, and an instance that will
		// not say what it is can still be measured against a manifest.
		claim = Claim{Version: "unknown", Commit: "unknown"}
	}

	v := &Verification{Instance: c.Origin, Claim: claim, Manifest: m}

	// Sorted so two runs report in the same order and a difference between them
	// is a difference in the instance.
	paths := make([]string, 0, len(m.Assets))
	for path := range m.Assets {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		expected := m.Assets[path]
		served, err := c.digestOf(ctx, path)
		v.Checked++

		switch {
		case err != nil:
			v.Mismatches = append(v.Mismatches, Mismatch{
				Path: path, Expected: expected, Served: err.Error(),
			})
		case served != expected:
			v.Mismatches = append(v.Mismatches, Mismatch{
				Path: path, Expected: expected, Served: served,
			})
		}
	}
	return v, nil
}

// digestOf fetches one asset and hashes what arrived.
func (c *Client) digestOf(ctx context.Context, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url(path), nil)
	if err != nil {
		return "", err
	}
	// Asking for the bytes as stored, because the manifest records those. This
	// also stops the transport decompressing on our behalf: Go only does that
	// for encodings it requested itself, and it does not request this one.
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := c.http().Do(req)
	if err != nil {
		return "", fmt.Errorf("could not be fetched: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the instance answered %d", resp.StatusCode)
	}

	// A server or a CDN may compress anyway. Hashing what arrived would then
	// differ from the manifest for a reason that has nothing to do with the
	// client being modified - and "this instance is not serving the published
	// client" is the worst possible way to say "something gzipped it".
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return "", fmt.Errorf(
			"served %s-encoded despite being asked for the bytes as stored, "+
				"so it cannot be compared; check whether something in front of the "+
				"instance is compressing responses", encoding)
	}

	return manifest.DigestOf(resp.Body)
}

// LoadManifest reads a manifest from JSON.
func LoadManifest(r io.Reader) (*manifest.Manifest, error) {
	var m manifest.Manifest
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		return nil, fmt.Errorf("client: unreadable manifest: %w", err)
	}
	return &m, nil
}

// FetchManifest reads a manifest from a URL.
//
// Used for the release's own copy. Nothing here talks to the instance being
// verified, and a caller passing an instance's URL would be defeating the
// point - which is why the default in the command names the release.
func (c *Client) FetchManifest(ctx context.Context, url string) (*manifest.Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: fetching the manifest from %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"client: %s answered %d; is there a published manifest for that version?",
			url, resp.StatusCode)
	}
	return LoadManifest(resp.Body)
}

// ReleaseManifestURL is where a version's manifest is published.
//
// Built into this binary rather than discovered, because the point of the check
// is that the statement comes from somewhere the instance does not control. A
// fork publishes its own and its own client names it here.
func ReleaseManifestURL(source, version string) string {
	base := strings.TrimRight(source, "/")
	return fmt.Sprintf("%s/releases/download/%s/manifest.json", base, version)
}
