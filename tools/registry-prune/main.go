// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Command registry-prune removes old edge builds from the container registry.
//
// Every push to main publishes five versions: a multi-platform index, the two
// images it references, and the provenance and SBOM attestations. Only the
// index is tagged. Nothing is wrong with the other four - they are how a
// multi-platform image is stored - but at five per push the registry grows
// without limit. See #225.
//
// # What it will not do
//
// It never touches a released image. A release has to stay pullable for as
// long as anybody might reproduce or verify it, which is the point of
// publishing digests and signatures at all. Only `edge` and `sha-` builds are
// candidates, and a version carrying any other tag is protected outright.
//
// It never deletes a child on its own. The children are referenced by an index
// rather than named, so removing one leaves an index that resolves to nothing
// on that architecture: the image still appears to exist, and a pull fails on
// an arm64 machine while succeeding on amd64. Deletions therefore go
// children-first and only for an index that is itself being removed.
//
// # Why it plans before it acts
//
// Deleting is not reversible and a registry does not ask twice, so the default
// is to print the plan and change nothing. -apply is a deliberate second step.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

func main() {
	var (
		owner   = flag.String("owner", "", "user the package belongs to")
		pkg     = flag.String("package", "sendan", "container package name")
		keep    = flag.Int("keep", 10, "how many edge builds to keep")
		apply   = flag.Bool("apply", false, "actually delete; otherwise only print the plan")
		timeout = flag.Duration("timeout", 2*time.Minute, "budget for the whole run")
	)
	flag.Parse()

	if *owner == "" {
		fail(errors.New("-owner is required"))
	}
	if *keep < 1 {
		// Keeping none would delete the edge image that main currently points
		// at, which is the one thing here that somebody might be pulling.
		fail(fmt.Errorf("-keep must be at least 1, got %d", *keep))
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fail(errors.New("GITHUB_TOKEN is unset"))
	}

	c := &client{
		http:     &http.Client{Timeout: *timeout},
		token:    token,
		owner:    *owner,
		pkg:      *pkg,
		api:      "https://api.github.com",
		registry: "https://ghcr.io",
	}

	versions, err := c.versions()
	if err != nil {
		fail(err)
	}

	plan, err := planPrune(versions, c.children, *keep)
	if err != nil {
		fail(err)
	}

	report(plan, versions, *keep)

	if !*apply {
		fmt.Println("\nnothing was deleted; pass -apply to carry this out.")
		return
	}
	for _, v := range plan {
		if err := c.delete(v.ID); err != nil {
			fail(fmt.Errorf("deleting %d (%s): %w", v.ID, short(v.Digest), err))
		}
		fmt.Printf("deleted %d %s %s\n", v.ID, short(v.Digest), strings.Join(v.Tags, ","))
	}
}

// version is one entry in the registry, tagged or not.
type version struct {
	ID      int64
	Digest  string
	Tags    []string
	Created time.Time
}

// isEdge reports whether a version is one of the builds from main.
//
// Named tags rather than a pattern for what to protect: a tag this does not
// recognise is left alone. Getting that the wrong way round would make every
// future tagging scheme a deletion.
func (v version) isEdge() bool {
	for _, t := range v.Tags {
		if t != "edge" && !strings.HasPrefix(t, "sha-") {
			return false
		}
	}
	return len(v.Tags) > 0
}

// planPrune decides what to delete, children before their index.
//
// children resolves an index digest to the digests it references. It is called
// only for indexes, and a failure to resolve one is fatal rather than skipped:
// deleting an index whose children could not be listed is how children are
// orphaned.
func planPrune(versions []version, children func(digest string) ([]string, error), keep int) ([]version, error) {
	byDigest := make(map[string]version, len(versions))
	for _, v := range versions {
		byDigest[v.Digest] = v
	}

	var edges []version
	for _, v := range versions {
		if v.isEdge() {
			edges = append(edges, v)
		}
	}
	// Newest first, so "keep" means the most recent ones. Ties broken by ID,
	// which rises with time, so the order is total and a run is repeatable.
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Created.Equal(edges[j].Created) {
			return edges[i].ID > edges[j].ID
		}
		return edges[i].Created.After(edges[j].Created)
	})

	if len(edges) <= keep {
		return nil, nil
	}
	doomed, kept := edges[keep:], edges[:keep]

	// Everything reachable from an index that survives, so a child shared with
	// a doomed index is never taken with it. Sharing is not hypothetical: two
	// builds of unchanged source produce the same child digest.
	protected := make(map[string]bool)
	for _, v := range versions {
		if len(v.Tags) > 0 && !v.isEdge() {
			// Released images and anything else carrying a tag this does not
			// recognise. Their children are protected too, which is why this
			// walks them rather than only marking the index.
			//
			// The tag test is what keeps it from protecting everything: an
			// untagged version is not an edge build either, and marking those
			// here would protect the very children a doomed index must take
			// with it.
			protected[v.Digest] = true
			refs, err := children(v.Digest)
			if err != nil {
				return nil, fmt.Errorf("listing children of %s: %w", short(v.Digest), err)
			}
			for _, r := range refs {
				protected[r] = true
			}
		}
	}
	for _, v := range kept {
		protected[v.Digest] = true
		refs, err := children(v.Digest)
		if err != nil {
			return nil, fmt.Errorf("listing children of %s: %w", short(v.Digest), err)
		}
		for _, r := range refs {
			protected[r] = true
		}
	}

	var out []version
	seen := make(map[int64]bool)
	for _, v := range doomed {
		refs, err := children(v.Digest)
		if err != nil {
			return nil, fmt.Errorf("listing children of %s: %w", short(v.Digest), err)
		}
		// Children first: an index without its children is a broken pull, an
		// orphaned child is only waste.
		for _, r := range refs {
			child, known := byDigest[r]
			if !known || protected[r] || seen[child.ID] {
				continue
			}
			seen[child.ID] = true
			out = append(out, child)
		}
		if !protected[v.Digest] && !seen[v.ID] {
			seen[v.ID] = true
			out = append(out, v)
		}
	}
	return out, nil
}

func report(plan, all []version, keep int) {
	edges := 0
	for _, v := range all {
		if v.isEdge() {
			edges++
		}
	}
	fmt.Printf("%d versions, %d of them edge builds; keeping %d\n", len(all), edges, keep)
	if len(plan) == 0 {
		fmt.Println("nothing to remove.")
		return
	}
	fmt.Printf("\nto remove, in this order:\n")
	for _, v := range plan {
		tags := strings.Join(v.Tags, ",")
		if tags == "" {
			tags = "(untagged)"
		}
		fmt.Printf("  %12d  %s  %-28s  %s\n", v.ID, short(v.Digest), tags, v.Created.Format(time.RFC3339))
	}
}

func short(digest string) string {
	d := strings.TrimPrefix(digest, "sha256:")
	if len(d) > 12 {
		d = d[:12]
	}
	return "sha256:" + d
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "registry-prune:", err)
	os.Exit(1)
}

// client talks to the two services this needs: the API that lists and deletes
// versions, and the registry that says which children an index references.
type client struct {
	http     *http.Client
	token    string
	owner    string
	pkg      string
	api      string
	registry string

	bearer string // registry token, fetched once
}

func (c *client) versions() ([]version, error) {
	var out []version
	for page := 1; ; page++ {
		url := fmt.Sprintf("%s/users/%s/packages/container/%s/versions?per_page=100&page=%d",
			c.api, c.owner, c.pkg, page)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/vnd.github+json")

		var body []struct {
			ID        int64     `json:"id"`
			Name      string    `json:"name"`
			CreatedAt time.Time `json:"created_at"`
			Metadata  struct {
				Container struct {
					Tags []string `json:"tags"`
				} `json:"container"`
			} `json:"metadata"`
		}
		if err := c.do(req, &body); err != nil {
			return nil, err
		}
		if len(body) == 0 {
			return out, nil
		}
		for _, b := range body {
			out = append(out, version{
				ID:      b.ID,
				Digest:  b.Name,
				Tags:    b.Metadata.Container.Tags,
				Created: b.CreatedAt,
			})
		}
	}
}

// children lists the digests an index references, and nothing for a plain
// image. A manifest that is not an index is not an error: the caller asks
// about every candidate and only some of them are indexes.
func (c *client) children(digest string) ([]string, error) {
	if c.bearer == "" {
		if err := c.authenticate(); err != nil {
			return nil, err
		}
	}
	url := fmt.Sprintf("%s/v2/%s/%s/manifests/%s", c.registry, strings.ToLower(c.owner), c.pkg, digest)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.bearer)
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ", "))

	var body struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := c.do(req, &body); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(body.Manifests))
	for _, m := range body.Manifests {
		out = append(out, m.Digest)
	}
	return out, nil
}

func (c *client) authenticate() error {
	url := fmt.Sprintf("%s/token?scope=repository:%s/%s:pull", c.registry, strings.ToLower(c.owner), c.pkg)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth("x-access-token", c.token)

	var body struct {
		Token string `json:"token"`
	}
	if err := c.do(req, &body); err != nil {
		return err
	}
	if body.Token == "" {
		return errors.New("the registry returned an empty token")
	}
	c.bearer = body.Token
	return nil
}

func (c *client) delete(id int64) error {
	url := fmt.Sprintf("%s/users/%s/packages/container/%s/versions/%d", c.api, c.owner, c.pkg, id)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	return c.do(req, nil)
}

func (c *client) do(req *http.Request, into any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		// The body carries the reason - a missing scope reads very differently
		// from a version somebody already removed - and a bare status code
		// sends the reader to the wrong place.
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s: %s: %s", req.Method, req.URL.Path, resp.Status, strings.TrimSpace(string(b)))
	}
	if into == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(into)
}
