// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package main

import (
	"errors"
	"testing"
	"time"
)

// A registry laid out the way a multi-platform build leaves it: one tagged
// index per push, each referencing two images and two attestations.
type build struct {
	index    version
	children []version
}

func at(n int) time.Time { return time.Date(2026, 1, n, 0, 0, 0, 0, time.UTC) }

func newBuild(t *testing.T, day int, tags ...string) build {
	t.Helper()
	id := int64(day * 100)
	b := build{index: version{ID: id, Digest: dig(day, 0), Tags: tags, Created: at(day)}}
	for i := 1; i <= 4; i++ {
		b.children = append(b.children, version{ID: id + int64(i), Digest: dig(day, i), Created: at(day)})
	}
	return b
}

func dig(day, n int) string {
	return "sha256:" + string(rune('a'+day)) + string(rune('0'+n)) + "00000000000000000000000000000000000000000000000000000000000000"
}

func flatten(builds ...build) ([]version, func(string) ([]string, error)) {
	var all []version
	refs := map[string][]string{}
	for _, b := range builds {
		all = append(all, b.index)
		for _, c := range b.children {
			all = append(all, c)
			refs[b.index.Digest] = append(refs[b.index.Digest], c.Digest)
		}
	}
	return all, func(d string) ([]string, error) { return refs[d], nil }
}

func ids(vs []version) []int64 {
	out := make([]int64, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.ID)
	}
	return out
}

func contains(vs []version, id int64) bool {
	for _, v := range vs {
		if v.ID == id {
			return true
		}
	}
	return false
}

func TestKeepsTheMostRecentBuilds(t *testing.T) {
	all, children := flatten(
		newBuild(t, 1, "sha-aaaaaaa"),
		newBuild(t, 2, "sha-bbbbbbb"),
		newBuild(t, 3, "edge", "sha-ccccccc"),
	)

	plan, err := planPrune(all, children, 2)
	if err != nil {
		t.Fatal(err)
	}
	// The oldest build only: its index plus its four children.
	if got := len(plan); got != 5 {
		t.Fatalf("removing %d versions %v, want the 5 of one build", got, ids(plan))
	}
	for _, id := range []int64{100, 101, 102, 103, 104} {
		if !contains(plan, id) {
			t.Errorf("%d was left behind", id)
		}
	}
}

func TestNothingToDoBelowTheThreshold(t *testing.T) {
	all, children := flatten(newBuild(t, 1, "edge"), newBuild(t, 2, "sha-bbbbbbb"))

	plan, err := planPrune(all, children, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 0 {
		t.Fatalf("removing %v with fewer builds than the threshold", ids(plan))
	}
}

func TestNeverTouchesAReleaseImage(t *testing.T) {
	// A release carries version tags. It has to stay pullable for as long as
	// anybody might reproduce or verify it, however old it is.
	release := newBuild(t, 1, "0.1.0", "0.1", "latest")
	all, children := flatten(
		release,
		newBuild(t, 2, "sha-bbbbbbb"),
		newBuild(t, 3, "edge"),
	)

	plan, err := planPrune(all, children, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range append([]version{release.index}, release.children...) {
		if contains(plan, v.ID) {
			t.Fatalf("the release image %d was selected for deletion", v.ID)
		}
	}
}

func TestAnIndexWithOtherTagsIsNotAnEdgeBuild(t *testing.T) {
	// A tag this does not recognise protects the version rather than exposing
	// it, so a future tagging scheme cannot become a deletion.
	odd := newBuild(t, 1, "edge", "nightly")
	all, children := flatten(odd, newBuild(t, 2, "edge"), newBuild(t, 3, "edge"))

	plan, err := planPrune(all, children, 1)
	if err != nil {
		t.Fatal(err)
	}
	if contains(plan, odd.index.ID) {
		t.Fatal("a version carrying an unrecognised tag was selected")
	}
}

func TestChildrenGoBeforeTheirIndex(t *testing.T) {
	// An index deleted first leaves children unreferenced but reachable; a
	// child deleted first only wastes space. The wrong order is a pull that
	// fails on one architecture and succeeds on the other.
	all, children := flatten(newBuild(t, 1, "edge"), newBuild(t, 2, "edge"))

	plan, err := planPrune(all, children, 1)
	if err != nil {
		t.Fatal(err)
	}
	last := plan[len(plan)-1]
	if last.ID != 100 {
		t.Fatalf("the index is at position %v, want it last: %v", last.ID, ids(plan))
	}
}

func TestAChildSharedWithASurvivingIndexIsKept(t *testing.T) {
	// Two builds of unchanged source produce the same child digest, so an
	// index that is being removed can reference a layer the kept one needs.
	old := newBuild(t, 1, "sha-aaaaaaa")
	recent := newBuild(t, 2, "edge")
	shared := old.children[0].Digest

	all := append([]version{old.index, recent.index}, append(old.children, recent.children...)...)
	children := func(d string) ([]string, error) {
		switch d {
		case old.index.Digest:
			return []string{shared, old.children[1].Digest}, nil
		case recent.index.Digest:
			return []string{shared, recent.children[1].Digest}, nil
		}
		return nil, nil
	}

	plan, err := planPrune(all, children, 1)
	if err != nil {
		t.Fatal(err)
	}
	if contains(plan, old.children[0].ID) {
		t.Fatal("a child the surviving index still references was selected")
	}
	if !contains(plan, old.index.ID) {
		t.Fatal("the old index survived")
	}
}

func TestRefusesToActWhenChildrenCannotBeListed(t *testing.T) {
	// Deleting an index whose children could not be listed is exactly how they
	// are orphaned, so this fails rather than guessing.
	all, _ := flatten(newBuild(t, 1, "edge"), newBuild(t, 2, "edge"))
	boom := func(string) ([]string, error) { return nil, errors.New("registry said no") }

	if _, err := planPrune(all, boom, 1); err == nil {
		t.Fatal("planned a deletion without knowing what it references")
	}
}

func TestUntaggedOrphansAreLeftAlone(t *testing.T) {
	// Something nothing references. It may be waste, or it may be a build in
	// flight; either way this is not the thing that decides.
	all, children := flatten(newBuild(t, 1, "edge"), newBuild(t, 2, "edge"))
	orphan := version{ID: 999, Digest: dig(9, 9), Created: at(1)}
	all = append(all, orphan)

	plan, err := planPrune(all, children, 1)
	if err != nil {
		t.Fatal(err)
	}
	if contains(plan, orphan.ID) {
		t.Fatal("an untagged version no index references was selected")
	}
}
