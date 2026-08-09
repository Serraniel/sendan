// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// The filename travels in the metadata envelope, which the sender wrote. Used
// as a path it would let them choose where the recipient's file lands.
func TestASenderCannotChooseWhereTheFileLands(t *testing.T) {
	traversal := []string{
		"../../.bashrc",
		"../evil",
		"/etc/passwd",
		"/../../etc/passwd",
		`..\..\evil.txt`,
		"subdir/../../out",
	}

	for _, sender := range traversal {
		got, err := safeName(sender)
		if err != nil {
			// Refusing is a fine outcome; escaping is not.
			continue
		}
		if strings.ContainsRune(got, filepath.Separator) {
			t.Errorf("%q became %q, which is a path", sender, got)
		}
		if got == ".." || got == "." {
			t.Errorf("%q became %q, which is a directory", sender, got)
		}
		if filepath.IsAbs(got) {
			t.Errorf("%q became the absolute path %q", sender, got)
		}
	}
}

// A name with directories in it is reduced to the file, not refused.
//
// Both are safe - the separator check would refuse it either way - so this is
// about being useful rather than about traversal: a sender who names a file
// "photos/holiday.jpg" meant "holiday.jpg", and refusing it would send the
// recipient to pass -o for no reason. Asserting only that traversal is blocked
// cannot see the difference, and a mutation removing the reduction survived
// until this was here.
func TestADirectoryInTheNameIsReducedToTheFile(t *testing.T) {
	for sender, want := range map[string]string{
		"photos/holiday.jpg": "holiday.jpg",
		"a/b/c/deep.txt":     "deep.txt",
		"subdir/../out.bin":  "out.bin",
	} {
		got, err := safeName(sender)
		if err != nil {
			t.Errorf("%q was refused rather than reduced: %v", sender, err)
			continue
		}
		if got != want {
			t.Errorf("%q became %q, want %q", sender, got, want)
		}
	}
}

// These survive filepath.Base intact and are not files, so they are refused
// rather than repaired: a recipient choosing with -o beats this guessing.
func TestNamesThatAreNotFilesAreRefused(t *testing.T) {
	for _, sender := range []string{"", ".", "..", "/", "//", "./", "../"} {
		if got, err := safeName(sender); err == nil {
			t.Errorf("%q was accepted as %q", sender, got)
		}
	}
}

func TestAnOrdinaryNameSurvives(t *testing.T) {
	for _, sender := range []string{
		"report.pdf",
		"archive.tar.gz",
		"notes",
		"отчёт.pdf",
		"a file with spaces.txt",
		".hidden",
	} {
		got, err := safeName(sender)
		if err != nil {
			t.Errorf("%q was refused: %v", sender, err)
			continue
		}
		if got != sender {
			t.Errorf("%q became %q", sender, got)
		}
	}
}

// The message has to name the file the sender chose, or a recipient cannot tell
// which of several transfers went wrong.
func TestARefusalNamesWhatWasRefused(t *testing.T) {
	_, err := safeName("../../evil")
	if err == nil {
		t.Skip("this name is accepted after reduction, which the other tests cover")
	}
	if !strings.Contains(err.Error(), "../../evil") {
		t.Errorf("the refusal does not say what was refused: %v", err)
	}
	if !strings.Contains(err.Error(), "-o") {
		t.Errorf("the refusal does not say what to do about it: %v", err)
	}
}

func TestHumanSizeReadsAsASize(t *testing.T) {
	cases := map[int64]string{
		0:             "0 bytes",
		999:           "999 bytes",
		1000:          "1.0 kB",
		300_000:       "300.0 kB",
		1_500_000:     "1.5 MB",
		2_000_000_000: "2.0 GB",
	}
	for n, want := range cases {
		if got := humanSize(n); got != want {
			t.Errorf("%d bytes reads as %q, want %q", n, got, want)
		}
	}
}
