// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package main

import (
	"os"
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

// Argument handling, which is the part a person meets first.
//
// A wrong argument must produce an explanation, not a transfer to somewhere
// unintended. These run through run() rather than main() so a failure is an
// error rather than an exit code.
func TestArgumentsThatCannotWorkAreRefused(t *testing.T) {
	t.Setenv("SENDAN_INSTANCE", "")

	cases := []struct {
		name string
		args []string
		says string
	}{
		{"nothing at all", nil, "no command"},
		{"an unknown command", []string{"sideways"}, "unknown command"},
		{"up with no instance", []string{"up", "f.txt"}, "no instance"},
		{"up with an unknown option", []string{"up", "--nope", "x"}, "unknown option"},
		{"up with two files", []string{"up", "--to", "http://x", "a", "b"}, "one file"},
		{"--to with no value", []string{"up", "--to"}, "needs a value"},
		{"down with no link", []string{"down"}, "no link"},
		{"down with two links", []string{"down", "a", "b"}, "one link"},
		{"-o with no value", []string{"down", "x", "-o"}, "needs a value"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := run(t.Context(), tc.args)
			if err == nil {
				t.Fatalf("%v was accepted", tc.args)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("%v: %v, want it to mention %q", tc.args, err, tc.says)
			}
		})
	}
}

func TestHelpIsNotAnError(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		if err := run(t.Context(), []string{arg}); err != nil {
			t.Errorf("%s: %v", arg, err)
		}
	}
}

// A pipe carries no filename, and an upload with no name is one a recipient
// cannot save. Saying so beats inventing one.
func TestAPipeWithoutANameIsRefused(t *testing.T) {
	t.Setenv("SENDAN_INSTANCE", "http://127.0.0.1:1")

	err := run(t.Context(), []string{"up", "-"})
	if err == nil {
		t.Fatal("a pipe with no name was accepted")
	}
	if !strings.Contains(err.Error(), "--name") {
		t.Errorf("%v does not say what to do about it", err)
	}
}

func TestADirectoryIsRefusedWithSomethingToDoAboutIt(t *testing.T) {
	t.Setenv("SENDAN_INSTANCE", "http://127.0.0.1:1")

	err := run(t.Context(), []string{"up", t.TempDir()})
	if err == nil {
		t.Fatal("a directory was accepted")
	}
	if !strings.Contains(err.Error(), "archive") {
		t.Errorf("%v does not suggest what to do instead", err)
	}
}

// The instance may come from the environment, which is what makes the command
// usable without repeating it.
func TestTheInstanceMayComeFromTheEnvironment(t *testing.T) {
	t.Setenv("SENDAN_INSTANCE", "http://127.0.0.1:1")

	file := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// It will fail to connect, which is the point: it got far enough to try.
	err := run(t.Context(), []string{"up", file})
	if err == nil {
		t.Fatal("an unreachable instance appeared to succeed")
	}
	if strings.Contains(err.Error(), "no instance") {
		t.Errorf("the environment was not consulted: %v", err)
	}
}

func TestALinkThatIsNotOneIsRefusedBeforeAnyRequest(t *testing.T) {
	err := run(t.Context(), []string{"down", "https://example.org/not-a-download"})
	if err == nil {
		t.Fatal("a link that addresses nothing was accepted")
	}
	if !strings.Contains(err.Error(), "does not address an upload") {
		t.Errorf("%v does not say what is wrong with it", err)
	}
}

// The requirement this command is built around: a password must never be
// available as a plain argument.
//
// An argument appears in the process list, in shell history, and in whatever a
// CI job records, and the password contributes to the wrapping key. A flag that
// accepted one is a flag people would use, so there must not be one - and the
// usage has to say where the password does come from, or somebody will look for
// the flag and conclude they misremembered.
func TestThereIsNoWayToPassAPasswordAsAnArgument(t *testing.T) {
	t.Setenv("SENDAN_INSTANCE", "http://127.0.0.1:1")

	// Anything that looks like it takes a password value must be refused as an
	// unknown option rather than quietly consuming it.
	for _, args := range [][]string{
		{"up", "--password=hunter2", "f"},
		{"up", "--password-value", "hunter2", "f"},
		{"up", "-p", "hunter2", "f"},
		{"up", "--pass", "hunter2", "f"},
	} {
		err := run(t.Context(), args)
		if err == nil {
			t.Errorf("%v was accepted", args)
			continue
		}
		if !strings.Contains(err.Error(), "unknown option") {
			t.Errorf("%v: %v, want it refused as an unknown option", args, err)
		}
	}

	// And the usage points at the ways there are, and says why.
	for _, mentions := range []string{"--password-file", "SENDAN_PASSWORD", "process list"} {
		if !strings.Contains(usage, mentions) {
			t.Errorf("the usage does not mention %q", mentions)
		}
	}
	if !strings.Contains(usage, "There is no --password <value>") {
		t.Error("the usage does not say that a password cannot be given as an argument")
	}

	// The options list must not offer one. Checked against the list rather than
	// the whole text, which mentions the flag in order to deny it.
	options := usage[strings.Index(usage, "Options for up:"):]
	options = options[:strings.Index(options, "There is no")]
	for _, line := range strings.Split(options, "\n") {
		if strings.Contains(line, "--password") && strings.Contains(line, "<") &&
			!strings.Contains(line, "--password-file") {
			t.Errorf("the options list offers a password value: %q", strings.TrimSpace(line))
		}
	}
}

// The new options are read before anything is opened or sent, so a mistake
// stops the command rather than being discovered after a file has been read.
func TestBadOptionsStopBeforeAnythingIsSent(t *testing.T) {
	t.Setenv("SENDAN_INSTANCE", "http://127.0.0.1:1")

	file := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cases := map[string][]string{
		"a lifetime that is not one": {"up", "--expires", "soon", file},
		"a count that is not one":    {"up", "--downloads", "many", file},
		"zero downloads":             {"up", "--downloads", "0", file},
		"--expires with no value":    {"up", "--expires"},
		"--downloads with no value":  {"up", "--downloads"},
	}

	for name, args := range cases {
		err := run(t.Context(), args)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		// Not a connection failure: it never got that far.
		if strings.Contains(err.Error(), "connection refused") {
			t.Errorf("%s: reached the network before noticing: %v", name, err)
		}
	}
}
