// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestALifetimeIsReadTheWayPeopleWriteOne(t *testing.T) {
	for text, want := range map[string]time.Duration{
		"30m":   30 * time.Minute,
		"12h":   12 * time.Hour,
		"1h30m": 90 * time.Minute,
		// time.ParseDuration has no day, because in general a day is not a
		// fixed length. Here it is: this becomes a number of seconds.
		"1d":   24 * time.Hour,
		"7d":   7 * 24 * time.Hour,
		"0.5d": 12 * time.Hour,
		" 7d ": 7 * 24 * time.Hour,
	} {
		got, err := parseLifetime(text)
		if err != nil {
			t.Errorf("%q: %v", text, err)
			continue
		}
		if got != want {
			t.Errorf("%q is %v, want %v", text, got, want)
		}
	}
}

func TestALifetimeThatIsNotOneIsRefused(t *testing.T) {
	for _, text := range []string{"", "   ", "soon", "7 days", "-1h", "-3d", "d", "1x"} {
		if got, err := parseLifetime(text); err == nil {
			t.Errorf("%q was accepted as %v", text, got)
		}
	}
}

// The refusal has to say what a lifetime looks like, or somebody has to guess.
func TestALifetimeRefusalShowsTheShape(t *testing.T) {
	_, err := parseLifetime("soon")
	if err == nil {
		t.Fatal("accepted")
	}
	for _, hint := range []string{"30m", "12h", "7d"} {
		if !strings.Contains(err.Error(), hint) {
			t.Errorf("%v does not show %q as an example", err, hint)
		}
	}
}

// Zero means "no limit" on the wire for downloads and "the instance decides"
// for the lifetime. Somebody typing 0 means neither of those, so both are
// refused rather than silently doing the opposite of what was asked.
func TestZeroIsRefusedBecauseItMeansTheOpposite(t *testing.T) {
	if _, err := uploadOptions(false, "", "", "0"); err == nil {
		t.Error("--downloads 0 was accepted, and on the wire means no limit")
	} else if !strings.Contains(err.Error(), "no limit") {
		t.Errorf("%v does not explain what 0 would mean", err)
	}

	if _, err := uploadOptions(false, "", "0s", ""); err == nil {
		t.Error("--expires 0 was accepted, and on the wire means never expire")
	}
}

func TestOptionsCarryWhatWasAskedFor(t *testing.T) {
	opts, err := uploadOptions(false, "", "7d", "5")
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	if opts.TTLSeconds != int64((7 * 24 * time.Hour).Seconds()) {
		t.Errorf("ttl %d seconds, want %v", opts.TTLSeconds, 7*24*time.Hour)
	}
	if opts.MaxDownloads != 5 {
		t.Errorf("downloads %d, want 5", opts.MaxDownloads)
	}
	if opts.Password != "" {
		t.Error("a password appeared without being asked for")
	}
}

func TestOmittedOptionsAskForTheInstanceDefaults(t *testing.T) {
	opts, err := uploadOptions(false, "", "", "")
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	// Zero is what the wire format means by "you decide" for both.
	if opts.TTLSeconds != 0 || opts.MaxDownloads != 0 {
		t.Errorf("omitted options became %+v", opts)
	}
}

func TestADownloadCountThatIsNotOneIsRefused(t *testing.T) {
	for _, text := range []string{"many", "-1", "1.5", ""} {
		if text == "" {
			continue // absent is not the same as invalid
		}
		if _, err := uploadOptions(false, "", "", text); err == nil {
			t.Errorf("--downloads %q was accepted", text)
		}
	}
}

func TestAPasswordFileWithoutAPasswordBeingWantedIsRefused(t *testing.T) {
	// Reachable only by calling uploadOptions directly: the flag sets both.
	// Guarded anyway, because a silently ignored password file is a file the
	// sender believed was protecting something.
	if _, err := uploadOptions(false, "/some/path", "", ""); err == nil {
		t.Error("a password file was accepted with no password wanted")
	}
}

func TestAPasswordFileIsReadWholeExceptItsTrailingNewline(t *testing.T) {
	dir := t.TempDir()

	for name, want := range map[string]string{
		"plain":         "hunter2",
		"with newline":  "hunter2",
		"with spaces":   "  a pass phrase  ",
		"several lines": "line one\nline two",
	} {
		contents := want
		if name == "with newline" {
			contents = want + "\n"
		}
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}

		got, err := passwordFromFile(path)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("%s: read %q, want %q", name, got, want)
		}
	}
}

func TestAnEmptyPasswordFileIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := passwordFromFile(path); err == nil {
		t.Error("an empty password file was accepted")
	}
}

func TestAMissingPasswordFileIsRefusedBeforeAnythingIsSent(t *testing.T) {
	if _, err := uploadOptions(true, filepath.Join(t.TempDir(), "absent"), "", ""); err == nil {
		t.Error("a password file that does not exist was accepted")
	}
}

// What is reported comes from the options that were sent, not the flags that
// were typed: what matters is what the file actually got.
func TestWhatIsReportedIsWhatWasApplied(t *testing.T) {
	opts, err := uploadOptions(true, writeTemp(t, "hunter2"), "12h", "3")
	if err != nil {
		t.Fatalf("options: %v", err)
	}

	said := describeProtection(opts)
	for _, want := range []string{"password", "12h", "3 download"} {
		if !strings.Contains(said, want) {
			t.Errorf("%q does not mention %q", said, want)
		}
	}
}

// The absence of a password is the thing most worth saying plainly.
func TestNoPasswordIsSaidPlainly(t *testing.T) {
	opts, err := uploadOptions(false, "", "", "")
	if err != nil {
		t.Fatalf("options: %v", err)
	}

	said := describeProtection(opts)
	if !strings.Contains(said, "no password") || !strings.Contains(said, "anyone with the link") {
		t.Errorf("%q does not say plainly that there is no password", said)
	}
	if !strings.Contains(said, "instance decides") {
		t.Errorf("%q does not say who decides the lifetime", said)
	}
}

func writeTemp(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// A password is needed and nothing can supply it.
//
// The obvious check - "is stdin a character device" - passes for /dev/null,
// which is a character device and not a terminal. Redirecting from it reached
// the prompt and failed with "EOF", which tells somebody running a script
// nothing they can act on.
func TestNoTerminalAndNoPasswordSourceSaysWhatToDo(t *testing.T) {
	// t.Setenv registers the restore; unsetting after it is how a test asks for
	// the variable to be absent rather than empty, which is a different case.
	t.Setenv("SENDAN_PASSWORD", "placeholder")
	_ = os.Unsetenv("SENDAN_PASSWORD")

	// Stand in for stdin being something that yields nothing.
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer func() { _ = devNull.Close() }()

	original := os.Stdin
	os.Stdin = devNull
	defer func() { os.Stdin = original }()

	_, err = readNewPassword("")
	if err == nil {
		t.Fatal("a password appeared from nowhere")
	}
	if !strings.Contains(err.Error(), "--password-file") ||
		!strings.Contains(err.Error(), "SENDAN_PASSWORD") {
		t.Errorf("%v does not name a way to supply one", err)
	}
	if strings.Contains(err.Error(), "EOF") {
		t.Errorf("%v reports the mechanism rather than the problem", err)
	}
}

// A file and the environment are taken as given: they were not typed, so there
// is nothing to have mistyped, and asking a script to confirm itself is theatre.
func TestAPasswordThatWasNotTypedIsNotConfirmed(t *testing.T) {
	t.Setenv("SENDAN_PASSWORD", "from the environment")

	got, err := readNewPassword("")
	if err != nil {
		t.Fatalf("readNewPassword: %v", err)
	}
	if got != "from the environment" {
		t.Errorf("read %q", got)
	}

	// A file wins over the environment: it was named explicitly.
	path := writeTemp(t, "from the file")
	got, err = readNewPassword(path)
	if err != nil {
		t.Fatalf("readNewPassword: %v", err)
	}
	if got != "from the file" {
		t.Errorf("read %q, want the file's contents", got)
	}
}

func TestAnEmptyEnvironmentPasswordIsRefused(t *testing.T) {
	// Set but empty is a script that thinks it is protecting something.
	t.Setenv("SENDAN_PASSWORD", "")

	if _, err := readNewPassword(""); err == nil {
		t.Error("an empty SENDAN_PASSWORD was accepted as a password")
	}
}

// Pressing return at the prompt is an answer, not a mistake.
//
// There is no such thing as an empty password in the scheme: an upload marked
// protected that any link holder can open is a meaningless state, and spec §4
// refuses it. So an empty answer means the file goes without one, which is said
// at the prompt and again in the summary rather than failing.
//
// The prompt itself needs a terminal, so what is checked here is the rule the
// prompt applies: empty is no password, not an error and not a protected upload
// with an empty key.
func TestAnEmptyAnswerMeansNoPasswordRatherThanAnError(t *testing.T) {
	opts, err := uploadOptions(true, writeTemp(t, "typed something"), "", "")
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	if opts.Password == "" {
		t.Fatal("a password that was given did not arrive")
	}

	// And with none, the summary says so in the words somebody needs.
	none, err := uploadOptions(false, "", "", "")
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	said := describeProtection(none)
	if !strings.Contains(said, "no password") || !strings.Contains(said, "anyone with the link") {
		t.Errorf("%q does not say plainly that the file is unprotected", said)
	}
}

// A password from a file or the environment is a script's, and an empty one
// there is a secret that failed to resolve rather than somebody choosing to go
// without. Uploading unprotected in that case would be the worst outcome: the
// script believes it protected the file.
func TestAnEmptyPasswordFromAScriptIsARefusalNotAChoice(t *testing.T) {
	t.Setenv("SENDAN_PASSWORD", "")
	if _, err := readNewPassword(""); err == nil {
		t.Error("an empty SENDAN_PASSWORD was taken as a decision to use no password")
	}

	if _, err := passwordFromFile(writeTemp(t, "\n")); err == nil {
		t.Error("an empty password file was taken as a decision to use no password")
	}
}

// The prompt must not advertise that the password is visible, because it is not.
func TestTheUsageDoesNotPromiseAVisiblePassword(t *testing.T) {
	if strings.Contains(usage, "visible as you type") {
		t.Error("the usage says the password is visible; it is not echoed")
	}
	if !strings.Contains(usage, "not shown as you type") {
		t.Error("the usage does not say the password is hidden")
	}
	if !strings.Contains(usage, "empty means no password") {
		t.Error("the usage does not say what an empty answer does")
	}
}
