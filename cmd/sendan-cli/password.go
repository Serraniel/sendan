// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// There is deliberately no --password <value>.
//
// An argument appears in the process list, in shell history, and in whatever a
// CI job records. The password contributes to the wrapping key, so it is the one
// value in this program that must not be written down anywhere - and a flag that
// accepts it is a flag people will use. The three ways below are the ways there
// are.
//
// The prompt does not echo, the way a system password prompt behaves.

// errNoTerminal reports that a password is needed and nothing can supply it.
//
// It names the two ways that work without one, because the person reading it is
// running a script and needs to change the script rather than the command.
var errNoTerminal = errors.New(
	"a password is needed and there is no terminal to ask at: " +
		"use --password-file, or set SENDAN_PASSWORD")

// passwordFromFile reads a password from a file.
//
// The whole contents less one trailing newline, because a password may
// legitimately contain spaces, tabs, or a blank line, and an editor adds a
// newline that was never part of it. Trimming more than that would silently
// change the key and produce a file nobody can open.
func passwordFromFile(path string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the path is the user's own argument
	if err != nil {
		return "", fmt.Errorf("reading the password file: %w", err)
	}
	text := strings.TrimSuffix(string(raw), "\n")
	text = strings.TrimSuffix(text, "\r")
	if text == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return text, nil
}

// promptPassword asks at the terminal, without echoing.
//
// Not shown as it is typed, the way a system password prompt behaves. A
// password on screen survives a shoulder, a shared screen, and terminal
// scrollback, and none of those are exotic.
//
// This is what golang.org/x/term is for. It costs one small package and brings
// no new module tree - x/sys was already linked through argon2 - and it handles
// Windows, which hand-rolled termios would not.
func promptPassword(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// Nothing to ask at. Checked properly rather than by asking whether
		// stdin is a character device: /dev/null is one and is not a terminal,
		// so redirecting from it used to reach the prompt and fail with "EOF".
		return "", errNoTerminal
	}

	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	typed, err := term.ReadPassword(fd)
	// The newline the terminal did not echo, so the next line starts cleanly
	// whatever happened.
	fmt.Fprintln(os.Stderr)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "", errNoTerminal
		}
		return "", fmt.Errorf("reading the password: %w", err)
	}

	// Returned as typed. A password may legitimately begin or end with a space,
	// and trimming would silently change the key. ReadPassword stops at the
	// newline and does not include it.
	return string(typed), nil
}

// readPassword obtains the password for opening a file.
//
// The instance said one is required, so there is no ambiguity about whether the
// environment variable was meant for this.
func readPassword() (string, error) {
	if v, ok := os.LookupEnv("SENDAN_PASSWORD"); ok {
		return v, nil
	}
	return promptPassword("Password")
}

// readNewPassword obtains the password to protect an upload with.
//
// Prompting asks twice. A password mistyped here produces a file that nobody
// can open - not the sender, who never tries, and not the recipient, who is
// told only that the password did not work. Nothing later in the system can
// detect it, so the only place to catch it is before the file is sent.
//
// A file or the environment is taken as given: those are not typed, and asking
// a script to confirm itself would be theatre.
func readNewPassword(fromFile string) (string, error) {
	if fromFile != "" {
		return passwordFromFile(fromFile)
	}
	if v, ok := os.LookupEnv("SENDAN_PASSWORD"); ok {
		if v == "" {
			return "", errors.New("SENDAN_PASSWORD is set but empty")
		}
		return v, nil
	}

	first, err := promptPassword("Password to protect this file")
	if err != nil {
		return "", err
	}

	// Pressing return is an answer: no password. The scheme has no such thing
	// as an empty one - an upload marked protected that any link holder can
	// open is a meaningless state, and spec §4 refuses it - so this means the
	// upload goes without, and says so twice rather than failing.
	if first == "" {
		fmt.Fprintln(os.Stderr,
			"No password given, so this file will not have one: anyone with the link can open it.")
		return "", nil
	}

	again, err := promptPassword("The same password again")
	if err != nil {
		return "", err
	}
	if first != again {
		return "", errors.New(
			"those did not match, and a mistyped password here makes a file nobody can open; " +
				"the upload was not started")
	}
	return first, nil
}
