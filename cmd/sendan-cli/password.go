// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// There is deliberately no --password <value>.
//
// An argument appears in the process list, in shell history, and in whatever a
// CI job records. The password contributes to the wrapping key, so it is the one
// value in this program that must not be written down anywhere - and a flag that
// accepts it is a flag people will use. The three ways below are the ways there
// are.
//
// None of them disable terminal echo. Doing so needs a system call this binary
// otherwise has no reason to make, and the trust anchor is worth keeping small;
// the prompt says the password is visible rather than pretending otherwise.

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

// promptPassword asks at the terminal.
func promptPassword(prompt string) (string, error) {
	info, err := os.Stdin.Stat()
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return "", errNoTerminal
	}

	fmt.Fprintf(os.Stderr, "%s (it will be visible as you type): ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		// Reaching the end immediately means nothing was there to answer with.
		// The check above catches a pipe, but not every character device is a
		// terminal - /dev/null is one, and redirecting from it arrives here.
		// Telling somebody "EOF" leaves them to work out what to do.
		if errors.Is(err, io.EOF) {
			fmt.Fprintln(os.Stderr)
			return "", errNoTerminal
		}
		return "", fmt.Errorf("reading the password: %w", err)
	}
	fmt.Fprintln(os.Stderr)

	// Only the line ending is removed. A password may legitimately begin or end
	// with a space, and trimming it would silently change the key.
	return strings.TrimRight(line, "\r\n"), nil
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
	if first == "" {
		return "", errors.New("an empty password is not one; the upload was not started")
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
