// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

// readPassword obtains the password for a protected file.
//
// Never as a command line argument. Arguments appear in the process list, in
// shell history, and in whatever records a CI job keeps, and a password that
// contributes to the key is the one value that must not be written down
// anywhere. An environment variable is offered for scripts, where the
// alternative is worse.
//
// This does not disable terminal echo. Doing so needs a system call this binary
// otherwise has no reason to make, and a trust anchor is worth keeping small;
// the prompt says so rather than pretending the password is hidden.
func readPassword() (string, error) {
	if v, ok := os.LookupEnv("SENDAN_PASSWORD"); ok {
		return v, nil
	}

	info, err := os.Stdin.Stat()
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return "", errors.New(
			"this file needs a password and there is no terminal to ask at: set SENDAN_PASSWORD")
	}

	fmt.Fprint(os.Stderr, "Password (it will be visible as you type): ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading the password: %w", err)
	}
	fmt.Fprintln(os.Stderr)

	// Only the line ending is removed. A password may legitimately begin or end
	// with a space, and trimming it would silently change the key.
	return strings.TrimRight(line, "\r\n"), nil
}
