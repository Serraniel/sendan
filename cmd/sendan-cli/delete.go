// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Serraniel/sendan/internal/client"
)

// deleteUpload removes an upload before it expires.
//
// The owner token is read the way a password is - prompted for, or from a file,
// or from the environment - and for the same reason. It is a credential, and an
// argument appears in the process list, in shell history, and in whatever a
// continuous integration job records. There is deliberately no --token <value>.
func deleteUpload(ctx context.Context, args []string) error {
	var raw, tokenFile string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--token-file":
			var err error
			if tokenFile, err = value(args, &i, "--token-file"); err != nil {
				return err
			}
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown option %q", args[i])
			}
			if raw != "" {
				return errors.New("only one upload can be removed at a time")
			}
			raw = args[i]
		}
	}
	if raw == "" {
		return errors.New("no link given: sendan delete <link>")
	}

	// The link identifies the upload. Its secret is not needed and is not sent:
	// removing a file does not require the ability to read it.
	link, err := client.ParseLink(raw)
	if err != nil {
		return err
	}

	encoded, err := readOwnerToken(tokenFile)
	if err != nil {
		return err
	}
	token, err := client.DecodeToken(encoded)
	if err != nil {
		return err
	}

	c := &client.Client{Origin: link.Origin}
	if err := c.Revoke(ctx, link.ID(), token); err != nil {
		if errors.Is(err, client.ErrNotOwner) {
			return fmt.Errorf("%w.\nThe owner token is the one printed when the "+
				"upload was made, and it is\nthe only thing that removes it early", err)
		}
		return err
	}

	fmt.Fprintln(os.Stderr, "Removed. The link no longer resolves to anything.")
	return nil
}

// readOwnerToken obtains the token without it appearing in the process list.
func readOwnerToken(path string) (string, error) {
	if path != "" {
		return passwordFromFile(path)
	}
	if fromEnv := os.Getenv("SENDAN_OWNER_TOKEN"); fromEnv != "" {
		return fromEnv, nil
	}
	// Not echoed, like any other credential: somebody removing a file may be
	// doing it in front of other people.
	return promptPassword("Owner token: ")
}
