// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/Serraniel/sendan/internal/config"
	"github.com/Serraniel/sendan/internal/store"
)

const masterKeyUsage = `sendan — end-to-end encrypted file sharing

  sendan                         serve, configured from the environment
  sendan generate-master-key     print a new at-rest wrapping key
  sendan rotate-master-key       re-wrap every stored at-rest key

Options for rotate-master-key:
  --old <path>   file holding the key in force; omit when turning wrapping on
  --new <path>   file holding the key to adopt; omit to turn wrapping off

The instance must not be running. A rotation rewrites the whole table in one
transaction, so an instance still serving would read rows that no longer open
with the key it started with.

Configuration is documented in docs/configuration.md.
`

// generateMasterKey prints a new key and nothing else, so it composes:
//
//	sendan generate-master-key > /run/secrets/sendan-master-key
func generateMasterKey() error {
	key, err := store.NewMasterKey()
	if err != nil {
		return err
	}
	fmt.Println(key)

	// To stderr, so redirecting stdout into a file gets the key alone and the
	// warning still reaches whoever ran it.
	fmt.Fprintln(os.Stderr,
		"\nKeep this somewhere it survives the loss of the database, and nowhere\n"+
			"the database backup goes. Losing it makes every upload unrecoverable;\n"+
			"a copy beside the data protects nothing.")
	return nil
}

// rotateMasterKey re-wraps every stored at-rest key.
func rotateMasterKey(ctx context.Context, args []string) error {
	var oldPath, newPath string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--old":
			var err error
			if oldPath, err = flagValue(args, &i, "--old"); err != nil {
				return err
			}
		case "--new":
			var err error
			if newPath, err = flagValue(args, &i, "--new"); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown option %q", args[i])
		}
	}

	oldKey, err := readMasterKey(oldPath)
	if err != nil {
		return err
	}
	newKey, err := readMasterKey(newPath)
	if err != nil {
		return err
	}

	rewrap, err := store.Rewrap(oldKey, newKey)
	if err != nil {
		return err
	}

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	// Opened directly, without the wrapping the server applies: this command is
	// the thing that changes what wrapping means, so it has to see stored keys
	// as they are.
	metadata, err := store.Open(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer func() { _ = metadata.Close() }()

	rekeyer, ok := metadata.(store.Rekeyer)
	if !ok {
		return errors.New("this database backend cannot rotate keys")
	}

	changed, err := rekeyer.Rekey(ctx, rewrap)
	if err != nil {
		return fmt.Errorf("nothing was changed: %w", err)
	}

	fmt.Printf("re-wrapped %d uploads\n", changed)
	switch {
	case len(newKey) == 0:
		fmt.Fprintln(os.Stderr,
			"\nWrapping is now off. Unset SENDAN_MASTER_KEY_FILE before starting.")
	default:
		fmt.Fprintln(os.Stderr,
			"\nPoint SENDAN_MASTER_KEY_FILE at the new key before starting. The\n"+
				"previous key opens nothing now and can be destroyed.")
	}
	return nil
}

// readMasterKey reads a key from a file, or returns nil for no path.
func readMasterKey(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // the path is the operator's own argument
	if err != nil {
		return nil, fmt.Errorf("reading the master key: %w", err)
	}
	key, err := store.ParseMasterKey(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

func flagValue(args []string, i *int, name string) (string, error) {
	if *i+1 >= len(args) {
		return "", fmt.Errorf("%s needs a value", name)
	}
	*i++
	return args[*i], nil
}
