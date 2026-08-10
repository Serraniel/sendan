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
	"github.com/Serraniel/sendan/internal/manifest"
)

// upstream is where this build's manifests are published.
//
// Compiled in rather than discovered. The whole point of the check is that the
// statement being compared against comes from somewhere the instance under
// examination does not control, so asking the instance where to find it would
// undo it. A fork building its own client changes this to its own releases.
const upstream = "https://github.com/Serraniel/sendan"

// errNotPublished reports an instance serving something other than the client
// it claims. Separate so the exit status can distinguish it from a failure to
// carry out the check at all.
var errNotPublished = errors.New("this instance is not serving the published client")

func verify(ctx context.Context, args []string) error {
	var instance, manifestFrom string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--manifest":
			var err error
			if manifestFrom, err = value(args, &i, "--manifest"); err != nil {
				return err
			}
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown option %q", args[i])
			}
			if instance != "" {
				return errors.New("only one instance can be checked at a time")
			}
			instance = args[i]
		}
	}
	if instance == "" {
		return errors.New("no instance given: sendan verify <url>")
	}

	c := &client.Client{Origin: strings.TrimRight(instance, "/")}

	// Asked first, because which manifest to compare against depends on which
	// version the instance says it is. A claim decides what to check, never
	// whether the check passes.
	claim, claimErr := c.Claim(ctx)

	m, err := loadManifest(ctx, c, manifestFrom, claim)
	if err != nil {
		return err
	}

	result, err := c.Verify(ctx, m)
	if err != nil {
		return err
	}

	report(result, claimErr, m)
	if !result.OK() {
		return errNotPublished
	}
	return nil
}

// loadManifest finds the statement to compare against.
//
// Never from the instance. A file or an explicit URL if one was given, and
// otherwise the release for the version the instance claims - which is a claim,
// and is why a mismatch is reported rather than trusted.
func loadManifest(ctx context.Context, c *client.Client, from string, claim client.Claim) (*manifest.Manifest, error) {
	if from == "" {
		if claim.Version == "" || claim.Version == "dev" {
			return nil, fmt.Errorf(
				"the instance claims version %q, which names no release to compare against; "+
					"pass --manifest with the manifest for the build it should be running",
				claim.Version)
		}
		from = client.ReleaseManifestURL(upstream, claim.Version)
	}

	if strings.HasPrefix(from, "http://") || strings.HasPrefix(from, "https://") {
		return c.FetchManifest(ctx, from)
	}

	f, err := os.Open(from) //nolint:gosec // the path is the user's own argument
	if err != nil {
		return nil, fmt.Errorf("reading the manifest: %w", err)
	}
	defer func() { _ = f.Close() }()
	return client.LoadManifest(f)
}

// report prints the result.
//
// To stdout, because it is the answer to the question that was asked. What went
// wrong while asking goes to stderr.
func report(v *client.Verification, claimErr error, m *manifest.Manifest) {
	fmt.Printf("  instance   %s\n", v.Instance)

	if claimErr != nil {
		fmt.Fprintf(os.Stderr, "  claims     could not be read: %v\n", claimErr)
	} else {
		state := "unmodified"
		if v.Claim.Modified {
			state = "built from a modified tree"
		}
		fmt.Printf("  claims     %s, commit %s, %s\n",
			v.Claim.Version, short(v.Claim.Commit), state)
	}

	origin := "a manifest you supplied"
	if m.Version != "" {
		origin = m.Version
	}
	fmt.Printf("  manifest   %s\n\n", origin)

	if v.OK() {
		fmt.Printf("  ✓ %d of %d assets match the published client\n", v.Checked, v.Checked)
		return
	}

	for _, bad := range v.Mismatches {
		fmt.Printf("  ✗ %s\n", bad.Path)
		fmt.Printf("      served   %s\n", bad.Served)
		fmt.Printf("      expected %s\n", bad.Expected)
	}

	fmt.Printf("\n  %d of %d assets do not match.\n", len(v.Mismatches), v.Checked)
	fmt.Println("\n  This instance is not serving the published client. Do not assume")
	fmt.Println("  uploads made through it are end-to-end encrypted.")
}

func short(commit string) string {
	if len(commit) > 7 {
		return commit[:7]
	}
	if commit == "" {
		return "unknown"
	}
	return commit
}
