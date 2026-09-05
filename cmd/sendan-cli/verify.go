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
	"github.com/Serraniel/sendan/internal/signature"
)

// upstream is where this build's manifests are published.
//
// Compiled in rather than discovered. The whole point of the check is that the
// statement being compared against comes from somewhere the instance under
// examination does not control, so asking the instance where to find it would
// undo it. A fork building its own client changes this to its own releases.
const upstream = "https://github.com/Serraniel/sendan"

// releaseKey is the public half of the key this project's releases are signed
// with, in minisign's format.
//
// Compiled in for the same reason as upstream above: a key fetched at the time
// of checking is a key an attacker who can answer the fetch gets to choose. It
// is public, so there is nothing here to keep secret - what matters is that it
// arrives with the binary, in the copy somebody obtained and can compare.
//
// A fork signs its own releases and puts its own key here. Anyone can also pass
// --key to check against a key they obtained some other way.
const releaseKey = "RWQt826yhqM+nKsvcrv1lu/eePUVXmE2haeCmGUBpgzwu7CWVZxyRUVk"

// releasePQKey is the post-quantum half, in the same form.
//
// A release must satisfy both. Ed25519 rests on a primitive a quantum computer
// breaks, and SLH-DSA on a scheme with far less deployment behind it; requiring
// both means a forgery has to defeat the one that is still standing.
//
// Both are set, so both checks are required. They were empty while no keys
// existed, and the check was skipped rather than failed then: a build that
// demanded a signature nobody could make would verify nothing at all.
const releasePQKey = "U/vAc3e81vHgYeqfxDWYGHjGAtTZm4bz5Tz4lM42TJs="

// errNotPublished reports an instance serving something other than the client
// it claims. Separate so the exit status can distinguish it from a failure to
// carry out the check at all.
var errNotPublished = errors.New("this instance is not serving the published client")

func verify(ctx context.Context, args []string) error {
	var instance, manifestFrom, keyFrom string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--manifest":
			var err error
			if manifestFrom, err = value(args, &i, "--manifest"); err != nil {
				return err
			}
		case "--key":
			var err error
			if keyFrom, err = value(args, &i, "--key"); err != nil {
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

	m, authority, err := loadManifest(ctx, c, manifestFrom, keyFrom, claim)
	if err != nil {
		return err
	}

	result, err := c.Verify(ctx, m)
	if err != nil {
		return err
	}

	report(result, claimErr, m, authority)
	if !result.OK() {
		return errNotPublished
	}
	return nil
}

// loadManifest finds the statement to compare against, and says what makes it
// worth comparing against.
//
// Never from the instance. A file or an explicit URL if one was given, and
// otherwise the release for the version the instance claims - which is a claim,
// and is why a mismatch is reported rather than trusted.
//
// Anything fetched over the network must carry a signature, and a signature
// that does not check out ends the run. A local file does not: somebody who
// built the client from source and produced their own manifest is the authority
// for it, and demanding a signature from us on their own work would be asking
// them to trust us about something they already know first-hand. Which of the
// two happened is returned, and printed, because "verified" means different
// things either way and the user is entitled to know which one they got.
func loadManifest(ctx context.Context, c *client.Client, from, keyFrom string, claim client.Claim) (*manifest.Manifest, string, error) {
	if from == "" {
		if claim.Version == "" || claim.Version == "dev" {
			return nil, "", fmt.Errorf(
				"the instance claims version %q, which names no release to compare against; "+
					"pass --manifest with the manifest for the build it should be running",
				claim.Version)
		}
		from = client.ReleaseManifestURL(upstream, claim.Version)
	}

	if strings.HasPrefix(from, "http://") || strings.HasPrefix(from, "https://") {
		keys, err := loadKeys(keyFrom)
		if err != nil {
			return nil, "", err
		}

		m, err := c.FetchSignedManifest(ctx, from, keys)
		if err != nil {
			if errors.Is(err, client.ErrUnsigned) {
				return nil, "", fmt.Errorf(
					"%w.\n"+
						"Nothing here can be checked: an unsigned manifest is only as "+
						"trustworthy as\nwhoever served it, and that is exactly what is "+
						"under examination.\nBuild the client from source and pass the "+
						"manifest you produced\nwith --manifest", err)
			}
			return nil, "", err
		}
		return m, describeKeys(keyFrom, keys), nil
	}

	f, err := os.Open(from) //nolint:gosec // the path is the user's own argument
	if err != nil {
		return nil, "", fmt.Errorf("reading the manifest: %w", err)
	}
	defer func() { _ = f.Close() }()

	m, err := client.LoadManifest(f)
	if err != nil {
		return nil, "", err
	}
	return m, "a local file you supplied, unsigned - you are its authority", nil
}

// loadKeys resolves the keys a fetched manifest must be signed by.
//
// Either the keys compiled into this binary, or one named on the command line
// as a path or as the base64 line itself. --key names the Ed25519 key only: a
// fork checking against its own key is checking against its own release, and
// requiring it to supply both would make the option unusable for the case it
// exists for.
func loadKeys(from string) (client.Keys, error) {
	ed, err := loadKey(from)
	if err != nil {
		return client.Keys{}, err
	}
	keys := client.Keys{Ed25519: ed}

	// Only for this build's own key. A manifest checked against a key the user
	// supplied is checked against that key alone.
	if from == "" && releasePQKey != "" {
		pq, err := signature.ParsePQPublicKey(releasePQKey)
		if err != nil {
			return client.Keys{}, err
		}
		keys.PostQuantum = pq
	}
	return keys, nil
}

func loadKey(from string) (*signature.PublicKey, error) {
	if from == "" {
		if releaseKey == "" {
			return nil, errors.New(
				"this build has no release signing key compiled in, so a published " +
					"manifest\ncannot be checked. Pass --key with the key to check " +
					"against, or --manifest\nwith a manifest you produced yourself")
		}
		return signature.ParsePublicKey(releaseKey)
	}

	if b, err := os.ReadFile(from); err == nil { //nolint:gosec // the path is the user's own argument
		return signature.ParsePublicKey(string(b))
	}
	// Not a file, so take it as the key itself - which is how it is published,
	// and how somebody pastes one out of a message.
	return signature.ParsePublicKey(from)
}

// describeKeys says which keys a manifest satisfied, because "signed" means
// different things depending on how many signatures were checked.
func describeKeys(from string, keys client.Keys) string {
	if from != "" {
		return "signed by the key you passed"
	}
	if keys.PostQuantum != nil {
		return "signed by this build's release keys, classical and post-quantum"
	}
	return "signed by this build's release key"
}

// report prints the result.
//
// To stdout, because it is the answer to the question that was asked. What went
// wrong while asking goes to stderr.
func report(v *client.Verification, claimErr error, m *manifest.Manifest, authority string) {
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
	fmt.Printf("  manifest   %s\n", origin)
	fmt.Printf("             %s\n\n", authority)

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
