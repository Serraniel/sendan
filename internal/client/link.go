// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Package client speaks the Sendan API from the outside.
//
// It is the Go half of what web/src/lib does in the browser, and exists so the
// command line client and the browser are two front ends over one
// implementation of the scheme rather than two implementations of it. The
// cryptography itself is internal/crypto, shared with the server.
package client

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Serraniel/sendan/internal/crypto"
)

// Link is what a recipient is given: an upload to fetch and the secret that
// opens it.
type Link struct {
	// Origin is the instance, without a trailing slash.
	Origin     string
	FileID     []byte
	LinkSecret []byte
}

// encoding is unpadded base64url, the wire format's spelling for binary values
// (spec §1).
var encoding = base64.RawURLEncoding

var idPattern = regexp.MustCompile(`^/d/([A-Za-z0-9_-]+)$`)

// String renders the link a recipient opens, per spec §10.
//
// The secret goes in the fragment, which browsers do not transmit. That is what
// keeps it out of server, proxy and CDN logs, and it is also why a link that
// loses its tail is silently useless: the part most likely to be dropped in
// copying is the only part that cannot be recovered.
func (l Link) String() string {
	return fmt.Sprintf("%s/d/%s#%s",
		strings.TrimRight(l.Origin, "/"),
		encoding.EncodeToString(l.FileID),
		encoding.EncodeToString(l.LinkSecret))
}

// ID is the upload's identifier as it appears in a request path.
func (l Link) ID() string { return encoding.EncodeToString(l.FileID) }

// ParseLink reads a link a person supplied.
//
// The sizes are checked, so a link that lost characters in transit is reported
// as damaged rather than carried into a derivation that produces keys which
// merely fail to open anything. Which of the two happened is the difference
// between "this link is broken" and "this file is corrupt", and only one of
// them is worth asking the sender about.
func ParseLink(raw string) (Link, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return Link{}, fmt.Errorf("client: not a link: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Link{}, fmt.Errorf("client: %q is not an http or https link", raw)
	}

	match := idPattern.FindStringSubmatch(u.Path)
	if match == nil {
		return Link{}, fmt.Errorf("client: %q does not address an upload", u.Path)
	}

	fileID, err := encoding.DecodeString(match[1])
	if err != nil || len(fileID) != crypto.FileIDSize {
		return Link{}, fmt.Errorf("client: the upload identifier in this link is damaged")
	}

	if u.Fragment == "" {
		return Link{}, fmt.Errorf(
			"client: this link is missing the part after the #, which is the key. " +
				"It cannot be recovered - ask the sender for the whole link")
	}
	secret, err := encoding.DecodeString(u.Fragment)
	if err != nil || len(secret) != crypto.LinkSecretSize {
		return Link{}, fmt.Errorf("client: the key in this link is damaged or incomplete")
	}

	origin := u.Scheme + "://" + u.Host
	return Link{Origin: origin, FileID: fileID, LinkSecret: secret}, nil
}

// EncodeToken renders a token for a person to keep, in the wire format's
// encoding so it can be pasted back wherever one is accepted.
func EncodeToken(token []byte) string { return encoding.EncodeToString(token) }
