// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrNotOwner reports an owner token that does not match the upload.
//
// One error for a token that is wrong and for an upload that is not there. The
// instance answers the same way for both, deliberately, so that asking about
// identifiers in turn does not reveal which of them exist.
var ErrNotOwner = errors.New(
	"client: that owner token does not match this upload, or the upload is already gone")

// Revoke removes an upload before it would otherwise expire.
//
// The owner token is what proves the right to do it. The instance holds only
// its hash, so it can check one and cannot produce one - which is why losing
// the token means losing the ability to remove the upload early, and why
// nothing here can help with that.
func (c *Client) Revoke(ctx context.Context, id string, ownerToken []byte) error {
	if len(ownerToken) == 0 {
		return errors.New("client: no owner token")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.url("/api/uploads/"+id), nil)
	if err != nil {
		return err
	}
	// In a header rather than the path, so it does not reach an access log.
	req.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(ownerToken))

	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("client: reaching the instance: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusForbidden, http.StatusUnauthorized, http.StatusNotFound:
		return ErrNotOwner
	default:
		return &APIError{Status: resp.StatusCode, Message: describe(resp)}
	}
}

// DecodeToken reads a token as the client prints it.
func DecodeToken(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("client: the owner token is empty")
	}
	token, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("client: the owner token is not in the form this client prints")
	}
	return token, nil
}
