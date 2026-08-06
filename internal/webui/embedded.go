// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

//go:build embedui

package webui

import (
	"embed"
	"io/fs"
)

// dist is the built client.
//
// Behind a build tag so that `go build` and `go test` do not require the web
// client to have been built. Without that, every Go test run would depend on
// npm, and a contributor changing a storage backend would have to install a
// JavaScript toolchain to compile it.
//
// The pattern deliberately has no fallback file: with the tag set and no build
// output present, compilation fails. A release that forgets to build the client
// should not quietly produce a binary without one.
//
//go:embed all:dist
var dist embed.FS

// Assets returns the embedded client.
func Assets() (fs.FS, bool) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, false
	}
	return sub, true
}
