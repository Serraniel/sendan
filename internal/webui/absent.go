// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

//go:build !embedui

package webui

import "io/fs"

// Assets reports that no client is embedded in this build.
//
// Building with the embedui tag includes one. An untagged build is what a
// contributor gets by default, and it compiles without a JavaScript toolchain.
func Assets() (fs.FS, bool) { return nil, false }
