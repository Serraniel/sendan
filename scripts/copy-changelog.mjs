#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Puts the changelog where the client can serve it.
//
// Copied at build time rather than committed. release-please rewrites
// CHANGELOG.md inside its own release pull request, so a committed copy would
// be stale exactly there - and the check that caught it would fail on a bot
// pull request that cannot run this script to fix itself.
//
// Served by the instance rather than linked to a forge. SENDAN_SOURCE_URL is
// the operator's to set and need not be a GitHub URL, so a link built from it
// would guess at a layout most instances do not have. This way the changelog a
// visitor reads is the one belonging to the code that is answering them.

import { copyFileSync, existsSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const source = join(root, "CHANGELOG.md");
const target = join(root, "web", "static", "changelog.md");

if (existsSync(source)) {
  copyFileSync(source, target);
  console.log("changelog: copied");
} else {
  // A tree that has never been released has no changelog, and the footer link
  // still has to resolve to something. Saying so is better than a 404, which
  // reads as a broken instance rather than an unreleased one.
  writeFileSync(
    target,
    "# Changelog\n\nThis build was made from a working tree with no released\n" +
      "changelog. The source link in the footer leads to the code it was built\n" +
      "from.\n",
  );
  console.log("changelog: none in this tree, wrote a note");
}
