#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Writes the notices for the third-party code that ships inside the web client.
//
// MIT - which every one of them uses - requires its copyright and permission
// notice to travel with "all copies or substantial portions of the Software".
// What is distributed to a browser is the bundle, not this repository, so a
// link to the source does not discharge it: the notice has to be reachable
// from the thing that was served.
//
// Generated rather than written, because a hand-kept list is one that stops
// matching the dependency tree at the first upgrade. `scripts/verify.sh`
// regenerates it and fails if the committed file differs.
//
// Which packages count is decided here rather than inferred from the manifest:
// npm's dev/production split does not answer the question. Svelte and SvelteKit
// are devDependencies whose runtime code is compiled into the bundle and does
// ship; the linters and test runners beside them do not.

import { createHash } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const web = join(dirname(fileURLToPath(import.meta.url)), "..", "web");
const modules = join(web, "node_modules");

/** Packages whose code is compiled into what a browser receives. */
const SHIPPED = ["svelte", "@sveltejs/kit"];

function licenceText(pkg) {
  const dir = join(modules, pkg);
  const file = readdirSync(dir).find((name) => /^(LICENCE|LICENSE)/i.test(name));
  if (!file) throw new Error(`${pkg}: no licence file to include`);
  return readFileSync(join(dir, file), "utf8").trim();
}

function version(pkg) {
  return JSON.parse(readFileSync(join(modules, pkg, "package.json"), "utf8")).version;
}

const declared = JSON.parse(readFileSync(join(web, "package.json"), "utf8"));
const packages = [...new Set([...Object.keys(declared.dependencies ?? {}), ...SHIPPED])].sort();

const parts = [
  "Third-party notices",
  "===================",
  "",
  "The web client this instance serves contains code from the projects below.",
  "Their licences require these notices to travel with it, so they are served",
  "from the instance rather than only kept in the repository.",
  "",
  "Sendan itself is AGPL-3.0-or-later. Its own source is linked in the footer,",
  "which is a separate obligation and is not discharged by this file.",
  "",
];

for (const pkg of packages) {
  parts.push(
    "-".repeat(72),
    `${pkg} ${version(pkg)}`,
    "-".repeat(72),
    "",
    licenceText(pkg),
    "",
  );
}

const text = `${parts.join("\n").trimEnd()}\n`;
const out = join(web, "static", "third-party-notices.txt");
writeFileSync(out, text);

console.log(
  `${packages.length} packages, ${text.length} bytes, ` +
    `sha256:${createHash("sha256").update(text).digest("hex").slice(0, 12)}`,
);
