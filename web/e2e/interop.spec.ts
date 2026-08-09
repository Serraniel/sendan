// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * A file moved between the command line client and the browser.
 *
 * This is the case that catches divergence between the Go and TypeScript
 * implementations in a realistic setting rather than at the vector level: the
 * whole path, both directions, through a real instance. #62 listed it and could
 * not have it, because there was no command line client to run.
 *
 * The vectors pin the primitives. This pins everything built on them — the key
 * schedule's inputs, the metadata envelope, the tus metadata header, the link
 * format, and the declared length that both clients compute independently and
 * that the instance enforces.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "@playwright/test";
import { saveThroughInterface } from "./save.js";

const port = Number(process.env.SENDAN_E2E_PORT ?? 18091);
const origin = `http://localhost:${port}`;

/** Built once, from the same source the browser client came from. */
let cli = "";
let work = "";

test.beforeAll(() => {
  work = mkdtempSync(join(tmpdir(), "sendan-interop-"));
  cli = join(work, "sendan");
  execFileSync("go", ["build", "-o", cli, "./cmd/sendan-cli"], {
    cwd: join(process.cwd(), ".."),
    stdio: "pipe",
  });
});

function filled(n: number): Buffer {
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = (i * 31 + 7) % 256;
  return b;
}

test("a file the command line client sent opens in the browser", async ({ page }) => {
  const contents = filled(250_000);
  const source = join(work, "from-cli.bin");
  writeFileSync(source, contents);

  // stdout is the link and nothing else, which is what makes it composable.
  const link = execFileSync(cli, ["up", "--to", origin, source], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
  expect(link, `the client printed ${JSON.stringify(link)}`).toContain("#");

  await page.addInitScript(() => {
    delete (window as unknown as Record<string, unknown>).showSaveFilePicker;
  });
  await page.goto(link);

  // The description comes from the envelope, which only the link can open.
  await expect(page.locator("dd").first()).toHaveText("from-cli.bin");
  expect(await saveThroughInterface(page, "from-cli.bin")).toEqual(contents);
});

test("a file the browser sent opens in the command line client", async ({ page }) => {
  const contents = filled(250_000);

  await page.goto("/");
  await page.setInputFiles("#file", {
    name: "from-browser.bin",
    mimeType: "application/octet-stream",
    buffer: contents,
  });
  await page.click('button[type="submit"]');
  await expect(page.locator("#link")).toBeVisible({ timeout: 60_000 });
  const link = await page.locator("#link").inputValue();

  const out = join(work, "from-browser.bin");
  execFileSync(cli, ["down", link, "-o", out], { stdio: "pipe" });

  expect(readFileSync(out)).toEqual(contents);
});

/**
 * The password is the sharpest test of agreement: it goes through Argon2id in
 * two implementations, with parameters one of them chose, and contributes to
 * the wrapping key. A disagreement anywhere in that chain produces a file
 * neither can open rather than an error naming a password.
 */
test("a password-protected file crosses both ways", async ({ page }) => {
  const contents = filled(50_000);

  await page.goto("/");
  await page.setInputFiles("#file", {
    name: "secret.bin",
    mimeType: "application/octet-stream",
    buffer: contents,
  });
  await page.fill("#password", "correct horse");
  await page.click('button[type="submit"]');
  await expect(page.locator("#link")).toBeVisible({ timeout: 90_000 });
  const link = await page.locator("#link").inputValue();

  const out = join(work, "secret.bin");
  execFileSync(cli, ["down", link, "-o", out], {
    stdio: "pipe",
    env: { ...process.env, SENDAN_PASSWORD: "correct horse" },
  });
  expect(readFileSync(out)).toEqual(contents);

  // And the wrong one fails, rather than producing something.
  expect(() =>
    execFileSync(cli, ["down", link, "-o", join(work, "nope.bin")], {
      stdio: "pipe",
      env: { ...process.env, SENDAN_PASSWORD: "wrong horse" },
    }),
  ).toThrow();
});
