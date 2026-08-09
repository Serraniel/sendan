// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * The streaming upload path, over HTTP/2.
 *
 * Separate from the rest because it needs TLS: a browser will not stream a
 * request body over HTTP/1.1, and the Sendan binary serves plain HTTP. A proxy
 * terminates TLS in front of it, which is also how it is really deployed.
 *
 * Without this the path has no browser verification at all — and it is the one
 * a browser takes by default wherever HTTP/2 exists, which is every ordinary
 * deployment.
 */

import { expect, test } from "@playwright/test";
import { saveThroughInterface } from "./save.js";

function filled(n: number): Buffer {
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = (i * 31 + 7) % 256;
  return b;
}

test("the connection is HTTP/2, or nothing below is testing what it claims", async ({ page }) => {
  await page.goto("/");
  const protocol = await page.evaluate(
    () => (performance.getEntriesByType("navigation")[0] as PerformanceResourceTiming)?.nextHopProtocol,
  );
  expect(protocol, "not HTTP/2: the streaming path cannot be exercised").toBe("h2");
});

test("a file sent as one streamed request arrives intact", async ({ page }) => {
  // Larger than DEFAULT_CHUNK_SIZE, deliberately. A file that fits in one chunk
  // is sent in one PATCH by *either* path, so counting requests could not tell
  // them apart - switching streaming off left this test passing, until the file
  // grew past the point where the two behave differently.
  const contents = filled(5 * 1024 * 1024);

  const patches: { method: string; length: string | null }[] = [];
  page.on("request", (request) => {
    if (request.method() === "PATCH") {
      patches.push({ method: request.method(), length: request.headers()["content-length"] ?? null });
    }
  });

  await page.goto("/");
  const name = "streamed.bin";
  await page.setInputFiles("#file", {
    name,
    mimeType: "application/octet-stream",
    buffer: contents,
  });
  await page.click('button[type="submit"]');
  await expect(page.locator("#link")).toBeVisible({ timeout: 60_000 });

  // One request for the whole body, where the chunked path would take two.
  expect(patches.length, `PATCH requests: ${patches.length}`).toBe(1);

  // And it was genuinely streamed: a body whose length is not known in advance
  // carries no Content-Length. That is the signature of the path, rather than a
  // consequence of the file happening to be small.
  expect(patches[0]?.length, "the body declared a length, so it was buffered").toBeNull();

  // And the file is the file. Read back through the download flow, which knows
  // nothing about how it was sent.
  const link = await page.locator("#link").inputValue();
  await page.addInitScript(() => {
    delete (window as unknown as Record<string, unknown>).showSaveFilePicker;
  });
  await page.goto(link);
  await expect(page.locator("text=Download and decrypt")).toBeVisible({ timeout: 30_000 });

  expect(await saveThroughInterface(page, name)).toEqual(contents);
});

test("a password-protected file streams too", async ({ page }) => {
  const contents = filled(200_000);

  await page.goto("/");
  const name = "secret.bin";
  await page.setInputFiles("#file", {
    name,
    mimeType: "application/octet-stream",
    buffer: contents,
  });
  await page.fill("#password", "correct horse");
  await page.click('button[type="submit"]');
  await expect(page.locator("#link")).toBeVisible({ timeout: 60_000 });

  const link = await page.locator("#link").inputValue();
  await page.addInitScript(() => {
    delete (window as unknown as Record<string, unknown>).showSaveFilePicker;
  });
  await page.goto(link);
  await page.fill("#password", "correct horse");
  await page.click('button[type="submit"]');
  await expect(page.locator("text=Download and decrypt")).toBeVisible({ timeout: 30_000 });

  expect(await saveThroughInterface(page, name)).toEqual(contents);
});
