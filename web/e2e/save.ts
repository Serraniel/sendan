// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { readFile } from "node:fs/promises";
import { type Page, expect } from "@playwright/test";

/**
 * Presses the save control and returns the file, whichever path was taken.
 *
 * The client tries a file picker, then a service worker, then a blob in memory.
 * The first two hand the browser a download; the last renders a link to click.
 * Which one a browser takes is not always the same: Chromium is stricter about
 * registering a service worker behind a certificate it was told to ignore, so
 * a test over TLS can end up on a path that a test over plain HTTP does not.
 *
 * Tests about *which* mechanism writes the file assert on it directly, in
 * flows.spec.ts. Tests about something else use this and stay about that.
 */
export async function saveThroughInterface(page: Page, filename: string): Promise<Buffer> {
  const started = page.waitForEvent("download", { timeout: 30_000 }).catch(() => null);
  await page.click("text=Download and decrypt");

  let saved = await started;
  if (saved === null) {
    const anchor = page.locator(`a[download=${JSON.stringify(filename)}]`);
    await expect(anchor).toBeVisible({ timeout: 60_000 });
    const viaLink = page.waitForEvent("download", { timeout: 30_000 });
    await anchor.click();
    saved = await viaLink;
  }

  const path = await saved.path();
  expect(path, "the browser did not produce a file").not.toBeNull();
  return readFile(path as string);
}
