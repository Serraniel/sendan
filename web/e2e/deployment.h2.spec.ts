// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * The instance as it is actually deployed: behind a proxy that terminates TLS.
 *
 * Everything else reaches the instance directly over plain HTTP, where the
 * scheme it infers for itself happens to be right. That is why an upload
 * Location naming the wrong scheme went unnoticed until something reached it
 * the way a browser does — and why this file exists at all.
 */

import { expect, test } from "@playwright/test";
import { saveThroughInterface } from "./save.js";

function filled(n: number): Buffer {
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = (i * 31 + 7) % 256;
  return b;
}

test("the connection is TLS and HTTP/2, or nothing here tests what it claims", async ({ page }) => {
  const response = await page.goto("/");
  expect(new URL(response?.url() ?? "").protocol).toBe("https:");

  const protocol = await page.evaluate(
    () =>
      (performance.getEntriesByType("navigation")[0] as PerformanceResourceTiming)
        ?.nextHopProtocol,
  );
  expect(protocol, "not HTTP/2").toBe("h2");
});

test("an upload survives the proxy, and its link opens", async ({ page }) => {
  const contents = filled(300_000);

  // Every URL the client is told to use must be one it can reach from a page
  // loaded over HTTPS. An http:// one is refused as mixed content.
  const insecure: string[] = [];
  page.on("request", (request) => {
    if (request.url().startsWith("http://")) insecure.push(`${request.method()} ${request.url()}`);
  });

  await page.goto("/");
  await page.setInputFiles("#file", {
    name: "proxied.bin",
    mimeType: "application/octet-stream",
    buffer: contents,
  });
  await page.click('button[type="submit"]');
  await expect(page.locator("#link")).toBeVisible({ timeout: 60_000 });

  expect(insecure, `requests to plaintext URLs: ${insecure.join(", ")}`).toEqual([]);

  const link = await page.locator("#link").inputValue();
  expect(link.startsWith("https://"), `the link is ${link}`).toBe(true);

  await page.addInitScript(() => {
    delete (window as unknown as Record<string, unknown>).showSaveFilePicker;
  });
  await page.goto(link);
  await expect(page.locator("text=Download and decrypt")).toBeVisible({ timeout: 30_000 });

  expect(await saveThroughInterface(page, "proxied.bin")).toEqual(contents);
});
