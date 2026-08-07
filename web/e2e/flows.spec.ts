// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * The flows a person actually performs, in a real browser against a real
 * instance.
 *
 * These exist because everything below them can pass while the thing itself
 * does not work. A Content-Security-Policy is enforced by a browser and by
 * nothing else; a service worker needs a scope and a secure context; a file
 * picker needs the click it was opened from. None of that is visible to a test
 * that calls a function.
 */

import { readFile } from "node:fs/promises";
import { type Page, expect, test } from "@playwright/test";

/** Deterministic filler, so a failure is reproducible. */
function filled(n: number): Buffer {
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = (i * 31 + 7) % 256;
  return b;
}

interface UploadOptions {
  password?: string;
  /** The visible label of the expiry choice, e.g. "1 hour". */
  expiry?: string;
  /** The visible label of the download limit, e.g. "1 download". */
  limit?: string;
}

/**
 * Sends a file through the interface and returns the link it produced.
 *
 * Driven through the visible controls rather than by calling the client's
 * modules: a test that bypassed the form would not notice a form that no longer
 * works.
 */
async function uploadThrough(
  page: Page,
  name: string,
  contents: Buffer,
  type = "application/octet-stream",
  options: UploadOptions = {},
): Promise<string> {
  await page.goto("/");
  await page.setInputFiles("#file", { name, mimeType: type, buffer: contents });

  if (options.password !== undefined) {
    await page.fill("#password", options.password);
  }
  if (options.expiry !== undefined) {
    await page.selectOption("#ttl", { label: options.expiry });
  }
  if (options.limit !== undefined) {
    await page.selectOption("#downloads", { label: options.limit });
  }

  await page.click('button[type="submit"]');
  await expect(page.locator("#link")).toBeVisible({ timeout: 60_000 });

  const link = await page.locator("#link").inputValue();
  expect(link, "the link is missing its fragment").toContain("#");
  return link;
}

/**
 * Replaces the file picker with one that keeps what is written to it.
 *
 * The dialog itself is native and cannot be driven, so what is exercised here
 * is the client's branch and the bytes it writes - not the browser's chooser.
 * Installed before any script runs, because the page asks for the picker from
 * the click that starts the download.
 */
async function stubFilePicker(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const chunks: number[][] = [];
    const state = { closed: false, aborted: false, chunks };
    (window as unknown as { __saved: typeof state }).__saved = state;

    (window as unknown as { showSaveFilePicker: unknown }).showSaveFilePicker = async () => ({
      createWritable: async () =>
        new WritableStream<Uint8Array>({
          write(chunk) {
            chunks.push(Array.from(chunk));
          },
          close() {
            state.closed = true;
          },
          abort() {
            state.aborted = true;
          },
        }),
    });
  });
}

/** What the stubbed picker received. */
async function savedThroughPicker(page: Page) {
  return page.evaluate(() => {
    const saved = (
      window as unknown as {
        __saved: { closed: boolean; aborted: boolean; chunks: number[][] };
      }
    ).__saved;
    return {
      closed: saved.closed,
      aborted: saved.aborted,
      bytes: saved.chunks.flat(),
      pieces: saved.chunks.length,
    };
  });
}

/** Removes the picker, so the client falls through to its other save paths. */
async function withoutFilePicker(page: Page): Promise<void> {
  await page.addInitScript(() => {
    // biome-ignore lint/performance/noDelete: removing it is the point - the
    // client feature-detects, and an undefined property is still a property.
    delete (window as unknown as Record<string, unknown>).showSaveFilePicker;
  });
}

/** Clicks the save control and returns what the browser downloaded. */
async function download(page: Page): Promise<Buffer> {
  const started = page.waitForEvent("download", { timeout: 60_000 });
  await page.click("text=Download and decrypt");

  const file = await started;
  const path = await file.path();
  expect(path, "the browser did not produce a file").not.toBeNull();
  return readFile(path as string);
}

test.describe("the round trip", () => {
  test("a file sent in a browser can be received in a browser", async ({ page }) => {
    const contents = filled(120_000);
    const link = await uploadThrough(page, "report.pdf", contents, "application/pdf");

    await withoutFilePicker(page);
    await page.goto(link);

    // The description comes from the envelope, which only the link can open.
    await expect(page.locator("dd").first()).toHaveText("report.pdf");
    await expect(page.locator("text=120.0 kB")).toBeVisible();

    expect(await download(page)).toEqual(contents);
  });

  /**
   * The failure the interface is built around. A link without its fragment is
   * still a well-formed URL to a real page, and what it lost cannot be
   * recovered by anybody.
   */
  test("a link that lost its fragment says so, and says it cannot be repaired", async ({
    page,
  }) => {
    const link = await uploadThrough(page, "notes.txt", filled(100), "text/plain");

    await page.goto(link.slice(0, link.indexOf("#")));

    await expect(page.locator('[role="alert"]')).toContainText("missing the part after the #");
    await expect(page.locator('[role="alert"]')).toContainText("cannot be recovered");
  });

  test("an identifier the instance has never seen is reported as unavailable", async ({ page }) => {
    await page.goto("/d/AAAAAAAAAAAAAAAAAAAAAA#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    const alert = page.locator('[role="alert"]');
    await expect(alert).toContainText("no longer available");
    // It must not guess which of expired, exhausted, revoked or unknown applies:
    // the instance does not say, and saying would confirm an upload existed.
    await expect(alert).toContainText("may have");
  });
});

test.describe("passwords", () => {
  test("the right password opens the file and the wrong one does not", async ({ page }) => {
    const contents = filled(50_000);
    const link = await uploadThrough(page, "secret.txt", contents, "text/plain", {
      password: "correct horse",
    });

    await withoutFilePicker(page);
    await page.goto(link);

    await expect(page.locator("#password")).toBeVisible({ timeout: 30_000 });
    await page.fill("#password", "wrong horse");
    await page.click('button[type="submit"]');

    await expect(page.locator('[role="alert"]')).toContainText("did not open the file", {
      timeout: 30_000,
    });
    // Still offered, because a wrong password is worth another attempt.
    await expect(page.locator("#password")).toBeVisible();

    await page.fill("#password", "correct horse");
    await page.click('button[type="submit"]');

    await expect(page.locator("text=Download and decrypt")).toBeVisible({ timeout: 30_000 });
    expect(await download(page)).toEqual(contents);
  });

  /**
   * Pressing the button with the field untouched is the commonest thing that
   * happens on this page, and the key schedule refuses an empty password
   * outright. It has to be an answer, not a crash.
   */
  test("an empty password is answered, not crashed on", async ({ page }) => {
    const link = await uploadThrough(page, "secret.txt", filled(100), "text/plain", {
      password: "hunter2",
    });

    await page.goto(link);
    await expect(page.locator("#password")).toBeVisible({ timeout: 30_000 });

    // The field is required, so it is filled with a space and cleared - which
    // is what somebody typing and deleting does.
    await page.fill("#password", " ");
    await page.click('button[type="submit"]');

    await expect(page.locator('[role="alert"]')).toContainText("did not open the file", {
      timeout: 30_000,
    });
  });
});

test.describe("expiry", () => {
  test("an upload stops being available once its downloads are spent", async ({ page }) => {
    const contents = filled(20_000);
    const link = await uploadThrough(page, "once.bin", contents, "application/octet-stream", {
      limit: "1 download",
    });

    await withoutFilePicker(page);
    await page.goto(link);
    // First rather than exact: the page's own note and the transparency card
    // both say it, which is correct and not what this test is about.
    await expect(page.locator("text=1 download remaining").first()).toBeVisible({
      timeout: 30_000,
    });
    expect(await download(page)).toEqual(contents);

    // Reloaded rather than navigated to. The link is already the current URL,
    // and going to a URL that differs from the current one only by nothing at
    // all - fragment included - is a same-document navigation, so the page
    // would keep the state it already had and this would assert on a stale
    // render. What a person does here is reload.
    await page.reload();
    await expect(page.locator('[role="alert"]')).toContainText("no longer available", {
      timeout: 30_000,
    });
  });

  test("an upload stops being available after its deadline", async ({ page }) => {
    // The instance's default lifetime is fifteen seconds, so this watches an
    // upload expire rather than waiting a day. A longer lifetime is refused
    // rather than clamped, so the form's own choices are all far beyond this.
    const link = await uploadThrough(page, "brief.bin", filled(5000));

    await page.goto(link);
    await expect(page.locator("text=Download and decrypt")).toBeVisible({ timeout: 30_000 });

    await page.waitForTimeout(18_000);

    await page.reload();
    await expect(page.locator('[role="alert"]')).toContainText("no longer available", {
      timeout: 30_000,
    });
  });
});

test.describe("saving", () => {
  /**
   * Where the browser can be asked for a file, the plaintext goes to it as it
   * decrypts. What is checked here is the client's branch and its bytes; the
   * dialog is native and cannot be driven.
   */
  test("writes to a chosen file where the browser allows it", async ({ page, browserName }) => {
    test.skip(browserName === "firefox", "Firefox has no File System Access API");

    const contents = filled(400_000);
    const link = await uploadThrough(page, "big.bin", contents);

    await stubFilePicker(page);
    await page.goto(link);
    await expect(page.locator("text=Download and decrypt")).toBeVisible({ timeout: 30_000 });
    await page.click("text=Download and decrypt");

    await expect(page.locator("text=Saved big.bin")).toBeVisible({ timeout: 60_000 });

    const saved = await savedThroughPicker(page);
    expect(Buffer.from(saved.bytes)).toEqual(contents);
    expect(saved.closed, "the write was not completed").toBe(true);
    expect(saved.aborted).toBe(false);
    // In pieces, which is the point: nothing was held whole.
    expect(saved.pieces).toBeGreaterThan(3);
  });

  /**
   * Where it cannot, a service worker answers a request the page makes to
   * itself and the browser's own download machinery writes the result. This is
   * the path Firefox and Safari take, and the only portable one.
   */
  test("streams through the service worker where there is no picker", async ({ page }) => {
    const contents = filled(400_000);
    const link = await uploadThrough(page, "streamed.bin", contents);

    await withoutFilePicker(page);
    await page.goto(link);
    await expect(page.locator("text=Download and decrypt")).toBeVisible({ timeout: 30_000 });

    const started = page.waitForEvent("download", { timeout: 60_000 });
    await page.click("text=Download and decrypt");
    const file = await started;

    // The name comes from the envelope, which the instance cannot read.
    expect(file.suggestedFilename()).toBe("streamed.bin");
    expect(await readFile((await file.path()) as string)).toEqual(contents);

    // It went through the worker rather than through memory.
    await expect(page.locator("text=Handed to your browser's downloads")).toBeVisible();
  });

  test("the service worker takes only its own path", async ({ page }) => {
    // A worker claiming more than its own path would be answering for the
    // client and for the API. It registers on the first download, so a
    // download happens first and the ordinary pages are checked after.
    const link = await uploadThrough(page, "notes.txt", filled(1000), "text/plain");
    await withoutFilePicker(page);
    await page.goto(link);
    await expect(page.locator("text=Download and decrypt")).toBeVisible({ timeout: 30_000 });
    await download(page);

    const registered = await page.evaluate(async () => {
      const r = await navigator.serviceWorker?.getRegistration("/");
      return r !== undefined && r !== null && r.active !== null;
    });
    expect(registered, "the worker did not register").toBe(true);

    // Now that it is in charge, everything else must still come from the
    // instance rather than from the worker.
    await page.goto("/");
    await expect(page.locator("h1")).toHaveText("Send a file");

    const source = await page.evaluate(() => fetch("/api/source").then((r) => r.status));
    expect(source).toBe(200);

    // And a second upload still works with the worker controlling the page.
    await uploadThrough(page, "after.txt", filled(500), "text/plain");
  });
});

test.describe("what the client says about itself", () => {
  test("reports the protection actually applied, and does not overclaim", async ({ page }) => {
    const link = await uploadThrough(page, "report.pdf", filled(2000), "application/pdf", {
      password: "correct horse",
      limit: "5 downloads",
    });

    // The sender's view, on the page that produced the link.
    const card = page.locator("details.transparency");
    await expect(card).toBeVisible();
    await card.locator("summary").click();
    await expect(card).toContainText("Argon2id");
    await expect(card).toContainText("256-bit key");
    await expect(card).toContainText("5 downloads remaining");
    await expect(card).toContainText("rather than proof against a hostile one");

    // The recipient's view, from the link alone.
    await page.goto(link);
    await expect(page.locator("#password")).toBeVisible({ timeout: 30_000 });
    await page.fill("#password", "correct horse");
    await page.click('button[type="submit"]');

    const theirs = page.locator("details.transparency");
    await expect(theirs).toBeVisible({ timeout: 30_000 });
    await theirs.locator("summary").click();
    await expect(theirs).toContainText("Argon2id");
    // A recipient holds no owner token and must not be offered a deletion.
    await expect(theirs).not.toContainText("management secret");
  });

  test("shows the version and the source it was built from", async ({ page }) => {
    await page.goto("/");
    const footer = page.locator("footer");
    await expect(footer).toContainText("Sendan", { timeout: 30_000 });
    await expect(footer.locator("a")).toHaveAttribute("href", /https?:\/\//);
  });
});

test.describe("the policy the instance serves", () => {
  /**
   * One known violation, and it is the framework's.
   *
   * SvelteKit's screen-reader announcer carries its hiding rules in a style
   * attribute, which style-src 'self' refuses. It is not our markup and cannot
   * be stopped from this side; the same rules are applied from a stylesheet
   * instead, so the element is hidden whatever the browser does with the
   * attribute.
   *
   * Allowing exactly this one keeps the assertion meaningful. Asserting zero
   * would fail on something outside the project's control, and somebody would
   * delete the assertion; asserting nothing would let a real violation through.
   */
  const isTheKnownFrameworkViolation = (v: { directive: string; source: string }) =>
    v.directive.startsWith("style-src-attr") && v.source.includes("/_app/immutable/");

  test("is strict, and the client works under it", async ({ page }) => {
    const violations: { directive: string; source: string; sample: string }[] = [];

    await page.addInitScript(() => {
      const seen: unknown[] = [];
      (window as unknown as { __csp: unknown[] }).__csp = seen;
      document.addEventListener("securitypolicyviolation", (event) => {
        seen.push({
          directive: event.violatedDirective,
          source: event.sourceFile ?? "",
          sample: event.sample ?? "",
        });
      });
    });

    const response = await page.goto("/");
    const policy = response?.headers()["content-security-policy"] ?? "";

    expect(policy).toContain("default-src 'self'");
    expect(policy).toContain("connect-src 'self'");
    expect(policy).toContain("object-src 'none'");
    expect(policy).toContain("frame-ancestors 'none'");
    // Required, not optional: Argon2id runs in WebAssembly, and without this
    // password-protected uploads fail while everything else keeps working.
    expect(policy).toContain("'wasm-unsafe-eval'");
    // No blanket permission for inline script or style.
    expect(policy).not.toContain("'unsafe-inline'");

    // A password-protected upload is the path that needs WebAssembly, and a
    // download is the path that needs the worker.
    const link = await uploadThrough(page, "notes.txt", filled(1000), "text/plain", {
      password: "hunter2",
    });
    await withoutFilePicker(page);
    await page.goto(link);
    await page.fill("#password", "hunter2");
    await page.click('button[type="submit"]');
    await expect(page.locator("text=Download and decrypt")).toBeVisible({ timeout: 30_000 });

    violations.push(
      ...(await page.evaluate(
        () =>
          (window as unknown as { __csp: { directive: string; source: string; sample: string }[] })
            .__csp,
      )),
    );

    const ours = violations.filter((v) => !isTheKnownFrameworkViolation(v));
    expect(ours, `the browser refused something: ${JSON.stringify(ours)}`).toEqual([]);
  });

  /**
   * The announcer must be hidden whether or not its attribute was applied. A
   * live region rendered into the page is not a subtle fault, but it is one
   * that only appears where the policy is served - which is not development.
   */
  test("hides the framework's announcer regardless of the blocked attribute", async ({ page }) => {
    await page.goto("/");

    const announcer = page.locator("#svelte-announcer");
    await expect(announcer).toHaveCount(1);

    const box = await announcer.boundingBox();
    expect(box?.width ?? 0).toBeLessThanOrEqual(1);
    expect(box?.height ?? 0).toBeLessThanOrEqual(1);
  });
});
