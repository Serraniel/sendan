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

import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
    // The source link specifically. The footer carries other links, and
    // matching every anchor would assert that all of them are absolute, which
    // is not what this is about.
    await expect(footer.getByRole("link", { name: "source" })).toHaveAttribute(
      "href",
      /https?:\/\//,
    );
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

test.describe("a browser that cannot do this", () => {
  /**
   * What somebody saw before this check existed, on an instance served over
   * plain HTTP, verified by hand at a LAN address:
   *
   *   Cannot read properties of undefined (reading 'importKey')
   *
   * Reproducing the real insecure context in a browser test is not possible
   * here - browsers treat all of 127.0.0.0/8 as a secure context, so a test
   * server is always trusted. What is reproduced instead is the consequence:
   * crypto.subtle absent. The client cannot tell the difference, which is the
   * point.
   */
  test("is told so, rather than shown an exception", async ({ page }) => {
    await page.addInitScript(() => {
      Object.defineProperty(window.crypto, "subtle", { get: () => undefined });
    });

    await page.goto("/");

    const alert = page.locator('[role="alert"]');
    await expect(alert).toBeVisible();
    await expect(alert).toContainText("cannot be used here");
    await expect(alert).toContainText("cryptography");
    // Blamed on the browser, because here it genuinely is the browser: the
    // context is secure and WebCrypto is still absent.
    await expect(alert).not.toContainText("not set up");
    // The exception must not be what anybody reads.
    await expect(alert).not.toContainText("undefined");
    await expect(alert).not.toContainText("importKey");

    // And the interface is not offered, so there is nothing to press that
    // would fail.
    await expect(page.locator("#file")).toHaveCount(0);
  });

  /**
   * Missing WebAssembly costs password-protected files and nothing else, so
   * the interface stays. Refusing everything would withhold a service the
   * browser can perform.
   */
  test("still works where only passwords are impossible", async ({ page }) => {
    await page.addInitScript(() => {
      Object.defineProperty(window, "WebAssembly", { get: () => undefined });
    });

    await page.goto("/");

    await expect(page.locator('[role="alert"]')).toContainText("Some things will not work");
    await expect(page.locator('[role="alert"]')).toContainText("password");
    // Still offered, and still usable for a file without a password.
    await expect(page.locator("#file")).toBeVisible();

    const link = await uploadThrough(page, "notes.txt", filled(1000), "text/plain");
    expect(link).toContain("#");
  });

  test("says nothing at all on a browser that can", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#file")).toBeVisible();
    await expect(page.locator('[role="alert"]')).toHaveCount(0);
  });
});

test.describe("an instance without HTTPS", () => {
  /**
   * The operator's configuration, not the browser's fault. A browser
   * withholding WebCrypto outside a secure context is behaving correctly, and a
   * message blaming it would send the reader to change browsers over something
   * only the operator can fix.
   *
   * The real case cannot be reproduced here - browsers treat all of
   * 127.0.0.0/8 as a secure context, so a test server is always trusted. This
   * asserts what the client does when told the context is insecure; the real
   * one was verified by hand against an instance at a LAN address.
   */
  test("is named as the instance's problem, not the browser's", async ({ page }) => {
    await page.addInitScript(() => {
      Object.defineProperty(window, "isSecureContext", { get: () => false });
    });

    await page.goto("/");

    const alert = page.locator('[role="alert"]');
    await expect(alert).toContainText("This instance is not set up");
    await expect(alert).toContainText("HTTPS");
    await expect(alert).toContainText("Nothing was sent");
    await expect(alert).not.toContainText("This browser cannot");

    // Only the actionable one, not a list led by a browser complaint that is
    // a consequence of it.
    await expect(alert).not.toContainText("does not offer the cryptography");
  });
});

// The list of uploads this browser made. Exercised in a real browser because
// IndexedDB is the whole feature: a unit test of the decision around it proves
// the sorting, not that anything was ever stored.
test.describe("your uploads", () => {
  test("an upload appears in the list, and forgetting it does not remove the file", async ({
    page,
  }) => {
    const contents = Buffer.from("kept in this browser and nowhere else");

    // The first upload asks before anything is written down. Accepting is what
    // the person is consenting to: the link and the token live here only.
    page.once("dialog", (dialog) => {
      expect(dialog.message()).toContain("no way to recover");
      void dialog.accept();
    });

    const link = await uploadThrough(page, "kept.txt", contents);

    await page.goto("/uploads");
    await expect(page.getByText("kept.txt")).toBeVisible();
    // Read the value rather than matching an attribute selector: the value is
    // set as a property, so the attribute does not carry it.
    const shown = page.getByLabel(`Link for kept.txt`);
    await expect(shown).toHaveValue(link);

    // Forgetting the record must not touch the upload, and the page says so.
    await page.getByRole("button", { name: /forget this link/i }).click();
    await expect(page.getByText("kept.txt")).toHaveCount(0);

    // The file is still there: the link a recipient was given still works.
    await page.goto(link);
    await expect(page.getByRole("button", { name: /download/i })).toBeVisible();
  });

  test("deleting from the list removes the file for everybody", async ({ page }) => {
    const contents = Buffer.from("withdrawn after sending");

    page.once("dialog", (dialog) => void dialog.accept());
    const link = await uploadThrough(page, "withdrawn.txt", contents);

    // It is there first, or the assertion afterwards proves nothing.
    await page.goto(link);
    await expect(page.getByRole("button", { name: /download/i })).toBeVisible();

    await page.goto("/uploads");
    // Deleting is irreversible, so it asks before doing it.
    page.once("dialog", (dialog) => {
      expect(dialog.message()).toContain("cannot be undone");
      void dialog.accept();
    });
    await page.getByRole("button", { name: /delete this file/i }).click();

    await expect(page.getByText(/was deleted/i)).toBeVisible();
    // Scoped to the list: the notice names the file too, and matching that
    // would assert the confirmation away rather than the record.
    await expect(page.locator("ul.uploads").getByText("withdrawn.txt")).toHaveCount(0);

    // And the recipient's link no longer resolves to anything.
    await page.goto(link);
    await expect(page.getByText(/no longer available/i)).toBeVisible();
  });

  test("declining leaves nothing behind", async ({ page }) => {
    page.once("dialog", (dialog) => void dialog.dismiss());
    await uploadThrough(page, "not-kept.txt", Buffer.from("declined"));

    await page.goto("/uploads");
    await expect(page.getByText("not-kept.txt")).toHaveCount(0);
    await expect(page.getByText(/nothing here yet/i)).toBeVisible();
  });

  // The answer to the property the list has to warn about: an export is the
  // only thing that survives losing the browser. Exercised across two contexts
  // rather than one, because restoring into the same profile would prove
  // nothing about a list that is gone.
  test("an export restores the list in a browser that never had it", async ({ browser }) => {
    const first = await browser.newContext();
    const sender = await first.newPage();

    sender.once("dialog", (dialog) => void dialog.accept());
    const link = await uploadThrough(sender, "exported.txt", Buffer.from("carried across"));

    await sender.goto("/uploads");
    sender.once("dialog", (dialog) => {
      expect(dialog.message()).toContain("no way to recover the passphrase");
      void dialog.accept("a passphrase for the export");
    });

    const saved = sender.waitForEvent("download");
    await sender.getByRole("button", { name: /export this list/i }).click();

    // Saved somewhere of our own before the context goes: Playwright discards a
    // download's artifact with the context that produced it, and the whole
    // point here is that the file outlives the browser that wrote it.
    const file = join(tmpdir(), `sendan-export-${Date.now()}.sendanbk`);
    await (await saved).saveAs(file);
    await first.close();

    // A second browser: different profile, empty IndexedDB, nothing shared.
    const second = await browser.newContext();
    const receiver = await second.newPage();

    await receiver.goto("/uploads");
    await expect(receiver.getByText(/nothing here yet/i)).toBeVisible();

    receiver.once("dialog", (dialog) => void dialog.accept("a passphrase for the export"));
    await receiver.locator('input[type="file"]').setInputFiles(file);

    await expect(receiver.getByText(/imported 1 upload/i)).toBeVisible();
    await expect(receiver.locator("ul.uploads").getByText("exported.txt")).toBeVisible();

    // And what was restored still works: the link opens the file.
    await expect(receiver.getByLabel("Link for exported.txt")).toHaveValue(link);
    await second.close();
    await rm(file, { force: true });
  });

  test("the wrong passphrase does not open an export", async ({ page }) => {
    page.once("dialog", (dialog) => void dialog.accept());
    await uploadThrough(page, "guarded.txt", Buffer.from("guarded"));

    await page.goto("/uploads");
    page.once("dialog", (dialog) => void dialog.accept("the right passphrase"));
    const saved = page.waitForEvent("download");
    await page.getByRole("button", { name: /export this list/i }).click();
    const file = await (await saved).path();

    page.once("dialog", (dialog) => void dialog.accept("the wrong passphrase"));
    await page.locator('input[type="file"]').setInputFiles(file);

    await expect(page.getByText(/does not open the file/i)).toBeVisible();
  });

  test("the page says the list cannot be recovered", async ({ page }) => {
    await page.goto("/uploads");
    await expect(page.getByText(/no way to recover it/i)).toBeVisible();
    await expect(page.getByText(/does not know which uploads are yours/i)).toBeVisible();
  });
});

test.describe("the inline script that applies a stored theme", () => {
  // It must be inline to run before the first paint, and the policy forbids
  // 'unsafe-inline'. What makes that work is the server hashing every inline
  // script in the shell it serves. If the shell and the served bytes ever
  // diverge, the browser blocks the script and the theme flashes - a failure
  // that development never shows, because the dev server sets no policy.
  test("is covered by the policy the instance serves", async ({ page }) => {
    const errors: string[] = [];
    page.on("console", (message) => {
      if (message.type() === "error") errors.push(message.text());
    });

    const response = await page.goto("/");
    const policy = response?.headers()["content-security-policy"] ?? "";
    const scriptSrc = policy.split(";").find((d) => d.trim().startsWith("script-src")) ?? "";

    // The framework's bootstrap and this one.
    expect(scriptSrc.match(/'sha256-[^']+'/g) ?? []).toHaveLength(2);
    expect(scriptSrc).not.toContain("unsafe-inline");
    expect(errors.filter((message) => /Content Security Policy/i.test(message))).toEqual([]);
  });
});

test.describe("choosing a theme", () => {
  // One button, two states. It names what pressing it will do rather than what
  // is already true, because a button labelled "dark" could mean either and the
  // two readings are opposites.
  test("switches between light and dark", async ({ browser }) => {
    const context = await browser.newContext({ colorScheme: "light" });
    const page = await context.newPage();
    await page.goto("/");

    const root = page.locator("html");
    // Nothing chosen yet: the stylesheet's media query governs, and no
    // attribute is present at all.
    await expect(root).not.toHaveAttribute("data-theme");

    await page.getByRole("button", { name: "Switch to the dark theme" }).click();
    await expect(root).toHaveAttribute("data-theme", "dark");

    await page.getByRole("button", { name: "Switch to the light theme" }).click();
    await expect(root).toHaveAttribute("data-theme", "light");
    await context.close();
  });

  test("every press changes something visible", async ({ browser }) => {
    // The fault that prompted the rewrite: an earlier version offered
    // "follow your system" as a third state, so on a light system the first
    // press selected light and nothing moved.
    const context = await browser.newContext({ colorScheme: "light" });
    const page = await context.newPage();
    await page.goto("/");

    const background = () =>
      page.evaluate(() => getComputedStyle(document.body).backgroundColor);

    const before = await background();
    await page.getByRole("button", { name: /^Switch to the/ }).click();
    expect(await background()).not.toBe(before);
    await context.close();
  });

  test("a chosen theme survives a reload, and is applied before the page paints", async ({
    page,
  }) => {
    await page.goto("/");
    await page.getByRole("button", { name: /^Switch to the/ }).click();
    const chosen = await page.locator("html").getAttribute("data-theme");

    await page.reload();

    // Asserted on the first paint rather than after hydration: the inline
    // script in the shell is what sets this, and if it were removed the
    // attribute would only appear once the application had started - which is
    // exactly the flash it exists to prevent.
    const beforeScripts = await page.evaluate(() =>
      document.documentElement.getAttribute("data-theme"),
    );
    expect(beforeScripts).toBe(chosen);
  });

  test("an explicit light choice wins on a system set to dark", async ({ browser, browserName }) => {
    // Playwright's Firefox does not apply colour-scheme emulation: with
    // colorScheme "dark" the page still renders light and matchMedia reports
    // false, so the premise of this test cannot be established there. Verified
    // by probing both, rather than assumed - the two agree with each other,
    // which is what matters: the control says what the page is showing.
    //
    // Skipped rather than weakened, so that the property is still checked
    // somewhere instead of being softened into something that passes
    // everywhere and proves less.
    test.skip(browserName === "firefox", "colour-scheme emulation is not applied there");

    const context = await browser.newContext({ colorScheme: "dark" });
    const page = await context.newPage();

    await page.goto("/");

    // Waited for by name rather than clicked straight away. The label depends
    // on the system setting, which the control only learns once it has
    // hydrated, so clicking a fixed name races that - and loses by hanging on
    // a locator that never matches, which reports a timeout rather than the
    // reason. This says which of the two went wrong.
    const toggle = page.getByRole("button", { name: /^Switch to the/ });
    await expect(toggle).toHaveAccessibleName("Switch to the light theme");

    await toggle.click();

    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    const background = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(background).toBe("rgb(255, 255, 255)");
    await context.close();
  });
});

test.describe("choosing a file", () => {
  test("a dropped file is chosen, as the file input would have", async ({ page }) => {
    await page.goto("/");

    // Built in the page: a DataTransfer cannot be constructed from the test
    // side and handed across.
    const zone = page.locator("label.drop");
    await zone.evaluate((element) => {
      const data = new DataTransfer();
      data.items.add(new File(["dropped contents"], "dropped.txt", { type: "text/plain" }));
      element.dispatchEvent(new DragEvent("drop", { dataTransfer: data, bubbles: true }));
    });

    await expect(zone).toContainText("dropped.txt");
    // The action becomes available, which is the thing that proves the file was
    // taken rather than only displayed.
    await expect(page.getByRole("button", { name: "Encrypt and send" })).toBeEnabled();
  });

  test("the file input still works on its own", async ({ page }) => {
    // Dropping is an addition. If it ever became the only route, this fails.
    await page.goto("/");
    await page.setInputFiles("#file", {
      name: "chosen.txt",
      mimeType: "text/plain",
      buffer: Buffer.from("chosen"),
    });
    await expect(page.locator("label.drop")).toContainText("chosen.txt");
    await expect(page.getByRole("button", { name: "Encrypt and send" })).toBeEnabled();
  });
});

test.describe("the layout at every width", () => {
  // 320px is the narrowest width worth supporting, and the one where a single
  // element that refuses to shrink takes the whole document sideways with it.
  // A fieldset did exactly that: browsers give it a min-inline-size of
  // min-content, so the widest control inside it became the page's minimum.
  for (const [label, width] of [
    ["a small phone", 320],
    ["a tablet held upright", 768],
    ["a tablet on its side", 1024],
    ["a desktop display", 1440],
  ] as const) {
    test(`does not scroll sideways on ${label}`, async ({ browser }) => {
      const context = await browser.newContext({ viewport: { width, height: 800 } });
      const page = await context.newPage();

      for (const path of ["/", "/uploads"]) {
        await page.goto(path);
        const { document: documentWidth, window: windowWidth } = await page.evaluate(() => ({
          document: document.documentElement.scrollWidth,
          window: window.innerWidth,
        }));
        expect(documentWidth, `${path} at ${width}px`).toBeLessThanOrEqual(windowWidth);
      }

      await context.close();
    });
  }
});

test.describe("the size the instance accepts", () => {
  test("is stated before a file is chosen", async ({ page }) => {
    // Read from Tus-Max-Size, which the transfer protocol advertises. There is
    // no configuration endpoint to ask, so this is where the number comes from.
    await page.goto("/");
    await expect(page.locator("label.drop")).toContainText(/up to \d/);
  });

  test("a file over it is refused before anything is uploaded", async ({ page }) => {
    await page.goto("/");
    // The limit arrives from a request made after mount, so wait for it rather
    // than racing it. In use the race is harmless - a file chosen first is
    // still refused by the instance - but a test that sometimes checks the
    // wrong state is worse than no test.
    await expect(page.locator("label.drop")).toContainText(/up to \d/);

    // Larger than the instance accepts, without writing a file that large: the
    // page reads size from the File object, and this one reports what it is
    // told to. Uploading a real gigabyte to prove a refusal would be absurd.
    await page.evaluate(() => {
      const input = document.querySelector("#file") as HTMLInputElement;
      const file = new File(["small"], "enormous.bin");
      Object.defineProperty(file, "size", { value: 8 * 1024 * 1024 * 1024 });
      const data = new DataTransfer();
      data.items.add(file);
      input.files = data.files;
      input.dispatchEvent(new Event("change", { bubbles: true }));
    });

    // Names both sizes, so the next attempt is not a guess.
    const alert = page.getByRole("alert");
    await expect(alert).toContainText("8.6 GB");
    await expect(alert).toContainText(/accepts up to/);

    // And refuses to start, rather than uploading until the instance says no.
    await expect(page.getByRole("button", { name: "Encrypt and send" })).toBeDisabled();
  });
});

test.describe("the footer", () => {
  test("opens the source elsewhere, and keeps the page it is on", async ({ page }) => {
    await page.goto("/");
    const source = page.getByRole("link", { name: /^source/ });

    await expect(source).toHaveAttribute("target", "_blank");
    // noopener as well: without it the opened page holds a handle on this one,
    // which is a page with a link fragment in its address bar.
    const rel = (await source.getAttribute("rel")) ?? "";
    expect(rel).toContain("noopener");
    expect(rel).toContain("noreferrer");

    // Said out loud, not only shown: somebody who cannot see a tab appear is
    // otherwise left wondering where the page went.
    await expect(source).toContainText("opens in a new tab");
  });

  test("keeps the link to this browser's own list in place", async ({ page }) => {
    // Not every link should leave: this one stays on the instance, and opening
    // it in a new tab would be a different kind of surprise.
    await page.goto("/");
    const uploads = page.getByRole("contentinfo").getByRole("link", { name: /your uploads/i });
    await expect(uploads).not.toHaveAttribute("target", "_blank");
  });
});

test.describe("what the instance allows", () => {
  test("can be read before uploading anything", async ({ page }) => {
    await page.goto("/");

    // Folded away: somebody sending a file should not have to step over this,
    // and somebody deciding whether to trust an instance is doing something
    // deliberate.
    //
    // Located by the words on screen rather than by role. A summary does label
    // its details for a reader, but it is not the element's accessible name as
    // far as the role engine is concerned, so a role query finds nothing here
    // while the panel is plainly visible.
    const summary = page.getByText("What this instance allows");
    await expect(summary).toBeVisible();
    await expect(page.getByText(/largest upload/i)).toBeHidden();

    await summary.click();

    // The values come from the instance rather than from anything invented
    // here, so they are matched loosely: the assertion is that the rule is
    // named and answered, not what this particular instance was configured to.
    await expect(page.getByText(/largest upload/i)).toBeVisible();
    await expect(page.getByText(/kept by default/i)).toBeVisible();
    await expect(page.getByText(/third-party client endpoints/i)).toBeVisible();
  });

  test("says the connection is not encrypted when it is not", async ({ page }) => {
    // The e2e instance is served over plain HTTP, so this is the true answer
    // here - and it is the answer that matters most, since a page served
    // without transport encryption is one whose client could have been
    // replaced in transit.
    await page.goto("/");
    await page.getByText("What this instance allows").click();

    await expect(page.getByText("This connection")).toBeVisible();
    await expect(page.getByText("not encrypted")).toBeVisible();
  });

  test("says plainly that the instance is the one making these claims", async ({ page }) => {
    await page.goto("/");
    await page.getByText("What this instance allows").click();

    // Without this the panel reads as a guarantee, which it is not: an instance
    // can report whatever it likes.
    await expect(page.getByText(/convenience rather than a guarantee/i)).toBeVisible();
    await expect(page.getByText(/the key is made and used in this browser/i)).toBeVisible();
  });
});

test.describe("the retention options", () => {
  test("name the instance's own default rather than alluding to it", async ({ page }) => {
    // "This instance's default" is the option most people leave selected, and
    // it told them nothing about what they were agreeing to.
    await page.goto("/");

    const expiry = page.locator("#ttl");
    await expect(expiry).toContainText(/\(this instance's default\)/);
    // The value itself, not just the words: a duration in the option is the
    // whole point of the change.
    await expect(expiry).toContainText(/\d+\s+(second|minute|hour|day)s?\s+\(this instance/);
  });

  test("offer no lifetime the instance would refuse", async ({ page }) => {
    // An option that is present and then rejected is worse than one that is
    // absent: it invites a choice and takes it back.
    await page.goto("/");

    const offered = await page.locator("#ttl option").evaluateAll((options) =>
      options.map((o) => Number((o as HTMLOptionElement).value)),
    );

    const rules = await page.evaluate(async () => {
      const response = await fetch("/api/instance");
      return (await response.json()) as { maxTtlSeconds: number; allowInfiniteTtl: boolean };
    });

    for (const seconds of offered) {
      if (seconds > 0) expect(seconds).toBeLessThanOrEqual(rules.maxTtlSeconds);
    }

    // And "never" only where the instance permits it. On the test instance it
    // does not, so the option must be absent rather than present and refused.
    expect(offered.includes(-1)).toBe(rules.allowInfiniteTtl);
  });

  test("say what was applied, including when nothing will remove it", async ({ page }) => {
    page.once("dialog", (dialog) => void dialog.accept());
    await uploadThrough(page, "kept-briefly.txt", Buffer.from("brief"), "text/plain", {
      limit: "1 download",
    });

    // Previously this said nothing at all unless a deadline had been chosen
    // explicitly, so an upload taking the instance's default was described by
    // silence.
    await expect(page.getByText(/This upload/)).toBeVisible();
    await expect(page.getByText(/allows 1 download/)).toBeVisible();
  });
});
