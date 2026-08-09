// SPDX-License-Identifier: AGPL-3.0-or-later
import { defineConfig, devices } from "@playwright/test";

const port = Number(process.env.SENDAN_E2E_PORT ?? 18091);
const tlsPort = Number(process.env.SENDAN_E2E_TLS_PORT ?? 18191);

export default defineConfig({
  // Kept apart from src/, where vitest looks. A suite that ran under both
  // runners would fail under one of them for reasons about the runner.
  testDir: "e2e",
  testMatch: "**/*.spec.ts",

  // A browser flow is slower than a unit test and this is not a reason to
  // shorten it: the whole point is a real upload through a real server.
  timeout: 90_000,
  expect: { timeout: 15_000 },

  // Serially. The tests share one instance, and the expiry tests turn on how
  // long an upload has existed - which parallel load makes unreliable in a way
  // that would look like a bug in the expiry.
  workers: 1,
  fullyParallel: false,

  // Only the failing test reruns, and one that passes on retry is reported as
  // flaky rather than silently green.
  retries: process.env.CI ? 2 : 0,
  forbidOnly: !!process.env.CI,

  reporter: process.env.CI
    ? [["json", { outputFile: "playwright-report/results.json" }], ["list"]]
    : [["list"]],

  use: {
    baseURL: `http://localhost:${port}`,
    trace: "retain-on-failure",
    video: "retain-on-failure",
  },

  projects: [
    // Chromium has the File System Access API; Firefox does not. That is the
    // difference the save paths turn on, so both are run rather than one being
    // treated as representative.
    { name: "chromium", use: { ...devices["Desktop Chrome"] }, testIgnore: "**/*.h2.spec.ts" },
    { name: "firefox", use: { ...devices["Desktop Firefox"] }, testIgnore: "**/*.h2.spec.ts" },

    // Over TLS, and therefore over HTTP/2, which is the only way a browser will
    // stream a request body. Everything else runs against the instance
    // directly; only the flows that need HTTP/2 come here.
    {
      name: "chromium-h2",
      testMatch: "**/*.h2.spec.ts",
      use: {
        ...devices["Desktop Chrome"],
        baseURL: `https://localhost:${tlsPort}`,
        // The certificate is generated at startup and self-signed. Accepting it
        // is the point of the proxy, not a weakening of anything.
        ignoreHTTPSErrors: true,
      },
    },
  ],

  webServer: [
    {
      command: "../scripts/e2e-server.sh",
      url: `http://localhost:${port}/healthz`,
      // Building the client and the binary takes longer than starting them.
      timeout: 180_000,
      reuseExistingServer: !process.env.CI,
      stdout: "ignore",
      stderr: "pipe",
    },
    {
      command: "../scripts/e2e-tlsproxy.sh",
      url: `https://localhost:${tlsPort}/healthz`,
      ignoreHTTPSErrors: true,
      timeout: 120_000,
      reuseExistingServer: !process.env.CI,
      stdout: "ignore",
      stderr: "pipe",
    },
  ],
});
