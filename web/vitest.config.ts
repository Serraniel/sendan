// SPDX-License-Identifier: AGPL-3.0-or-later
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    include: ["src/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      // index.ts is a re-export barrel with no logic; counting it would only
      // measure whether something happens to import it.
      exclude: [
        "src/**/*.test.ts",
        "src/crypto/index.ts",
        "src/crypto/vectors/**",
        // Test scaffolding rather than client code.
        "src/testing/**",
        // vault.ts is IndexedDB glue, which only runs in a browser: a unit
        // test of it would exercise a stand-in rather than storage. It is
        // covered by e2e/flows.spec.ts, which writes a real record in a real
        // browser, reads it back, and confirms that forgetting it leaves the
        // upload downloadable.
        //
        // Excluding the file also stops its one pure function, partition,
        // counting here - src/lib/vault.test.ts still runs and still fails on
        // a regression, but no threshold enforces that it stays covered. That
        // is the cost of not adding an IndexedDB stand-in as a dependency.
        "src/lib/vault.ts",
      ],
      reporter: ["text", "lcov"],
      // A ratchet rather than a target, matching .coverage-floors on the Go
      // side: each threshold sits just below what is achieved, so a change that
      // reduces coverage fails rather than being noticed later. Raise them in
      // the same pull request that raises coverage.
      thresholds: {
        statements: 97,
        branches: 93,
        functions: 100,
        lines: 97,
      },
    },
  },
});
