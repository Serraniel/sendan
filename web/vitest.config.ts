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
      exclude: ["src/**/*.test.ts", "src/crypto/index.ts", "src/crypto/vectors/**"],
      reporter: ["text", "lcov"],
      // A ratchet rather than a target, matching .coverage-floors on the Go
      // side: each threshold sits just below what is achieved, so a change that
      // reduces coverage fails rather than being noticed later. Raise them in
      // the same pull request that raises coverage.
      thresholds: {
        statements: 90,
        branches: 85,
        functions: 95,
        lines: 90,
      },
    },
  },
});
