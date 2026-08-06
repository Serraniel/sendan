// SPDX-License-Identifier: AGPL-3.0-or-later
import { sveltekit } from "@sveltejs/kit/vite";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [sveltekit()],
  build: {
    // Every asset is served from the binary, so nothing may be fetched from a
    // third party at runtime. Inlining is disabled for the same reason the
    // policy forbids inline scripts.
    assetsInlineLimit: 0,
    sourcemap: false,
  },
});
