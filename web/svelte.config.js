// SPDX-License-Identifier: AGPL-3.0-or-later
import adapter from "@sveltejs/adapter-static";
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

/** @type {import('@sveltejs/kit').Config} */
export default {
  preprocess: vitePreprocess(),
  kit: {
    // Built into the Go binary, so the output is plain files with no server.
    // Written straight into the Go tree rather than copied there by a separate
    // step, because a copy step is a step someone forgets.
    adapter: adapter({
      pages: "../internal/webui/dist",
      assets: "../internal/webui/dist",
      // A single-page fallback rather than prerendered routes. A download URL
      // contains an upload identifier, so the set of pages is not known at
      // build time and never will be.
      fallback: "index.html",
      precompress: false,
      strict: true,
    }),

    // No inline styles or scripts. The Content-Security-Policy the server sends
    // permits neither, and a violation would appear only in a browser.
    inlineStyleThreshold: 0,

    // The link secret lives in the URL fragment. SvelteKit must not be told to
    // send anything to a server it does not already send.
    paths: { relative: true },
  },
};
