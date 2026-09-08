// SPDX-License-Identifier: AGPL-3.0-or-later
import adapter from "@sveltejs/adapter-static";
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

/** @type {import('@sveltejs/kit').Config} */
export default {
  preprocess: vitePreprocess(),
  kit: {
    // SvelteKit stamps every build with Date.now() unless told otherwise, and
    // that value reaches the bundle - so two builds of the same source, seconds
    // apart on one machine, emit different content hashes and therefore
    // different filenames.
    //
    // The release builds this client twice: once on a runner to produce the
    // signed asset manifest, once inside the Dockerfile to produce the image.
    // With a timestamp for a name the two disagree by construction, and v0.2.0
    // shipped exactly that - a manifest describing a client its own image did
    // not contain, so `sendan verify` reported the project's own release as
    // compromised. See #260.
    //
    // The commit is the right name: it changes when the code changes, which is
    // what SvelteKit uses this for, and it is identical for two builds of one
    // source. Without it - a working tree, a contributor's checkout - "dev",
    // which is stable for the same reason and honest about what it is.
    version: {
      name: process.env.SENDAN_COMMIT || process.env.SENDAN_VERSION || "dev",
    },

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

    serviceWorker: {
      // Registered by hand instead, from src/lib/save.ts. The automatic
      // registration is relative, and the download page lives at /d/<id>, so it
      // would ask for /d/service-worker.js and take a scope that does not cover
      // the path the worker exists to answer. It is also registered only when a
      // download needs it, rather than on every visit to a page that may not.
      register: false,
    },
  },
};
