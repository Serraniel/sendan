// SPDX-License-Identifier: AGPL-3.0-or-later

// No server rendering and no prerendering. Every file is encrypted and
// decrypted in the browser, so there is nothing a server could usefully render,
// and a download URL carries its secret in the fragment - which a server never
// receives and therefore could never render with.
export const ssr = false;
export const prerender = false;
