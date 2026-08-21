// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * Contrast of the interface's colour tokens, in both themes.
 *
 * This reads `app.css` rather than a copy of the values, because a test holding
 * its own copy would keep passing after somebody edited the stylesheet - which
 * is the only moment it exists to catch. Someone adjusting a colour because it
 * looks better should fail a test, not a person using the result.
 *
 * The thresholds are WCAG 2.1 AA: 4.5:1 for body text, 3:1 for large text and
 * for the boundary of anything a person operates.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const css = readFileSync(fileURLToPath(new URL("./app.css", import.meta.url)), "utf8");

/** Relative luminance, per WCAG 2.1. */
function luminance(hex: string): number {
  const value = hex.replace("#", "");
  const channel = (at: number): number => {
    const c = Number.parseInt(value.slice(at, at + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(0) + 0.7152 * channel(2) + 0.0722 * channel(4);
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

/**
 * The tokens of one theme.
 *
 * The light theme is the bare `:root` block and the dark one is the block for
 * an explicit choice. The third block - dark under `prefers-color-scheme` -
 * repeats the second, and `themes agree` below is what holds it to that.
 */
function tokensOf(selector: string): Record<string, string> {
  const at = css.indexOf(selector);
  if (at === -1) throw new Error(`app.css has no ${selector} block`);

  const open = css.indexOf("{", at);
  const close = css.indexOf("\n}", open);
  const body = css.slice(open, close);

  const tokens: Record<string, string> = {};
  for (const [, name, value] of body.matchAll(/(--[a-z-]+):\s*(#[0-9a-fA-F]{6});/g)) {
    if (name && value) tokens[name] = value.toLowerCase();
  }
  return tokens;
}

const light = tokensOf(":root {");
const dark = tokensOf(':root[data-theme="dark"] {');

/** Pairs that must hold, described the way somebody would see them. */
const pairs: Array<[string, string, string, number]> = [
  ["body text on the page", "--text", "--surface", 4.5],
  ["body text on a raised surface", "--text", "--surface-raised", 4.5],
  ["body text on a sunken surface", "--text", "--surface-sunken", 4.5],
  ["muted text on the page", "--text-muted", "--surface", 4.5],
  ["muted text on a raised surface", "--text-muted", "--surface-raised", 4.5],
  ["a link on the page", "--accent", "--surface", 4.5],
  ["a link on a raised surface", "--accent", "--surface-raised", 4.5],
  ["a link on a sunken surface", "--accent", "--surface-sunken", 4.5],
  ["the accent on its own quiet fill", "--accent", "--accent-quiet", 4.5],
  ["muted text on a sunken surface", "--text-muted", "--surface-sunken", 4.5],
  ["the label of the primary action, hovered", "--on-accent", "--accent-hover", 4.5],
  ["destructive text once hovered", "--danger-hover", "--danger-quiet", 4.5],
  ["the label of the primary action", "--on-accent", "--accent", 4.5],
  ["destructive text on the page", "--danger", "--surface", 4.5],
  ["destructive text on a raised surface", "--danger", "--surface-raised", 4.5],
  ["destructive text on its quiet fill", "--danger", "--danger-quiet", 4.5],
  ["the label of a destructive fill", "--on-danger", "--danger", 4.5],
  // Boundaries of things a person operates, and the focus ring, are
  // non-text: 3:1, and they carry meaning that colour alone must convey.
  ["the edge of a control", "--border-strong", "--surface", 3],
  ["the focus ring against the page", "--focus", "--surface", 3],
  ["the focus ring against a raised surface", "--focus", "--surface-raised", 3],
];

describe.each([
  ["light", light],
  ["dark", dark],
])("the %s theme", (name, tokens) => {
  it("defines every token the other theme defines", () => {
    const other = name === "light" ? dark : light;
    // Not a style rule: a token missing from one theme falls back to the
    // other's value, which is how an unreadable pair reaches a page without
    // anybody writing one.
    expect(Object.keys(tokens).sort()).toEqual(Object.keys(other).sort());
  });

  it.each(pairs)("has enough contrast for %s", (_label, fg, bg, required) => {
    const front = tokens[fg];
    const back = tokens[bg];
    expect(front, `${fg} is not defined in the ${name} theme`).toBeDefined();
    expect(back, `${bg} is not defined in the ${name} theme`).toBeDefined();

    const ratio = contrast(front as string, back as string);
    // Reported to two decimals so a failure says how far off it is, which is
    // the difference between "darken this a little" and "pick another colour".
    expect(
      Number(ratio.toFixed(2)),
      `${fg} on ${bg} is ${ratio.toFixed(2)}:1, needs ${required}:1`,
    ).toBeGreaterThanOrEqual(required);
  });
});

describe("the two dark blocks", () => {
  it("agree, so a chosen dark theme looks like an inherited one", () => {
    const inherited = tokensOf(':root:not([data-theme="light"]) {');
    expect(inherited).toEqual(dark);
  });
});

describe("the palette", () => {
  // The house colours, present so that a change to one is a deliberate act
  // rather than a drift. The two adjusted derivations are absent on purpose:
  // they are documented in app.css where they are defined.
  it("uses the house colours where they are legible as given", () => {
    expect(dark["--surface-raised"]).toBe("#373b3e");
    expect(dark["--text-muted"]).toBe("#bec8d1");
    expect(dark["--accent"]).toBe("#86cecb");
    expect(light["--accent"]).toBe("#137a7f");
  });

  it("uses the accent for positive states rather than a green", () => {
    // A convention across this project's interfaces, and the reason no green
    // token exists to reach for.
    expect(light["--positive"]).toBe(light["--accent"]);
    expect(dark["--positive"]).toBe(dark["--accent"]);
  });
});
