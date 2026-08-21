// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * Choosing between the light theme, the dark one, and whatever the system says.
 *
 * Three states rather than two. A control that only alternates light and dark
 * strands somebody who wants to go back to following their system, and there is
 * no way back from a stored preference they cannot clear.
 *
 * ## Where the preference lives
 *
 * One key in `localStorage`, beside the acknowledgement flag the upload list
 * keeps. It is a fact about this browser rather than about any upload, and it
 * should survive the list being emptied. Nothing is sent to the instance: the
 * choice is applied here and the server never learns it.
 *
 * ## Applying it before the page paints
 *
 * `app.html` carries a small inline script that reads the same key and sets the
 * same attribute before the stylesheet is applied, so a stored preference does
 * not flash the other theme first. That works because the content security
 * policy hashes every inline script in the shell rather than forbidding them,
 * so no exception had to be added for it - see `internal/webui/webui.go`.
 *
 * The two must agree about the key and the attribute, and the test here holds
 * this side to it.
 */

/** Where the preference is kept. Shared with the inline script in `app.html`. */
export const THEME_KEY = "sendan.theme";

/** What somebody can choose. */
export type ThemeChoice = "system" | "light" | "dark";

/** What the page ends up displaying. */
export type Theme = "light" | "dark";

/** The document element, narrowed to what this needs, so a test needs no DOM. */
export interface ThemeRoot {
  setAttribute(name: string, value: string): void;
  removeAttribute(name: string): void;
}

/** Storage, narrowed to what this needs, so a test can pass a fake one. */
export interface ThemeStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

function isChoice(value: unknown): value is ThemeChoice {
  return value === "system" || value === "light" || value === "dark";
}

/**
 * The stored choice, or "system" when there is none.
 *
 * A browser that refuses storage - a private window, site data disabled - is
 * not a broken one, and following the system there is the right answer rather
 * than an error somebody has to read.
 */
export function storedChoice(store: ThemeStore | null = safeStore()): ThemeChoice {
  if (store === null) return "system";
  try {
    const value = store.getItem(THEME_KEY);
    return isChoice(value) ? value : "system";
  } catch {
    return "system";
  }
}

/**
 * Records a choice, or forgets it when the choice is to follow the system.
 *
 * Removing rather than storing "system" matters: a stored "system" and no entry
 * at all mean the same thing, and keeping the entry would leave something
 * behind for somebody who has just asked for nothing in particular.
 */
export function rememberChoice(choice: ThemeChoice, store: ThemeStore | null = safeStore()): void {
  if (store === null) return;
  try {
    if (choice === "system") store.removeItem(THEME_KEY);
    else store.setItem(THEME_KEY, choice);
  } catch {
    // Not being able to remember it is not a reason to refuse to apply it.
  }
}

/** What a choice comes out as, given what the system currently says. */
export function resolve(choice: ThemeChoice, systemPrefersDark: boolean): Theme {
  if (choice === "light" || choice === "dark") return choice;
  return systemPrefersDark ? "dark" : "light";
}

/**
 * The next choice in the cycle: system, light, dark, and back.
 *
 * A cycle rather than a menu because there are three states and one control.
 * The order starts from what is currently in effect, so the first press always
 * moves away from what is on screen.
 */
export function nextChoice(choice: ThemeChoice): ThemeChoice {
  switch (choice) {
    case "system":
      return "light";
    case "light":
      return "dark";
    case "dark":
      return "system";
  }
}

/**
 * Puts a choice into effect on the document.
 *
 * "system" removes the attribute rather than setting one, so the stylesheet's
 * media query governs again. Setting `data-theme="light"` and following the
 * system are different states and must not collapse into each other.
 */
export function applyChoice(choice: ThemeChoice, root: ThemeRoot): void {
  if (choice === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", choice);
}

/** What to call the control, given what it will do next. */
export function labelFor(choice: ThemeChoice): string {
  switch (choice) {
    case "system":
      return "Theme: following your system";
    case "light":
      return "Theme: light";
    case "dark":
      return "Theme: dark";
  }
}

function safeStore(): ThemeStore | null {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null;
  }
}
