// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  applyChoice,
  labelFor,
  opposite,
  rememberChoice,
  resolve,
  storedChoice,
  THEME_KEY,
  type ThemeChoice,
  type ThemeRoot,
  type ThemeStore,
} from "./theme.js";

/** Stands in for the document element, so this needs no DOM. */
function fakeRoot(initial: string | null = null): ThemeRoot & { value: string | null } {
  return {
    value: initial,
    setAttribute(name, v) {
      if (name === "data-theme") this.value = v;
    },
    removeAttribute(name) {
      if (name === "data-theme") this.value = null;
    },
  };
}

function fakeStore(initial: Record<string, string> = {}): ThemeStore & { data: typeof initial } {
  const data = { ...initial };
  return {
    data,
    getItem: (k) => data[k] ?? null,
    setItem: (k, v) => {
      data[k] = v;
    },
    removeItem: (k) => {
      delete data[k];
    },
  };
}

/** A browser that refuses storage, which private modes do. */
const hostileStore: ThemeStore = {
  getItem() {
    throw new DOMException("denied", "SecurityError");
  },
  setItem() {
    throw new DOMException("denied", "SecurityError");
  },
  removeItem() {
    throw new DOMException("denied", "SecurityError");
  },
};

describe("the stored choice", () => {
  it("is to follow the system when nothing was chosen", () => {
    expect(storedChoice(fakeStore())).toBe("system");
  });

  it("is whatever was chosen", () => {
    expect(storedChoice(fakeStore({ [THEME_KEY]: "dark" }))).toBe("dark");
    expect(storedChoice(fakeStore({ [THEME_KEY]: "light" }))).toBe("light");
  });

  it("ignores a value that is not a choice", () => {
    // Somebody else's key collision, or an older version of this. Following the
    // system beats applying a theme nobody asked for.
    expect(storedChoice(fakeStore({ [THEME_KEY]: "solarized" }))).toBe("system");
  });

  it("follows the system when storage refuses to be read", () => {
    expect(storedChoice(hostileStore)).toBe("system");
  });

  it("follows the system when there is no storage at all", () => {
    expect(storedChoice(null)).toBe("system");
  });

  it("finds storage for itself when none is passed", () => {
    // The path the interface actually takes: every other test here hands in a
    // store, so without this the lookup is never exercised. There is no
    // localStorage in this environment, which is the same situation as a
    // browser that has taken it away.
    expect(storedChoice()).toBe("system");
  });
});

describe("remembering a choice", () => {
  it("writes light and dark", () => {
    const store = fakeStore();
    rememberChoice("dark", store);
    expect(store.data[THEME_KEY]).toBe("dark");
  });

  it("removes the entry when the choice is to follow the system", () => {
    // A stored "system" and no entry mean the same thing, and leaving one
    // behind keeps a record of somebody asking for nothing in particular.
    const store = fakeStore({ [THEME_KEY]: "dark" });
    rememberChoice("system", store);
    expect(THEME_KEY in store.data).toBe(false);
  });

  it("does not throw when storage refuses to be written", () => {
    expect(() => rememberChoice("dark", hostileStore)).not.toThrow();
    expect(() => rememberChoice("system", hostileStore)).not.toThrow();
  });

  it("does not throw when there is no storage to find", () => {
    expect(() => rememberChoice("dark")).not.toThrow();
  });
});

describe("resolving a choice", () => {
  it("takes an explicit choice over the system", () => {
    expect(resolve("light", true)).toBe("light");
    expect(resolve("dark", false)).toBe("dark");
  });

  it("follows the system when asked to", () => {
    expect(resolve("system", true)).toBe("dark");
    expect(resolve("system", false)).toBe("light");
  });
});

describe("switching", () => {
  it("goes to the other theme", () => {
    expect(opposite("light")).toBe("dark");
    expect(opposite("dark")).toBe("light");
  });

  it("names what pressing it will do, not what is already true", () => {
    // A button labelled "dark" could mean the theme is dark or that pressing
    // makes it dark, and the two readings are opposites.
    expect(labelFor("light")).toBe("Switch to the dark theme");
    expect(labelFor("dark")).toBe("Switch to the light theme");
  });
});

describe("applying a choice", () => {
  it("sets the attribute for an explicit choice", () => {
    const root = fakeRoot();
    applyChoice("dark", root);
    expect(root.value).toBe("dark");
  });

  it("removes the attribute when following the system", () => {
    // Not "light": an explicit light choice and following a light system are
    // different states, and collapsing them breaks the override in one
    // direction.
    const root = fakeRoot("dark");
    applyChoice("system", root);
    expect(root.value).toBeNull();
  });
});

describe("the inline script in the shell", () => {
  // It runs before this module loads and writes the same attribute from the
  // same key. Nothing but agreement makes that work, and nothing but a test
  // keeps them in agreement.
  const shell = readFileSync(fileURLToPath(new URL("../app.html", import.meta.url)), "utf8");

  it("reads the key this module writes", () => {
    expect(shell).toContain(`localStorage.getItem("${THEME_KEY}")`);
  });

  it("sets the attribute this module sets", () => {
    expect(shell).toContain('setAttribute("data-theme", t)');
  });

  it("applies only the two explicit choices", () => {
    // "system" must leave the attribute off, or the stylesheet's media query
    // never governs again.
    expect(shell).toContain('t === "light" || t === "dark"');
  });

  it("survives storage refusing to answer", () => {
    // An exception here would stop the shell before the application starts,
    // which is a blank page rather than a wrong colour.
    const at = shell.indexOf(THEME_KEY);
    const around = shell.slice(Math.max(0, at - 200), at + 400);
    expect(around).toContain("try {");
    expect(around).toContain("catch");
  });
});
