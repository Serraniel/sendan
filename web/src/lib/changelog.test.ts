// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { type Block, render } from "./changelog.js";

function htmlOf(blocks: Block[]): string {
  return blocks.map((b) => (b.kind === "list" ? b.items.join("\n") : b.html)).join("\n");
}

describe("headings", () => {
  it("keeps the level", () => {
    const blocks = render("# Changelog\n\n## 0.2.0\n\n### Features");
    expect(blocks.map((b) => b.kind === "heading" && b.level)).toEqual([1, 2, 3]);
  });

  it("is not a heading without the space", () => {
    // `#20` appears in commit messages, and turning it into a heading would
    // swallow the rest of the line.
    const [block] = render("#20 was fixed");
    expect(block?.kind).toBe("paragraph");
  });
});

describe("list items", () => {
  it("gathers consecutive items into one list", () => {
    const blocks = render("* one\n* two\n\n* three");
    expect(blocks).toEqual([
      { kind: "list", items: ["one", "two"] },
      { kind: "list", items: ["three"] },
    ]);
  });
});

describe("inline constructs", () => {
  it("renders a link, opened away from this page", () => {
    const html = htmlOf(render("see [#20](https://example.test/issues/20)"));
    expect(html).toBe(
      'see <a href="https://example.test/issues/20" target="_blank" rel="noopener noreferrer">#20</a>',
    );
  });

  it("renders bold runs separately", () => {
    // Greedy matching would join these into one run spanning the middle.
    expect(htmlOf(render("**web:** and **cli:**"))).toBe(
      "<strong>web:</strong> and <strong>cli:</strong>",
    );
  });

  it("renders inline code", () => {
    expect(htmlOf(render("use `--password-file`"))).toBe("use <code>--password-file</code>");
  });
});

describe("what it refuses", () => {
  it("shows markup as text rather than interpreting it", () => {
    const html = htmlOf(render("a <script>alert(1)</script> and <b>b</b>"));
    expect(html).not.toContain("<script");
    expect(html).not.toContain("<b>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("does not turn a javascript: link into one", () => {
    // Only http and https become links. Everything else stays the text it was,
    // which is why this needs no list of dangerous schemes to keep current.
    const html = htmlOf(render("[click](javascript:alert(1))"));
    expect(html).not.toContain("<a ");
    expect(html).toContain("[click]");
  });

  it("does not let a quote escape an href", () => {
    const html = htmlOf(render('[x](https://example.test/" onmouseover="alert(1))'));
    expect(html).not.toContain('onmouseover="alert(1)"');
  });

  it("escapes an ampersand once, and only once", () => {
    // Escaped for display, unescaped to test the scheme, escaped again to be
    // written: a link whose query survives is the evidence that round trip is
    // right.
    const html = htmlOf(render("[x](https://example.test/?a=1&b=2)"));
    expect(html).toContain('href="https://example.test/?a=1&amp;b=2"');
  });
});

describe("the changelog this project actually ships", () => {
  // Against the committed file rather than a sample, so what is checked is what
  // is served. A sample stays correct while the generator changes.
  const source = readFileSync(
    fileURLToPath(new URL("../../../CHANGELOG.md", import.meta.url)),
    "utf8",
  );
  const blocks = render(source);

  it("begins with the title and a release", () => {
    expect(blocks[0]).toEqual({ kind: "heading", level: 1, html: "Changelog" });
    expect(blocks[1]?.kind).toBe("heading");
  });

  it("produces no unrendered Markdown", () => {
    // A construct the generator emits and this does not handle would survive
    // into the output as its own syntax, which is the failure worth catching.
    const html = htmlOf(blocks);
    expect(html).not.toMatch(/\[[^\]]*\]\([^)]*\)/);
    expect(html).not.toMatch(/\*\*/);
    expect(html).not.toMatch(/^#{1,6}\s/m);
  });

  it("renders every release heading", () => {
    const versions = source.split("\n").filter((l) => /^## /.test(l)).length;
    const headings = blocks.filter((b) => b.kind === "heading" && b.level === 2).length;
    expect(headings).toBe(versions);
  });
});
