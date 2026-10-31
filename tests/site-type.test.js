// The type system: every size, line height and letter spacing in the stylesheet
// comes from the tokens in :root, and /type draws each token.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { typeHtml, typeMarkdown } from "../site/type.mjs";

const ROOT = join(import.meta.dirname, "..");
const css = readFileSync(join(ROOT, "site", "styles.css"), "utf8");
const rules = css.slice(css.indexOf("--out: cubic-bezier"));

describe("type system", () => {
  it("uses tokens for every font size, or a size relative to its parent", () => {
    const raw = [...rules.matchAll(/font-size:\s*([^;}]+)/g)].map((m) => m[1].trim()).filter((v) => !/^(var\(--t-|inherit$|[\d.]+em$)/.test(v));
    expect(raw).toEqual([]);
    expect(rules).not.toMatch(/[\s{;]font:\s*\d/);
  });

  it("uses tokens for line height and letter spacing", () => {
    const lh = [...rules.matchAll(/line-height:\s*([^;}]+)/g)].map((m) => m[1].trim()).filter((v) => !/^(var\(|calc\(|1$|\d+px$)/.test(v));
    const ls = [...rules.matchAll(/letter-spacing:\s*([^;}]+)/g)].map((m) => m[1].trim()).filter((v) => !/^(var\(--tr-|0$)/.test(v));
    expect(lh).toEqual([]);
    expect(ls).toEqual([]);
  });

  it("never fakes a style, and sets no weight outside the three", () => {
    expect(css).toMatch(/html \{ font-synthesis: none;/);
    expect([...rules.matchAll(/font-weight:\s*([^;}]+)/g)].map((m) => m[1].trim()).filter((v) => !v.startsWith("var(--w-"))).toEqual([]);
  });

  it("draws every size token on /type", () => {
    const tokens = [...css.matchAll(/^\s*--(t-[a-z0-9]+):/gm)].map((m) => m[1]);
    const html = typeHtml({ origin: "https://example.test", styles: "/styles.css", foot: "" });
    const md = typeMarkdown({ origin: "https://example.test" });
    for (const t of tokens) {
      expect(html, t).toContain(`<code>--${t}</code>`);
      expect(css, t).toContain(`.ty-${t} {`);
      expect(md, t).toContain(`--${t}`);
    }
  });
});
