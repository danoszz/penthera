/**
 * The site's footer (site/frame.mjs) is one piece on every page and maps
 * every page the build renders, so a new landing page, benchmark or approved
 * post cannot ship without a way to reach it.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildSite } from "../site/build.mjs";
import { footGroups, siteFooter, siteRail } from "../site/frame.mjs";

let dir, out, pages;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "penthera-foot-"));
  out = join(dir, "dist");
  // No network: the star count is not read.
  const stars = process.env.PENTHERA_SITE_STARS;
  process.env.PENTHERA_SITE_STARS = "off";
  try { await buildSite({ out, drafts: false }); } finally {
    if (stars === undefined) delete process.env.PENTHERA_SITE_STARS; else process.env.PENTHERA_SITE_STARS = stars;
  }
  pages = readdirSync(out, { recursive: true }).map(String).filter((f) => f.endsWith(".html"));
}, 180_000);

afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** The URL a built file is served at (cleanUrls; folder index files share their folder's URL). */
const urlOf = (f) => "/" + f.replace(/\\/g, "/").replace(/(^|\/)index\.html$/, "").replace(/\.html$/, "");
const lum = (hex) => {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
const footerOf = (html) => /<footer class="foot">[\s\S]*?<\/footer>/.exec(html)?.[0];
const hrefs = (html) => new Set([...html.matchAll(/href="([^"]+)"/g)].map((m) => m[1].replace(/#.*$/, "") || "/"));

describe("site rail", () => {
  it("is on every built page, once, before <main>", () => {
    for (const f of pages) {
      const html = readFileSync(join(out, f), "utf8");
      expect(html.match(/<nav class="rail"/g), f).toHaveLength(1);
      expect(html.indexOf('<nav class="rail"'), f).toBeLessThan(html.indexOf("<main"));
    }
  });

  it("marks the section you are in", () => {
    const current = (html) => /<a [^>]*aria-current="\w+"[^>]*>([^<]+)<\/a>/.exec(html)?.[1];
    expect(current(siteRail({ url: "/" }))).toBeUndefined();
    expect(current(siteRail({ url: "/research" }))).toBe("Research");
    expect(current(siteRail({ url: "/research-e20" }))).toBe("Research");
    expect(current(siteRail({ url: "/benchmarks/secrets" }))).toBe("Benchmarks");
    expect(current(siteRail({ url: "/terms" }))).toBeUndefined();
  });

  it("carries no data-h: /pro's horizontal page looks for that attribute", () => {
    expect(siteRail({ url: "/pro" })).not.toMatch(/\sdata-h[=\s>]/);
  });

  it("holds the download back only on the homepage and drops Blog without a post", () => {
    expect(siteRail({ url: "/" })).toContain("data-hero");
    expect(siteRail({ url: "/" })).toContain('class="rail-download" href="#get"');
    expect(siteRail({ url: "/pro" })).not.toContain("data-hero");
    expect(siteRail({ url: "/pro" })).toContain('class="rail-download" href="/#get"');
    expect(siteRail({ url: "/pro", blog: false })).not.toContain('href="/blog"');
  });

  it("is an opaque plate fixed to the bottom, with no blur and its own hover ink", () => {
    const css = readFileSync(join(out, "styles.css"), "utf8");
    const rail = /\.rail \{[^}]*\}/.exec(css)[0];
    expect(rail).toMatch(/position: fixed;/);
    expect(rail).toMatch(/bottom: var\(--rail-gap\)/);
    expect(rail).not.toMatch(/backdrop-filter/);
    expect(css).toMatch(/\.rail-links a:hover \{ background: var\(--accent\); color: var\(--on-accent\); \}/);
  });
});

describe("site footer", () => {
  it("is on every built page, once, outside <main>", () => {
    expect(pages.length).toBeGreaterThan(10);
    for (const f of pages) {
      const html = readFileSync(join(out, f), "utf8");
      expect(html.match(/<footer class="foot">/g), f).toHaveLength(1);
      expect(html.indexOf('<footer class="foot">'), f).toBeGreaterThan(html.indexOf("</main>"));
    }
  });

  it("links every built page from every page's footer", () => {
    // /pro is unlisted on purpose (site/pages/pro.md): it works, and nothing links it.
    const urls = [...new Set(pages.map(urlOf))].map((u) => (u === "/" ? "/" : u.replace(/\/$/, ""))).filter((u) => u !== "/pro");
    for (const f of pages) {
      const links = hrefs(footerOf(readFileSync(join(out, f), "utf8")));
      // The homepage is linked as the live check (/#scan) and by the wordmark.
      for (const u of urls) expect(links.has(u), `${f} footer misses ${u}`).toBe(true);
    }
  });

  it("is a labelled nav landmark with grouped lists", () => {
    const foot = footerOf(readFileSync(join(out, "index.html"), "utf8"));
    expect(foot).toMatch(/<nav class="foot-nav" aria-label="Site map">/);
    for (const g of ["product", "research", "trust", "elsewhere"]) expect(foot).toContain(`<ul aria-labelledby="foot-${g}">`);
  });

  it("keeps the facts, the controls and no dither behind the wordmark", () => {
    const foot = siteFooter({ version: "9.9.9", stars: "12" });
    for (const s of ["MIT license", "Scan only what you own", "No cookies, no third-party requests", "Penthera 9.9.9", "data-theme-toggle", "Star Penthera on GitHub, 12 stars", 'href="/#get"']) expect(foot).toContain(s);
    expect(siteFooter({ home: true })).toContain('href="#get"');
    // The dither ramp is its own row, never the wordmark's parent.
    expect(foot).toMatch(/<div class="foot-field" aria-hidden="true">(<i><\/i>)+<\/div>\s*<a class="foot-mark"/);
  });

  it("sets benchmarks and posts in under their parent, each label short enough for one line", () => {
    const foot = footerOf(readFileSync(join(out, "index.html"), "utf8"));
    expect(foot).toMatch(/<li class="foot-sub"><a href="\/benchmarks\/secrets">/);
    expect(foot).toMatch(/<li class="foot-sub"><a href="\/blog\//);
    for (const [, text] of foot.matchAll(/<li[^>]*><a [^>]*>([^<]+)<\/a>/g)) expect(text.length, text).toBeLessThanOrEqual(24);
  });

  it("gives each group a pill of its own, with no numbers, legible on any ground", () => {
    const foot = footerOf(readFileSync(join(out, "index.html"), "utf8"));
    expect(foot).toMatch(/<p class="foot-k" id="foot-product">Product<\/p>/);
    const css = readFileSync(join(out, "styles.css"), "utf8");
    const pills = [1, 2, 3, 4].map((n) => new RegExp(`\\.foot-group:nth-child\\(${n}\\) \\.foot-k \\{ --pill-ink: (#[0-9a-f]{6}); --pill-tilt: ([^;]+); --pill-bg: ([^;]+); \\}`).exec(css));
    for (const p of pills) expect(p).not.toBeNull();
    expect(new Set(pills.map((p) => p[3])).size).toBe(4);
    expect(new Set(pills.map((p) => p[2])).size).toBe(4);
    // Every colour of a finish, so the ink holds on its lightest and darkest stop.
    for (const [, ink, , bg] of pills) for (const [stop] of bg.matchAll(/#[0-9a-f]{6}/g)) expect(ratio(ink, stop), `${ink} on ${stop}`).toBeGreaterThanOrEqual(4.5);
  });

  it("uses a post's or benchmark's short label and falls back to its title", () => {
    const links = footGroups({ benchmarks: [{ slug: "b", label: "Long", nav: "Short" }], posts: [{ slug: "a", title: "A title", nav: "A" }, { slug: "c", title: "C title" }] }).flatMap((g) => g.links);
    expect(links.find((l) => l.href === "/benchmarks/b").text).toBe("Short");
    expect(links.find((l) => l.href === "/blog/a").text).toBe("A");
    expect(links.find((l) => l.href === "/blog/c").text).toBe("C title");
  });

  it("sets a hovered link in the accent's own ink, at 4.5:1 or better in both themes", () => {
    const css = readFileSync(join(out, "styles.css"), "utf8");
    // `.foot-nav a` outranks the global a:hover, so it must set the colour itself.
    expect(css).toMatch(/\.foot-nav a:hover \{[^}]*background: var\(--accent\);[^}]*color: var\(--on-accent\);/);
    // The first two palettes are the light and dark themes the footer sits on.
    const palettes = [...css.matchAll(/--accent: (#[0-9a-f]{6});[\s\S]*?--on-accent: (#[0-9a-f]{6});/g)].slice(0, 2);
    expect(palettes).toHaveLength(2);
    for (const [, accent, ink] of palettes) expect(ratio(accent, ink)).toBeGreaterThanOrEqual(4.5);
  });

  it("lists only what it is given: no blog without an approved post", () => {
    const none = footGroups({ pages: [], benchmarks: [], posts: [] }).flatMap((g) => g.links.map((l) => l.href));
    expect(none).not.toContain("/blog");
    const one = footGroups({ posts: [{ slug: "a", title: "A" }] }).flatMap((g) => g.links.map((l) => l.href));
    expect(one).toEqual(expect.arrayContaining(["/blog", "/blog/a"]));
  });
});
