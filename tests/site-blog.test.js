/**
 * The blog (site/blog.mjs): only posts Daan approved are published, listed,
 * in the feed and in the sitemap; drafts are checked and never shipped; every
 * number in a post is a fact from published.json or appears in one of its
 * sources; the BlogPosting JSON-LD parses.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync, readFileSync, readdirSync, writeFileSync, mkdirSync, existsSync, cpSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildSite } from "../site/build.mjs";
import { facts, parsePost, readPosts, rowId } from "../site/blog.mjs";
import { n2 } from "../site/benchmarks.mjs";
import { renderMarkdown } from "../site/terms.mjs";

const ROOT = join(import.meta.dirname, "..");
const BLOG = join(ROOT, "blog");
const ORIGIN = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).homepage.replace(/\/+$/, "");
const pub = JSON.parse(readFileSync(join(ROOT, "bench", "public", "published.json"), "utf8"));
const files = readdirSync(BLOG).filter((f) => f.endsWith(".md") && f !== "README.md");

let dir;
const builds = {};

/** Build into dir/<name>, with the blog from blogDir. */
async function build(name, blogDir, drafts = false) {
  const out = join(dir, name);
  await buildSite({ out, blogDir, drafts });
  builds[name] = (f) => readFileSync(join(out, f), "utf8");
  builds[name].has = (f) => existsSync(join(out, f));
}

/** A copy of blog/ in which exactly the `approve` posts carry an approval date; the rest are drafts. */
function fixture(name, approve) {
  const d = join(dir, name);
  mkdirSync(d, { recursive: true });
  for (const f of files) {
    const md = readFileSync(join(BLOG, f), "utf8");
    writeFileSync(join(d, f), md.replace(/^approved: .*$/m, approve.includes(f) ? "approved: 2026-11-02" : "approved: false"));
  }
  cpSync(join(BLOG, "figures"), join(d, "figures"), { recursive: true });
  return d;
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "penthera-blog-"));
  const prev = process.env.PENTHERA_SITE_STARS;
  process.env.PENTHERA_SITE_STARS = "off";
  try {
    await build("none", fixture("blog-none", []));
    await build("one", fixture("blog-one", ["sealed-half-benchmark.md"]));
    await build("preview", fixture("blog-preview", ["sealed-half-benchmark.md"]), true);
  } finally {
    if (prev === undefined) delete process.env.PENTHERA_SITE_STARS;
    else process.env.PENTHERA_SITE_STARS = prev;
  }
}, 180_000);

afterAll(() => rmSync(dir, { recursive: true, force: true }));

const ld = (html) => [...html.matchAll(/<script type="application\/ld\+json">([^<]*)<\/script>/g)].map((m) => JSON.parse(m[1]));
const locs = (xml) => [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);

describe("blog drafts", () => {
  it("every post in the repo is a draft or carries the date Daan approved it", () => {
    expect(files.length).toBeGreaterThanOrEqual(1);
    for (const f of files) expect(readFileSync(join(BLOG, f), "utf8"), f).toMatch(/^approved: (?:false|\d{4}-\d{2}-\d{2})$/m);
  });

  it("with no approved post: no /blog, no feed, no sitemap or llms.txt entry, no link to it", () => {
    const r = builds.none;
    expect(r.has("blog.html")).toBe(false);
    expect(r.has("blog/feed.xml")).toBe(false);
    for (const f of files) expect(r.has(`blog/${f.replace(/\.md$/, ".html")}`), f).toBe(false);
    expect(locs(r("sitemap.xml")).some((l) => l.includes("/blog"))).toBe(false);
    expect(r("llms.txt")).not.toContain("/blog");
    for (const f of ["index.html", "benchmarks.html", "website-security-check.html"]) expect(r(f), f).not.toContain('href="/blog"');
  });

  it("a draft next to an approved post stays out of the index, the feed, the sitemap and llms.txt", () => {
    const o = builds.one;
    expect(o.has("blog/sealed-half-benchmark.html")).toBe(true);
    expect(o.has("blog/secret-scanners-creddata.html")).toBe(false);
    expect(o.has("blog/secret-scanners-creddata.md")).toBe(false);
    for (const f of ["blog.html", "blog.md", "blog/feed.xml", "sitemap.xml", "llms.txt"]) {
      expect(o(f), f).toContain("sealed-half-benchmark");
      expect(o(f), f).not.toContain("secret-scanners-creddata");
    }
    expect(locs(o("sitemap.xml"))).toEqual(expect.arrayContaining([`${ORIGIN}/blog`, `${ORIGIN}/blog/sealed-half-benchmark`]));
  });

  it("PENTHERA_BLOG_DRAFTS renders drafts for a local preview, with noindex, still unlisted", () => {
    const p = builds.preview;
    const html = p("blog/secret-scanners-creddata.html");
    expect(html).toContain('<meta name="robots" content="noindex, nofollow">');
    expect(html).toContain("Draft: not approved");
    for (const f of ["blog.html", "blog/feed.xml", "sitemap.xml", "llms.txt"]) expect(p(f), f).not.toContain("secret-scanners-creddata");
    expect(p("blog/sealed-half-benchmark.html")).not.toContain("noindex");
  });

  it("refuses an approval that is not a date", () => {
    const md = readFileSync(join(BLOG, files[0]), "utf8").replace(/^approved: .*$/m, "approved: false");
    expect(() => parsePost(md.replace(/^approved: false$/m, "approved: yes"), "x.md")).toThrow(/approved must be false or the date/);
    expect(() => parsePost(md.replace(/^approved: false\n/m, ""), "x.md")).toThrow(/no approved/);
  });

  it("an approval redeploys production: vercel.json's filter covers blog/", () => {
    const { ignoreCommand } = JSON.parse(readFileSync(join(ROOT, "vercel.json"), "utf8"));
    expect(ignoreCommand.split(/\s+/)).toContain("blog");
  });

  it("refuses to publish a post that links a draft", () => {
    expect(() => readPosts(fixture("blog-early", ["secret-scanners-creddata.md"]), pub)).toThrow(/links \/blog\/sealed-half-benchmark, which is not approved/);
  });
});

describe("blog, published", () => {
  it("links /blog from the homepage footer and every page's footer once a post is approved", () => {
    const o = builds.one;
    for (const f of ["index.html", "benchmarks.html", "benchmarks/secrets.html", "website-security-check.html", "blog/sealed-half-benchmark.html"]) {
      expect(o(f), f).toContain('<a href="/blog">Blog</a>');
    }
  });

  it("each post carries BlogPosting JSON-LD that parses, and the index a Blog", () => {
    const o = builds.one;
    const [doc] = ld(o("blog/sealed-half-benchmark.html"));
    const post = doc["@graph"].find((x) => x["@type"] === "BlogPosting");
    const meta = readPosts(join(dir, "blog-one"), pub).published[0];
    expect(post.headline).toBe(meta.title);
    expect(post.datePublished).toBe(meta.date);
    expect(post.url).toBe(`${ORIGIN}/blog/sealed-half-benchmark`);
    expect(post.author.name).toBeTruthy();
    expect(post.isBasedOn["@id"]).toBe(`${ORIGIN}/benchmarks#dataset`);
    expect(post.citation.every((c) => c.startsWith("https://github.com/danoszz/penthera/blob/main/"))).toBe(true);
    const [index] = ld(o("blog.html"));
    expect(index["@graph"][0].blogPost).toEqual([{ "@id": `${ORIGIN}/blog/sealed-half-benchmark#post` }]);
    expect(o("blog/index.html")).toBe(o("blog.html"));
  });

  it("shows each post's figures inline: the SVG is served, with alt text, a size and a caption", () => {
    const o = builds.one;
    const html = o("blog/sealed-half-benchmark.html");
    const figs = [...html.matchAll(/<figure class="md-fig"><img src="\/blog\/figures\/([\w-]+\.svg)" width="(\d+)" height="(\d+)" alt="([^"]*)" loading="lazy"><figcaption>([\s\S]*?)<\/figcaption><\/figure>/g)];
    expect(figs.length).toBeGreaterThan(0);
    expect(html.match(/<img /g)).toHaveLength(figs.length);
    for (const [, name, w, h, alt, cap] of figs) {
      expect(o.has(`blog/figures/${name}`), name).toBe(true);
      expect(o(`blog/figures/${name}`)).toMatch(new RegExp(`<svg[^>]* width="${w}" height="${h}"`));
      expect(alt.length, name).toBeGreaterThan(40);
      expect(cap.trim().length, name).toBeGreaterThan(20);
    }
    // The Markdown copy and the feed point at the served file.
    expect(o("blog/sealed-half-benchmark.md")).toContain(`](${ORIGIN}/blog/figures/dev-to-test.svg)`);
    expect(builds.one("blog/feed.xml")).toContain(`${ORIGIN}/blog/figures/dev-to-test.svg`);
    // A draft's figures are not shipped.
    expect(o.has("blog/figures/secrets-precision-recall.svg")).toBe(false);
  });

  it("sets single asterisks in italics, outside code and sums", () => {
    expect(renderMarkdown("*The Annals of Statistics*, *7*(1), 1–26.")).toContain("<em>The Annals of Statistics</em>, <em>7</em>(1), 1–26.");
    expect(renderMarkdown("Run `lint *.js and *.ts` with **care**.")).toContain("<code>lint *.js and *.ts</code> with <strong>care</strong>.");
    expect(renderMarkdown("Two * three * four.")).toContain("Two * three * four.");
    for (const f of ["blog/sealed-half-benchmark.html"]) expect(builds.one(f).replace(/<code>.*?<\/code>/g, "").replace(/<script[\s\S]*?<\/script>/g, ""), f).not.toMatch(/\*\w/);
  });

  it("prints the blog on light paper, whatever the reader's theme", () => {
    for (const f of ["blog.html", "blog/sealed-half-benchmark.html"]) {
      expect(builds.one(f), f).toContain('<html lang="en" data-theme="light" data-paper>');
      expect(builds.one(f), f).toContain('<meta name="color-scheme" content="light">');
    }
    const theme = readFileSync(join(ROOT, "site/theme.js"), "utf8");
    expect(theme).toContain('if (!paper) root.setAttribute("data-theme"');
    expect(theme).toContain('paper ? [] : document.querySelectorAll("[data-theme-toggle]")');
  });

  it("every figure in the repo's posts exists in blog/figures/ and has alt text", () => {
    for (const f of files) {
      const md = readFileSync(join(BLOG, f), "utf8");
      for (const [, alt, name] of md.matchAll(/!\[([^\]]*)\]\(figures\/([^)\s]+)\)/g)) {
        expect(existsSync(join(BLOG, "figures", name)), `${f}: ${name}`).toBe(true);
        expect(alt.trim().length, `${f}: ${name}`).toBeGreaterThan(40);
      }
    }
  });

  it("refuses a figure that is missing or has no alt text", () => {
    const d = fixture("blog-fig", ["sealed-half-benchmark.md"]);
    const post = join(d, "sealed-half-benchmark.md");
    const md = readFileSync(post, "utf8");
    writeFileSync(post, md.replace("(figures/dev-to-test.svg)", "(figures/nope.svg)"));
    expect(() => readPosts(d, pub)).toThrow(/figure nope\.svg is not in blog\/figures/);
    writeFileSync(post, md.replace(/!\[[^\]]*\]\(figures\/dev-to-test\.svg\)/, "![](figures/dev-to-test.svg)"));
    expect(() => readPosts(d, pub)).toThrow(/needs alt text/);
  });

  it("serves an Atom feed of the approved posts", () => {
    const feed = builds.one("blog/feed.xml");
    expect(feed).toMatch(/^<\?xml version="1\.0" encoding="utf-8"\?>\n<feed xmlns="http:\/\/www\.w3\.org\/2005\/Atom">/);
    expect(feed.match(/<entry>/g)).toHaveLength(1);
    expect(feed).toContain(`<link rel="self" type="application/atom+xml" href="${ORIGIN}/blog/feed.xml"/>`);
    expect(feed).toMatch(/<updated>\d{4}-\d{2}-\d{2}T00:00:00Z<\/updated>/);
    // The content is escaped HTML, with no raw tag inside the XML.
    const content = feed.match(/<content type="html">([\s\S]*?)<\/content>/)[1];
    expect(content).not.toMatch(/<[a-z]/);
  });
});

describe("blog numbers", () => {
  /** Number tokens a reader sees: placeholders and code left out. */
  const numbers = (s) => s.replace(/\{\{fact:[\w.-]+\}\}/g, " ").replace(/`[^`]*`/g, " ").replace(/\]\([^)]*\)/g, "]")
    .match(/(?<![\w.\/-])\d+(?:[.,/]\d+)*(?![\w])/g) || [];

  it("every number is a fact from published.json or appears in one of the post's sources", () => {
    for (const f of files) {
      const raw = readFileSync(join(BLOG, f), "utf8");
      const p = parsePost(raw, f);
      const sources = p.sources.map((s) => {
        expect(existsSync(join(ROOT, s)), `${f}: ${s}`).toBe(true);
        return readFileSync(join(ROOT, s), "utf8");
      });
      for (const n of numbers(`${p.title}\n${p.description}\n${p.body}`)) {
        expect(sources.some((s) => s.includes(n)), `${f}: ${n} is in none of its sources`).toBe(true);
      }
    }
    // Every placeholder resolves (an unknown one throws).
    expect(() => readPosts(BLOG, pub)).not.toThrow();
  });

  it("facts print published.json's values", () => {
    const f = facts(pub);
    for (const [b, bench] of Object.entries(pub.benchmarks)) {
      for (const r of bench.rows) {
        expect(f[`${b}.${rowId(r)}.score`], `${b} ${r.tool}`).toBe(Number.isInteger(r.score) ? r.score.toLocaleString("en-US") : n2(r.score));
        expect(f[`${b}.${rowId(r)}.version`]).toBe(r.version);
      }
      expect(f[`${b}.of`]).toBe(String(bench.of));
    }
    expect(f["secrets.penthera.place"]).toMatch(/^\d+(st|nd|rd|th)$/);
  });

  it("follows the voice guide: a question line, no em dashes, no superlatives, descriptions under 160", () => {
    for (const p of readPosts(BLOG, pub).drafts) {
      expect(p.question, p.slug).toMatch(/\?$/);
      expect(`${p.title} ${p.md}`, p.slug).not.toContain("—");
      expect(p.md, p.slug).not.toMatch(/\b(the best|the only|#1|leader|perfect|seamless|robust|powerful|cutting-edge|game-changing)\b/i);
      expect(p.description.length, p.slug).toBeLessThanOrEqual(160);
      // Links to other posts may point only at posts in blog/.
      for (const m of p.md.matchAll(/\]\(\/blog\/([\w-]+)\)/g)) expect(files, p.slug).toContain(`${m[1]}.md`);
    }
  });
});
