/**
 * /benchmarks and its pages (site/benchmarks.mjs): every number on them is a
 * number in bench/public/published.json, losses are stated as plainly as
 * wins, each page is in the sitemap and llms.txt, and the Dataset JSON-LD
 * parses.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildSite } from "../site/build.mjs";
import { BENCHMARKS, benchmarkViews, betterThanUs, fieldTools, n2, ord, pubHash, tiedPhrase } from "../site/benchmarks.mjs";

const ROOT = join(import.meta.dirname, "..");
const ORIGIN = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).homepage.replace(/\/+$/, "");
const PUB_TEXT = readFileSync(join(ROOT, "bench", "public", "published.json"), "utf8");
const pub = JSON.parse(PUB_TEXT);
const views = benchmarkViews(pub);

let dir, out;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "penthera-benchmarks-"));
  out = join(dir, "dist");
  const prev = process.env.PENTHERA_SITE_STARS;
  process.env.PENTHERA_SITE_STARS = "off";
  try {
    await buildSite({ out });
  } finally {
    if (prev === undefined) delete process.env.PENTHERA_SITE_STARS;
    else process.env.PENTHERA_SITE_STARS = prev;
  }
}, 180_000);

afterAll(() => rmSync(dir, { recursive: true, force: true }));

const read = (f) => readFileSync(join(out, f), "utf8");
const unesc = (s) => s.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'");
/** The visible text of a page: no head, no tags. */
const text = (html) => unesc(html.slice(html.indexOf("<body>")).replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ");
const ld = (html) => [...html.matchAll(/<script type="application\/ld\+json">([^<]*)<\/script>/g)].map((m) => JSON.parse(m[1]));

/** Every number in published.json, as the pages print it (two decimals). */
function printable(o, set = new Set()) {
  if (typeof o === "number") set.add(n2(o));
  else if (o && typeof o === "object") for (const v of Object.values(o)) printable(v, set);
  return set;
}

describe("benchmark pages", () => {
  it("has a hub and one page per benchmark in published.json, each also as Markdown", () => {
    expect(views.map((v) => v.key).sort()).toEqual(Object.keys(pub.benchmarks).sort());
    expect(existsSync(join(out, "benchmarks.html"))).toBe(true);
    // /benchmarks resolves next to the benchmarks/ folder on any host.
    expect(read("benchmarks/index.html")).toBe(read("benchmarks.html"));
    expect(read("benchmarks.md")).toMatch(/^# /);
    for (const v of views) {
      expect(read(`benchmarks/${v.c.slug}.html`), v.key).toContain(`<link rel="canonical" href="${ORIGIN}/benchmarks/${v.c.slug}">`);
      expect(read(`benchmarks/${v.c.slug}.md`), v.key).toMatch(/^# /);
    }
  });

  it("prints only numbers that are in published.json", () => {
    const allowed = printable(pub);
    for (const f of ["benchmarks.html", "benchmarks.md", ...views.flatMap((v) => [`benchmarks/${v.c.slug}.html`, `benchmarks/${v.c.slug}.md`])]) {
      const body = f.endsWith(".html") ? text(read(f)) : read(f);
      // Two-decimal numbers (scores, rates, interval bounds); versions are skipped.
      for (const m of body.matchAll(/(?<![\d.])-?\d\.\d\d(?![\d.])/g)) expect(allowed.has(m[0]), `${f}: ${m[0]}`).toBe(true);
    }
  });

  it("shows every tool's rank, score, interval and counts, as published.json has them", () => {
    for (const v of views) {
      const html = read(`benchmarks/${v.c.slug}.html`);
      const rows = [...html.matchAll(/<tr(?: class="is-us")?><td>([^<]*(?:<span[^>]*>[^<]*<\/span>)*[^<]*)<\/td><th scope="row">([^<]+) <span class="bm-ver">([^<]+)<\/span><\/th>(.*?)<\/tr>/g)];
      expect(rows.length, v.key).toBe(pub.benchmarks[v.key].rows.length);
      for (const r of pub.benchmarks[v.key].rows) {
        const row = rows.find((m) => unesc(m[2]) === r.tool && unesc(m[3]) === r.version);
        expect(row, `${v.key}: ${r.tool} ${r.version}`).toBeTruthy();
        const cells = unesc(row[4].replace(/<[^>]+>/g, " "));
        if (r.rank != null && !r.excluded) expect(row[1], `${v.key}: ${r.tool}`).toBe(String(r.rank));
        else expect(row[1], `${v.key}: ${r.tool}`).toContain("Not ranked");
        expect(cells, `${v.key}: ${r.tool}`).toContain(n2(r.score));
        const fmt = ([k, n]) => `${k.toLocaleString("en-US")}/${n.toLocaleString("en-US")}`;
        const ci = (c) => `[${n2(c[0])}, ${n2(c[1])}]`;
        if (v.key === "secrets") {
          for (const x of [n2(r.p), ci(r.precisionCI), fmt(r.precision), n2(r.r), ci(r.recallCI), fmt(r.recall)]) expect(cells, `${r.tool}`).toContain(x);
        } else if (v.key === "library") {
          for (const x of [fmt(r.command), fmt(r.code), fmt(r.pooled), ci(r.pooledCI)]) expect(cells, `${r.tool}`).toContain(x);
        } else {
          for (const x of [n2(r.r), ci(r.detectCI), fmt(r.detect), n2(r.fa), ci(r.benignCI), fmt(r.benign)]) expect(cells, `${v.key}: ${r.tool}`).toContain(x);
        }
      }
    }
  });

  it("states losses as plainly as wins: who ranks above Penthera, ties, and where another tool does better", () => {
    for (const v of views) {
      const body = text(read(`benchmarks/${v.c.slug}.html`));
      expect(body, v.key).toContain(`Penthera ${v.us.version} ranked ${ord(v.us.rank)} of ${v.b.of} free tools`);
      for (const r of v.ranked.filter((x) => x.rank < v.us.rank)) expect(body, v.key).toContain(`${r.tool} ranked 1st`);
      if (v.close) expect(body, v.key).toContain(`within the margin of error`);
      // A point rank goes out with its rank interval (bench/public/rank-intervals.json) when that spans more than one place.
      if (v.iv && v.iv.rank[0] !== v.iv.rank[1]) expect(body, v.key).toContain(`ranked ${ord(v.us.rank)} of ${v.b.of} free tools${tiedPhrase(v.iv)}`);
      if (v.iv) expect(body, v.key).toContain("How sure the rank is:");
      for (const [a, z] of v.ties) expect(body, v.key).toContain(`${a.tool} and ${z.tool} have the same score`);
      for (const x of betterThanUs(v)) expect(body, v.key).toContain(`${x.measure}: ${x.tool.tool} ${n2(x.theirs)}, Penthera ${n2(x.ours)}`);
      // Rows that were not ranked are shown with the reason, never hidden.
      for (const r of v.unranked) expect(body, `${v.key}: ${r.tool}`).toContain(`${r.tool} ${r.version}: `);
    }
    // The published outcome, as of this file: second on secrets, behind deepsecrets; a near tie with ODGen.
    const secrets = views.find((v) => v.key === "secrets"), lib = views.find((v) => v.key === "library");
    if (secrets.us.rank !== 1) expect(text(read("benchmarks.html"))).toContain(`behind ${secrets.top.tool}`);
    if (lib.close) expect(text(read("benchmarks.html"))).toContain(`within the margin of error of ${lib.close.tool}`);
  });

  it("follows the voice guide: no em dashes, no superlatives, and no number typed by hand in the prose", () => {
    for (const f of ["benchmarks.html", ...views.map((v) => `benchmarks/${v.c.slug}.html`)]) {
      const body = text(read(f));
      expect(body, f).not.toContain("—");
      expect(body, f).not.toMatch(/\b(the best|the only|#1|leader|leading|perfect|seamless|robust|powerful|cutting-edge|game-changing)\b/i);
    }
    for (const c of Object.values(BENCHMARKS)) for (const l of c.limits) expect(l, c.slug).not.toMatch(/\d/);
  });

  it("has a title, a description under 160 characters and one h1 per page", () => {
    for (const f of ["benchmarks.html", ...views.map((v) => `benchmarks/${v.c.slug}.html`)]) {
      const html = read(f);
      const d = unesc(html.match(/<meta name="description" content="([^"]+)">/)[1]);
      expect(d.length, f).toBeLessThanOrEqual(160);
      expect(html, f).toMatch(/<title>[^<]+ · Penthera<\/title>/);
      expect(html.match(/<h1[ >]/g), f).toHaveLength(1);
      expect(html, f).not.toMatch(/\{\{|<script(?![^>]*\bsrc=)(?![^>]*type="application\/ld\+json")[^>]*>| style=/);
    }
  });

  it("carries schema.org Dataset and BreadcrumbList JSON-LD that parses", () => {
    for (const v of views) {
      const [doc] = ld(read(`benchmarks/${v.c.slug}.html`));
      expect(doc["@context"]).toBe("https://schema.org");
      const ds = doc["@graph"].find((x) => x["@type"] === "Dataset");
      expect(ds.name, v.key).toBeTruthy();
      expect(ds.description.length, v.key).toBeGreaterThanOrEqual(50);
      expect(ds.description.length, v.key).toBeLessThanOrEqual(5000);
      expect(ds.datePublished).toBe(pub.date);
      expect(ds.url).toBe(`${ORIGIN}/benchmarks/${v.c.slug}`);
      expect(ds.measurementTechnique).toBe(v.b.measure);
      expect(ds.isBasedOn.url).toMatch(/^https:\/\/github\.com\//);
      expect(ds.distribution.encodingFormat).toBe("application/json");
      expect(ds.isPartOf["@id"]).toBe(`${ORIGIN}/benchmarks#dataset`);
      const crumbs = doc["@graph"].find((x) => x["@type"] === "BreadcrumbList");
      expect(crumbs.itemListElement.map((i) => i.item)).toEqual([`${ORIGIN}/`, `${ORIGIN}/benchmarks`, `${ORIGIN}/benchmarks/${v.c.slug}`]);
    }
    const [hub] = ld(read("benchmarks.html"));
    const ds = hub["@graph"].find((x) => x["@type"] === "Dataset");
    expect(ds["@id"]).toBe(`${ORIGIN}/benchmarks#dataset`);
    expect(ds.hasPart.map((p) => p["@id"])).toEqual(views.map((v) => `${ORIGIN}/benchmarks/${v.c.slug}#dataset`));
    // The homepage's SoftwareApplication points at it.
    const app = ld(read("index.html")).flatMap((x) => x["@graph"] || [x]).find((x) => x["@type"] === "SoftwareApplication");
    expect(app.subjectOf["@id"]).toBe(`${ORIGIN}/benchmarks#dataset`);
  });

  it("uses a page's share card only while it shows this published.json", () => {
    const meta = join(ROOT, "site", "media", "social", "bench", "source.json");
    const fresh = existsSync(meta) && JSON.parse(readFileSync(meta, "utf8")).published === pubHash(PUB_TEXT);
    for (const [f, slug] of [["benchmarks.html", "hub"], ...views.map((v) => [`benchmarks/${v.c.slug}.html`, v.c.slug])]) {
      const img = read(f).match(/<meta property="og:image" content="([^"]+)">/)[1];
      if (fresh) {
        expect(img, f).toMatch(new RegExp(`^${ORIGIN}/media/social/bench/${slug}\\.png\\?v=[0-9a-f]{10}$`));
        expect(existsSync(join(out, "media", "social", "bench", `${slug}.png`)), f).toBe(true);
      } else expect(img, f).toBe(`${ORIGIN}/media/social/og.png`);
    }
  });
});

describe("benchmark pages, linked and listed", () => {
  it("are in the sitemap, dated by published.json", () => {
    const xml = read("sitemap.xml");
    for (const p of ["benchmarks", ...views.map((v) => `benchmarks/${v.c.slug}`)]) {
      expect(xml, p).toContain(`<url><loc>${ORIGIN}/${p}</loc><lastmod>${pub.date}</lastmod></url>`);
    }
    for (const m of xml.matchAll(/<lastmod>([^<]+)<\/lastmod>/g)) expect(m[1]).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it("are linked from the homepage's benchmark section and the README's table", () => {
    const home = read("index.html");
    expect(home).toContain('<a href="/benchmarks">');
    const readme = readFileSync(join(ROOT, "README.md"), "utf8");
    for (const v of views) {
      expect(home, v.key).toContain(`<a href="/benchmarks/${v.c.slug}">`);
      expect(readme, v.key).toContain(`](${ORIGIN}/benchmarks/${v.c.slug})`);
    }
  });

  it("lead llms.txt, llms-full.txt and /index.md, with the lab numbers labelled as regression checks", () => {
    const llms = read("llms.txt");
    const at = llms.indexOf("## Public benchmarks");
    expect(at).toBeGreaterThan(0);
    expect(at).toBeLessThan(llms.indexOf("## When to use Penthera"));
    expect(at).toBeLessThan(llms.indexOf("## Docs"));
    expect(llms).toMatch(/\[Regression benchmark\]\([^)]+\): .*A regression check run on every release, not a measure of accuracy/);
    const full = read("llms-full.txt");
    expect(full.indexOf("## Public benchmarks")).toBeLessThan(full.indexOf("<!-- Source:"));
    const md = read("index.md");
    expect(md.indexOf(`${ORIGIN}/benchmarks/secrets.md`)).toBeLessThan(md.indexOf("Regression checks:"));
    for (const v of views) {
      const line = `Penthera ${v.us.version} ranked ${ord(v.us.rank)} of ${v.b.of} free tools`;
      for (const [f, body] of [["llms.txt", llms], ["llms-full.txt", full], ["index.md", md]]) {
        expect(body, `${f}: ${v.key}`).toContain(`(${ORIGIN}/benchmarks/${v.c.slug}.md): ${line}`);
      }
    }
  });

  it("redeploy when published.json changes: vercel.json's production filter covers bench/", () => {
    const { ignoreCommand } = JSON.parse(readFileSync(join(ROOT, "vercel.json"), "utf8"));
    expect(ignoreCommand.split(/\s+/)).toContain("bench");
  });

  it("gives the homepage a title and description that name the product and the category", () => {
    const home = read("index.html");
    const title = home.match(/<title>([^<]+)<\/title>/)[1];
    expect(title.length).toBeLessThanOrEqual(60);
    expect(title).toBe("Penthera: free security scanner and fixer for your app");
    const d = unesc(home.match(/<meta name="description" content="([^"]+)">/)[1]);
    expect(d.length).toBeLessThanOrEqual(160);
    expect(d).toContain(`Benchmarked against ${fieldTools(pub)} free tools`);
  });
});
