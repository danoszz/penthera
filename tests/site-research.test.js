/**
 * /research (site/research.mjs): the page builds, every entry links to a page
 * that exists, the featured benchmark gives each rank with its interval, and
 * a study that is not registered is never labelled Registered.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync, readFileSync, existsSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildSite } from "../site/build.mjs";
import { benchmarkViews, ord, tiedPhrase } from "../site/benchmarks.mjs";
import { readPosts } from "../site/blog.mjs";
import { FILTERS, PURPOSE, STATUSES, TYPES, e11bHeadline, inFilter, parsePrereg, researchEntries, studyStatus } from "../site/research.mjs";

const ROOT = join(import.meta.dirname, "..");
const ORIGIN = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).homepage.replace(/\/+$/, "");
const pub = JSON.parse(readFileSync(join(ROOT, "bench", "public", "published.json"), "utf8"));
const BLOB = "https://github.com/danoszz/penthera/blob/main/";
const PREREG = join(ROOT, "docs", "research", "prereg");

let dir, out, entries;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "penthera-research-"));
  out = join(dir, "dist");
  const prev = process.env.PENTHERA_SITE_STARS;
  process.env.PENTHERA_SITE_STARS = "off";
  try {
    await buildSite({ out });
  } finally {
    if (prev === undefined) delete process.env.PENTHERA_SITE_STARS;
    else process.env.PENTHERA_SITE_STARS = prev;
  }
  entries = researchEntries({ root: ROOT, pub, posts: readPosts(join(ROOT, "blog"), pub).published });
}, 180_000);

afterAll(() => rmSync(dir, { recursive: true, force: true }));

const read = (f) => readFileSync(join(out, f), "utf8");
const unesc = (s) => s.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'");
/** Visible text with inline tags removed in place, so "<span>1st</span> of 6" reads "1st of 6". */
const inline = (html) => unesc((html.includes("<body>") ? html.slice(html.indexOf("<body>")) : html).replace(/<[^>]+>/g, "")).replace(/\s+/g, " ");
/** GitHub's heading anchor for a Markdown heading. */
const slug = (h) => h.trim().toLowerCase().replace(/[^\w\- ]/g, "").replace(/ /g, "-");
/** The <li> of each entry on the page. */
const items = (html) => [...html.matchAll(/<li class="hub-row[\s\S]*?<\/li>/g)].map((m) => m[0]);

describe("/research", () => {
  it("builds as HTML and Markdown, with one h1, the purpose line, and is in the sitemap, llms.txt and the footer", () => {
    const html = read("research.html");
    expect(html).toContain(`<link rel="canonical" href="${ORIGIN}/research">`);
    expect(html.match(/<h1[ >]/g)).toHaveLength(1);
    expect(inline(html)).toContain(PURPOSE);
    expect(read("research.md")).toMatch(/^# Penthera research/);
    expect(read("sitemap.xml")).toContain(`<loc>${ORIGIN}/research</loc>`);
    expect(read("llms.txt")).toContain(`(${ORIGIN}/research.md)`);
    for (const f of ["index.html", "benchmarks.html", "research.html"]) expect(read(f), f).toContain('<a href="/research">Research</a>');
    // The theme and the page's own script, both files; no inline style, no tracking.
    expect(html).not.toMatch(/\{\{| style=|track\.js|insights/);
    const scripts = [...html.matchAll(/<script(?![^>]*type="application\/ld\+json")[^>]*>/g)].map((m) => m[0]);
    expect(scripts).toHaveLength(2);
    expect(scripts[0]).toBe('<script src="/theme.js">');
    expect(scripts[1]).toMatch(/^<script src="\/hub\.js\?v=[\w-]+">$/);
    expect(html).not.toMatch(/<script>[^<]|\son[a-z]+="/);
    const d = unesc(html.match(/<meta name="description" content="([^"]+)">/)[1]);
    expect(d.length).toBeLessThanOrEqual(160);
  });

  it("puts the whole list in the HTML; only the script hides entries, and it is a file with no dependencies", () => {
    const html = read("research.html");
    const lis = items(html);
    expect(lis).toHaveLength(entries.length);
    // No entry is hidden in the HTML; the controls are hidden until a script runs.
    for (const li of lis) expect(li).not.toMatch(/<[^>]*\shidden[\s>=]/);
    // Every dated entry also reaches the Markdown that agents read.
    expect(read("research.md").split("\n").filter((l) => l.startsWith("- 20"))).toHaveLength(entries.filter((e) => e.date).length);
    const js = read("hub.js");
    expect(js).toBe(readFileSync(join(ROOT, "site", "hub.js"), "utf8"));
    expect(js).not.toMatch(/\bimport\b|require\(|fetch\(|XMLHttpRequest|sendBeacon|localStorage|document\.cookie/);
    // Accessible controls: a labelled search, and links that work without a script.
    expect(html).toMatch(/<label class="sr" for="hub-q">[^<]+<\/label>/);
    expect(html).toMatch(/<input id="hub-q"[^>]*type="search"/);
    for (const k of ["/news", "/research", "/blog"]) expect(html).toContain(`href="${k}" data-chip`);
  });

  it("offers a link for every status, with counts that match the list", () => {
    const html = read("research.html");
    const st = [...html.matchAll(/href="\/research\?status=([a-z]+)" data-status="\1">(\w+) (\d+)</g)];
    expect(st.length).toBeGreaterThan(0);
    for (const [, key, label, n] of st) {
      expect(STATUSES).toContain(label);
      expect(key).toBe(label.toLowerCase());
      expect(Number(n)).toBe(entries.filter((e) => e.status === label).length);
    }
    // Every entry carries its kind and type, the keys the filters use.
    for (const li of items(html)) expect(li).toMatch(/data-kind="[a-z]+"[^>]*data-type="[a-z-]+"/);
  });

  it("lists each study once: E17 is one entry, with its re-run as a note", () => {
    const html = read("research.html");
    const e17 = entries.filter((e) => e.id === "E17");
    expect(e17).toHaveLength(1);
    expect(e17[0]).toMatchObject({ type: "Study", status: "Result" });
    expect(e17[0].headline).toMatch(/macOS and Ubuntu/);
    expect(e17[0].notes.map((n) => n.text).join(" ")).toMatch(/Re-run 29 Oct.*verdict unchanged/);
    const li = items(html).filter((l) => l.includes('data-id="rE17"'));
    expect(li).toHaveLength(1);
    expect(li[0]).toContain("#registered-run-28-oct-2026");
    expect(li[0]).toContain("#deviation-the-normaliser-29-oct-2026");
    // Every study id appears once.
    const ids = entries.filter((e) => e.type === "Study").map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("says the E11b ranks briefly, in the interval wording", () => {
    const h = e11bHeadline(pub);
    expect(h.length).toBeLessThan(110);
    for (const v of benchmarkViews(pub)) {
      const t = tiedPhrase(v.iv);
      expect(h, v.key).toContain(t ? t.replace(/^, /, "") : ord(v.us.rank));
    }
    expect(h).not.toMatch(/;/);
  });

  it("lists every entry newest first, each with a known type, and a status only on studies", () => {
    const html = read("research.html");
    expect(items(html)).toHaveLength(entries.length);
    const dates = entries.map((e) => e.date).filter(Boolean);
    expect(dates).toEqual([...dates].sort().reverse());
    for (const e of entries) {
      expect(TYPES, e.title).toContain(e.type);
      if (e.type === "Study") expect(STATUSES, e.title).toContain(e.status);
      else expect(e.status, e.title).toBeUndefined();
      expect(e.summary.length, e.title).toBeGreaterThan(0);
    }
    // Every filter has entries: "Results" holds the studies with a result.
    for (const f of FILTERS) expect(entries.some((e) => inFilter(e, f)), f.label).toBe(true);
  });

  it("links every entry to a page that exists: a built page, or a file (and heading) in the repo", () => {
    const html = read("research.html");
    const hrefs = [...html.matchAll(/<(?:h2|h3)[^>]*><a href="([^"]+)"/g), ...html.matchAll(/class="rs-more" href="([^"]+)"/g)].map((m) => unesc(m[1]));
    expect(hrefs.length).toBeGreaterThan(entries.length);
    for (const h of hrefs) {
      if (h.startsWith("/")) {
        const p = h.slice(1);
        expect(existsSync(join(out, `${p}.html`)) || existsSync(join(out, p, "index.html")), h).toBe(true);
      } else {
        expect(h.startsWith(BLOB), h).toBe(true);
        const [file, anchor] = h.slice(BLOB.length).split("#");
        expect(existsSync(join(ROOT, file)), h).toBe(true);
        if (anchor) {
          const heads = [...readFileSync(join(ROOT, file), "utf8").matchAll(/^#{1,6} (.+)$/gm)].map((m) => slug(m[1]));
          expect(heads, h).toContain(anchor);
        }
      }
    }
  });

  it("gives each benchmark rank with its interval, in the words of site/benchmarks.mjs", () => {
    const html = read("research.html");
    const text = inline(html.slice(html.indexOf('class="rs-feature'), html.indexOf("rs-list-title")));
    expect(html).toMatch(/<section class="rs-feature[^"]*"[\s\S]*?href="\/benchmarks"/);
    const views = benchmarkViews(pub);
    expect(views.some((v) => tiedPhrase(v.iv))).toBe(true);
    for (const v of views) {
      expect(text, v.key).toContain(`${ord(v.us.rank)} of ${v.b.of}${tiedPhrase(v.iv)}`);
      // A rank whose interval spans more than one place never appears without it.
      if (tiedPhrase(v.iv)) expect(text.replace(`${ord(v.us.rank)} of ${v.b.of}${tiedPhrase(v.iv)}`, ""), v.key).not.toContain(`${ord(v.us.rank)} of ${v.b.of} `);
    }
    const md = read("research.md");
    for (const v of views) expect(md, v.key).toContain(`${ord(v.us.rank)} of ${v.b.of}${tiedPhrase(v.iv)}`);
  });

  it("never labels an unregistered study Registered, or shows a result for it", async () => {
    // The real protocols: a status that says it is not registered is Draft on the page.
    const html = read("research.html");
    const { readdirSync } = await import("node:fs");
    const drafts = readdirSync(PREREG).filter((f) => /^E\d/.test(f)).map((f) => parsePrereg(readFileSync(join(PREREG, f), "utf8"), f)).filter((p) => /not registered|\bdraft\b/i.test(p.status));
    expect(drafts.length).toBeGreaterThan(0);
    for (const p of drafts) {
      const e = entries.find((x) => x.type === "Study" && x.id === p.id);
      expect(e.status, p.id).toBe("Draft");
      expect(e.headline, p.id).toBeUndefined();
      const li = items(html).find((l) => l.includes(`data-id="r${p.id}"`));
      expect(li, p.id).toBeTruthy();
      expect(li, p.id).toContain('data-status="draft"');
      expect(li, p.id).not.toMatch(/data-status="(registered|result)"| · Registered · | · Result · /);
    }
    // The rule itself, on wordings the protocols use.
    for (const s of ["Draft, not registered. Registration is the maintainer's written acceptance", "draft for review, not registered. It is registered by the commit that merges it", "Registered draft", ""]) {
      expect(studyStatus(s, true), s).toBe("Draft");
    }
    expect(studyStatus("Registered. Accepted by the maintainer on 28 Oct 2026")).toBe("Registered");
    expect(studyStatus("Registered. The commit that merges this file to main is the registration timestamp.", true)).toBe("Result");
    expect(studyStatus("Completed 2026-10-25. Approved by Daan")).toBe("Registered");
  });

  it("uses the public name for State of the Web, with the id kept out of what readers see", () => {
    const li = items(read("research.html")).filter((l) => /data-id="rE20r?"/.test(l));
    expect(li).toHaveLength(2);
    for (const l of li) {
      expect(l).toContain("State of the Web 2026");
      expect(l).toContain('data-status="registered"');
      expect(l.replace(/<[^>]+>/g, " ")).not.toMatch(/\bE20|\bsafe\b/i);
    }
    for (const f of ["research.md", "news.md"]) expect(read(f)).not.toMatch(/\[E20|Study E20/);
    expect(read("llms.txt")).toContain("[State of the Web 2026](");
    expect(read("index.html")).toContain('<a href="/research-e20">State of the Web</a>');
  });

  it("reads a new protocol's status from its own file: a draft lands as Draft", () => {
    const d = join(dir, "prereg");
    mkdirSync(d, { recursive: true });
    writeFileSync(join(d, "E99-test.md"), "# E99: A test study (pre-registration)\n\n| | |\n|---|---|\n| Status | **Draft, not registered.** Nothing binds yet |\n| Date written | 2026-11-01 |\n");
    writeFileSync(join(d, "E98-test.md"), "# E98: Another (pre-registration)\n\n| | |\n|---|---|\n| Status | **Registered.** The merge commit is the timestamp |\n| Date written | 2026-11-02 |\n");
    const got = researchEntries({ root: ROOT, preregDir: d });
    expect(got.filter((e) => e.type === "Study").map((e) => [e.id, e.status, e.date])).toEqual([["E98", "Registered", "2026-11-02"], ["E99", "Draft", "2026-11-01"]]);
  });
});
