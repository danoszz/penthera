/**
 * The hub: /news, /research and /blog are one page. The same template renders
 * each URL as real HTML with its filter applied, so every link works without a
 * script and each page keeps its own title and canonical. site/hub.js and the
 * browser's view transitions make switching feel like one page.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { blogLd, paperPage } from "./blog.mjs";
import { smart } from "./frame.mjs";
import { PURPOSE, researchLd } from "./research.mjs";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const shortDate = (d) => (d ? new Date(`${d}T00:00:00Z`).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" }) : "");

/** The title is always a four-letter word on one grid, so any word can become any other. */
const GLYPHS = {
  A: "01110 10001 10001 11111 10001 10001 10001", B: "11110 10001 10001 11110 10001 10001 11110", E: "11111 10000 10000 11110 10000 10000 11111",
  G: "01110 10001 10000 10111 10001 10001 01111", H: "10001 10001 10001 11111 10001 10001 10001", I: "11111 00100 00100 00100 00100 00100 11111",
  K: "10001 10010 10100 11000 10100 10010 10001", L: "10000 10000 10000 10000 10000 10000 11111", N: "10001 11001 10101 10101 10011 10001 10001",
  O: "01110 10001 10001 10001 10001 10001 01110", P: "11110 10001 10001 11110 10000 10000 10000", R: "11110 10001 10001 11110 10100 10010 10001",
  S: "01111 10000 10000 01110 00001 00001 11110", W: "10001 10001 10001 10101 10101 11011 10001",
};
const lit = (word, col, row) => col % 6 !== 5 && GLYPHS[word[Math.floor(col / 6)]].split(" ")[row][col % 6] === "1";

export const mosaic = (word) => {
  const cells = [];
  for (let y = 0; y < 7; y++) for (let x = 0; x < 23; x++) cells.push(`<rect x="${x}" y="${y}" width="1" height="1" class="r${y}${lit(word, x, y) ? " on" : ""}"/>`);
  return `<svg class="ttx-title" viewBox="0 0 23 7" preserveAspectRatio="none" aria-hidden="true" data-word="${word}" data-glyphs="${esc(JSON.stringify(GLYPHS))}">${cells.join("")}</svg>`;
};

/** Every view: its URL, its word, and the name a reader sees. */
const VIEWS = {
  all: { href: "/news", chip: "All", word: "NEWS", view: "news", h1: "News", title: "News: what changed at Penthera", description: "Research, benchmarks, releases and lessons from Penthera, newest first." },
  research: { href: "/research", chip: "Research", word: "LABS", view: "research", h1: "Research", title: "Research: studies and results", description: "Every Penthera study, result and case study, with its status, newest first." },
  articles: { href: "/blog", chip: "Articles", word: "BLOG", view: "blog", h1: "Blog", title: "Blog: how Penthera is built and measured", description: "Posts on how Penthera is built and measured, with the data behind every number." },
  release: { href: "/news?kind=release", chip: "Releases", word: "SHIP", view: "release", kind: "release", h1: "Releases", title: "Releases" },
  lesson: { href: "/news?kind=lesson", chip: "Lessons", word: "WARN", view: "lesson", kind: "lesson", h1: "Incident lessons", title: "Incident lessons" },
  benchmark: { href: "/news?kind=benchmark", chip: "Benchmarks", word: "RANK", view: "benchmark", kind: "benchmark", h1: "Benchmarks", title: "Benchmarks" },
};

const KIND = { Study: ["research", "Research"], Result: ["research", "Research"], "Case study": ["lesson", "Incident lesson"], Benchmark: ["benchmark", "Benchmark"], Release: ["release", "Release"], Post: ["article", "Article"] };

/** Stable releases from the changelog, with no hand-written summary. */
export function releases(root) {
  const rows = [...readFileSync(join(root, "CHANGELOG.md"), "utf8").matchAll(/^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})/gm)];
  return rows.slice(0, 6).map(([, v, date]) => ({ date, type: "Release", title: `Penthera ${v}`, summary: "What changed, in the changelog.", href: `https://github.com/danoszz/penthera/releases/tag/v${v}` }));
}

/** One row. Kind and status are words; a row that leaves the site says so. */
function row(e, i, posts) {
  const [kind, label] = KIND[e.type] || ["research", e.type];
  const post = e.type === "Post" ? posts.find((p) => `/blog/${p.slug}` === e.href) : null;
  const fig = post && Object.entries(post.figures || {})[0];
  const away = /^https?:/.test(e.href);
  const meta = [label, e.status, e.id, shortDate(e.date), away ? "GitHub ↗" : ""].filter(Boolean).map(esc).join(" · ");
  const shown = post && post.category === "Benchmark" ? "benchmark" : kind;
  return `      <li class="hub-row${fig ? " hub-article" : ""}" data-kind="${shown}" data-status="${esc((e.status || "").toLowerCase())}" data-type="${esc(e.type.toLowerCase().replace(/\s+/g, "-"))}" data-id="r${esc((e.id || e.href).replace(/[^\w]+/g, "-"))}">
        <p class="hub-meta">${meta}</p>
        <h2><a href="${esc(e.href)}"${away ? ' rel="noopener"' : ""}>${smart(esc(e.headline || e.title))}</a></h2>
        ${fig ? `<img src="/blog/figures/${fig[0]}" width="${fig[1].width}" height="${fig[1].height}" alt="" loading="lazy">` : ""}
        ${e.type === "Study" && e.headline ? `<p class="hub-sub">${smart(esc(e.title))}</p>` : ""}<p class="hub-line">${smart(esc(e.summary))}${e.type === "Study" && e.result ? ` <a class="hub-more" href="${esc(e.result)}">Read the result</a>` : ""}</p>${(e.notes || []).map((n) => `<p class="hub-note">${smart(esc(n.text))} <a class="hub-more" href="${esc(n.href)}">Read the re-run</a></p>`).join("")}
      </li>`;
}

/** A view of the hub, as a whole page. */
export function hubHtml(key, entries, { origin, styles, foot, script, posts, feature = "" }) {
  const v = VIEWS[key];
  const rows = entries.filter((e) => (key === "all" ? e.status !== "Draft" : key === "research" ? e.type !== "Release" && e.type !== "Benchmark" : e.type === "Post"));
  const statuses = ["Registered", "Running", "Result", "Draft"].map((s) => [s, rows.filter((e) => e.status === s).length]).filter(([, n]) => n);
  const chips = Object.entries(VIEWS).map(([k, c]) => `<a class="hub-chip" href="${c.href}" data-chip="${k}" data-word="${c.word}" data-view="${c.view}" data-h1="${esc(c.h1)}"${c.kind ? ` data-kind="${c.kind}"` : ""}${k === key ? ' aria-current="page"' : ""}>${c.chip}</a>`).join("");
  const body = `    <nav class="hub-chips" aria-label="Show">${chips}</nav>
${key === "research" ? `    <p class="hub-purpose">${smart(esc(PURPOSE))}</p>
    <nav class="hub-status" aria-label="Status">${statuses.map(([s, n]) => `<a href="/research?status=${s.toLowerCase()}" data-status="${s.toLowerCase()}">${s} ${n}</a>`).join("")}</nav>
    <form class="hub-search" action="/research" role="search"><label class="sr" for="hub-q">Search the research</label><input id="hub-q" name="q" type="search" placeholder="Search"></form>
    <div class="rs">${feature}</div>\n` : ""}    <ul class="hub-list">
${rows.map((e, i) => row(e, i, posts)).join("\n")}
    </ul>
    <p class="hub-none" hidden>Nothing here yet.</p>
    <nav class="ttx-keys" aria-label="More pages"><a href="/benchmarks">Benchmarks</a><a href="/news/feed.xml">Atom feed</a><a href="${v.href}.md">Markdown copy</a></nav>`;
  const ld = key === "research" ? researchLd(rows, { url: `${origin}/research`, origin, description: v.description }) : key === "articles" ? blogLd(posts, origin) : "";
  return paperPage({ title: v.title, description: v.description, url: `${origin}${v.href}`, path: v.href, h1: v.h1, ld, body, styles, theme: "/theme.js", foot, type: "website", mast: true,
    mastHtml: mosaic(v.word), view: v.view, headScript: script, number: "P100", bar: "Penthera news", dateline: "",
    crumb: `<a class="tag" data-f="4" data-c="0" data-t="0" href="/">Penthera</a><span class="tag" data-f="3" data-c="0" data-t="0">${esc(v.chip === "All" ? "News" : v.chip)}</span>` });
}

/** /news as Markdown, for agents: every row, with kind and status in words. */
export function hubMarkdown(entries, { origin }) {
  const rows = entries.filter((e) => e.status !== "Draft").map((e) => `- [${e.headline || e.title}](${e.href.startsWith("/") ? origin + e.href : e.href}) (${[KIND[e.type]?.[1] || e.type, e.status, e.date].filter(Boolean).join(", ")}): ${e.summary}`);
  return `# Penthera news\n\n> What changed at Penthera, and what does it mean for me?\n\n${rows.join("\n")}\n`;
}

/** The Atom feed of /news: all kinds except Drafts. */
export function hubFeed(entries, { origin }) {
  const xml = (s) => esc(s).replace(/&#39;/g, "'");
  const rows = entries.filter((e) => e.status !== "Draft" && e.date);
  return `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Penthera news</title>
  <id>${origin}/news</id>
  <link rel="alternate" type="text/html" href="${origin}/news"/>
  <link rel="self" type="application/atom+xml" href="${origin}/news/feed.xml"/>
  <updated>${rows[0]?.date || "1970-01-01"}T00:00:00Z</updated>
${rows.map((e) => `  <entry><title>${xml(e.headline || e.title)}</title><id>${xml(e.href.startsWith("/") ? origin + e.href : e.href)}</id><link href="${xml(e.href.startsWith("/") ? origin + e.href : e.href)}"/><updated>${e.date}T00:00:00Z</updated><summary>${xml(e.summary)}</summary></entry>`).join("\n")}
</feed>
`;
}
