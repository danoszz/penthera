/**
 * The engineering blog: /blog, from Markdown in blog/ at the repo root.
 *
 *   ---
 *   title: We benchmarked 10 free secret scanners. We came second.
 *   nav: Secret scanner test    # the footer's label, one short line
 *   description: Under 160 characters.
 *   date: 2026-11-03
 *   approved: false              # Daan sets a date (YYYY-MM-DD) to publish
 *   sources: bench/public/published.json, bench/public/RESULTS.md
 *   keywords: secret scanner benchmark, gitleaks vs trufflehog
 *   ---
 *   > The one question the post answers?
 *
 *   Body. Numbers from published.json are placeholders, {{fact:secrets.penthera.f1}},
 *   filled in at build time; any other number must appear verbatim in one of
 *   the post's sources (tests/site-blog.test.js checks it).
 *
 * Drafts. Only `approved: <date>` publishes a post. A post with
 * `approved: false` is a draft: the build checks it (front matter, facts) and
 * writes nothing for it, so it is not on the site, in the index, the feed, the
 * sitemap or llms.txt. PENTHERA_BLOG_DRAFTS=1 renders drafts too, for a local
 * preview, at /blog/<slug> with noindex and a draft banner, still unlisted.
 * With no approved post there is no /blog at all, and nothing links to it.
 *
 * Each published post is /blog/<slug> (BlogPosting JSON-LD) and
 * /blog/<slug>.md; the index is /blog, the Atom feed /blog/feed.xml.
 *
 * Figures. An SVG in blog/figures/ shows inline as a paragraph that starts
 * with an image line, the caption on the lines after it:
 *
 *   ![Alt text: what the figure shows](figures/dev-to-test.svg)
 *   What to read in it, and where it comes from.
 *
 * The path works on GitHub as it is; the build serves the file at
 * /blog/figures/ and refuses a figure that is missing or has no alt text.
 */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { renderMarkdown } from "./terms.mjs";
import { RANK_INTERVALS, fieldTools, n2, ord } from "./benchmarks.mjs";

/** F-beta: beta below 1 weighs precision more, above 1 recall. */
const fBeta = (p, r, beta) => (p && r ? ((1 + beta * beta) * p * r) / (beta * beta * p + r) : 0);
import { ldScript, siteFooter, smart } from "./frame.mjs";

export { smart };

const REPO = "https://github.com/danoszz/penthera";
const AUTHOR = { "@type": "Person", name: "Daan van der Zwaag", url: "https://daanvanderzwaag.com" };
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const longDate = (d) => new Date(`${d}T00:00:00Z`).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });

// ── Facts from published.json ───────────────────────────────────────────────

/** A row's id in a fact path: penthera, penthera-before, or the tool's name as a slug. */
export const rowId = (r) => (r.kind === "penthera" ? "penthera" : r.kind === "penthera-before" ? "penthera-before" : r.tool.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""));

const fmt = (v) => {
  if (typeof v === "number") return Number.isInteger(v) ? v.toLocaleString("en-US") : n2(v);
  if (Array.isArray(v) && v.length === 2 && v.every(Number.isInteger)) return `${v[0].toLocaleString("en-US")}/${v[1].toLocaleString("en-US")}`;
  if (Array.isArray(v) && v.length === 2 && v.every((x) => typeof x === "number")) return `${n2(v[0])} to ${n2(v[1])}`;
  return typeof v === "string" ? v : null;
};

/**
 * Every fact a post may quote, by path: `date`, `tools`, `paid`,
 * `<benchmark>.of|field|n`, `<benchmark>.median.<measure>` and
 * `<benchmark>.<row>.<field>` (score, rank, place, p, r, f1, precisionCI, detect, ...),
 * `secrets.<row>.f05|f2`, and `<benchmark>.penthera.interval|first` (the rank interval).
 * A pair of counts prints as k/n, an interval as "a to b", a rate with two decimals.
 */
export function facts(pub) {
  const f = { date: longDate(pub.date), "date.iso": pub.date, tools: String(fieldTools(pub)), paid: pub.paidTools.names.join(", ") };
  for (const [b, bench] of Object.entries(pub.benchmarks)) {
    for (const k of ["of", "field", "n"]) if (bench[k] != null) f[`${b}.${k}`] = fmt(bench[k]);
    for (const [m, s] of Object.entries(bench.others || {})) f[`${b}.median.${m}`] = n2(s.median);
    for (const r of bench.rows) {
      for (const [k, v] of Object.entries(r)) {
        const s = fmt(v);
        if (s != null) f[`${b}.${rowId(r)}.${k}`] = s;
      }
      if (r.rank != null) f[`${b}.${rowId(r)}.place`] = ord(r.rank);
      // F0.5 leans on precision and F2 on recall: how much a rank depends on the weight.
      if (b === "secrets" && r.p != null && r.r != null) {
        f[`${b}.${rowId(r)}.f05`] = n2(fBeta(r.p, r.r, 0.5));
        f[`${b}.${rowId(r)}.f2`] = n2(fBeta(r.p, r.r, 2));
      }
    }
    // Penthera's rank interval (bench/public/rank-intervals.json): "1st to 3rd", and the share of draws it was first.
    const iv = RANK_INTERVALS.penthera[b];
    if (iv) {
      f[`${b}.penthera.interval`] = `${ord(iv.rank[0])} to ${ord(iv.rank[1])}`;
      f[`${b}.penthera.first`] = `${Math.round(iv.first * 100)}%`;
    }
  }
  return f;
}

/** Fill {{fact:path}}; an unknown fact is a build error. */
export function fillFacts(text, f, file) {
  return text.replace(/\{\{fact:([\w.-]+)\}\}/g, (m, k) => {
    if (!(k in f)) throw new Error(`${file}: unknown fact ${m}`);
    return f[k];
  });
}

// ── Posts ───────────────────────────────────────────────────────────────────

/** Parse one post. Throws on a missing or malformed field. */
export function parsePost(md, file) {
  const src = md.replace(/\r\n/g, "\n");
  const m = /^---\n([\s\S]*?)\n---\n/.exec(src);
  if (!m) throw new Error(`${file}: no front matter`);
  const meta = Object.fromEntries(m[1].split("\n").map((l) => /^(\w+):\s*(.*?)(?:\s+#.*)?$/.exec(l)).filter(Boolean).map((x) => [x[1], x[2]]));
  for (const k of ["title", "description", "date", "approved", "sources"]) if (!meta[k]) throw new Error(`${file}: front matter has no ${k}`);
  if (!DAY.test(meta.date)) throw new Error(`${file}: date must be YYYY-MM-DD`);
  if (meta.approved !== "false" && !DAY.test(meta.approved)) throw new Error(`${file}: approved must be false or the date Daan approved it (YYYY-MM-DD)`);
  const body = src.slice(m[0].length);
  const question = /^> (.+)$/m.exec(body)?.[1];
  if (!question) throw new Error(`${file}: no question line (> ...) at the top`);
  if (/^# /m.test(body)) throw new Error(`${file}: no # heading in the body; the title is the h1`);
  return {
    ...meta,
    approved: meta.approved === "false" ? null : meta.approved,
    sources: meta.sources.split(",").map((s) => s.trim()).filter(Boolean),
    keywords: (meta.keywords || "").split(",").map((s) => s.trim()).filter(Boolean),
    question,
    body,
  };
}

/**
 * Every post in `dir`, newest first, with its facts filled in.
 * @returns {{ published: object[], drafts: object[] }}
 */
export function readPosts(dir, pub) {
  if (!existsSync(dir)) return { published: [], drafts: [] };
  const f = pub ? facts(pub) : {};
  const posts = readdirSync(dir).filter((n) => n.endsWith(".md") && n !== "README.md").sort().map((n) => {
    const file = `blog/${n}`;
    const p = parsePost(readFileSync(join(dir, n), "utf8"), file);
    const md = fillFacts(p.body, f, file).replace(/(!\[[^\]]*\]\()figures\//g, "$1/blog/figures/");
    const post = { slug: n.slice(0, -3), ...p, title: fillFacts(p.title, f, file), description: fillFacts(p.description, f, file), md, figures: postFigures(md, dir, file) };
    if (post.description.length > 160) throw new Error(`${file}: description is ${post.description.length} characters; search engines cut it at about 160`);
    return post;
  }).sort((a, z) => z.date.localeCompare(a.date) || a.slug.localeCompare(z.slug));
  const published = posts.filter((p) => p.approved);
  // A published post may not link a draft: that page does not exist.
  const live = new Set(published.map((p) => p.slug));
  for (const p of published) {
    for (const m of p.md.matchAll(/\]\(\/blog\/([\w-]+)\)/g)) if (!live.has(m[1])) throw new Error(`blog/${p.slug}.md links /blog/${m[1]}, which is not approved`);
  }
  return { published, drafts: posts.filter((p) => !p.approved) };
}

/**
 * The figures a post shows, by file name: where the SVG is and its size. A
 * missing file, a figure without alt text or an SVG without a size is a build error.
 */
export function postFigures(md, dir, file) {
  const out = {};
  for (const m of md.matchAll(/!\[([^\]]*)\]\(\/blog\/figures\/([^)\s]+)\)/g)) {
    const [, alt, name] = m;
    if (!/^[\w-]+\.svg$/.test(name)) throw new Error(`${file}: figure ${name} must be an .svg in blog/figures/`);
    if (alt.trim().length < 20) throw new Error(`${file}: figure ${name} needs alt text that says what it shows`);
    const path = join(dir, "figures", name);
    if (!existsSync(path)) throw new Error(`${file}: figure ${name} is not in blog/figures/`);
    const svg = readFileSync(path, "utf8");
    const width = /<svg[^>]*\swidth="(\d+)"/.exec(svg)?.[1], height = /<svg[^>]*\sheight="(\d+)"/.exec(svg)?.[1];
    if (!width || !height) throw new Error(`${file}: figure ${name} has no width and height`);
    out[name] = { path, width: Number(width), height: Number(height) };
  }
  return out;
}

/** Give each figure its size, so the page does not jump as it loads. */
const sized = (html, figures) => html.replace(/<img src="\/blog\/figures\/([^"]+)"/g, (m, name) => (figures?.[name] ? `${m} width="${figures[name].width}" height="${figures[name].height}"` : m));

// ── HTML, Markdown, Atom ────────────────────────────────────────────────────

/** Two words in one grid: BLOG, and DATA behind a click (site/blog.js). */
const GLYPHS = {
  B: "11110 10001 10001 11110 10001 10001 11110", L: "10000 10000 10000 10000 10000 10000 11111", O: "01110 10001 10001 10001 10001 10001 01110", G: "01110 10001 10000 10111 10001 10001 01111",
  D: "11110 10001 10001 10001 10001 10001 11110", A: "01110 10001 10001 11111 10001 10001 10001", T: "11111 00100 00100 00100 00100 00100 00100",
};
const lit = (word, col, row) => {
  const glyph = GLYPHS[word[Math.floor(col / 6)]];
  return col % 6 !== 5 && glyph.split(" ")[row][col % 6] === "1";
};
const mosaic = () => {
  const cells = [];
  for (let y = 0; y < 7; y++) for (let x = 0; x < 23; x++) {
    const blog = lit("BLOG", x, y), data = lit("DATA", x, y);
    cells.push(`<rect x="${x}" y="${y}" width="1" height="1" class="r${y}${blog ? " on b" : ""}${data ? " d" : ""}"/>`);
  }
  return `<svg class="ttx-title" viewBox="0 0 23 7" aria-hidden="true">${cells.join("")}</svg>`;
};

/** The four coloured links at the bottom of a page, teletext's Fastext keys. */
const fastext = (keys) => `    <nav class="ttx-keys" aria-label="More pages">${keys.map(([href, text]) => `<a href="${esc(href)}">${esc(text)}</a>`).join("")}</nav>`;

/** A post's page number. The oldest is P101, so a new post never renumbers the others. */
const pageNumbers = (posts) => new Map(posts.map((p, i) => [p.slug, `P${100 + posts.length - i}`]));

function page({ title, description, url, path, h1, crumb, ld, body, styles, theme, foot = siteFooter(), draft = false, type = "article", feed = true, number = "P100", dateline = "", mast = false, script = "" }) {
  return `<!doctype html>
<html lang="en" data-theme="light" data-paper>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(title)} · Penthera</title>
  <meta name="description" content="${esc(description)}">
  <meta name="color-scheme" content="light">
  <meta name="theme-color" content="#0000ed">
${draft ? '  <meta name="robots" content="noindex, nofollow">\n' : ""}  <link rel="canonical" href="${url}">
  <link rel="alternate" type="text/markdown" href="${path}.md">
${feed ? '  <link rel="alternate" type="application/atom+xml" href="/blog/feed.xml" title="Penthera blog">\n' : ""}  <meta property="og:site_name" content="Penthera">
  <meta property="og:title" content="${esc(h1)}">
  <meta property="og:description" content="${esc(description)}">
  <meta property="og:type" content="${type}">
  <meta property="og:url" content="${url}">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="${styles}">
  <script src="${theme}"></script>
${script ? `  <script src="${script}" defer></script>\n` : ""}  ${ld}
</head>
<body>
  <p class="ttx-bar"><span class="ttx-page">${number}</span><span>Penthera blog</span><span class="ttx-date">${dateline}</span></p>
  <main class="terms land blog${mast ? "" : " blog-post"}" id="main">
${draft ? '    <p class="blog-draft">Draft: not approved, not listed and not indexed.</p>\n' : ""}    <nav class="eyebrow ttx-crumbs" aria-label="Breadcrumb">${crumb}</nav>
    <h1>${mast ? `${mosaic()}<span class="sr">${esc(h1)}</span>` : smart(esc(h1))}</h1>
${body}
  </main>
  ${foot}
</body>
</html>
`;
}

/** Make site paths absolute, for the Markdown copy and the feed. */
const absolute = (md, origin) => md.replace(/\]\(\/(?!\/)/g, `](${origin}/`);

const sourceLinks = (p) => p.sources.map((s) => `<a href="${REPO}/blob/main/${esc(s)}">${esc(s.split("/").pop())}</a>`).join(", ");

/** The schema.org BlogPosting for a post. */
export function postLd(p, origin) {
  const url = `${origin}/blog/${p.slug}`;
  return {
    "@type": "BlogPosting",
    "@id": `${url}#post`,
    headline: p.title,
    description: p.description,
    url,
    mainEntityOfPage: url,
    datePublished: p.date,
    dateModified: p.date,
    author: AUTHOR,
    publisher: { "@type": "Person", name: AUTHOR.name, url: AUTHOR.url },
    keywords: p.keywords,
    isPartOf: { "@type": "Blog", "@id": `${origin}/blog#blog`, url: `${origin}/blog`, name: "Penthera blog" },
    citation: p.sources.map((s) => `${REPO}/blob/main/${s}`),
    ...(p.sources.includes("bench/public/published.json") ? { isBasedOn: { "@id": `${origin}/benchmarks#dataset` } } : {}),
  };
}

/** One post as HTML. */
export function postHtml(p, { origin, styles = "/styles.css", theme = "/theme.js", script = "/blog.js", foot, number = "P100", next }) {
  const path = `/blog/${p.slug}`;
  const url = `${origin}${path}`;
  const minutes = Math.max(1, Math.round(p.md.split(/\s+/).length / 220));
  const html = smart(sized(renderMarkdown(p.md), p.figures)).replace(/<h2 id=/g, '<h2 class="sticker" id=');
  const sections = [...html.matchAll(/<h2 class="sticker" id="([^"]+)">(.*?)<\/h2>/g)].map(([, id, text]) => `<li><a href="#${id}">${text}</a></li>`);
  const body = `    <aside class="paper-side" aria-label="About this post">
      <p class="blog-meta"><span><time datetime="${p.date}">${longDate(p.date)}</time></span><span>${esc(AUTHOR.name)}</span><span>${minutes} min read</span></p>
${sections.length > 2 ? `      <nav class="paper-toc" aria-label="In this post"><ol>${sections.join("")}</ol></nav>\n` : ""}    </aside>
    <div class="paper-body">
${html}
    </div>
    <p class="blog-src">Sources: ${sourceLinks(p)}.</p>
${fastext([["/blog", "All posts"], next ? [`/blog/${next.slug}`, `${next.number} ${next.nav || next.title}`] : ["/benchmarks", "Benchmarks"], ["/blog/feed.xml", "Atom feed"], [`${path}.md`, "Markdown copy"]])}`;
  const ld = ldScript([postLd(p, origin), {
    "@type": "BreadcrumbList",
    itemListElement: [["Penthera", "/"], ["Blog", "/blog"], [p.title, path]].map(([n, u], i) => ({ "@type": "ListItem", position: i + 1, name: n, item: `${origin}${u}` })),
  }]);
  return page({ title: p.title, description: p.description, url, path, h1: p.title, ld, body, styles, theme, script, foot, draft: !p.approved, number, dateline: longDate(p.date),
    crumb: `<a class="tag" href="/">Penthera</a><a class="tag tag-steel" href="/blog">Blog</a>` });
}

/** One post as Markdown, for agents. */
export function postMarkdown(p, { origin }) {
  return `# ${p.title}\n\n${absolute(p.md, origin).trimEnd()}\n\n${p.date} · ${AUTHOR.name} · Sources: ${p.sources.map((s) => `${REPO}/blob/main/${s}`).join(", ")}\n`;
}

/** /blog: the published posts, newest first. */
export function blogIndexHtml(posts, { origin, styles = "/styles.css", theme = "/theme.js", script = "/blog.js", foot }) {
  const numbers = pageNumbers(posts);
  const lead = Object.keys(posts[0]?.figures || {})[0];
  const body = `    <ul class="ttx-front">
${posts.map((p, i) => `      <li><p class="ttx-line"><span class="tag">${numbers.get(p.slug)}</span><time class="tag tag-steel" datetime="${p.date}">${longDate(p.date)}</time></p><h2><a href="/blog/${p.slug}">${smart(esc(p.title))}</a></h2>${i === 0 && lead ? `<img src="/blog/figures/${lead}" width="${posts[0].figures[lead].width}" height="${posts[0].figures[lead].height}" alt="" loading="lazy">` : ""}<p>${smart(esc(p.description))}</p></li>`).join("\n")}
    </ul>
${fastext([["/benchmarks", "Benchmarks"], ["/research", "Research"], ["/blog/feed.xml", "Atom feed"], ["/blog.md", "Markdown copy"]])}`;
  const ld = ldScript([{
    "@type": "Blog", "@id": `${origin}/blog#blog`, url: `${origin}/blog`, name: "Penthera blog", author: AUTHOR,
    blogPost: posts.map((p) => ({ "@id": `${origin}/blog/${p.slug}#post` })),
  }]);
  return page({ title: "Blog: how Penthera is built and measured", description: "Posts on how Penthera is built and measured, with the data and the protocol behind every number.",
    url: `${origin}/blog`, path: "/blog", h1: "Blog", ld, body, styles, theme, foot, type: "website", mast: true, script, dateline: posts[0] ? longDate(posts[0].date) : "", crumb: `<a class="tag" href="/">Penthera</a><span class="tag tag-steel">Blog</span>` });
}

/** /blog.md */
export function blogIndexMarkdown(posts, { origin }) {
  return `# Penthera blog\n\n> How is Penthera built and measured?\n\n${posts.map((p) => `- [${p.title}](${origin}/blog/${p.slug}.md) (${p.date}): ${p.description}`).join("\n")}\n\nAtom feed: ${origin}/blog/feed.xml\n`;
}

const xml = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

/** The Atom feed of the published posts. */
export function atomFeed(posts, { origin }) {
  const updated = posts[0]?.date || "1970-01-01";
  return `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Penthera blog</title>
  <subtitle>How Penthera is built and measured.</subtitle>
  <id>${origin}/blog</id>
  <link rel="alternate" type="text/html" href="${origin}/blog"/>
  <link rel="self" type="application/atom+xml" href="${origin}/blog/feed.xml"/>
  <updated>${updated}T00:00:00Z</updated>
  <author><name>${xml(AUTHOR.name)}</name><uri>${AUTHOR.url}</uri></author>
${posts.map((p) => `  <entry>
    <title>${xml(p.title)}</title>
    <id>${origin}/blog/${p.slug}</id>
    <link rel="alternate" type="text/html" href="${origin}/blog/${p.slug}"/>
    <published>${p.date}T00:00:00Z</published>
    <updated>${p.date}T00:00:00Z</updated>
    <summary>${xml(p.description)}</summary>
    <content type="html">${xml(renderMarkdown(absolute(p.md, origin)))}</content>
  </entry>`).join("\n")}
</feed>
`;
}

/**
 * The files the blog adds to the site, as site path to content. Nothing when
 * no post is approved; drafts only with `drafts: true` (a local preview).
 */
export function blogFiles(posts, { origin, styles, script, drafts = false, foot }) {
  const out = {};
  if (posts.published.length) {
    const index = blogIndexHtml(posts.published, { origin, styles, script, foot });
    out["blog.html"] = index;
    out["blog/index.html"] = index;
    out["blog.md"] = blogIndexMarkdown(posts.published, { origin });
    out["blog/feed.xml"] = atomFeed(posts.published, { origin });
  }
  const numbers = pageNumbers(posts.published);
  for (const p of [...posts.published, ...(drafts ? posts.drafts : [])]) {
    const at = posts.published.indexOf(p);
    const after = at < 0 ? null : posts.published[(at + 1) % posts.published.length];
    const next = after && after !== p ? { ...after, number: numbers.get(after.slug) } : null;
    out[`blog/${p.slug}.html`] = postHtml(p, { origin, styles, script, foot, number: numbers.get(p.slug) || "Draft", next });
    if (p.approved) out[`blog/${p.slug}.md`] = postMarkdown(p, { origin });
  }
  return out;
}
