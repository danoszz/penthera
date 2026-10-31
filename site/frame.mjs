/**
 * Pieces every generated page shares: the JSON-LD data block and the footer.
 *
 * The footer is one piece for every page, the homepage included (2026-10-29).
 * Its map is built from what the build knows: the landing pages in
 * site/pages/, the benchmark pages, the approved blog posts and /research.
 * A new page appears in it without an edit here, and tests/site-footer.test.js
 * fails if a built page is missing from it. Drafts never appear, so no page
 * links an unapproved post or an empty /blog.
 */

const REPO = "https://github.com/danoszz/penthera";
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** A JSON-LD data block; "<" escaped so no value can close the element. */
export const ldScript = (graph) => `<script type="application/ld+json">${JSON.stringify({ "@context": "https://schema.org", "@graph": graph }).replace(/</g, "\\u003c")}</script>`;

/**
 * The footer's map, in four groups, with each benchmark and post set in under
 * its parent. A page's footer label is its `nav`, kept short enough to stay on
 * one line (tests/site-footer.test.js), or its title.
 * @param {{ pages?: {slug: string, h1: string, nav?: string, eyebrow?: string}[],
 *   benchmarks?: {slug: string, label: string, nav?: string}[], posts?: {slug: string, title: string, nav?: string}[] }} known
 *   what the build rendered: landing pages, benchmark pages, approved posts
 * @returns {{ id: string, label: string, links: {href: string, text: string, sub?: boolean, rel?: string, track?: string}[] }[]}
 */
export function footGroups({ pages = [], benchmarks = [], posts = [] } = {}) {
  // The study page's source is frozen by its protocol, so its public name lives here.
  const page = (p) => ({ href: `/${p.slug}`, text: p.slug === "research-e20" ? "State of the Web" : p.nav || p.h1 });
  const research = pages.filter((p) => p.eyebrow === "Research");
  const contact = pages.filter((p) => p.slug === "contact");
  const product = pages.filter((p) => p.eyebrow !== "Research" && p.slug !== "contact");
  return [
    { id: "product", label: "Product", links: [
      { href: "/#scan", text: "Live check" },
      ...product.map(page),
      { href: "https://www.npmjs.com/package/penthera", text: "npm package" },
      { href: REPO, text: "GitHub" },
    ] },
    { id: "research", label: "Research", links: [
      { href: "/news", text: "News" },
      { href: "/research", text: "Research" },
      ...research.map(page),
      { href: "/benchmarks", text: "Benchmarks" },
      ...benchmarks.map((b) => ({ href: `/benchmarks/${b.slug}`, text: b.nav || b.label, sub: true })),
      ...(posts.length ? [{ href: "/blog", text: "Blog" }, ...posts.map((p) => ({ href: `/blog/${p.slug}`, text: p.nav || p.title, sub: true }))] : []),
      { href: `${REPO}/blob/main/docs/METHODOLOGY.md`, text: "Methodology" },
      { href: `${REPO}/blob/main/docs/references.md`, text: "References" },
    ] },
    { id: "trust", label: "Trust", links: [
      { href: "/trust", text: "Trust" },
      { href: "/terms", text: "Terms" },
      { href: "/type", text: "Type system" },
      ...contact.map(page),
      { href: `${REPO}/blob/main/docs/privacy.md`, text: "Privacy and network use" },
      { href: "/.well-known/security.txt", text: "security.txt" },
      { href: "/llms.txt", text: "llms.txt" },
      { href: `${REPO}/tree/main/site`, text: "Source of this page" },
    ] },
    { id: "elsewhere", label: "Elsewhere", links: [
      { href: "https://x.com/penthera_org", text: "@penthera_org on X", rel: "me", track: "x-footer" },
      { href: `${REPO}/discussions`, text: "GitHub Discussions" },
      { href: `${REPO}/issues`, text: "Issues" },
    ] },
  ];
}

/**
 * Real quotation marks, apostrophes and ellipses in the text of a page. The
 * build runs every page through it, so copy can be typed plainly. Code, scripts
 * and the head stay as typed: a command must still paste.
 */
export function smart(html) {
  let last = " ";
  return html.split(/(<head[\s\S]*?<\/head>|<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>|<textarea[\s\S]*?<\/textarea>|<pre\b[\s\S]*?<\/pre>|<code\b[\s\S]*?<\/code>|<kbd\b[\s\S]*?<\/kbd>|<samp\b[\s\S]*?<\/samp>|<[^>]+>)/).map((part, i) => {
    if (i % 2) {
      if (/^<(code|pre|kbd|samp)\b/.test(part)) last = "x";
      else if (/^<\/?(p|li|h\d|div|td|th|dd|dt|figcaption|figure|section|button|summary)\b/.test(part)) last = " ";
      return part;
    }
    const out = part.replace(/&#39;|&quot;|'|"|(?<!\.)\.\.\.(?!\.)/g, (m, at, text) => {
      if (m === "...") return "…";
      const before = at ? text[at - 1] : last;
      const opens = /[\s([–—]/.test(before);
      if (m === "&quot;" || m === '"') return opens ? "“" : "”";
      return opens && !/\d/.test(text[at + m.length] || "") ? "‘" : "’";
    });
    if (part) last = part[part.length - 1];
    return out;
  }).join("");
}

/**
 * A reading page's body: contents in the margin, the text in the reading
 * column. Articles, terms, trust and landing pages share it, so text sits in
 * the same place everywhere. site/blog.js marks the section being read. The
 * "who is this page for" line stays in the Markdown copy, for agents and
 * contributors; a reader on the page doesn't need it unless `question` is set.
 */
export function reading(page, { question = false } = {}) {
  const html = question ? page : page.replace(/^\s*<p class="terms-for">.*?<\/p>\n?/, "");
  const sections = [...html.matchAll(/<h2 id="([^"]+)">(.*?)<\/h2>/g)].map(([, id, text]) => `<li><a href="#${id}">${text}</a></li>`);
  const toc = sections.length > 2 ? `<nav class="paper-toc" aria-label="On this page"><ol>${sections.join("")}</ol></nav>` : "";
  return `    <aside class="paper-side" aria-label="On this page">${toc}</aside>
    <div class="paper-body">
${html}
    </div>`;
}

/**
 * Stickers: every tag and eyebrow gets a finish, a cut and now and then a small
 * tilt from the page and its place on it, so a page never changes between
 * builds. A tag that already has a finish keeps it: a category always looks the
 * same. The picks are data attributes; styles.css draws them.
 */
export function stickers(html, seed = "") {
  const TILT = [0, 0, 1, 0, 0, 2, 0];
  let n = [...seed].reduce((h, c) => (h * 31 + c.charCodeAt(0)) % 9973, 7);
  return html.replace(/<(\w+) class="((?:[^"]*\s)?(?:tag|eyebrow|sticker)(?:\s[^"]*)?)"(?! data-f)/g, (m, el, cls) => {
    if (/ttx-crumbs/.test(cls)) return m;
    n += 1;
    return `${m} data-f="${(n * 3) % 5}" data-c="${n % 3 ? 0 : 1}" data-t="${TILT[n % 7]}"`;
  });
}

const STAR = '<svg class="star-glyph" viewBox="0 0 9 9" aria-hidden="true"><path d="M4 0h1v2h1v1h3v1H8v1H7v1h1v3H7V8H6V7H3v1H2v1H1V6h1V5H1V4H0V3h3V2h1z"/></svg>';
const DOWN = '<svg class="download-glyph" viewBox="0 0 9 10" aria-hidden="true"><path d="M4 0h1v6h1V5h1V4h1v1H7v1H6v1H5v1H4V7H3V6H2V5H1V4h1v1h1v1h1zM0 9h9v1H0z"/></svg>';

/** The dock's destinations, and the first path segment each one owns. */
const RAIL = [
  { text: "Research", href: "/research", match: "research" },
  { text: "Benchmarks", href: "/benchmarks", match: "benchmarks" },
  { text: "Blog", href: "/blog", match: "blog" },
];

/**
 * The navigation of every page: a steel dock fixed to the bottom of the window.
 * The build puts it before <main> on each page it renders (site/build.mjs), so
 * a new page gets it without an edit. It never moves. Its star and download
 * sit inside the plate: on the homepage the plate opens for them once the
 * hero has scrolled away (data-hero, cleared by check/ui.js), so they stay on
 * screen if no script runs.
 * @param {{ url?: string, stars?: string, blog?: boolean }} opts
 *   url: the page's path; stars: the GitHub count; blog: false drops Blog while no post is approved
 */
export function siteRail({ url = "/", stars = "", blog = true, header = process.env.PENTHERA_NAV_H || "1" } = {}) {
  const home = url === "/";
  const seg = url.split("/")[1] || "";
  // News takes the Blog slot, current on /blog too.
  const rail = RAIL.map((r) => (r.match === "blog" ? { text: "News", href: "/news", match: "news" } : r));
  const links = rail.filter((r) => blog || r.match !== "blog").map((r) => {
    const on = seg === r.match || (r.match === "research" && seg.startsWith("research-")) || (r.match === "news" && seg === "blog");
    return `<a href="${r.href}"${on ? ` aria-current="${url === r.href ? "page" : "true"}"` : ""}>${r.text}</a>`;
  }).join("");
  return `<nav class="rail"${home ? " data-hero" : ""} data-head="${header}" aria-label="Main">
    <a class="rail-mark" href="/"><span aria-hidden="true"></span><span class="sr">Penthera, home</span></a>
    <div class="rail-links">${links}</div>
    <div class="rail-more"><div class="rail-more-in">
      <a class="rail-star" href="${REPO}" data-track="github-star-dock" aria-label="Star Penthera on GitHub${stars ? `, ${esc(stars)} stars` : ""}">
        ${STAR}
        <span class="star-word">Star</span><span class="star-count">${esc(stars)}</span>
      </a>
      <a class="rail-download" href="${home ? "#get" : "/#get"}" data-track="download-dock">
        ${DOWN}
        <span>Install</span>
      </a>
    </div></div>
  </nav>`;
}

const link = (l) => `<li${l.sub ? ' class="foot-sub"' : ""}><a href="${esc(l.href)}"${l.rel ? ` rel="${l.rel}"` : ""}${l.track ? ` data-track="${l.track}"` : ""}>${esc(l.text)}</a></li>`;

/**
 * The footer of every page. Outside <main>, after it.
 * @param {{ groups?: ReturnType<typeof footGroups>, version?: string, stars?: string, home?: boolean }} opts
 *   home: on the homepage the Install button goes to #get on the same page
 */
export function siteFooter({ groups = footGroups(), version = "", stars = "", home = false } = {}) {
  const nav = groups.map((g) => `<div class="foot-group">
        <p class="foot-k" id="foot-${g.id}">${esc(g.label)}</p>
        <ul aria-labelledby="foot-${g.id}">
          ${g.links.map(link).join("\n          ")}
        </ul>
      </div>`).join("\n      ");
  return `<footer class="foot">
    <div class="foot-head">
      <p class="foot-status"><span class="foot-led" aria-hidden="true"></span>Built from Penthera${version ? ` ${esc(version)}` : ""}. Code scans run offline. Rules decide.</p>
      <div class="foot-ctas">
        <button class="theme glass" type="button" role="switch" aria-checked="true" aria-label="Dark theme" data-theme-toggle hidden>
          <span class="theme-track" aria-hidden="true"><span class="theme-knob"></span></span>
        </button>
        <a class="star glass" href="${REPO}" data-track="github-star-bottom" aria-label="Star Penthera on GitHub${stars ? `, ${esc(stars)} stars` : ""}">
          ${STAR}
          <span class="star-word">Star</span><span class="star-count">${esc(stars)}</span>
        </a>
        <a class="download glass" href="${home ? "#get" : "/#get"}">
          ${DOWN}
          <span>Install</span>
        </a>
      </div>
    </div>
    <nav class="foot-nav" aria-label="Site map">
      ${nav}
    </nav>
    <div class="foot-field" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div>
    <a class="foot-mark" href="#main"><span class="foot-word" aria-hidden="true"></span><span class="sr">Penthera, back to the top</span></a>
    <p class="foot-facts"><span>MIT license</span><span>Scan only what you own or are authorized to test</span><span>No cookies, no third-party requests, anonymous page views only</span></p>
  </footer>`;
}
