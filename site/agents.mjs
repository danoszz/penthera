/**
 * The site's files for agents and crawlers, built from the repo so they
 * cannot drift from it:
 *
 *   /llms.txt                    site/llms.txt with the build's placeholders filled in
 *   /llms-full.txt               README.md and the docs below, as one Markdown file
 *   /README.md, /docs/**.md      the same pages one by one, links made absolute
 *   /sitemap.xml                 the page, the landing and benchmark pages and every
 *                                file above, each with the date it last changed
 *   /robots.txt                  everyone allowed, pointing at the sitemap
 *   /.well-known/security.txt    RFC 9116, pointing at SECURITY.md
 *   /index.md, /openapi.json,    the homepage as Markdown, the live check's spec and
 *   /server.json                 the MCP Registry manifest (site/agent-ready.mjs)
 *
 * Every npm pin in a mirrored page (`penthera@1.2.3`) is rewritten to the
 * package's own version, so an agent that copies a command gets a version
 * that is published under the build's version. Links between mirrored pages
 * point at their mirrors; every other link points at the file on GitHub.
 */
import { frontMatterToHeading } from "./terms.mjs";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, posix } from "node:path";
import { agentReadyFiles, whenToUse } from "./agent-ready.mjs";
import { landingPages } from "./landing.mjs";
import { benchmarkViews, rankingList } from "./benchmarks.mjs";

export const REPO = "https://github.com/danoszz/penthera";

/** Docs pages that are about running the project, not about using Penthera. */
const SKIP = new Set(["docs/voice.md", "docs/marketing.md", "docs/internal-audit.md", "docs/mcp-listing.md"]);
const DIRS = ["docs", "docs/commands", "docs/use-cases", "docs/compare", "docs/mcp-clients"];
const MEDIA = /\.(png|jpe?g|gif|svg|mp4|webm|vtt)$/i;

/**
 * The pages to mirror, in reading order: README.md, docs/index.md, then the
 * pages in the order docs/index.md first links them, then the rest by path.
 * @returns {string[]} repo-relative paths
 */
export function docPages(root) {
  const all = new Set();
  for (const d of DIRS) {
    if (!existsSync(join(root, d))) continue;
    for (const f of readdirSync(join(root, d))) {
      const p = `${d}/${f}`;
      if (f.endsWith(".md") && statSync(join(root, p)).isFile() && !SKIP.has(p)) all.add(p);
    }
  }
  const order = ["README.md", "docs/index.md"];
  const index = readFileSync(join(root, "docs", "index.md"), "utf8");
  for (const m of index.matchAll(/\]\(([^)#\s]+\.md)(?:#[^)]*)?\)/g)) order.push(posix.normalize(posix.join("docs", m[1])));
  const seen = new Set();
  return [...order, ...[...all].sort()].filter((p) => (p === "README.md" || all.has(p)) && !seen.has(p) && seen.add(p));
}

/** Make a page's relative links absolute: to a mirror when there is one, else to GitHub. */
export function absoluteLinks(md, from, { root, origin, mirrored }) {
  const resolve = (target) => {
    if (/^([a-z][a-z0-9+.-]*:|#|\/)/i.test(target)) return target;
    const [path, hash = ""] = target.split(/(?=#)/);
    const abs = posix.normalize(posix.join(posix.dirname(from), path)).replace(/\/$/, "");
    if (abs.startsWith("..")) return target;
    if (mirrored.has(abs)) return `${origin}/${abs}${hash}`;
    if (MEDIA.test(abs)) return `${REPO}/raw/main/${abs}`;
    const dir = existsSync(join(root, abs)) && statSync(join(root, abs)).isDirectory();
    return `${REPO}/${dir ? "tree" : "blob"}/main/${abs}${hash}`;
  };
  return md
    .replace(/(\]\()([^)\s]+)(\))/g, (m, open, target, close) => open + resolve(target) + close)
    .replace(/(<(?:img|a|source|video)\b[^>]*?\b(?:src|href|poster)=")([^"]+)(")/g, (m, open, target, close) => open + resolve(target) + close);
}

/** Rewrite npm pins (`penthera@1.2.3`, not `owner/penthera@...`) to `version`. */
export const pinTo = (text, version) => text.replace(/(?<![\w/-])penthera@\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?/g, `penthera@${version}`);

/**
 * The date a file last changed in git (YYYY-MM-DD), for the sitemap's
 * <lastmod>; null outside a git checkout or for a file git does not track.
 */
export function lastChanged(root, file) {
  try {
    return execFileSync("git", ["log", "-1", "--format=%cs", "--", file], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || null;
  } catch {
    return null;
  }
}

/** The "Public benchmarks" block for llms.txt and llms-full.txt: one ranking per line. */
export function benchmarkBlock(pub, origin) {
  if (!pub?.benchmarks) return "";
  return `## Public benchmarks

Penthera against the free open-source tools on four public datasets, scored once on a sealed half of each (${pub.date}). Every tool, interval and limit: [${origin}/benchmarks](${origin}/benchmarks.md).

${rankingList(pub, origin, ".md")}

`;
}

/** The blog's approved posts for llms.txt, as Markdown links. */
const blogList = (posts, origin) => (posts.length ? `## Blog\n\n${posts.map((p) => `- [${p.title}](${origin}/blog/${p.slug}.md) (${p.date}): ${p.description}`).join("\n")}\n\nAtom feed: ${origin}/blog/feed.xml\n\n` : "");

/**
 * Every file for agents and crawlers.
 * @param {{ root: string, site: string, version: string, origin: string, values: Record<string,string>, pub?: object, posts?: object[], research?: object[], now?: Date }} o
 * @returns {Record<string, string>} site path (no leading slash) to content
 */
export function agentFiles({ root, site, version, origin, values, pub = null, posts = [], research = [], now = new Date() }) {
  const pages = docPages(root);
  const mirrored = new Set(pages);
  const out = {};
  const mirror = (p) => pinTo(absoluteLinks(frontMatterToHeading(readFileSync(join(root, p), "utf8")), p, { root, origin, mirrored }), version).trimEnd() + "\n";

  for (const p of pages) {
    out[p] = `<!-- ${origin}/${p}: a copy of ${REPO}/blob/main/${p}, built from Penthera ${version}. -->\n\n${mirror(p)}`;
  }

  out["llms-full.txt"] = [
    "# Penthera: the full documentation",
    "",
    `> Penthera ${version}. README.md and the user documentation from ${REPO}, as one Markdown file. Each page is also at its own URL, listed in ${origin}/llms.txt. Only scan targets you own or are authorized to test.`,
    "",
    benchmarkBlock(pub, origin).trimEnd(),
    "",
    ...pages.flatMap((p) => ["", "---", "", `<!-- Source: ${REPO}/blob/main/${p} · ${origin}/${p} -->`, "", mirror(p)]),
  ].join("\n").replace(/\n{3,}/g, "\n\n");

  // llms.txt: the template, plus when to reach for Penthera (before the docs),
  // the landing pages (after them) and the live check's spec (with the other
  // machine-readable files).
  // An unlisted page keeps its URL, and stays out of every list.
  const landing = landingPages(site).filter((p) => !p.unlisted);
  // /contact is a landing page for the build, but it is no question for the check.
  const asked = landing.filter((p) => p.slug !== "contact");
  const questions = asked.length ? `## Questions the live check answers\n\n${asked.map((p) => (p.slug === "research-e20" ? `- [State of the Web 2026](${origin}/${p.slug}.md): what the study's crawler, User-Agent Penthera-Research/E20, requests from a homepage, and how to opt out or be removed. Published as totals.` : `- [${p.h1}](${origin}/${p.slug}.md): ${p.description}`)).join("\n")}\n\n` : "";
  out["llms.txt"] = fill(readFileSync(join(site, "llms.txt"), "utf8"), { ...values, ORIGIN: origin }, "llms.txt")
    .replace(/^## Docs$/m, (m) => `${benchmarkBlock(pub, origin)}${whenToUse({ version, origin })}\n${m}`)
    .replace(/^## Trust$/m, (m) => `${questions}${blogList(posts, origin)}${m}`)
    .replace(/^## Machine-readable\n\n/m, (m) => `${m}- [OpenAPI for the live check](${origin}/openapi.json): POST /api/check, a public site's passive security report\n`);
  Object.assign(out, agentReadyFiles({ root, version, origin, values, pub }));

  // /terms, the live check's terms: build.mjs renders it from this file.
  const terms = existsSync(join(root, "docs", "live-check-terms.md")) ? ["terms"] : [];
  // Each URL with the file it is built from, for <lastmod>; the benchmark
  // pages change when published.json does, on the date it records.
  const bench = pub?.benchmarks ? benchmarkViews(pub).map((v) => [`benchmarks/${v.c.slug}`, pub.date]) : [];
  const urls = [
    ["", "site/index.html"], ["index.md", "site/agent-ready.mjs"], ...terms.map((t) => [t, "docs/live-check-terms.md"]),
    ...(existsSync(join(root, "docs", "trust.md")) ? [["trust", "docs/trust.md"]] : []),
    ["type", "site/type.mjs"],
    ...(bench.length ? [["benchmarks", pub.date], ...bench] : []),
    // /research is dated by its newest entry.
    ...(research.length ? [["research", research.find((e) => e.date)?.date || "site/research.mjs"], ["news", research.find((e) => e.date)?.date || "site/news.mjs"]] : []),
    ...landing.map((p) => [p.slug, `site/pages/${p.slug}.md`]),
    // Approved posts only: a draft is never built, so never listed.
    ...(posts.length ? [["blog", posts[0].date], ...posts.map((p) => [`blog/${p.slug}`, p.date])] : []),
    ["llms.txt", "site/llms.txt"], ["llms-full.txt", null], ["openapi.json", null], ["server.json", "server.json"], ...pages.map((p) => [p, p]),
  ];
  const lastmod = (src) => (src == null ? null : /^\d{4}-\d{2}-\d{2}$/.test(src) ? src : lastChanged(root, src));
  out["sitemap.xml"] = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.map(([u, src]) => {
    const d = lastmod(src);
    return `  <url><loc>${origin}/${u}</loc>${d ? `<lastmod>${d}</lastmod>` : ""}</url>`;
  }).join("\n")}\n</urlset>\n`;

  out["robots.txt"] = [
    "# penthera.org is a static page and the files listed in the sitemap. All of it is public;",
    "# crawlers, search engines and AI agents are welcome. For agents: /llms.txt.",
    "User-agent: *",
    "Allow: /",
    "",
    `Sitemap: ${origin}/sitemap.xml`,
    "",
  ].join("\n");

  // RFC 9116: Expires must be less than a year away; a deploy refreshes it.
  const expires = new Date(now.getTime() + 300 * 86_400_000);
  expires.setUTCHours(0, 0, 0, 0);
  out[".well-known/security.txt"] = [
    "# Report a vulnerability in Penthera itself (not a finding Penthera reported) privately,",
    "# through a GitHub security advisory. The policy says what to expect.",
    `Contact: ${REPO}/security/advisories/new`,
    `Expires: ${expires.toISOString().replace(".000", "")}`,
    `Policy: ${REPO}/blob/main/SECURITY.md`,
    "Preferred-Languages: en",
    `Canonical: ${origin}/.well-known/security.txt`,
    "",
  ].join("\n");
  return out;
}

/** Fill {{NAME}} placeholders; an unknown one is a build error. */
export function fill(text, values, file) {
  return text.replace(/\{\{(\w+)\}\}/g, (m, k) => {
    if (!(k in values)) throw new Error(`${file}: unknown placeholder ${m}`);
    return values[k];
  });
}
