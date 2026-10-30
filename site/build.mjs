#!/usr/bin/env node
/**
 * Build the static site into site/dist.
 *
 *   node site/build.mjs [--out <dir>]
 *
 * The browser check (site/check) is bundled with the lib/ modules it imports,
 * so the rules that run in the page are the rules in this checkout. Node
 * built-ins resolve to the small shims in site/check/shims; the rule packs and
 * popular-package lists are embedded and mounted in an in-memory folder.
 * Each pack's signature is verified here, with the real lib/rules/sshsig.js,
 * because the browser cannot do it synchronously.
 *
 * One network request: the GitHub star count for the nav button, read once at
 * build time (the page itself cannot fetch). PENTHERA_SITE_STARS=<n> sets it,
 * PENTHERA_SITE_STARS=off skips it, and a failed request falls back to the
 * last count read (site/stars.json). No server code. Output: plain files for
 * any static host.
 */
import { cpSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { build } from "rolldown";
import { bundledPackDirs, activePacks, loadSigners, NAMESPACE } from "../lib/rules/index.js";
import { verifyWithSigners } from "../lib/rules/sshsig.js";
import { COUNTS } from "../scripts/docs-numbers.mjs";
import { agentFiles, docPages, fill, REPO } from "./agents.mjs";
import { jsonLd } from "./agent-ready.mjs";
import { landingPages, landingHtml, landingMarkdown } from "./landing.mjs";
import { termsPage, docPage } from "./terms.mjs";
import { publicBenchHtml } from "./public-bench.mjs";
import { readPosts, blogFiles } from "./blog.mjs";
import { siteFooter, siteRail, smart, stickers, footGroups } from "./frame.mjs";
import { benchmarkHtml, benchmarkMarkdown, benchmarkViews, cardFor, fieldTools, hubHtml, hubMarkdown } from "./benchmarks.mjs";
import { cardRows, rowTag } from "./check/card.js";
import { researchEntries, researchHtml, researchMarkdown } from "./research.mjs";

const SITE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(SITE, "..");
const SHIMS = join(SITE, "check", "shims");
const posix = (p) => p.split(sep).join("/");

// ── What lib/ reads from disk, embedded ─────────────────────────────────────

function embeddedFiles() {
  const files = {};
  const add = (abs, as = `/penthera/${posix(relative(ROOT, abs))}`) => {
    const buf = readFileSync(abs);
    files[as] = abs.endsWith(".gz") ? { b64: buf.toString("base64") } : { text: buf.toString("utf8") };
  };
  for (const dir of bundledPackDirs()) for (const f of readdirSync(dir)) add(join(dir, f));
  add(join(ROOT, "lib", "rules", "allowed_signers"));
  add(join(ROOT, "lib", "deps", "popular-packages.json.gz"));
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  files["/penthera/package.json"] = { text: JSON.stringify({ name: pkg.name, version: pkg.version }) };
  return { files, version: pkg.version };
}

function signatures() {
  const out = {};
  const signers = loadSigners();
  for (const dir of bundledPackDirs()) {
    const sigPath = join(dir, "pack.json.sig");
    if (!existsSync(sigPath)) continue;
    const sig = readFileSync(sigPath, "utf8");
    const v = verifyWithSigners(readFileSync(join(dir, "pack.json")), sig, NAMESPACE, signers);
    if (!v.ok) throw new Error(`${posix(relative(ROOT, dir))}: pack.json.sig does not verify (${v.reason}); refusing to build`);
    out[sig.trim()] = { ok: true, principal: v.principal };
  }
  return out;
}

/** The "Load an example" files: the malicious agents fixture the test suite uses. */
function examples() {
  const dir = join(ROOT, "tests", "fixtures", "agents", "malicious");
  return [".mcp.json", ".claude/settings.json", "AGENTS.md"].map((p) => ({ path: p, text: readFileSync(join(dir, p), "utf8") }));
}

// ── Bundle ──────────────────────────────────────────────────────────────────

function sitePlugin({ files, version, sigs }) {
  const NODE = { fs: "fs.js", path: "path.js", os: "os.js", crypto: "crypto.js", zlib: "zlib.js", url: "url.js", buffer: "buffer.js" };
  const SSHSIG = join(ROOT, "lib", "rules", "sshsig.js");
  const virtual = {
    "virtual:assets": `export const FILES = ${JSON.stringify(files)};\nexport const BUILD = ${JSON.stringify({ version })};`,
    "virtual:signatures": `export const SIGNATURES = ${JSON.stringify(sigs)};`,
    "virtual:examples": `export const EXAMPLES = ${JSON.stringify(examples())};`,
  };
  return {
    name: "penthera-site",
    resolveId(source, importer) {
      if (source in virtual) return `\0${source}`;
      const node = source.replace(/^node:/, "");
      if (source.startsWith("node:") || (importer && NODE[node] && !source.startsWith("."))) {
        if (!NODE[node]) throw new Error(`${importer} imports ${source}, which the browser check has no shim for`);
        return join(SHIMS, NODE[node]);
      }
      if (importer && source.startsWith(".") && resolve(dirname(importer), source) === SSHSIG) return join(SHIMS, "sshsig.js");
      return null;
    },
    load(id) {
      if (id.startsWith("\0virtual:")) return virtual[id.slice(1)];
      return null;
    },
    // lib/ finds its data next to itself (new URL("./x.gz", import.meta.url)).
    // Point each module at its own place in the mounted /penthera tree.
    transform(code, id) {
      if (!id.startsWith(join(ROOT, "lib") + sep) || !code.includes("import.meta.url")) return null;
      return code.replaceAll("import.meta.url", JSON.stringify(`file:///penthera/${posix(relative(ROOT, id))}`));
    },
  };
}


/** Rule counts and runtime dependencies, from the same source as the README (scripts/docs-numbers.mjs). */
function ruleNumbers() {
  const deps = Object.keys(JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).dependencies || {});
  return {
    N_URL: String(COUNTS.urlTemplates), N_SECRETS: String(COUNTS.secretPatterns), N_CAPS: String(COUNTS.capabilities),
    N_AGENTS: String(COUNTS.agentRules), N_RECIPES: String(COUNTS.recipes),
    DEPS_N: deps.length === 1 ? "one runtime dependency" : `${deps.length} runtime dependencies`,
    DEPS_LIST: deps.join(", "),
  };
}

/**
 * The before/after example: a real scan of the test server, from
 * site/example.json (written by site/tools/example.mjs), and the rule counts
 * behind it. Fix recipes are not counted as rules.
 */
export function exampleValues(packRules) {
  const e = JSON.parse(readFileSync(join(SITE, "example.json"), "utf8"));
  const f = e.finding, u = new URL(f.url);
  const sum = ["critical", "high", "medium", "low"].filter((s) => e.counts[s]).map((s) => `<span class="nowrap">${e.counts[s]} ${s}</span>`);
  const rules = COUNTS.urlTemplates + COUNTS.secretPatterns + COUNTS.capabilities + COUNTS.agentRules + packRules;
  return {
    EX_CMD: esc(e.command), EX_SUM: sum.join(" · "), EX_INFO: String(e.counts.info),
    EX_CHECKS: String(e.checks), EX_REQ: String(e.requests), EX_HOST: esc(u.hostname),
    EX_SEV: f.severity.toUpperCase(), EX_TITLE: esc(f.title), EX_DESC: esc(f.description), EX_CONF: esc(f.confidence),
    EX_EVIDENCE: esc(`GET ${decodeURIComponent(u.pathname + u.search)}`), EX_STATUS: String(f.status),
    RULES_ALL: String(rules), REFS: String(COUNTS.references),
    PKGS: (COUNTS.popularNpm + COUNTS.popularPypi).toLocaleString("en-US"),
  };
}

/**
 * The hero's example result: the live check's own passive report
 * (api/_lib/tier1.mjs), run at build time against the test server in
 * tests/fixtures/mock-server.js on loopback. Nothing leaves the machine: the
 * host is an IP address, so no DNS is asked. The random port is shown as
 * 8765, the port the other examples use.
 */
export async function exampleCheck() {
  const { startMockServer } = await import("../tests/fixtures/mock-server.js");
  const { passiveReport } = await import("../api/_lib/tier1.mjs");
  const server = await startMockServer(0);
  try {
    const r = await passiveReport(new URL(server.url), { allowPrivate: true, anyPort: true, typed: server.url, timeout: 5000 });
    const port = (s) => String(s).replaceAll(`127.0.0.1:${server.port}`, "127.0.0.1:8765");
    return JSON.parse(port(JSON.stringify(r)));
  } finally {
    await server.close();
  }
}

/** The metal example card: the markup ui.js renders for your result, labelled Example. */
export function exampleCardHtml(report) {
  // Three rows and no button: the scan form is the one action on the screen.
  const rows = cardRows(report, { withPassed: true }).slice(0, 3);
  const meter = Array.from({ length: 100 }, (_, i) => (i < report.score ? '<i class="on"></i>' : "<i></i>")).join("");
  return `<section class="card card-example" aria-labelledby="example-title">
          <div class="card-top"><span class="card-label" id="example-title">Example</span><span class="card-host">real output<span class="card-wide"> · test server</span></span></div>
          <p class="card-verdict">${esc(report.verdict)}</p>
          <div class="card-score"><div class="meter" role="img" aria-label="${report.score} out of 100">${meter}</div><p class="score-n">${report.score}<span>/100</span></p></div>
          <ul class="card-rows">
${rows.map((c) => `            <li${c.passed ? ' class="ok"' : ""}><span class="card-tag">${esc(rowTag(c))}</span>${esc(c.title)}</li>`).join("\n")}
          </ul>
        </section>`;
}

/** Wilson score interval, 95%, as README and bench/ report it. */
function wilson(k, n, z = 1.96) {
  const p = k / n;
  const d = 1 + z * z / n;
  const c = (p + z * z / (2 * n)) / d;
  const h = (z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d;
  return `${Math.max(0, c - h).toFixed(2)} to ${Math.min(1, c + h).toFixed(2)}`;
}

const KNOWN_VULN = join(ROOT, "bench", "known-vuln");

/**
 * Pooled precision of a scorer report's standard run: findings that match the
 * answer key or were labelled correct, over every labelled finding (cannot-tell
 * counts as incorrect), as bench/known-vuln/score.mjs computes it.
 */
function e10Precision(file) {
  const md = readFileSync(file, "utf8");
  const run = md.slice(md.indexOf("Run `standard`"));
  const line = run.split("\n").find((l) => l.startsWith("| **Pooled** |"));
  if (!line) throw new Error(`E10: no pooled standard row in ${file}`);
  const [, matched, correct, incorrect] = line.split("|").slice(2, 6).map((c) => +c.trim());
  const k = matched + correct, n = k + incorrect;
  return { k, n, rate: k / n, ci: wilson(k, n) };
}

/**
 * The E10 pilot, before and after the recall fixes, from
 * bench/known-vuln/RESULTS-after-fixes.md ("Before and after" table and the
 * held-out WebGoat line) and the pooled rows of the two scorer reports. Only
 * counts are read; rates and Wilson intervals are computed here, and
 * tests/site.test.js checks them against what the files state.
 * @returns {{ apps: object[], pooled: object, precision: object, heldOut: object }}
 */
export function e10Numbers(dir = KNOWN_VULN) {
  const file = join(dir, "RESULTS-after-fixes.md");
  const md = readFileSync(file, "utf8");
  const table = md.slice(md.indexOf("## Before and after"));
  const kn = (s) => { const m = /(\d+)\/(\d+)/.exec(s); if (!m) throw new Error(`E10: no k/n in "${s}"`); return { k: +m[1], n: +m[2] }; };
  const pair = (label) => {
    const line = table.split("\n").find((l) => l.startsWith(`| ${label} |`));
    if (!line) throw new Error(`E10: no "${label}" row in ${file}`);
    const [b, a] = line.split("|").slice(2, 4).map((c) => kn(c));
    return { before: { ...b, rate: b.k / b.n, ci: wilson(b.k, b.n) }, after: { ...a, rate: a.k / a.n, ci: wilson(a.k, a.n) } };
  };
  const held = /Held-out check: WebGoat[\s\S]*?\*\*(\d+)\/(\d+),[^*]*\*\* both times/.exec(md);
  if (!held) throw new Error(`E10: no held-out WebGoat result in ${file}`);
  const hk = +held[1], hn = +held[2];
  return {
    apps: [
      { id: "juice-shop", name: "OWASP Juice Shop", ...pair("juice-shop") },
      { id: "dvna", name: "DVNA", ...pair("dvna") },
    ],
    pooled: pair("**Pooled recall**"),
    precision: { before: e10Precision(join(dir, "RESULTS.md")), after: e10Precision(file) },
    heldOut: { name: "WebGoat", k: hk, n: hn, rate: hk / hn, ci: wilson(hk, hn) },
  };
}

/**
 * The before/after bars, one row per app. Names and numbers are HTML text; the
 * SVG only draws (the CSP forbids inline styles, so widths are attributes).
 */
function e10Bars(e) {
  const rows = [...e.apps, { name: "Both apps", ...e.pooled }];
  const ci = (s) => s.split(" to ").map((x) => (Number(x) * 100).toFixed(1));
  // Each slot is 12 units tall: the bar fills the middle 8, the interval's
  // caps run the full 12 so they stay visible past the bar's edges.
  const bar = (y, r, cls) => {
    const [lo, hi] = ci(r.ci), mid = y + 6;
    return `<rect class="${cls}" x="0" y="${y + 2}" width="${Math.max(0.6, r.rate * 100).toFixed(1)}" height="8"/>`
      + `<path class="e10-ci" d="M${lo} ${mid}H${hi}M${lo} ${y}V${y + 12}M${hi} ${y}V${y + 12}"/>`;
  };
  return rows.map((r) => `<div class="e10-row"><span class="e10-name">${esc(r.name)}</span>`
    + `<svg class="e10-bar" viewBox="0 0 100 26" preserveAspectRatio="none" aria-hidden="true">${bar(0, r.before, "e10-before")}${bar(14, r.after, "e10-after")}</svg>`
    + `<span class="e10-nums">${r.before.k}/${r.before.n} <span aria-hidden="true">→</span><span class="sr"> to </span> ${r.after.k}/${r.after.n}</span></div>`).join("\n");
}

function e10Values() {
  const e = e10Numbers();
  const r = (x) => x.toFixed(2);
  const v = {};
  for (const a of e.apps) {
    const key = a.id === "juice-shop" ? "JS" : "DV";
    Object.assign(v, {
      [`E10_${key}_B`]: `${a.before.k}/${a.before.n}`, [`E10_${key}_A`]: `${a.after.k}/${a.after.n}`,
      [`E10_${key}_B_R`]: r(a.before.rate), [`E10_${key}_B_CI`]: a.before.ci,
      [`E10_${key}_A_R`]: r(a.after.rate), [`E10_${key}_A_CI`]: a.after.ci,
    });
  }
  const p = e.pooled, pr = e.precision, w = e.heldOut;
  Object.assign(v, {
    E10_P_B: `${p.before.k}/${p.before.n}`, E10_P_A: `${p.after.k}/${p.after.n}`,
    E10_P_B_OF: `${p.before.k} of ${p.before.n}`, E10_P_A_OF: `${p.after.k} of ${p.after.n}`,
    E10_P_B_R: r(p.before.rate), E10_P_B_CI: p.before.ci, E10_P_A_R: r(p.after.rate), E10_P_A_CI: p.after.ci,
    E10_PR_B: r(pr.before.rate), E10_PR_B_CI: pr.before.ci, E10_PR_B_N: String(pr.before.n),
    E10_PR_A: r(pr.after.rate), E10_PR_A_CI: pr.after.ci, E10_PR_A_N: String(pr.after.n),
    E10_WG: `${w.k}/${w.n}`, E10_WG_R: r(w.rate), E10_WG_CI: w.ci,
    E10_BARS: e10Bars(e),
  });
  return v;
}

/** The benchmark's Total row from bench/RESULTS.md (generated by npm run bench). */
function benchNumbers() {
  const row = readFileSync(join(ROOT, "bench", "RESULTS.md"), "utf8").match(/^\| \*\*Total\*\* \|[^|]*\| \*\*(\d+)\*\* \| \*\*(\d+)\*\* \| \*\*(\d+)\*\* \|/m);
  if (!row) throw new Error("bench/RESULTS.md: no Total row; run npm run bench");
  const [tp, fp, fn] = row.slice(1).map(Number);
  return {
    BENCH_P: (tp / (tp + fp)).toFixed(2), BENCH_P_CI: wilson(tp, tp + fp),
    BENCH_R: (tp / (tp + fn)).toFixed(2), BENCH_R_CI: wilson(tp, tp + fn),
    BENCH_N: String(tp + fp),
    BENCH_TP: String(tp), BENCH_FP: String(fp), BENCH_FN: String(fn),
    BENCH_EGRESS: (readFileSync(join(ROOT, "bench", "RESULTS.md"), "utf8").match(/Requests to non-loopback hosts: \*\*(\d+)\*\*/) || [])[1] ?? "not reported",
  };
}

const REPO_BLOB = "https://github.com/danoszz/penthera/blob/main/";
/** The production origin, from package.json: sitemap, robots.txt, security.txt and the doc mirrors use it. */
const ORIGIN = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).homepage.replace(/\/+$/, "");

/** site/compare.json, parsed and checked: every filled cell has a source. */
export function readCompare(file = join(SITE, "compare.json")) {
  const c = JSON.parse(readFileSync(file, "utf8"));
  for (const r of c.rows) {
    for (const t of c.tools) {
      const cell = r.cells[t.id];
      if (!cell) throw new Error(`compare.json: "${r.label}" has no cell for ${t.id}`);
      if (cell.t && !cell.s.length) throw new Error(`compare.json: "${r.label}" / ${t.id} has no source`);
    }
  }
  return c;
}

/**
 * The comparison table. A source in the repo links to its file on GitHub and
 * is named by its file; a vendor source is named by its host.
 */
function compareTable(c, values) {
  const url = (s) => (/^https:\/\//.test(s) ? s : REPO_BLOB + s);
  const name = (s) => (/^https:\/\//.test(s) ? new URL(s).hostname.replace(/^(www|docs)\./, "") : s.split("#")[0].split("/").pop());
  const fill = (t) => t.replace(/\{\{(\w+)\}\}/g, (m, k) => { if (!(k in values)) throw new Error(`compare.json: unknown placeholder ${m}`); return values[k]; });
  const head = c.tools.map((t) => `<th scope="col"><a href="${REPO_BLOB}${t.page}">${esc(t.name)}</a>`
    + (t.checked ? `<span class="cmp-date">checked ${t.checked}</span>` : "") + "</th>").join("");
  const body = c.rows.map((r) => `<tr><th scope="row">${esc(r.label)}</th>` + c.tools.map((t) => {
    const cell = r.cells[t.id];
    if (!cell.t) return `<td class="cmp-none"><span aria-hidden="true">—</span><span class="sr">Not covered on our compare page</span></td>`;
    const src = cell.s.map((s) => `<a href="${esc(url(s))}">${esc(name(s))}</a>`).join(", ");
    return `<td><p>${esc(fill(cell.t))} <span class="cmp-src">Source: ${src}</span></p></td>`;
  }).join("") + "</tr>").join("\n");
  return `<table class="cmp"><thead><tr><th scope="col"><span class="sr">Question</span></th>${head}</tr></thead>\n<tbody>\n${body}\n</tbody></table>`;
}

/** The short version above the table: each tool and where it goes further, from the same sourced row. */
function compareSummary(c, values) {
  const row = c.rows.find((r) => r.label === "Where it goes further");
  const fill = (t) => t.replace(/\{\{(\w+)\}\}/g, (m, k) => values[k] ?? m);
  const items = c.tools.map((t) => `<li><a href="${REPO_BLOB}${t.page}">${esc(t.name)}</a><span>${esc(fill(row.cells[t.id].t))}</span></li>`).join("\n");
  return `<ul class="cmp-sum">\n${items}\n</ul>`;
}

const STARS_FILE = join(SITE, "stars.json");

/**
 * GitHub stars for the nav button, formatted (49, 1.2k). Order: the
 * PENTHERA_SITE_STARS override, a live API read (authenticated with
 * GITHUB_TOKEN when set, as the anonymous limit is 60 an hour), then the last
 * count that was read, kept in site/stars.json so a rate limit or an offline
 * build still shows a number. "" only when no count was ever read.
 */
async function starCount() {
  const env = process.env.PENTHERA_SITE_STARS;
  if (env === "off") return "";
  let n = env ? Number(env) : null;
  if (n == null) {
    try {
      const headers = { accept: "application/vnd.github+json", "user-agent": "penthera-site-build" };
      if (process.env.GITHUB_TOKEN) headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
      const res = await fetch("https://api.github.com/repos/danoszz/penthera", { headers, signal: AbortSignal.timeout(5000) });
      if (res.ok) {
        n = (await res.json()).stargazers_count;
        if (Number.isFinite(n)) writeFileSync(STARS_FILE, JSON.stringify({ stars: n, checked: new Date().toISOString().slice(0, 10) }, null, 2) + "\n");
      }
    } catch {
      // Offline or rate-limited: fall back to the last count read.
    }
  }
  if (n == null && existsSync(STARS_FILE)) n = JSON.parse(readFileSync(STARS_FILE, "utf8")).stars;
  if (!Number.isFinite(n) || n < 0) return "";
  return n >= 1000 ? `${(n / 1000).toFixed(n >= 10_000 ? 0 : 1).replace(/\.0$/, "")}k` : String(n);
}

/**
 * AGENTS.md, the repo's instructions for coding agents, is linked from the
 * page and llms.txt only once it exists, so neither points at a missing file.
 */
function agentsMd() {
  if (!existsSync(join(ROOT, "AGENTS.md"))) return { AGENTS_MD_LI: "", AGENTS_MD_LLMS: "" };
  const url = `${REPO}/blob/main/AGENTS.md`;
  return {
    AGENTS_MD_LI: `        <li><a href="${url}"><code>AGENTS.md</code></a><span>How to work on Penthera's own code, for coding agents.</span></li>\n`,
    AGENTS_MD_LLMS: `- [AGENTS.md](${url}): how to work on Penthera's own code, for coding agents\n`,
  };
}

/** True for a semver pre-release such as 1.9.0-rc.1. */
export const prerelease = (v) => /^\d+\.\d+\.\d+-/.test(v);

/**
 * The version the site tells people to install. While main carries a
 * pre-release (between the release PR and the tag reaching npm), the pins stay
 * on the latest stable release in CHANGELOG.md, so every copied command works.
 */
export function siteVersion(version, file = join(ROOT, "CHANGELOG.md")) {
  if (!prerelease(version)) return version;
  const stable = /^## \[(\d+\.\d+\.\d+)\]/m.exec(readFileSync(file, "utf8"))?.[1];
  return stable || version;
}

/** The oldest release in CHANGELOG.md whose notes mention `text`, or null. */
export function firstRelease(text, file = join(ROOT, "CHANGELOG.md")) {
  let first = null;
  for (const sec of readFileSync(file, "utf8").split(/^## /m).slice(1)) {
    const v = /^\[(\d[^\]]*)\]/.exec(sec)?.[1];
    if (v && sec.includes(text)) first = v;
  }
  return first;
}

/**
 * While the package version is a release candidate, the MCP server is not on
 * npm's `latest` tag: say so wherever its config is shown. Empty once stable.
 */
export function mcpNote(version) {
  if (!prerelease(version)) return { MCP_NOTE: "", MCP_NOTE_MD: "" };
  const since = firstRelease("`penthera mcp`") || version;
  return {
    MCP_NOTE: `New in ${since}, a release candidate on npm's <code>next</code> tag (<code>penthera@next</code>).`,
    MCP_NOTE_MD: `New in ${since}, a release candidate on npm's \`next\` tag (\`penthera@next\`).`,
  };
}

const esc = (t) => String(t).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

/** Check site/news.json: a date, one short line, an https source. Throws on the first bad item. */
export function readNews(file = join(SITE, "news.json")) {
  const { items } = JSON.parse(readFileSync(file, "utf8"));
  if (!Array.isArray(items) || !items.length) throw new Error("news.json: no items");
  for (const [i, n] of items.entries()) {
    const where = `news.json items[${i}]`;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(n.date || "") || Number.isNaN(Date.parse(n.date))) throw new Error(`${where}: date must be YYYY-MM-DD`);
    if (typeof n.text !== "string" || !n.text.trim() || n.text.length > 120) throw new Error(`${where}: text must be 1 to 120 characters`);
    if (!/^https:\/\/[^\s"]+$/.test(n.source || "")) throw new Error(`${where}: source must be an https URL`);
  }
  return items;
}

/**
 * The ticker: the list twice, so the scroll loops without a seam. The second
 * copy is hidden from assistive tech and from the tab order.
 */
function tickerHtml(items) {
  const fmt = (d) => new Date(`${d}T00:00:00Z`).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
  const list = (hidden) => `<ul class="ticker-list"${hidden ? ' aria-hidden="true"' : ""}>${items.map((n) =>
    `<li><svg class="lock" viewBox="0 0 12 14" aria-hidden="true"><use href="#i-lock"/></svg><time datetime="${n.date}">${fmt(n.date)}</time> <a href="${esc(n.source)}"${hidden ? ' tabindex="-1"' : ""}>${esc(n.text)}</a></li>`).join("")}</ul>`;
  return `<div class="ticker" role="region" aria-label="Security news"><div class="ticker-track">${list(false)}${list(true)}</div></div>`;
}

/**
 * The site's absolute origin, for share cards (platforms need absolute image
 * URLs): SITE_URL, else the production URL Vercel gives the build, else the
 * deployment URL. Locally it is empty and the tags fall back to relative paths.
 */
function siteUrl(env = process.env) {
  const raw = env.SITE_URL || (env.VERCEL_PROJECT_PRODUCTION_URL && `https://${env.VERCEL_PROJECT_PRODUCTION_URL}`) || (env.VERCEL_URL && `https://${env.VERCEL_URL}`) || "";
  return raw.replace(/\/+$/, "");
}

const hash = (buf) => createHash("sha256").update(buf).digest("hex").slice(0, 10);
const kb = (n) => Math.round(n / 1024);

/**
 * Bundle one entry of site/check for the browser.
 * @param {string} input entry file
 * @param {string} file output file
 */
export async function bundle(input, file, { minify = true } = {}) {
  const { files, version } = embeddedFiles();
  await build({
    input,
    platform: "browser",
    plugins: [sitePlugin({ files, version, sigs: signatures() })],
    output: { file, format: "esm", minify, codeSplitting: false },
    logLevel: "warn",
  });
  return { version };
}

/**
 * Build the site.
 * @param {{ out?: string, engine?: string, blogDir?: string, drafts?: boolean }} opts engine: also write the
 *   check's engine alone (no DOM code) to this file, for tests; blogDir: the
 *   posts (default blog/); drafts: also render unapproved posts, unlisted
 *   (default: PENTHERA_BLOG_DRAFTS=1, for a local preview)
 */
export async function buildSite({ out = join(SITE, "dist"), engine, blogDir = join(ROOT, "blog"), drafts = process.env.PENTHERA_BLOG_DRAFTS === "1" } = {}) {
  const OUT = resolve(out);
  const t0 = Date.now();
  rmSync(OUT, { recursive: true, force: true });
  mkdirSync(OUT, { recursive: true });

  const { version } = await bundle(join(SITE, "check", "ui.js"), join(OUT, "check.js"));
  if (engine) await bundle(join(SITE, "check", "engine.js"), resolve(engine), { minify: false });

  // Static files, as they are.
  for (const f of ["styles.css", "theme.js", "track.js", "pro.js", "gopro.js", "research.js", "blog.js"]) cpSync(join(SITE, f), join(OUT, f));
  // The IndexNow key file, served at /<key>.txt (scripts/indexnow.mjs).
  for (const f of readdirSync(SITE).filter((n) => /^[0-9a-f]{32}\.txt$/.test(n))) cpSync(join(SITE, f), join(OUT, f));
  cpSync(join(SITE, "media"), join(OUT, "media"), { recursive: true });
  // The dashboard's own font and marks, so the site and penthera ui match.
  const UI = join(ROOT, "src", "ui", "static");
  for (const f of ["favicon.svg", "logo.svg"]) cpSync(join(UI, f), join(OUT, f));
  mkdirSync(join(OUT, "fonts"), { recursive: true });
  for (const f of ["DepartureMono-Regular.woff2", "DepartureMono-LICENSE.txt"]) cpSync(join(UI, "fonts", f), join(OUT, "fonts", f));
  // The walkthrough is no longer on the page; it stays at its URL for links shared before.
  cpSync(join(ROOT, "assets", "walkthrough.mp4"), join(OUT, "media", "walkthrough.mp4"));
  cpSync(join(ROOT, "assets", "walkthrough-poster.jpg"), join(OUT, "media", "walkthrough.jpg"));
  cpSync(join(ROOT, "assets", "walkthrough.vtt"), join(OUT, "media", "walkthrough.vtt"));
  // The tour's three dashboard shots live in site/media/tour/ (site/tools/tour-shots.mjs).

  // The page: version-stamp the assets it loads and fill in measured numbers.
  const packs = activePacks();
  const checkBytes = statSync(join(OUT, "check.js")).size;
  const popular = JSON.parse((await import("node:zlib")).gunzipSync(readFileSync(join(ROOT, "lib", "deps", "popular-packages.json.gz"))).toString("utf8"));
  const values = {
    VERSION: siteVersion(version),
    RULES: String(packs.reduce((n, p) => n + p.count, 0)),
    PACKS: packs.map((p) => `${p.name}@${p.version}`).join(", "),
    POPULAR: popular.names.length.toLocaleString("en-US"),
    CHECK_KB: String(kb(checkBytes)),
    ...benchNumbers(),
    ...ruleNumbers(),
    ...exampleValues(packs.reduce((n, p) => n + p.count, 0)),
    ...e10Values(),
    EX_CARD: exampleCardHtml(await exampleCheck()),
    STARS: await starCount(),
    TICKER: tickerHtml(readNews()),
    SITE_URL: siteUrl(),
    ...mcpNote(siteVersion(version)),
    ORIGIN,
    DOC_PAGES: String(docPages(ROOT).length - 1),
    ...agentsMd(),
    // Structured data for search engines and agents: <script type="application/ld+json"> in <head>.
    JSONLD: jsonLd({ version, origin: ORIGIN }),
  };
  // Content-hashed share URLs: link previews cache by URL (X for days), so a
  // changed card or reel gets a new one.
  values.OG_IMAGE = `${values.SITE_URL}/media/social/og.png?v=${hash(readFileSync(join(SITE, "media", "social", "og.png")))}`;
  values.OG_VIDEO = `${values.SITE_URL}/media/social/reel.mp4?v=${hash(readFileSync(join(SITE, "media", "social", "reel.mp4")))}`;
  values.STARS_LABEL = values.STARS ? `, ${values.STARS} stars` : "";
  // The public-benchmark ranking (E11b), from bench/public/published.json.
  // PENTHERA_PUBLISHED points a local preview at a sample file instead.
  const pubFile = process.env.PENTHERA_PUBLISHED || join(ROOT, "bench", "public", "published.json");
  const pubText = existsSync(pubFile) ? readFileSync(pubFile, "utf8") : null;
  const pub = pubText ? JSON.parse(pubText) : null;
  values.PUBLIC_BENCH = pub ? publicBenchHtml(pub) : "";
  // The free tools in the ranking, for the homepage's description.
  values.BENCH_TOOLS = pub ? String(fieldTools(pub)) : "other";
  // The blog (site/blog.mjs): approved posts only; no approved post, no /blog and no link to it.
  const posts = readPosts(blogDir, pub);
  // The footer of every page: a map of what this build renders, so a new
  // landing page, benchmark or approved post shows up in it by itself.
  const groups = footGroups({
    pages: landingPages(SITE),
    benchmarks: pub ? benchmarkViews(pub).map((v) => ({ slug: v.c.slug, label: v.c.label, nav: v.c.nav })) : [],
    posts: posts.published,
  });
  const footer = (home = false) => siteFooter({ groups, version: values.VERSION, stars: values.STARS, home });
  const foot = footer();
  values.FOOTER = footer(true);
  const cmp = readCompare();
  values.COMPARE = compareTable(cmp, values);
  values.COMPARE_SUMMARY = compareSummary(cmp, values);
  let html = fill(readFileSync(join(SITE, "index.html"), "utf8"), values, "index.html");
  html = html.replace(/(href|src)="\/(styles\.css|theme\.js|check\.js)"/g, (m, attr, f) => `${attr}="/${f}?v=${hash(readFileSync(join(OUT, f)))}"`);
  writeFileSync(join(OUT, "index.html"), html);
  // /terms: the live check's terms, rendered from docs/live-check-terms.md.
  const styles = `/styles.css?v=${hash(readFileSync(join(OUT, "styles.css")))}`;
  writeFileSync(join(OUT, "terms.html"), termsPage(ROOT, { styles, foot }));
  // /trust: how Penthera itself is built and released, from docs/trust.md.
  writeFileSync(join(OUT, "trust.html"), docPage(ROOT, {
    file: "trust.md", slug: "trust", eyebrow: "Trust", styles, foot,
    description: "How Penthera is built, released and run: npm provenance, one dependency, public checks, no telemetry. Links you can verify.",
  }));
  // Landing pages, one search question each (site/pages/, site/landing.mjs).
  for (const p of landingPages(SITE)) {
    writeFileSync(join(OUT, `${p.slug}.html`), landingHtml(p, { origin: ORIGIN, values, styles, foot, pub }));
    writeFileSync(join(OUT, `${p.slug}.md`), landingMarkdown(p, { origin: ORIGIN, values }));
  }
  // The benchmark pages, from the same published.json: /benchmarks and one
  // page per benchmark, each also as Markdown. The hub is written as
  // benchmarks.html (cleanUrls) and as benchmarks/index.html, so /benchmarks
  // resolves whichever a host tries first next to the benchmarks/ folder.
  if (pub) {
    const image = (slug) => { const f = cardFor(SITE, pubText, slug); return f ? `${ORIGIN}/${f}?v=${hash(readFileSync(join(SITE, f)))}` : undefined; };
    mkdirSync(join(OUT, "benchmarks"), { recursive: true });
    const hub = hubHtml(pub, { origin: ORIGIN, styles, image: image("hub"), foot });
    writeFileSync(join(OUT, "benchmarks.html"), hub);
    writeFileSync(join(OUT, "benchmarks", "index.html"), hub);
    writeFileSync(join(OUT, "benchmarks.md"), hubMarkdown(pub, { origin: ORIGIN }));
    for (const v of benchmarkViews(pub)) {
      writeFileSync(join(OUT, "benchmarks", `${v.c.slug}.html`), benchmarkHtml(v.key, pub, { origin: ORIGIN, styles, image: image(v.c.slug), foot }));
      writeFileSync(join(OUT, "benchmarks", `${v.c.slug}.md`), benchmarkMarkdown(v.key, pub, { origin: ORIGIN }));
    }
  }
  // /research: every study, result, case study and post, newest first (site/research.mjs).
  const research = researchEntries({ root: ROOT, pub, posts: posts.published });
  const script = `/research.js?v=${hash(readFileSync(join(OUT, "research.js")))}`;
  writeFileSync(join(OUT, "research.html"), researchHtml(research, { origin: ORIGIN, pub, styles, script, foot }));
  writeFileSync(join(OUT, "research.md"), researchMarkdown(research, { origin: ORIGIN, pub }));
  // The figures of every post the build renders, at /blog/figures/.
  for (const p of [...posts.published, ...(drafts ? posts.drafts : [])]) {
    for (const [name, fig] of Object.entries(p.figures)) {
      mkdirSync(join(OUT, "blog", "figures"), { recursive: true });
      cpSync(fig.path, join(OUT, "blog", "figures", name));
    }
  }
  for (const [f, text] of Object.entries(blogFiles(posts, { origin: ORIGIN, styles, script: `/blog.js?v=${hash(readFileSync(join(OUT, "blog.js")))}`, drafts, foot }))) {
    mkdirSync(dirname(join(OUT, f)), { recursive: true });
    writeFileSync(join(OUT, f), text);
  }
  // For agents and crawlers: llms.txt (the same placeholders, so its pins
  // match the page), the docs as Markdown, the sitemap, robots.txt and
  // security.txt. All from the repo, at the package's homepage.
  for (const [f, text] of Object.entries(agentFiles({ root: ROOT, site: SITE, version: siteVersion(version), origin: ORIGIN, values, pub, posts: posts.published, research }))) {
    mkdirSync(dirname(join(OUT, f)), { recursive: true });
    writeFileSync(join(OUT, f), text);
  }

  // The rail goes on every rendered page here, so no page template can miss it,
  // and so do the real quotes and apostrophes.
  for (const f of readdirSync(OUT, { recursive: true }).map(String).filter((n) => n.endsWith(".html"))) {
    const url = "/" + f.replace(/\\/g, "/").replace(/(^|\/)index\.html$/, "").replace(/\.html$/, "");
    const html = readFileSync(join(OUT, f), "utf8");
    writeFileSync(join(OUT, f), stickers(smart(html), url).replace(/<main\b/, `${siteRail({ url: url === "/" ? "/" : url.replace(/\/$/, ""), stars: values.STARS, blog: posts.published.length > 0 })}\n$&`));
  }

  const total = readdirSync(OUT, { recursive: true }).map((f) => join(OUT, f)).filter((f) => statSync(f).isFile()).reduce((n, f) => n + statSync(f).size, 0);
  writeFileSync(join(OUT, "build.json"), JSON.stringify({ version, ...values, bytes: total }, null, 2) + "\n");
  console.log(`${posix(relative(process.cwd(), OUT)) || "."}: check.js ${values.CHECK_KB} KB, ${values.RULES} pack rules (${values.PACKS}), ${kb(total)} KB in all, ${Date.now() - t0} ms`);
  return { out: OUT, values, bytes: total };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { values: args } = parseArgs({ options: { out: { type: "string" }, engine: { type: "string" } } });
  buildSite({ out: args.out, engine: args.engine }).catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}
