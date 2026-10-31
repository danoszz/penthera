/**
 * What the page loads: the passive report reads the page's HTML and the
 * scripts and stylesheets the page itself references, as a browser would,
 * and nothing else. No guessed paths, no invented query strings, no source
 * maps fetched (a reference is reported, not followed). Every request goes
 * through the guard (guard.mjs), pinned to the vetted address.
 *
 * Checks built here: secrets in the page and its same-site scripts (the CLI's
 * own secret rules), JavaScript libraries against the vendored Retire.js
 * data, a CMS version named in <meta name="generator">, Subresource Integrity
 * on third-party files, mixed content, source map references and security.txt.
 */
import { fetchBody, parseTarget, CheckError } from "./guard.mjs";
import { findSecretsInText } from "../../lib/whitebox/secrets.js";
import { loadSnapshot } from "../../lib/retirejs.js";
import { registrableDomain } from "../../src/utils/url.js";

export const LIMITS = Object.freeze({
  pageBytes: 1_500_000,
  fileBytes: 2_000_000,
  sameSiteFiles: 8,
  thirdPartyFiles: 6,
  requests: 20,
  budgetMs: 8000,
  fileTimeout: 4000,
  concurrency: 4,
  scanChars: 300_000,   // library banners sit at the top of a file
});

// ── HTML ─────────────────────────────────────────────────────────────────

const ATTR = /([^\s=/>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+)))?/g;
const TAG = /<(script|link|img|iframe|audio|video|source|embed|object|form|meta|base)\b((?:[^>"']|"[^"]*"|'[^']*')*)>/gi;

// &amp; last, so "&amp;quot;" stays the text "&quot;" instead of turning into a quote.
const decode = (s) => s.replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'").replace(/&#x2f;|&#47;/gi, "/").replace(/&amp;/gi, "&").trim();

function attrsOf(s) {
  const out = Object.create(null);
  for (const m of s.matchAll(ATTR)) {
    const name = m[1].toLowerCase();
    if (!(name in out)) out[name] = decode(m[2] ?? m[3] ?? m[4] ?? "");
  }
  return out;
}

const siteOf = (u) => registrableDomain(u.hostname.replace(/^\[|\]$/g, ""));

/**
 * The files and links a page references, from its HTML. Regex parsing: good
 * enough for src, href and action, and it never runs anything.
 * @param {string} html  @param {string} pageUrl
 */
export function parsePage(html, pageUrl) {
  const page = new URL(pageUrl);
  // Comments hide nothing from a browser's loader; inline script bodies are
  // code, not tags, so neither is scanned for tags.
  const markup = String(html).replace(/<!--[\s\S]*?-->/g, " ").replace(/(<script\b[^>]*>)[\s\S]*?(<\/script\b[^>]*>)/gi, "$1$2");
  const tags = [...markup.matchAll(TAG)].map((m) => ({ tag: m[1].toLowerCase(), attrs: attrsOf(m[2]) }));
  let base = page;
  const baseTag = tags.find((t) => t.tag === "base" && t.attrs.href);
  if (baseTag) { try { base = new URL(baseTag.attrs.href, page); } catch {} }
  const resolve = (v) => { try { return v ? new URL(v, base) : null; } catch { return null; } };

  const assets = [];
  const insecure = [];
  const insecureForms = [];
  let generator = "";
  for (const { tag, attrs } of tags) {
    if (tag === "meta" && (attrs.name || "").toLowerCase() === "generator") { generator ||= attrs.content || ""; continue; }
    if (tag === "form") {
      const action = resolve(attrs.action);
      if (action?.protocol === "http:") insecureForms.push(action.href);
      continue;
    }
    let url = null;
    let kind = null;
    let active = false;
    if (tag === "script") { url = resolve(attrs.src); kind = "script"; active = true; }
    else if (tag === "link") {
      const rel = (attrs.rel || "").toLowerCase().split(/\s+/);
      const as = (attrs.as || "").toLowerCase();
      if (rel.includes("stylesheet") || (rel.includes("preload") && as === "style")) { kind = "style"; active = true; }
      else if (rel.includes("modulepreload") || (rel.includes("preload") && as === "script")) { kind = "script"; active = true; }
      else if (!rel.some((r) => ["icon", "preload", "prefetch", "manifest"].includes(r))) continue;
      url = resolve(attrs.href);
    } else if (tag === "object") { url = resolve(attrs.data); active = true; }
    else if (tag === "iframe" || tag === "embed") { url = resolve(attrs.src); active = true; }
    else if (tag !== "base") url = resolve(attrs.src);
    if (!url || !/^https?:$/.test(url.protocol)) continue;
    if (url.protocol === "http:" && page.protocol === "https:") insecure.push({ tag, url: url.href, active });
    if (kind) assets.push({ url: url.href, kind, integrity: attrs.integrity || "", sameSite: siteOf(url) === siteOf(page) });
  }
  const seen = new Set();
  return {
    assets: assets.filter((a) => !seen.has(a.url) && seen.add(a.url)),
    insecure, insecureForms, generator: generator.slice(0, 120),
  };
}

// ── Fetching what the page references ────────────────────────────────────

/** A request budget shared by every fetch in one report. */
export function makeBudget({ requests = LIMITS.requests, budgetMs = LIMITS.budgetMs, now = Date.now } = {}) {
  const deadline = now() + budgetMs;
  let used = 0;
  return {
    get used() { return used; },
    left: () => deadline - now(),
    hop() {
      if (used >= requests || deadline - now() < 300) throw new CheckError("budget", "Request budget spent.", 429, "");
      used++;
    },
  };
}

async function pool(items, n, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k]); }
  }));
  return out;
}

/**
 * Fetch the page's own scripts and stylesheets: scripts first, up to 8
 * same-site and 6 third-party files, 2 MB each, inside the budget. An
 * http:// file on an https page is not fetched (a browser blocks it), and
 * nothing that looks like a source map is.
 */
export async function loadAssets(parsed, pageUrl, budget, opts = {}) {
  const https = pageUrl.startsWith("https:");
  const usable = parsed.assets.filter((a) => {
    const u = new URL(a.url);
    return !(https && u.protocol === "http:") && !/\.map$/i.test(u.pathname);
  });
  const order = (list) => [...list.filter((a) => a.kind === "script"), ...list.filter((a) => a.kind === "style")];
  const pick = [
    ...order(usable.filter((a) => a.sameSite)).slice(0, LIMITS.sameSiteFiles),
    ...order(usable.filter((a) => !a.sameSite)).slice(0, LIMITS.thirdPartyFiles),
  ];
  const files = await pool(pick, LIMITS.concurrency, async (a) => {
    const timeout = Math.min(LIMITS.fileTimeout, budget.left() - 200);
    if (timeout < 500) return null;
    try {
      const res = await fetchBody(parseTarget(a.url, opts), {
        ...opts, timeout, maxBytes: LIMITS.fileBytes, maxRedirects: 2, accept: "*/*", onHop: () => budget.hop(),
      });
      return { ...a, status: res.status, headers: res.headers, body: res.status === 200 ? res.body : "", truncated: res.truncated };
    } catch {
      return null;
    }
  });
  const read = files.filter(Boolean);
  return { files: read, wanted: usable.length, skipped: usable.length - read.length };
}

// ── Checks ───────────────────────────────────────────────────────────────

const label = (url) => { const u = new URL(url); return u.pathname || "/"; };
const curlBody = (url, pattern) => `curl -s ${url} | grep -Eo '${pattern}' | head`;

// Keys that a browser page is meant to carry when restricted by referrer
// (Maps, Firebase). The same shape is used for Gemini keys, which must never
// be public, so these are a note, not a failure.
const PUBLIC_SHAPE = new Set(["Google API key (Gemini / Firebase / Maps)"]);
// Assignment-shaped rules: right more often than not in a repo, but a public
// search-only key or a form label can match in a bundle. Reported as possible.
const LOOSE = new Set(["Generic API key assignment", "Hardcoded password", "JWT secret assignment", "Hardcoded session secret"]);

/** Never echo a secret: a short prefix and the length. */
export function redact(match) {
  const value = (/['"]([^'"]+)['"]/.exec(match) || [, match])[1];
  const keep = Math.min(6, Math.floor(value.length / 4));
  return `${value.slice(0, keep)}… (${value.length} chars)`;
}

export function secretChecks(html, files, pageUrl) {
  const sources = [{ where: "the page", text: html, url: pageUrl }, ...files.filter((f) => f.sameSite && f.kind === "script" && f.body).map((f) => ({ where: label(f.url), text: f.body, url: f.url }))];
  const hits = [];
  for (const s of sources) {
    for (const h of findSecretsInText(s.text)) hits.push({ ...h, where: s.where, url: s.url });
  }
  const real = hits.filter((h) => !PUBLIC_SHAPE.has(h.name));
  const strong = real.filter((h) => !LOOSE.has(h.name));
  const pub = hits.filter((h) => PUBLIC_SHAPE.has(h.name));
  const show = (list) => list.slice(0, 4).map((h) => `${h.name}: ${redact(h.match)} in ${h.where}`).join(" | ") + (list.length > 4 ? ` | and ${list.length - 4} more` : "");
  const scripts = sources.length - 1;
  const checks = [{
    id: "secrets", category: "secrets", weight: 14, passed: real.length === 0,
    severity: strong.some((h) => h.severity === "critical") ? "critical" : strong.length ? "high" : real.length ? "medium" : "info",
    title: strong.length ? `${strong.length === 1 ? "A secret key is" : `${strong.length} secret keys are`} in what the page sends`
      : real.length ? "Possible secret in what the page sends" : "No secrets found in the page or its scripts",
    evidence: real.length ? show(real) : `Checked the page and ${scripts} same-site script${scripts === 1 ? "" : "s"} with Penthera's secret rules.`,
    fix: "Revoke and rotate the key now: anyone who loaded the page has it. Then move the call that needs it to your server, and keep the key in a server-side environment variable (not one prefixed NEXT_PUBLIC_, VITE_ or REACT_APP_, which are copied into the bundle).",
    verify: real.length ? `curl -s ${real[0].url} | grep -c '${real[0].match.slice(0, 6).replace(/[^A-Za-z0-9_-]/g, "")}'` : `curl -s ${pageUrl} | head -c 300`,
  }];
  if (pub.length) {
    checks.push({
      id: "public-keys", category: "secrets", weight: 0, passed: false, severity: "low",
      title: "Google API key in the page",
      evidence: show(pub),
      fix: "Maps and Firebase keys are meant to be in the page, but only when restricted. In Google Cloud console, limit this key to your own domains and to the APIs it needs. If it is a Gemini key, revoke it and call Gemini from your server.",
      verify: `curl -s ${pub[0].url} | grep -c 'AIza'`,
    });
  }
  return checks;
}

// Retire.js extractor semantics: §§version§§ is the version's place.
const VERSION_RE = "([\\d][\\d.a-z\\-]+)";
const retireCache = new Map();
function extract(text, patterns) {
  for (const p of patterns || []) {
    let re = retireCache.get(p);
    if (re === undefined) {
      try { re = new RegExp(p.replace(/§§version§§/g, VERSION_RE), "i"); } catch { re = null; }
      retireCache.set(p, re);
    }
    const m = re && re.exec(text);
    if (m?.[1]) return m[1];
  }
  return null;
}

const parts = (v) => String(v).split(/[.-]/).map((p) => parseInt(p, 10) || 0);
function below(a, b) {
  const x = parts(a), y = parts(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) < (y[i] || 0);
  }
  return false;
}
const affected = (v, vuln) => (!vuln.below || below(v, vuln.below)) && (!vuln.atOrAbove || !below(v, vuln.atOrAbove));
const SEV = ["info", "low", "medium", "high"];

/**
 * JavaScript libraries, from script URLs and file banners, against the
 * Retire.js data vendored in lib/data (never fetched live here). Only a
 * library and version that data covers is called vulnerable.
 */
export function libraryChecks(html, parsed, files, pageUrl, { db: given } = {}) {
  const loaded = given ? { db: given, fetchedAt: "test" } : loadSnapshot();
  if (!loaded) {
    return [{
      id: "libraries", category: "page", weight: 0, passed: false, severity: "info",
      title: "Library check did not run", evidence: "The vendored Retire.js data could not be read; this is not a clean result.",
      fix: "Run npx penthera on your own machine for the library check.", verify: `curl -s ${pageUrl} | grep -Eo '<script[^>]+src=[^>]+>'`,
    }];
  }
  const urls = parsed.assets.map((a) => a.url);
  const texts = [html, ...files.map((f) => f.body || "")].map((t) => t.slice(0, LIMITS.scanChars));
  const found = [];
  for (const [name, lib] of Object.entries(loaded.db)) {
    const ex = lib?.extractors;
    if (!ex || name === "retire-example" || name === "dont check") continue;
    let version = null;
    let where = "";
    for (const u of urls) {
      version = extract(u, ex.uri) || extract(new URL(u).pathname.split("/").pop(), ex.filename);
      if (version) { where = u; break; }
    }
    if (!version) {
      for (let i = 0; i < texts.length && !version; i++) {
        version = extract(texts[i], ex.filecontent);
        if (version) where = i === 0 ? pageUrl : files[i - 1].url;
      }
    }
    if (!version) continue;
    const vulns = (lib.vulnerabilities || []).filter((v) => affected(version, v));
    found.push({ name, version, where, vulns });
  }
  const bad = found.filter((f) => f.vulns.length);
  const date = String(loaded.fetchedAt || "").slice(0, 10);
  const describe = (f) => {
    const ids = [...new Set(f.vulns.flatMap((v) => v.identifiers?.CVE || []))];
    const fixed = f.vulns.map((v) => v.below).filter(Boolean).sort((a, b) => (below(a, b) ? 1 : -1))[0];
    return `${f.name} ${f.version}: ${ids.length ? ids.slice(0, 4).join(", ") + (ids.length > 4 ? ` and ${ids.length - 4} more` : "") : `${f.vulns.length} known issue${f.vulns.length > 1 ? "s" : ""}`}${fixed ? ` (fixed in ${fixed})` : ""}`;
  };
  const worst = bad.flatMap((f) => f.vulns.map((v) => v.severity || "medium")).reduce((a, s) => (SEV.indexOf(s) > SEV.indexOf(a) ? s : a), "low");
  return [{
    id: "libraries", category: "page", weight: 8, passed: bad.length === 0,
    severity: bad.length ? (SEV.includes(worst) ? worst : "medium") : "info",
    title: bad.length === 1 ? `${bad[0].name} ${bad[0].version} has known vulnerabilities` : bad.length ? `${bad.length} JavaScript libraries have known vulnerabilities`
      : found.length ? "No known-vulnerable JavaScript libraries" : "No known JavaScript libraries detected",
    evidence: bad.length ? bad.map(describe).join(" | ")
      : `${found.length ? `Found ${found.map((f) => `${f.name} ${f.version}`).join(", ")}. ` : ""}Checked script names and banners against the Retire.js data${date ? ` of ${date}` : ""}.`,
    fix: bad.length ? `Upgrade ${bad.map((f) => f.name).join(", ")} to the fixed version or later, rebuild and redeploy. If a plugin pins the old version, update or replace the plugin.` : "",
    verify: bad.length ? `curl -s ${bad[0].where} | head -c 300` : "",
  }];
}

/** A CMS or site generator named with its version. Penthera has no advisory data for these, so it is a note. */
export function generatorCheck(parsed, pageUrl) {
  const g = parsed.generator;
  if (!g || !/\d+\.\d+/.test(g)) return [];
  const wp = /wordpress/i.test(g);
  return [{
    id: "generator", category: "disclosure", weight: 0, passed: false, severity: "info",
    title: `${g.split(/[;,]/)[0].trim().slice(0, 60)} named in the page`,
    evidence: `<meta name="generator" content="${g}">. Penthera has no advisory data for this product: compare the version with the vendor's security advisories.`,
    fix: wp
      ? "Keep WordPress and its plugins updated, and remove the tag with remove_action('wp_head', 'wp_generator'); in your theme or a small plugin."
      : "Keep the CMS updated, and remove the generator meta tag from the page template so the version is not advertised.",
    verify: `curl -s ${pageUrl} | grep -io '<meta[^>]*generator[^>]*>'`,
  }];
}

// Hosts that serve different bytes per browser or per release on purpose, so
// an integrity hash cannot work; their own docs say not to use one.
const NO_SRI = /(^|\.)(fonts\.googleapis\.com|googletagmanager\.com|google-analytics\.com|js\.stripe\.com|maps\.googleapis\.com|www\.google\.com|www\.gstatic\.com|challenges\.cloudflare\.com|connect\.facebook\.net|static\.cloudflareinsights\.com|js\.hs-scripts\.com|widget\.intercom\.io|plausible\.io|cdn\.usefathom\.com)$/i;

export function sriCheck(parsed, pageUrl) {
  const third = parsed.assets.filter((a) => !a.sameSite);
  if (!third.length) return [];
  const missing = third.filter((a) => !a.integrity);
  const fixable = missing.filter((a) => !NO_SRI.test(new URL(a.url).hostname));
  const dynamic = missing.length - fixable.length;
  return [{
    id: "sri", category: "page", weight: 4, passed: fixable.length === 0,
    severity: fixable.length ? (fixable.some((a) => a.kind === "script") ? "medium" : "low") : "info",
    title: fixable.length ? `${fixable.length} third-party file${fixable.length > 1 ? "s" : ""} without Subresource Integrity` : "Third-party files pinned with Subresource Integrity",
    evidence: (fixable.length ? fixable.slice(0, 4).map((a) => a.url.slice(0, 120)).join(" | ") + (fixable.length > 4 ? ` | and ${fixable.length - 4} more` : "")
      : `${third.length - missing.length} of ${third.length} carry an integrity hash.`)
      + (dynamic ? ` ${dynamic} from services that change their files on purpose (Google Fonts, Tag Manager, Stripe and similar) are not counted.` : ""),
    fix: "Add integrity=\"sha384-...\" and crossorigin=\"anonymous\" to each <script> and <link rel=\"stylesheet\"> from another domain, pinned to an exact version. Most CDNs show the hash next to the URL; or host the file yourself.",
    verify: curlBody(pageUrl, "<(script|link)[^>]+(src|href)=\"https://[^\"]+\"[^>]*>"),
  }];
}

export function mixedContentCheck(parsed, pageUrl, headers) {
  if (!pageUrl.startsWith("https:")) return [];
  const csp = [].concat(headers["content-security-policy"] || []).join(", ");
  const upgraded = /upgrade-insecure-requests/i.test(csp);
  const { insecure, insecureForms } = parsed;
  const bad = insecure.length + insecureForms.length;
  const active = insecure.some((i) => i.active) || insecureForms.length > 0;
  const items = [...insecureForms.map((u) => `form action ${u}`), ...insecure.map((i) => `<${i.tag}> ${i.url}`)];
  return [{
    id: "mixed-content", category: "page", weight: 6, passed: bad === 0 || upgraded,
    severity: bad && !upgraded ? (active ? "medium" : "low") : "info",
    title: !bad ? "No http:// content on the https page" : upgraded ? "http:// links on the page are upgraded by the CSP"
      : insecureForms.length ? "A form sends its data over http://" : `${insecure.length} http:// file${insecure.length > 1 ? "s" : ""} on an https page`,
    evidence: bad ? items.slice(0, 4).map((s) => s.slice(0, 140)).join(" | ") + (items.length > 4 ? ` | and ${items.length - 4} more` : "") + (upgraded ? " (upgrade-insecure-requests is set)" : "") : "",
    fix: "Change every http:// in src, href and form action to https:// (or a relative path). As a safety net, add upgrade-insecure-requests to the Content-Security-Policy.",
    verify: curlBody(pageUrl, "(src|href|action|data)=\"http://[^\"]+\""),
  }];
}

export function sourceMapCheck(files) {
  const own = files.filter((f) => f.sameSite && f.kind === "script" && f.status === 200);
  if (!own.length) return [];
  const refs = [];
  for (const f of own) {
    const header = f.headers?.sourcemap || f.headers?.["x-sourcemap"];
    const comment = /[#@]\s*sourceMappingURL\s*=\s*(\S+)/.exec(f.body.slice(-4096)) || /[#@]\s*sourceMappingURL\s*=\s*(\S+)/.exec(f.body);
    const ref = header || comment?.[1];
    if (ref) refs.push({ file: f.url, ref: ref.startsWith("data:") ? "an inline source map" : ref.slice(0, 80) });
  }
  return [{
    id: "source-maps", category: "page", weight: 2, passed: refs.length === 0,
    severity: refs.length ? "low" : "info",
    title: refs.length ? `${refs.length} script${refs.length > 1 ? "s" : ""} point to a source map` : "No source map references in the page's scripts",
    evidence: refs.length ? refs.slice(0, 4).map((r) => `${label(r.file)} → ${r.ref}`).join(" | ") + ". Not fetched; a source map can hold your original source code."
      : `Checked ${own.length} same-site script${own.length > 1 ? "s" : ""}.`,
    fix: "Stop publishing source maps to the public site, or upload them to your error tracker only. Vite: build.sourcemap: 'hidden'. webpack: devtool: 'hidden-source-map'. Next.js: productionBrowserSourceMaps: false.",
    verify: refs.length ? `curl -s ${refs[0].file} | tail -c 200` : "",
  }];
}

/** GET /.well-known/security.txt: a file meant to be fetched (RFC 9116). */
export async function securityTxtCheck(pageUrl, budget, opts = {}, now = Date.now()) {
  const origin = new URL(pageUrl).origin;
  const url = `${origin}/.well-known/security.txt`;
  const verify = `curl -s ${url}`;
  const fix = `Publish ${url} with at least a Contact: line (an email or a form URL) and an Expires: date under a year ahead, such as:\nContact: mailto:security@${new URL(pageUrl).hostname.replace(/^www\./, "")}\nExpires: ${new Date(now + 300 * 86_400_000).toISOString().slice(0, 10)}T00:00:00.000Z`;
  let res;
  try {
    const timeout = Math.min(4000, budget.left() - 200);
    if (timeout < 500) throw new CheckError("budget", "", 0, "");
    res = await fetchBody(parseTarget(url, opts), { ...opts, timeout, maxBytes: 32_768, maxRedirects: 2, accept: "text/plain", onHop: async (u) => { await opts.gate?.(u); budget.hop(); } });
  } catch {
    return [{ id: "security-txt", category: "contact", weight: 0, passed: false, severity: "info", title: "Could not read security.txt", evidence: "The request did not finish in time; this says nothing about the site.", fix: "Nothing to fix from this result.", verify }];
  }
  opts.onResponse?.("security.txt", res);
  const type = String(res.headers["content-type"] || "");
  const present = res.status === 200 && !/html/i.test(type) && /^\s*Contact\s*:/mi.test(res.body);
  if (!present) {
    return [{ id: "security-txt", category: "contact", weight: 3, passed: false, severity: "low", title: "No security.txt", evidence: `${url} answered ${res.status}${/html/i.test(type) ? " with an HTML page" : ""}`, fix, verify }];
  }
  const expiresRaw = /^\s*Expires\s*:\s*(.+)$/mi.exec(res.body)?.[1]?.trim() || "";
  const expires = Date.parse(expiresRaw);
  const expired = Number.isFinite(expires) && expires < now;
  const ok = Number.isFinite(expires) && !expired;
  return [{
    id: "security-txt", category: "contact", weight: 3, passed: ok,
    severity: ok ? "info" : "low",
    title: ok ? "security.txt published" : expired ? `security.txt expired on ${expiresRaw.slice(0, 10)}` : "security.txt has no valid Expires field",
    evidence: [/^\s*Contact\s*:.*$/mi.exec(res.body)?.[0].trim().slice(0, 120), expiresRaw && `Expires: ${expiresRaw.slice(0, 40)}`].filter(Boolean).join("; "),
    fix: ok ? "" : "Set Expires: to a date under a year ahead, and put a reminder in your calendar to renew it. " + fix.split("such as:")[1].trim(),
    verify,
  }];
}

// ── Opt-out ──────────────────────────────────────────────────────────────

export const TOKEN = "penthera-quickcheck";

/**
 * True when robots.txt has a group naming our token with Disallow: /.
 * Only a group that names Penthera-QuickCheck counts, never the * group:
 * "*" speaks to crawlers, which walk a site, while this check fetches what
 * one browser visit to one page fetches. Blocking it takes one line from the
 * owner, aimed at us. Groups follow RFC 9309: consecutive User-agent lines
 * share the rules that follow them. `tokens` adds names for callers that
 * identify themselves differently (the E20 study, bench/front-door).
 */
export function optedOut(robots, tokens = [TOKEN]) {
  const names = tokens.map((t) => String(t).toLowerCase());
  let agents = [];
  let inRules = false;
  // RFC 9309 ends a line with CR, LF or CRLF.
  for (const raw of String(robots).replace(/^\uFEFF/, "").split(/\r\n|\r|\n/)) {
    const line = raw.replace(/#.*/, "").trim();
    const m = /^([a-z-]+)\s*:\s*(.*)$/i.exec(line);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const value = m[2].trim();
    if (key === "user-agent") {
      if (inRules) { agents = []; inRules = false; }
      // The product token ends at a slash or a space (RFC 9309 § 2.2.1).
      agents.push(value.split(/[/\s]/)[0].toLowerCase());
    } else if (key === "disallow" || key === "allow") {
      inRules = true;
      if (key === "disallow" && (value === "/" || value === "/*") && agents.some((a) => names.includes(a))) return true;
    }
  }
  return false;
}

/**
 * GET /robots.txt through the guard (4 s, 64 KB, in the request budget) and
 * refuse when the owner opted out. No file, or any fetch error, means go on.
 * `optOutAll` (the E20 study only) also refuses on a `*` group with Disallow: /.
 * `onRobots` (study only) hears every outcome and may throw, so the study sets
 * its own rules; a study run also reads any 2xx. `robotsHop` (study only) checks
 * each hop of the file's own redirects. The live check sets neither, and keeps
 * "go on".
 */
export async function checkOptOut(origin, budget, opts = {}) {
  const timeout = Math.min(4000, budget.left() - 200);
  if (timeout < 500) { opts.onRobots?.({ origin, error: "budget" }); return; }
  let res;
  let hops = 0;
  const onHop = async (u) => {
    if (hops++) opts.onAnswered?.();
    await opts.robotsHop?.(u);
    budget.hop();
  };
  try {
    res = await fetchBody(parseTarget(`${origin}/robots.txt`, opts), { ...opts, timeout, maxBytes: opts.robotsMaxBytes ?? 65_536, maxRedirects: opts.robotsRedirects ?? 2, accept: "text/plain", onHop });
  } catch (e) {
    opts.onRobots?.({ origin, error: e?.code || "internal", cause: e });
    return;
  }
  opts.onResponse?.("robots", res);
  opts.onRobots?.({ origin, status: res.status, body: res.body, headers: res.headers, truncated: res.truncated });
  const readable = opts.onRobots ? res.status >= 200 && res.status < 300 : res.status === 200;
  // The study hands in its own reading. The live check keeps the plain one.
  const refuses = opts.optedOut ?? optedOut;
  if (readable && refuses(res.body, opts.optOutTokens)) {
    throw new CheckError("opted_out", "This site's owner opted out of Penthera's online check.", 403, "Ask the owner, or, if it's your site, run npx penthera on your own machine.");
  }
  // The E20 study (bench/front-door) also honors `User-agent: *` with
  // `Disallow: /`, because a survey is closer to a crawler. The live check
  // never sets optOutAll, so the API never sends this. Same code, marked
  // `all`, so the study can count it apart from an opt-out naming us.
  if (readable && opts.optOutAll && refuses(res.body, ["*"])) {
    throw Object.assign(new CheckError("opted_out", "This site's robots.txt disallows every user agent.", 403, ""), { all: true });
  }
}
