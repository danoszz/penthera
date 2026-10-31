#!/usr/bin/env node
/**
 * E20 runner: how safe is the web's front door?
 * Protocol: docs/research/prereg/E20-front-door.md (cohorts: tranco = E20,
 * the Tranco top 1000; yc = E20b, recent Y Combinator companies).
 *
 *   node bench/front-door/run.mjs --self-test
 *       Loopback only: starts tests/fixtures/mock-server.js and visits it.
 *   node bench/front-door/run.mjs --list <file> --loopback <port> [--cohort tranco|yc]
 *       Loopback only: every name resolves to 127.0.0.1:<port>, DNS records
 *       come from a stub. Nothing leaves the machine.
 *   Any other run is refused: E20 is closed, and E20-R2 runs from replicate.mjs.
 *   node bench/front-door/run.mjs --compare <a/aggregate.json> <b/aggregate.json>
 *       The difference per check between two cohorts, offline.
 *
 * Options: --exclude <file> (the exclusion list, § 5: "<domain> <category>"
 * per line; a domain also covers its subdomains; never visited), --out <dir>
 * (default bench/front-door/results/<cohort>-<time>, git-ignored).
 * Loopback runs only: --limit N (default 1000 tranco, 400 yc), --concurrency N
 * (default 4, at most 8), --delay MS (default 1000, per worker between sites).
 *
 * Per site, through the live check's passiveReport (api/_lib/tier1.mjs) with
 * assets: false and secrets: false: GET /robots.txt (a group naming
 * Penthera-Research or Penthera-QuickCheck, or the * group, with Disallow: /
 * stops the visit),
 * GET / with at most 4 redirects, GET /.well-known/security.txt, and public
 * DNS lookups for SPF, DMARC and CAA. One visit per site, no retries, no
 * scripts or stylesheets fetched, no paths guessed, no payloads.
 *
 * Sub-measure B (§ 4.2, pending the maintainer's decision): from the homepage
 * already fetched, one same-site "Log in / App / Dashboard" link, and one GET
 * of that page (its robots.txt first). No login, no forms, no scripts. Off on
 * a registered run until the prereg's "Sub-measure B" row says Adopted; on
 * loopback, --app-page turns it on for tests.
 *
 * Writes raw.jsonl (per site, private, never published) and aggregate.json
 * (no site names) to the output directory.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, appendFileSync, existsSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { lookup as dnsLookup } from "node:dns/promises";
import { passiveReport } from "../../api/_lib/tier1.mjs";
import { parseTarget, fetchBody, CheckError } from "../../api/_lib/guard.mjs";
import { scrub } from "./classify.mjs";
import { isIP } from "node:net";
import { siteOrg } from "./psl.mjs";
import { grade } from "../../api/_lib/grade.mjs";
import { makeBudget } from "../../api/_lib/page.mjs";
import { registrableDomain } from "../../src/utils/url.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const PREREG = join(ROOT, "docs", "research", "prereg", "E20-front-door.md");

// § 4 of the protocol. Changing any of these after registration is a deviation.
export const USER_AGENT = "Penthera-Research/E20 (+https://penthera.org/research/e20; opt out: robots.txt User-agent: Penthera-Research)";
export const OPT_OUT_TOKENS = ["penthera-research", "penthera-quickcheck"];
export const LIMITS = Object.freeze({
  siteRequests: 20,
  concurrency: 4, maxConcurrency: 8,
  delayMs: 1000,
  siteBudgetMs: 8000, siteHardCapMs: 20_000,
  maxSites: 1000,
});
export const COHORTS = Object.freeze({
  tranco: { label: "Tranco list", defaultLimit: 1000 },
  yc: { label: "YC list", defaultLimit: 420 },
});
// E20b scope: the public homepage only. A host that names a logged-in app, an
// API or a payment flow is not a homepage, so it is excluded, never visited.
const NOT_A_HOMEPAGE = /^(app|apps|dashboard|console|portal|admin|login|signin|auth|account|accounts|my|api|checkout|pay|payments|billing|shop|store)\./i;
// § 5: the categories an exclusion list line may name.
export const EXCLUSION_CATEGORIES = Object.freeze(["adult", "gambling", "health", "government", "at-risk"]);
export const EXCLUSION_LABEL = "Exclusion list";
// Groups smaller than this are not reported (no group that small can stay anonymous).
export const MIN_GROUP = 20;

// ── List and registration ──────────────────────────────────────────────────

export const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

/** The hash the prereg records for a cohort (or "exclusions"), or null while it says `pending`. */
export function recordedHash(preregText, cohort) {
  const label = cohort === "exclusions" ? EXCLUSION_LABEL : COHORTS[cohort]?.label;
  if (!label) return null;
  const m = new RegExp(`\\|\\s*${label} SHA-256\\s*\\|\\s*\`([0-9a-f]{64})\``).exec(preregText);
  return m ? m[1] : null;
}

export const isRegistered = (preregText) => /^\|\s*Status\s*\|\s*\*\*Registered\./m.test(preregText);

/** § 4.2: sub-measure B runs on a registered run only when the prereg's row says Adopted. */
export const appPageAdopted = (preregText) => /^\|\s*Sub-measure B \(app page\)\s*\|\s*\*\*Adopted/m.test(preregText);

/**
 * E20 ran on 30 October 2026 and is closed. This file stays a library for E20-R2
 * (replicate.mjs, which holds the locks) and runs on loopback only: a registered
 * E20 run could leave from any machine, and the study's rule is that the
 * maintainer's home connection never touches a study site.
 */
export function authorize({ loopback } = {}) {
  if (loopback) return { mode: "loopback" };
  throw new Error("Refused: E20 is closed. This runner is loopback only; a real run goes through replicate.mjs.");
}

/** A hostname from a list cell: "Example.com", "https://www.example.com/about" → example.com, www.example.com. */
export function hostOf(cell) {
  const raw = String(cell || "").trim();
  if (!raw) return "";
  try {
    return new URL(/^[a-z]+:\/\//i.test(raw) ? raw : `https://${raw}`).hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return "";
  }
}

/**
 * Rows of a CSV list. Tranco's file has no header ("rank,domain"); the YC
 * file has one with at least "batch" and "domain" (or "website").
 * Each row: { rank, host, group }. group is the TLD (tranco) or the batch (yc).
 */
export function readList(text, cohort) {
  const lines = String(text).split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (!lines.length) return [];
  const first = lines[0].split(",").map((c) => c.trim().toLowerCase());
  const header = !/^\d+$/.test(first[0]);
  const col = (names, fallback) => { const i = header ? first.findIndex((c) => names.includes(c)) : -1; return i === -1 ? fallback : i; };
  const hostCol = col(["domain", "website", "url"], 1);
  const batchCol = col(["batch"], -1);
  const rows = [];
  const seen = new Set();
  for (const [i, line] of (header ? lines.slice(1) : lines).entries()) {
    const cells = line.split(",").map((c) => c.trim());
    const host = hostOf(cells[hostCol]);
    if (!host || seen.has(host)) continue;   // one visit per site
    seen.add(host);
    const rank = !header && /^\d+$/.test(cells[0]) ? Number(cells[0]) : i + 1;
    const group = cohort === "yc" ? (batchCol >= 0 ? cells[batchCol] || "unknown" : "unknown") : host.split(".").pop();
    rows.push({ rank, host, group });
  }
  return rows;
}

/**
 * The exclusion list (§ 5): one "<domain> <category>" per line, # comments.
 * Returns Map(domain → category). Throws on an unknown category or a bad
 * domain, so a typo cannot silently let a site through.
 */
export function readExclusions(text) {
  const out = new Map();
  for (const [i, raw] of String(text).split(/\r?\n/).entries()) {
    const line = raw.replace(/#.*/, "").trim();
    if (!line) continue;
    const [cell, category, ...rest] = line.split(/\s+/);
    const host = /^[a-z0-9.-]+$/i.test(cell) ? cell.toLowerCase().replace(/^\.+|\.$/g, "") : "";
    if (!host || rest.length) throw new Error(`exclusion list line ${i + 1}: expected "<domain> <category>", got "${raw.trim()}"`);
    if (!EXCLUSION_CATEGORIES.includes(category)) throw new Error(`exclusion list line ${i + 1}: category must be one of ${EXCLUSION_CATEGORIES.join(", ")}, got "${category ?? ""}"`);
    out.set(host, category);
  }
  return out;
}

/** The category that excludes a host: the host itself or any parent domain is listed ("gov" covers every .gov host). */
export function exclusionFor(host, exclusions) {
  const labels = String(host).toLowerCase().replace(/\.+$/, "").split(".");
  for (let i = 0; i < labels.length; i++) {
    const c = exclusions.get(labels.slice(i).join("."));
    if (c) return c;
  }
  return null;
}

// ── One visit ──────────────────────────────────────────────────────────────

const loopbackLookup = async () => [{ address: "127.0.0.1", family: 4 }];
const enodata = () => Promise.reject(Object.assign(new Error("ENODATA"), { code: "ENODATA" }));
export const STUB_DNS = { resolveTxt: enodata, resolveCaa: enodata };

/**
 * § 8.7: evidence can quote an email address (a security.txt Contact, a
 * DMARC rua= address), which may name a person. The raw record keeps the
 * domain after the @ and drops the rest, before anything is written.
 */
export const redact = (text) => String(text || "").replace(/[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/gi, "<redacted>@$1");

/** What a raw record keeps of a check: no fix text, evidence capped and redacted. */
// The grader cuts evidence at 120 to 200 characters, so a long one may end inside an
// address. Drop that last token: a cut address no longer looks like one.
const EVIDENCE_CUT = 118;
const dropCutToken = (e) => { const t = String(e || ""); return t.length < EVIDENCE_CUT ? t : t.slice(0, Math.max(...[" ", ",", ";"].map((c) => t.lastIndexOf(c)), 0)); };
// A malformed Set-Cookie puts its value where the grader expects a name, so no cookie text is stored.
export const slim = (c) => ({ id: c.id, passed: c.passed, severity: c.severity, weight: c.weight, evidence: c.id === "cookies" ? "" : scrub(redact(dropCutToken(c.evidence))).slice(0, 300) });

/**
 * RFC 9309 § 2.3.1, as the study applies it (Amendment 2). A 2xx is parsed. A
 * 4xx means no rules. A 5xx, an unreachable file or a spent budget means
 * complete disallow. 429 is a 4xx in the RFC; the study treats it as a request
 * to stay away. A 2xx that can't be read to its end proves nothing, so a
 * compressed or cut-off file counts as unavailable, and so does a 3xx with no
 * Location, which no client can follow.
 */
export const robotsAccess = ({ status, error, encoded, truncated, binary }) => (error || status === 429 || status >= 500 || (status >= 300 && status < 400) || ((encoded || truncated || binary) && status < 300) ? "disallow" : "allow");
/** NUL, or the two bad bytes a UTF-16 BOM decodes to: a file we can't read as text, whatever it says. */
export const robotsBinary = (body) => String(body ?? "").includes("\0") || String(body ?? "").startsWith("\uFFFD\uFFFD");
export const ROBOTS_REDIRECTS = 5;
// RFC 9309 § 2.5 asks a crawler to read at least 500 KiB.
export const ROBOTS_MAX_BYTES = 512_000;
// These say what happened to the origin, not what its robots.txt says, so the
// visit ends with the same outcome the homepage would have given. Nothing
// more is sent to that origin.
const ROBOTS_KEEP_OUTCOME = new Set(["not_found", "unreachable", "tls_invalid", "timeout", "not_public"]);
// Nothing answered at all. A reset can be a refusal, and a refusal gets no retry.
const NO_ANSWER = new Set(["ECONNREFUSED", "EHOSTUNREACH", "ENETUNREACH", "ETIMEDOUT", "EADDRNOTAVAIL"]);
const AFTER_TLS = new Set(["unreachable", "timeout", "not_found"]);
// No TLS session could be set up: old versions, or plain HTTP on the TLS port. An alert
// that says access is denied is a refusal, though, and a refusal gets no fallback.
const TLS_HANDSHAKE = /^(?:EPROTO$|ERR_SSL_(?!.*ACCESS_DENIED))/;
const tlsFailed = (e) => e.code === "tls_invalid" || TLS_HANDSHAKE.test(e.netCode ?? "");
/** The outcome a record names. A handshake failure is its own, not `unreachable`. */
const outcomeOf = (e) => (!(e instanceof CheckError) ? "internal" : TLS_HANDSHAKE.test(e.netCode ?? "") ? "tls_handshake" : e.code);

/** IPv4 only, so one published address accounts for every request (§ 5). */
export const ipv4Lookup = (host, opts = {}) => dnsLookup(host, { ...opts, family: 4 });

const robotsStop = (reason) => Object.assign(new CheckError("robots_stop", "robots.txt stops this visit.", 403, ""), { reason });

/**
 * The study's rules for hops, robots.txt and fallbacks, for one visit.
 * `outcomes` keeps what each origin answered. Every hop must stay off the
 * exclusion list, off a literal IP address, out of an origin whose robots.txt
 * failed, and inside the rules of its origin. A fallback runs only when nothing
 * from the listed origin has answered.
 */
export function strictRobots({ exclude = new Map(), outcomes = [], listedHost } = {}) {
  const bodies = new Map();
  const failed = new Set();
  let answered = false;
  const refuseHost = (u) => {
    if (exclusionFor(u.hostname, exclude)) throw robotsStop("exclusion_redirect");
    if (u.hostname.startsWith("[")) throw robotsStop("ipv6_literal");
    if (isIP(u.hostname)) throw robotsStop("ipv4_literal");
    if (failed.has(u.origin)) throw robotsStop("robots_unavailable");
  };
  return {
    robotsRedirects: ROBOTS_REDIRECTS,
    robotsMaxBytes: ROBOTS_MAX_BYTES,
    // The early check asks the real matcher, so an Allow that beats `Disallow: /` counts here too.
    optedOut: (body, tokens) => wholeSiteStop(body, OPT_OUT_TOKENS, tokens.includes("*")),
    robotsHop: refuseHost,
    onAnswered() { answered = true; },
    onRobots({ origin, status, error, body, headers, truncated, cause }) {
      if (status !== undefined) answered = true;
      const encoding = headers?.["content-encoding"];
      const encoded = Boolean(encoding) && !/^identity$/i.test(encoding);
      const binary = robotsBinary(body);
      const access = robotsAccess({ status, error, encoded, truncated, binary });
      outcomes.push({ status: status ?? null, error: error ?? null, access, ...(encoded ? { encoded } : {}), ...(truncated ? { truncated } : {}), ...(binary ? { binary } : {}) });
      if (access === "disallow") failed.add(origin);
      if (cause?.code === "robots_stop" || (cause instanceof CheckError && ROBOTS_KEEP_OUTCOME.has(cause.code))) throw cause;
      if (access === "disallow") throw robotsStop("robots_unavailable");
      if (status >= 200 && status < 300) bodies.set(origin, body);
    },
    onHopUrl(u) {
      refuseHost(u);
      const body = bodies.get(u.origin);
      if (body === undefined) return;
      const verdict = robotsVerdict(body, u.pathname + u.search);
      if (verdict === "opted_out") throw Object.assign(new CheckError("opted_out", "This site's owner opted out.", 403, ""), { redirectedTo: u.hostname });
      // Another organization's rule is theirs: the listed site didn't ask to be left out.
      if (verdict === "disallowed") throw robotsStop(listedHost && siteOrg(u.hostname) !== siteOrg(listedHost) ? "redirect_disallow_path" : "robots_disallow_path");
    },
    allowFallback: (e) => !answered && (tlsFailed(e) || NO_ANSWER.has(e.netCode)),
    allowWww: () => !answered,
    // A bad certificate stays the outcome when plain http has nothing either.
    fallbackError: (https, http) => (tlsFailed(https) && (AFTER_TLS.has(http.code) || http.reason === "robots_unavailable") ? https : http),
  };
}

/**
 * One site, one visit. Loopback: http://<host>:<port>/ with the name pinned
 * to 127.0.0.1. Registered: https://<host>/ (the passive report falls back to
 * http when https does not connect); when the name does not resolve, one try
 * at www.<host>.
 */
export async function visit(row, { loopbackPort, now, appPage = false, exclude = new Map(), lookup, evidence, strict = false, budgetMs = LIMITS.siteBudgetMs, hardCapMs = LIMITS.siteHardCapMs, meter: given } = {}) {
  let page = null;
  let httpsFailed = null;
  const responses = [];
  const robots = [];
  const rules = strict ? strictRobots({ exclude, outcomes: robots, listedHost: row.host }) : null;
  const meter = strict ? (given ?? { requests: 0, bytes: 0, redirects: 0, hosts: [] }) : undefined;
  const base = {
    userAgent: USER_AGENT, optOutTokens: OPT_OUT_TOKENS, optOutAll: true, assets: false, secrets: false,
    budgetMs, now, lookup, onPage: (p) => { page = p; }, onResponse: (kind, res) => responses.push({ kind, res }),
    onFallback: (e) => { httpsFailed = { error: outcomeOf(e), ...(e.tlsReason ? { tlsReason: e.tlsReason } : {}), ...(e.netCode ? { netCode: e.netCode } : {}) }; },
    ...rules, meter, ...(strict ? { budget: makeBudget({ requests: LIMITS.siteRequests, budgetMs }), skipDns: true } : {}),
  };
  const counters = () => ({ requests: meter.requests, bytes: meter.bytes, redirects: meter.redirects });
  const withRobots = (r) => (strict ? { ...r, robots, counters: counters(), hops: [...meter.hosts], ...(httpsFailed ? { httpsFailed } : {}) } : r);
  const opts = loopbackPort
    ? { ...base, lookup: loopbackLookup, allowPrivate: true, anyPort: true, dns: STUB_DNS }
    : base;
  const at = new Date().toISOString();
  if (NOT_A_HOMEPAGE.test(row.host)) return { ...row, at, status: "excluded", reason: "not_a_homepage" };

  const attempt = (host) => {
    const typed = loopbackPort ? `http://${host}:${loopbackPort}/` : host;
    return passiveReport(parseTarget(typed, { anyPort: Boolean(loopbackPort) }), { ...opts, typed });
  };
  const capped = (p) => {
    let timer;
    return Promise.race([p, new Promise((_, reject) => { timer = setTimeout(() => reject(new CheckError("timeout", "Hard cap", 504, "")), hardCapMs); })])
      .finally(() => clearTimeout(timer));
  };
  try {
    let report;
    try {
      report = await capped(attempt(row.host));
    } catch (e) {
      if (loopbackPort || !(e instanceof CheckError) || e.code !== "not_found" || row.host.startsWith("www.") || rules?.allowWww() === false) throw e;
      report = await capped(attempt(`www.${row.host}`));
    }
    const record = withRobots({
      ...row, at, status: "ok",
      finalHost: new URL(report.url).hostname, httpStatus: report.status, redirects: report.redirects.length,
      score: report.score, checks: report.checks.map(slim),
      platform: page ? platformOf(page.headers, page.html) : { edge: "unknown", builder: "unknown" },
    });
    // E20-R only: what the response carried, for the classifier (replicate.mjs).
    if (evidence && page) record.evidence = evidence(page, responses);
    // § 4.2, pending: one app or login page, only when B is on.
    // Amendment 2: the app page is never requested under the strict rules.
    if (appPage && !strict) record.app = await capped(visitAppPage(page, { loopbackPort, now, exclude, lookup })).catch((e) => ({ status: "error", error: e instanceof CheckError ? e.code : "internal" }));
    return record;
  } catch (e) {
    // § 5, decided 29 Oct: a `*` group with Disallow: / is an opt-out for E20, counted as excluded.
    // An opt-out by the organization a redirect led to is theirs, not the listed site's: its DNS is still read.
    if (e instanceof CheckError && e.code === "opted_out" && e.redirectedTo && siteOrg(e.redirectedTo) !== siteOrg(row.host)) return withRobots({ ...row, at, status: "excluded", reason: "redirect_opted_out" });
    if (e instanceof CheckError && e.code === "opted_out" && e.all) return withRobots({ ...row, at, status: "excluded", reason: "robots_disallow_all" });
    if (e instanceof CheckError && e.code === "opted_out") return withRobots({ ...row, at, status: "opted_out" });
    if (e instanceof CheckError && e.code === "robots_stop") return withRobots({ ...row, at, status: "excluded", reason: e.reason });
    return withRobots({ ...row, at, status: "error", error: outcomeOf(e), ...(e?.tlsReason ? { tlsReason: e.tlsReason } : {}), ...(e?.netCode ? { netCode: e.netCode } : {}) });
  }
}

// ── Hosting platform (§ 6.7, exploratory) ──────────────────────────────────

/**
 * Where the homepage is served from and what built it, read from the
 * response headers and the generator tag of the page already fetched. Fixed
 * rules, no extra request. First match wins; "other" when nothing matches.
 */
export const EDGE_RULES = Object.freeze([
  ["vercel", (h) => "x-vercel-id" in h || /vercel/i.test(h.server || "")],
  ["netlify", (h) => "x-nf-request-id" in h || /netlify/i.test(h.server || "")],
  ["cloudflare", (h) => "cf-ray" in h || /cloudflare/i.test(h.server || "")],
  ["cloudfront", (h) => "x-amz-cf-id" in h || /cloudfront/i.test(h.via || "")],
  ["fastly", (h) => "x-fastly-request-id" in h || /fastly|cache-[a-z]{3}\d/i.test((h["x-served-by"] || "") + (h.via || ""))],
  ["akamai", (h) => "x-akamai-transformed" in h || "akamai-grn" in h || /akamai/i.test(h.server || "")],
  ["github-pages", (h) => /^github\.com$/i.test(h.server || "")],
  ["google", (h) => /^(gws|esf|gse|google frontend)$/i.test(h.server || "")],
]);
export const BUILDER_RULES = Object.freeze([
  ["webflow", /^webflow\b/i], ["framer", /^framer\b/i], ["wordpress", /^wordpress\b/i], ["wix", /^wix\b/i],
  ["squarespace", /^squarespace\b/i], ["hubspot", /^hubspot\b/i], ["ghost", /^ghost\b/i], ["shopify", /^shopify\b/i],
]);
const GENERATOR = /<meta\b[^>]*\bname\s*=\s*["']?generator["']?[^>]*>/i;

export function platformOf(headers = {}, html = "") {
  const h = Object.fromEntries(Object.entries(headers || {}).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v.join(", ") : String(v)]));
  const edge = EDGE_RULES.find(([, test]) => test(h))?.[0] || "other";
  const tag = GENERATOR.exec(String(html || ""))?.[0] || "";
  const content = /\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(tag);
  const gen = (content?.[1] ?? content?.[2] ?? "").trim();
  const builder = gen ? BUILDER_RULES.find(([, re]) => re.test(gen))?.[0] || "other" : "none";
  return { edge, builder };
}

// ── Sub-measure B: one app or login page (§ 4.2, pending) ──────────────────

/** § 4.2: which link counts, and what B may send. Changing these after registration is a deviation. */
export const APP_LINK_TEXT = /^(log ?in|sign ?in|app|open app|go to app|launch app|web app|dashboard|go to dashboard|console|my account)$/i;
export const APP_LINK_PATH = /^\/(login|log-in|signin|sign-in|app|dashboard|console)\/?$/i;
export const APP_PAGE = Object.freeze({ requests: 4, budgetMs: 6000, maxRedirects: 2, maxBytes: 262_144 });
// B grades only the response of the linked page, with the homepage's header checks.
export const APP_CHECKS = Object.freeze(["https", "hsts", "csp", "framing", "nosniff", "referrer", "permissions", "cookies", "csp-scripts", "cors", "disclosure", "tls", "cert"]);

// &amp; last, so "&amp;quot;" stays "&quot;" instead of being unescaped twice.
const decode = (t) => t.replace(/&nbsp;/gi, " ").replace(/&#39;|&apos;/gi, "'").replace(/&quot;/gi, '"').replace(/&amp;/gi, "&");

/**
 * The first link on the homepage that names a login or app page: its text,
 * or its path, matches the fixed lists above. Only http(s), only the same
 * registrable domain as the homepage (so never an outside sign-in provider),
 * never the homepage itself. Query string and fragment are dropped: B sends
 * no query string. Returns a URL string or null.
 */
export function findAppLink(html, pageUrl) {
  const page = new URL(pageUrl);
  const site = registrableDomain(page.hostname);
  const markup = String(html || "").replace(/<!--[\s\S]*?-->/g, " ").replace(/<script\b[^>]*>[\s\S]*?<\/script\b[^>]*>/gi, " ");
  for (const m of markup.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi)) {
    const href = /\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))/i.exec(m[1]);
    const raw = href ? (href[1] ?? href[2] ?? href[3] ?? "").trim() : "";
    if (!raw) continue;
    let url;
    try { url = new URL(decode(raw), page); } catch { continue; }
    if (!/^https?:$/.test(url.protocol) || url.username || url.password) continue;
    if (registrableDomain(url.hostname) !== site) continue;
    url.search = "";
    url.hash = "";
    if (url.hostname === page.hostname && url.pathname === page.pathname) continue;
    const text = decode(m[2].replace(/<[^>]*>/g, " ")).replace(/\s+/g, " ").trim();
    if (APP_LINK_TEXT.test(text) || APP_LINK_PATH.test(url.pathname)) return url.href;
  }
  return null;
}

const UNRESERVED = /[A-Za-z0-9\-._~]/;
const URL_ENCODES = new Set(['"', "<", ">", "`", "{", "}", " ", "^", "|", "\\"]);

/**
 * RFC 9309 § 2.2.2: rule and path compare in one form. Octets of unreserved characters
 * are decoded, other escapes keep upper-case hex, and anything a URL parser encodes is
 * encoded. `*` and `$` stay. A malformed `%` stays literal, so it matches only itself:
 * a rule we can't read can still stop a visit, and a path can't dodge a rule by it.
 */
export function percentForm(text) {
  const s = String(text);
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === "%" && /^[0-9a-f]{2}$/i.test(s.slice(i + 1, i + 3))) {
      const hex = s.slice(i + 1, i + 3).toUpperCase();
      const plain = String.fromCharCode(parseInt(hex, 16));
      out += UNRESERVED.test(plain) ? plain : `%${hex}`;
      i += 2;
    } else if (ch.charCodeAt(0) >= 128) {
      const whole = String.fromCodePoint(s.codePointAt(i));
      out += Buffer.from(whole, "utf8").toString("hex").toUpperCase().replace(/../g, (b) => `%${b}`);
      i += whole.length - 1;
    } else {
      out += URL_ENCODES.has(ch) ? `%${ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0")}` : ch;
    }
  }
  return out;
}

/** Every valid escape decoded once, so `%2F` and `/` meet. Bytes stay bytes: only ASCII is decoded. */
export const percentDecoded = (text) => String(text).replace(/%([0-7][0-9A-F])/g, (_m, hex) => String.fromCharCode(parseInt(hex, 16)));

/**
 * A robots rule against a path, with no regex: `*` is any run, a final `$` ends
 * the path, and a rule is otherwise a prefix. Each part is found once, left to
 * right, so a line of stars can't cost more than one pass per part.
 */
export function globMatch(rule, path) {
  const anchored = rule.endsWith("$");
  const parts = (anchored ? rule.slice(0, -1) : rule).split("*");
  if (!path.startsWith(parts[0])) return false;
  let at = parts[0].length;
  const middle = parts.slice(1, anchored ? -1 : undefined);
  for (const part of middle) {
    const found = path.indexOf(part, at);
    if (found < 0) return false;
    at = found + part.length;
  }
  if (!anchored) return true;
  if (parts.length === 1) return path === parts[0];
  const last = parts.at(-1);
  return path.length - last.length >= at && path.endsWith(last);
}

// The rules that take out a whole site.
const WHOLE_SITE = new Set(["/", "/*"]);

/** The rule that decides one path (RFC 9309), and whether a group names us. The longest match wins; on a tie, Allow. */
function robotsRule(robots, path, tokens) {
  const names = tokens.map((t) => t.toLowerCase());
  const groups = [];
  let cur = null;
  for (const raw of String(robots || "").replace(/^\uFEFF/, "").split(/\r\n|\r|\n/)) {
    const m = /^([a-z-]+)\s*:\s*(.*)$/i.exec(raw.replace(/#.*/, "").trim());
    if (!m) continue;
    const key = m[1].toLowerCase();
    const value = m[2].trim();
    if (key === "user-agent") {
      if (!cur || cur.rules.length) groups.push(cur = { agents: [], rules: [] });
      cur.agents.push(value.split(/[/\s]/)[0].toLowerCase());
    } else if ((key === "allow" || key === "disallow") && cur) cur.rules.push({ allow: key === "allow", value });
  }
  const ours = groups.filter((g) => g.agents.some((a) => names.includes(a)));
  const rules = (ours.length ? ours : groups.filter((g) => g.agents.includes("*"))).flatMap((g) => g.rules).filter((r) => r.value);
  let best = null;
  const target = percentForm(path);
  const plain = percentDecoded(target);
  for (const r of rules) {
    const value = percentForm(r.value);
    // A Disallow also matches on the decoded form, so a reserved character can't slip past it.
    if (!globMatch(value, target) && (r.allow || !globMatch(percentDecoded(value), plain))) continue;
    if (!best || value.length > best.value.length || (value.length === best.value.length && r.allow)) best = { allow: r.allow, value };
  }
  return { ours: ours.length > 0, best };
}

/**
 * Does the rule that decides the homepage take the whole site out? It asks of a
 * group naming us or, with `star`, of the `*` group that stands in when none does.
 */
export function wholeSiteStop(robots, tokens = OPT_OUT_TOKENS, star = false) {
  const { ours, best } = robotsRule(robots, "/", tokens);
  return Boolean(best && !best.allow && WHOLE_SITE.has(best.value)) && ours === !star;
}

/**
 * What robots.txt says about one path for us: "opted_out" when a Disallow wins and
 * a group naming us takes out the whole site, "disallowed" for any other winning
 * Disallow, else "allowed". `*` and a trailing `$` in rules are supported.
 */
export function robotsVerdict(robots, path, tokens = OPT_OUT_TOKENS) {
  const { best } = robotsRule(robots, path, tokens);
  if (!best || best.allow) return "allowed";
  return wholeSiteStop(robots, tokens) ? "opted_out" : "disallowed";
}

/**
 * Sub-measure B for one site: the linked page's robots.txt, then one GET of
 * the page, through the guard. Every hop must stay on the homepage's
 * registrable domain; a redirect elsewhere is not followed (off_site). Only
 * the response headers are graded: no form, no login, no script.
 */
export async function visitAppPage(page, { loopbackPort, now, exclude = new Map(), lookup } = {}) {
  if (!page?.html) return { status: "no_link" };
  const link = findAppLink(page.html, page.url);
  if (!link) return { status: "no_link" };
  const target = new URL(link);
  const category = exclusionFor(target.hostname, exclude);
  if (category) return { status: "excluded", reason: "exclusion_list", category };
  const site = registrableDomain(new URL(page.url).hostname);
  const guard = loopbackPort ? { lookup: loopbackLookup, allowPrivate: true, anyPort: true } : { lookup };
  const budget = makeBudget({ requests: APP_PAGE.requests, budgetMs: APP_PAGE.budgetMs });
  const onHop = (u) => {
    if (registrableDomain(u.hostname) !== site) throw new CheckError("off_site", "Redirect to another site, not followed.", 422, "");
    budget.hop();
  };
  const opts = { ...guard, userAgent: USER_AGENT, onHop };
  let robots = "";
  try {
    const r = await fetchBody(parseTarget(`${target.origin}/robots.txt`, guard), { ...opts, timeout: 4000, maxBytes: 65_536, maxRedirects: 2, accept: "text/plain" });
    if (r.status === 200) robots = r.body;
  } catch {
    // No robots.txt, or not readable: go on, as for the homepage.
  }
  const verdict = robotsVerdict(robots, target.pathname);
  if (verdict === "opted_out") return { status: "opted_out" };
  if (verdict === "disallowed") return { status: "excluded", reason: "robots_disallow_path" };
  try {
    const res = await fetchBody(parseTarget(link, guard), { ...opts, timeout: 6000, maxBytes: APP_PAGE.maxBytes, maxRedirects: APP_PAGE.maxRedirects });
    return {
      status: "ok", httpStatus: res.status, redirects: res.hops.length - 1,
      sameHost: new URL(res.url).hostname === new URL(page.url).hostname,
      checks: grade(res, { now }).checks.filter((c) => APP_CHECKS.includes(c.id)).map(slim),
    };
  } catch (e) {
    return { status: "error", error: e instanceof CheckError ? e.code : "internal" };
  }
}

// ── Aggregates ─────────────────────────────────────────────────────────────

// § 6: z for a 95% interval, and for the decision intervals of the 11
// confirmatory claims (Bonferroni, 1 - 0.05/11 two-sided: z = 2.8376).
export const Z95 = 1.959964;
export const CONFIRMATORY_CLAIMS = 11;
export const Z_DECISION = 2.837597;
// § 6.4: the smallest difference in shares that matters (10 percentage points).
export const SESOI = 0.10;
// § 6.6, pending: B's two directional hypotheses (HB1, HB2), their own family: 1 - 0.05/2 two-sided, z = 2.2414.
export const Z_B = 2.241403;
export const HB = Object.freeze({ framing: "HB1", csp: "HB2" });
// § 6.2: the bootstrap for the median score, fixed so a re-run gives the same interval.
export const BOOTSTRAP = Object.freeze({ resamples: 10_000, seed: 20_20 });

/** Wilson score interval for k of n (95% by default). */
export function wilson(k, n, z = Z95) {
  if (!n) return { p: null, lo: null, hi: null };
  const p = k / n;
  const d = 1 + (z * z) / n;
  const centre = (p + (z * z) / (2 * n)) / d;
  const half = (z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))) / d;
  return { p, lo: Math.max(0, centre - half), hi: Math.min(1, centre + half) };
}

const quantile = (sorted, q) => {
  if (!sorted.length) return null;
  const i = (sorted.length - 1) * q;
  const lo = Math.floor(i), hi = Math.ceil(i);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (i - lo);
};

/** A small seeded generator (mulberry32), so every bootstrap is reproducible. */
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Percentile bootstrap intervals for a statistic of one sample, or of the
 * difference between two (b given: stat(a) - stat(b)), at each of
 * `levels`. Seeded (§ 6.2), so a re-run gives the same interval.
 */
export function bootstrap(a, b, { stat = (xs) => quantile([...xs].sort((x, y) => x - y), 0.5), levels = [0.95], resamples = BOOTSTRAP.resamples, seed = BOOTSTRAP.seed } = {}) {
  if (!a.length || (b && !b.length)) return { estimate: null, ci: [null, null], cis: levels.map(() => [null, null]) };
  const next = rng(seed);
  const draw = (xs) => Array.from(xs, () => xs[Math.floor(next() * xs.length)]);
  const value = (xs, ys) => (ys ? stat(xs) - stat(ys) : stat(xs));
  const out = [];
  for (let i = 0; i < resamples; i++) out.push(value(draw(a), b ? draw(b) : null));
  out.sort((x, y) => x - y);
  const cis = levels.map((l) => [quantile(out, (1 - l) / 2), quantile(out, 1 - (1 - l) / 2)]);
  return { estimate: value(a, b), ci: cis[0], cis };
}

// § 2: the checks the hypotheses name, plus derived ones.
const DERIVED = {
  "https+hsts": (byId) => (byId.https && byId.https.weight > 0 ? byId.https.passed && Boolean(byId.hsts?.passed) : undefined),
  "spf+dmarc": (byId) => (byId.spf?.weight > 0 && byId.dmarc?.weight > 0 ? byId.spf.passed && byId.dmarc.passed : undefined),
};

/** Per check: passed (true/false) or undefined when it could not be judged (weight 0) or does not apply. */
function outcomes(checks) {
  const byId = Object.fromEntries((checks || []).map((c) => [c.id, c]));
  // weight 0 is "could not check" (DNS did not answer, security.txt timed out): unknown, not a fail.
  const out = Object.entries(byId).map(([id, c]) => [id, c.weight > 0 ? c.passed : undefined]);
  for (const [id, fn] of Object.entries(DERIVED)) out.push([id, fn(byId)]);
  return out;
}

function prevalence(records, pick = (r) => r.checks) {
  const tally = {};
  for (const r of records) {
    for (const [id, passed] of outcomes(pick(r))) {
      const t = (tally[id] ||= { n: 0, passed: 0, unknown: 0 });
      if (passed === undefined) t.unknown++;
      else { t.n++; if (passed) t.passed++; }
    }
  }
  return Object.fromEntries(Object.entries(tally).sort(([a], [b]) => a.localeCompare(b)).map(([id, t]) => {
    const w = wilson(t.passed, t.n);
    const d = wilson(t.passed, t.n, Z_DECISION);
    return [id, { ...t, share: w.p, ci95: [w.lo, w.hi], ciDecision: [d.lo, d.hi] }];
  }));
}

// § 2, Q1 to Q7: the band each hypothesis predicts, for one cohort.
export const HYPOTHESES = Object.freeze({
  Q1: { check: "https+hsts", band: [0.45, 0.75] },
  Q2: { check: "csp", band: [0, 0.4] },
  Q3: { check: "framing", band: [0.55, 0.85] },
  Q4: { check: "cookies", band: [0, 0.3] },
  Q5: { check: "caa", band: [0, 0.4] },
  Q6: { check: "spf+dmarc", band: [0.4, 0.7] },
  Q7: { score: "median", band: [50, 75] },
});

/**
 * § 6.5: a band hypothesis against its decision interval. "supported" when
 * the interval lies inside the band, "refuted" when it lies wholly outside,
 * else "inconclusive". A band that starts at 0 is an "under" hypothesis.
 */
export function bandDecision([lo, hi], [from, to]) {
  if (lo === null || hi === null) return "no_data";
  if (lo >= from && hi <= to) return "supported";
  if (hi < from || lo > to) return "refuted";
  return "inconclusive";
}

/**
 * § 6.5, Q8: a predicted direction (+1: startups higher, -1: lower) against
 * the decision interval of the difference (startups minus top sites).
 * "supported" when the interval excludes 0 on the predicted side, "refuted"
 * when it excludes 0 on the other side, "no_meaningful_difference" when it
 * lies within ±SESOI, else "inconclusive".
 */
export function directionDecision([lo, hi], sign, sesoi = SESOI) {
  if (lo === null || hi === null) return "no_data";
  if (sign > 0 ? lo > 0 : hi < 0) return "supported";
  if (sign > 0 ? hi < 0 : lo > 0) return "refuted";
  if (lo >= -sesoi && hi <= sesoi) return "no_meaningful_difference";
  return "inconclusive";
}

const groupBy = (records, key, minGroup) => {
  const groups = {};
  for (const r of records) (groups[key(r)] ||= []).push(r);
  const kept = Object.entries(groups).filter(([, rs]) => rs.length >= minGroup).sort(([a], [b]) => a.localeCompare(b));
  return {
    groups: Object.fromEntries(kept.map(([g, rs]) => [g, { sites: rs.length, medianScore: quantile(rs.map((r) => r.score).sort((a, b) => a - b), 0.5), checks: prevalence(rs) }])),
    suppressed: Object.values(groups).filter((rs) => rs.length < minGroup).length,
  };
};

// § 4.2 and § 6.6: the checks compared between the homepage and the app page of the same site.
export const PAIRED_CHECKS = Object.freeze(["https+hsts", "csp", "framing", "nosniff", "referrer", "cookies"]);

/** § 6.6, pending: sub-measure B. Counts, prevalence on the app page, and the paired comparison. */
function appSection(records) {
  const withB = records.filter((r) => r.app);
  if (!withB.length) return undefined;
  const status = {};
  for (const r of withB) {
    const key = r.app.status === "error" ? `error:${r.app.error}` : r.app.status === "excluded" ? `excluded:${r.app.reason}` : r.app.status;
    status[key] = (status[key] || 0) + 1;
  }
  const ok = withB.filter((r) => r.app.status === "ok");
  const paired = {};
  for (const id of PAIRED_CHECKS) {
    const t = { both: 0, homeOnly: 0, appOnly: 0, neither: 0 };
    for (const r of ok) {
      const home = Object.fromEntries(outcomes(r.checks))[id];
      const app = Object.fromEntries(outcomes(r.app.checks))[id];
      if (home === undefined || app === undefined) continue;
      t[home && app ? "both" : home ? "homeOnly" : app ? "appOnly" : "neither"]++;
    }
    const discordant = t.homeOnly + t.appOnly;
    const w = wilson(t.appOnly, discordant);
    paired[id] = { ...t, n: t.both + t.homeOnly + t.appOnly + t.neither, discordant, appBetterShare: w.p, ci95: [w.lo, w.hi] };
    if (HB[id]) {
      // HB1, HB2: the app page passes more often than the homepage of the same site (share of discordant pairs above 0.5).
      const d = wilson(t.appOnly, discordant, Z_B);
      Object.assign(paired[id], { hypothesis: HB[id], ciDecision: [d.lo, d.hi], decision: d.lo === null ? "no_data" : d.lo > 0.5 ? "supported" : d.hi < 0.5 ? "refuted" : "inconclusive" });
    }
  }
  return {
    sites: { withHomepage: withB.length, visited: ok.length, ...status, sameHost: ok.filter((r) => r.app.sameHost).length },
    checks: prevalence(ok, (r) => r.app.checks),
    paired,
  };
}

/** The aggregate: counts, per-check prevalence, the score distribution, groups. No site names. */
/** Every record that didn't grade, by what happened to it. */
export function statusCounts(records) {
  const status = {};
  for (const r of records.filter((x) => x.status !== "ok")) {
    const key = r.status === "error" ? `error:${r.error}` : r.status === "excluded" ? `excluded:${r.reason}` : r.status;
    status[key] = (status[key] || 0) + 1;
  }
  return status;
}

export function aggregate(records, meta = {}, { orgOf = registrableDomain } = {}) {
  const ok = records.filter((r) => r.status === "ok");
  const status = statusCounts(records);
  const scores = ok.map((r) => r.score).sort((a, b) => a - b);
  const histogram = Array.from({ length: 10 }, (_, i) => ({ from: i * 10, to: i === 9 ? 100 : i * 10 + 9, sites: 0 }));
  for (const s of scores) histogram[Math.min(9, Math.floor(s / 10))].sites++;
  const exclusionCategories = {};
  for (const r of records.filter((x) => x.reason === "exclusion_list")) exclusionCategories[r.category || "unknown"] = (exclusionCategories[r.category || "unknown"] || 0) + 1;
  const byGroup = groupBy(ok, (r) => r.group, MIN_GROUP);
  const checks = prevalence(ok);
  const median = bootstrap(scores, null, { levels: [0.95, 1 - 0.05 / CONFIRMATORY_CLAIMS] });
  const medianDecision = { ci: median.cis[1] };
  // § 6.3, sensitivity: one record per registrable domain the homepage ended on, first by rank.
  const seenSite = new Set();
  const dedup = ok.filter((r) => {
    const site = orgOf(r.finalHost || r.host);
    if (seenSite.has(site)) return false;
    seenSite.add(site);
    return true;
  });
  const hypotheses = Object.fromEntries(Object.entries(HYPOTHESES).map(([q, h]) => {
    if (h.score) return [q, { band: h.band, estimate: quantile(scores, 0.5), ciDecision: medianDecision.ci, decision: bandDecision(medianDecision.ci, h.band) }];
    const c = checks[h.check];
    return [q, { check: h.check, band: h.band, estimate: c?.share ?? null, ciDecision: c?.ciDecision ?? [null, null], decision: bandDecision(c?.ciDecision ?? [null, null], h.band) }];
  }));
  const edge = groupBy(ok, (r) => r.platform?.edge || "unknown", MIN_GROUP);
  const builder = groupBy(ok, (r) => r.platform?.builder || "unknown", MIN_GROUP);
  const app = appSection(ok);
  return {
    experiment: "E20", ...meta,
    sites: { listed: records.length, visited: ok.length, ...status },
    exclusionCategories,
    checks,
    score: {
      n: scores.length,
      mean: scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : null,
      min: scores[0] ?? null, p10: quantile(scores, 0.1), p25: quantile(scores, 0.25), median: quantile(scores, 0.5),
      p75: quantile(scores, 0.75), p90: quantile(scores, 0.9), max: scores.at(-1) ?? null,
      medianCi95: median.cis[0], medianCiDecision: medianDecision.ci,
      histogram,
    },
    hypotheses,
    byGroup: byGroup.groups,
    groupsSuppressed: byGroup.suppressed,
    byPlatform: { edge: edge.groups, builder: builder.groups, suppressed: edge.suppressed + builder.suppressed },
    sensitivity: { onePerFinalSite: { sites: dedup.length, medianScore: quantile(dedup.map((r) => r.score).sort((a, b) => a - b), 0.5), checks: prevalence(dedup) } },
    ...(app ? { app } : {}),
  };
}

/** Newcombe's hybrid score interval (method 10) for the difference p1 − p2. */
export function newcombe(k1, n1, k2, n2, z = Z95) {
  const a = wilson(k1, n1, z), b = wilson(k2, n2, z);
  if (a.p === null || b.p === null) return { diff: null, ci95: [null, null] };
  const diff = a.p - b.p;
  return {
    diff,
    ci95: [diff - Math.sqrt((a.p - a.lo) ** 2 + (b.hi - b.p) ** 2), diff + Math.sqrt((a.hi - a.p) ** 2 + (b.p - b.lo) ** 2)],
  };
}

/** Standard normal CDF (Abramowitz and Stegun 7.1.26, error under 1.5e-7). */
function phi(x) {
  const t = 1 / (1 + 0.3275911 * Math.abs(x) / Math.SQRT2);
  const y = 1 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * Math.exp(-(x * x) / 2);
  return x >= 0 ? (1 + y) / 2 : (1 - y) / 2;
}

/** Two-sided p-value of the pooled two-proportion z test (§ 6.4, secondary checks only). */
export function twoProportionP(k1, n1, k2, n2) {
  if (!n1 || !n2) return null;
  const p = (k1 + k2) / (n1 + n2);
  const se = Math.sqrt(p * (1 - p) * (1 / n1 + 1 / n2));
  if (!se) return 1;
  return Math.min(1, 2 * (1 - phi(Math.abs(k1 / n1 - k2 / n2) / se)));
}

/** Benjamini–Hochberg adjusted p-values (q-values), in the input's order; nulls stay null. */
export function benjaminiHochberg(ps) {
  const idx = ps.map((p, i) => [p, i]).filter(([p]) => p !== null).sort((a, b) => a[0] - b[0]);
  const m = idx.length;
  const out = ps.map(() => null);
  let min = 1;
  for (let r = m; r >= 1; r--) {
    const [p, i] = idx[r - 1];
    min = Math.min(min, (p * m) / r);
    out[i] = min;
  }
  return out;
}

// § 2, Q8: the predicted direction of startups (b) minus top sites (a) on the confirmatory checks.
export const Q8 = Object.freeze({ "https+hsts": +1, csp: -1, caa: -1, "spf+dmarc": -1 });

/**
 * Per check present in both aggregates: share in each and the difference
 * b − a (startups minus top sites when a is E20 and b is E20b), with a 95%
 * interval. The four Q8 checks also get a decision interval and a decision;
 * every other check gets a two-sided p-value and a Benjamini–Hochberg
 * q-value, and is exploratory. With raw scores, the difference in median
 * score gets a seeded bootstrap interval.
 */
export function compare(a, b, { scoresA, scoresB } = {}) {
  const out = {};
  for (const id of Object.keys(a.checks).filter((k) => b.checks[k])) {
    const x = a.checks[id], y = b.checks[id];
    const d = newcombe(y.passed, y.n, x.passed, x.n);
    out[id] = { a: x.share, b: y.share, diff: d.diff, ci95: d.ci95 };
    if (Q8[id]) {
      const dd = newcombe(y.passed, y.n, x.passed, x.n, Z_DECISION);
      Object.assign(out[id], { confirmatory: true, predicted: Q8[id] > 0 ? "higher" : "lower", ciDecision: dd.ci95, decision: directionDecision(dd.ci95, Q8[id]) });
    } else {
      out[id].p = twoProportionP(y.passed, y.n, x.passed, x.n);
    }
  }
  const secondary = Object.keys(out).filter((id) => !out[id].confirmatory);
  const q = benjaminiHochberg(secondary.map((id) => out[id].p));
  secondary.forEach((id, i) => { out[id].q = q[i]; });
  const result = { a: a.cohort, b: b.cohort, direction: "b minus a", checks: out };
  if (scoresA?.length && scoresB?.length) {
    const m = bootstrap(scoresB, scoresA);
    result.medianScoreDiff = { estimate: m.estimate, ci95: m.ci };
  }
  return result;
}

// ── The run ────────────────────────────────────────────────────────────────

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Visits every row, `concurrency` at a time, each worker waiting `delayMs`
 * between sites (both fixed to § 4 unless on loopback). `exclude` is the
 * exclusion list (readExclusions); a listed host is never visited. Appends each record to raw.jsonl as it lands, then writes
 * aggregate.json. Returns { records, aggregate }.
 */
export async function runStudy(rows, { cohort, out, loopbackPort, concurrency = LIMITS.concurrency, delayMs = LIMITS.delayMs, exclude = new Map(), appPage = false, meta = {}, onRecord } = {}) {
  // § 4, decided 29 Oct: a run that leaves loopback uses the registered rate, whatever was passed.
  if (!loopbackPort) { concurrency = LIMITS.concurrency; delayMs = LIMITS.delayMs; }
  concurrency = Math.max(1, Math.min(LIMITS.maxConcurrency, Math.floor(concurrency)));
  delayMs = Math.max(0, Math.floor(delayMs));
  mkdirSync(out, { recursive: true });
  // Belt and braces: the raw results never enter git, wherever --out points.
  writeFileSync(join(out, ".gitignore"), "*\n");
  const raw = join(out, "raw.jsonl");
  writeFileSync(raw, "");
  const records = new Array(rows.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, rows.length) }, async () => {
    while (next < rows.length) {
      const k = next++;
      const row = rows[k];
      const category = exclusionFor(row.host, exclude);
      records[k] = category
        ? { ...row, at: new Date().toISOString(), status: "excluded", reason: "exclusion_list", category }
        : await visit(row, { loopbackPort, appPage, exclude });
      appendFileSync(raw, JSON.stringify({ cohort, ...records[k] }) + "\n");
      onRecord?.(records[k], k);
      if (next < rows.length && delayMs) await sleep(delayMs);
    }
  }));
  const agg = aggregate(records, { cohort, ...meta, concurrency, delayMs, appPage, userAgent: USER_AGENT });
  writeFileSync(join(out, "aggregate.json"), JSON.stringify(agg, null, 2) + "\n");
  return { records, aggregate: agg };
}

/**
 * Loopback self-test: four names, all pinned to the mock server on
 * 127.0.0.1 (one is an app. host, one is on the exclusion list). Checks that each site got exactly /robots.txt, / and
 * /.well-known/security.txt, once each, and that aggregates came out.
 */
export async function selfTest({ out } = {}) {
  const { startMockServer } = await import(pathToFileURL(join(ROOT, "tests", "fixtures", "mock-server.js")).href);
  const mock = await startMockServer(0);
  try {
    const rows = readList("1,site-1.e20-selftest.example.com\n2,site-2.e20-selftest.example.com\n3,app.e20-selftest.example.com\n2,site-2.e20-selftest.example.com\n4,ministry.e20-selftest.gov\n", "tranco");
    const exclude = readExclusions("# self-test\ngov government\n");
    const dir = out || join(ROOT, "bench", "front-door", "results", `selftest-${Date.now()}`);
    const { records, aggregate: agg } = await runStudy(rows, { cohort: "tranco", out: dir, loopbackPort: mock.port, delayMs: 0, exclude, meta: { selfTest: true } });
    const paths = mock.requests.map((r) => `${r.method} ${r.url}`).sort();
    const expected = ["GET /", "GET /", "GET /.well-known/security.txt", "GET /.well-known/security.txt", "GET /robots.txt", "GET /robots.txt"];
    const problems = [];
    if (rows.length !== 4) problems.push(`expected 4 unique rows, got ${rows.length}`);
    if (JSON.stringify(paths) !== JSON.stringify(expected)) problems.push(`unexpected requests: ${paths.join(", ")}`);
    if (records.filter((r) => r.status === "ok").length !== 2) problems.push("expected 2 visited sites");
    if (records.find((r) => r.host.startsWith("app."))?.status !== "excluded") problems.push("app. host was not excluded");
    if (records.find((r) => r.host.endsWith(".gov"))?.category !== "government" || agg.exclusionCategories.government !== 1) problems.push("exclusion-list host was not excluded");
    if (agg.sites.visited !== 2 || !agg.checks.https) problems.push("aggregate is incomplete");
    if (JSON.stringify(agg).includes("e20-selftest")) problems.push("aggregate names a site");
    return { ok: problems.length === 0, problems, requests: paths, out: dir, aggregate: agg };
  } finally {
    await mock.close();
  }
}

// ── CLI ────────────────────────────────────────────────────────────────────

function flag(args, name) {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
}

async function main(args) {
  if (args.includes("--self-test")) {
    const r = await selfTest({ out: flag(args, "--out") });
    console.log(r.ok ? `E20 self-test passed: ${r.requests.length} requests, all to 127.0.0.1 (${r.out})` : `E20 self-test FAILED:\n  ${r.problems.join("\n  ")}`);
    return r.ok ? 0 : 1;
  }
  if (args.includes("--compare")) {
    const i = args.indexOf("--compare");
    const files = [args[i + 1], args[i + 2]];
    const [a, b] = files.map((f) => JSON.parse(readFileSync(f, "utf8")));
    // The median-score bootstrap needs the scores; they are read from the private raw.jsonl next to each aggregate, and only the interval is printed.
    const scores = files.map((f) => {
      const raw = join(dirname(resolve(f)), "raw.jsonl");
      return existsSync(raw) ? readFileSync(raw, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)).filter((r) => r.status === "ok").map((r) => r.score) : undefined;
    });
    console.log(JSON.stringify(compare(a, b, { scoresA: scores[0], scoresB: scores[1] }), null, 2));
    return 0;
  }
  const listFile = flag(args, "--list");
  if (!listFile) {
    console.error("Usage: node bench/front-door/run.mjs --self-test | --list <file> --loopback <port> [--app-page] | --compare <a/aggregate.json> <b/aggregate.json>");
    return 2;
  }
  const cohort = flag(args, "--cohort") || "tranco";
  if (!COHORTS[cohort]) { console.error(`--cohort must be one of ${Object.keys(COHORTS).join(", ")}`); return 2; }
  const loopbackPort = flag(args, "--loopback") ? Number(flag(args, "--loopback")) : undefined;
  if (loopbackPort !== undefined && !(loopbackPort > 0 && loopbackPort < 65536)) { console.error("--loopback needs a port"); return 2; }
  const bytes = readFileSync(listFile);
  const listHash = sha256(bytes);
  const excludeBytes = flag(args, "--exclude") ? readFileSync(flag(args, "--exclude")) : null;
  const excludeHash = excludeBytes ? sha256(excludeBytes) : undefined;
  const rateFlags = ["--concurrency", "--delay", "--limit", "--app-page"].filter((f) => args.includes(f));
  const preregText = existsSync(PREREG) ? readFileSync(PREREG, "utf8") : "";
  // § 4.2: B is set by the prereg on a registered run, and by --app-page on loopback only.
  const appPage = loopbackPort ? args.includes("--app-page") : appPageAdopted(preregText);
  let exclude;
  try {
    authorize({ loopback: Boolean(loopbackPort), registered: flag(args, "--registered"), cohort, listHash, excludeHash, rateFlags, preregText });
    exclude = excludeBytes ? readExclusions(excludeBytes.toString("utf8")) : new Map();
  } catch (e) {
    console.error(e.message);
    return 3;
  }
  const limit = Math.min(LIMITS.maxSites, Number((loopbackPort && flag(args, "--limit")) || COHORTS[cohort].defaultLimit));
  const rows = readList(bytes.toString("utf8"), cohort).slice(0, limit);
  const out = resolve(flag(args, "--out") || join(ROOT, "bench", "front-door", "results", `${cohort}-${new Date().toISOString().replace(/[:.]/g, "-")}`));
  const { aggregate: agg } = await runStudy(rows, {
    cohort, out, loopbackPort, exclude, appPage,
    concurrency: Number(flag(args, "--concurrency") || LIMITS.concurrency),
    delayMs: Number(flag(args, "--delay") ?? LIMITS.delayMs),
    meta: { listSha256: listHash, exclusionSha256: excludeHash ?? null, loopback: Boolean(loopbackPort), startedFrom: process.version },
    onRecord: (r, k) => process.stderr.write(`\r${k + 1}/${rows.length} ${r.status.padEnd(9)}`),
  });
  process.stderr.write("\n");
  console.log(`E20 ${cohort}: ${agg.sites.visited} of ${agg.sites.listed} visited. Raw (private): ${join(out, "raw.jsonl")}. Aggregate: ${join(out, "aggregate.json")}`);
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}
