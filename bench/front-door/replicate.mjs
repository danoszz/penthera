#!/usr/bin/env node
/**
 * E20-R runner: passes over eleven fixed lists, from one published address.
 * Protocol: docs/research/prereg/E20r-front-door-replication.md, Amendment 2.
 *
 *   node bench/front-door/replicate.mjs --self-test
 *       Loopback only: visits tests/fixtures/mock-server.js.
 *   node bench/front-door/replicate.mjs (--pass 3 | --pass 2 | --pilot <n> [--pilot-round <k>]) --registered E20R --lists <dir> --exclude <file> --homepage-only <file> --removals <file> --prior-optouts <file> --pilot-dropped <file>
 *       The registered run. Refused unless the prereg says Registered, Amendment
 *       2 is adopted, no placeholder is left, the checkout is a clean commit on
 *       the tip of origin main, this machine's one public IPv4 is the registered address, the
 *       classifier and suffix list match their frozen hashes, and every list
 *       matches its hash. Pass 1 ran on 30 October 2026 and is refused. --pilot
 *       takes exactly 50 sites from the claim lists, one fixed folder per round, two live rounds at most,
 *       and writes pilot-sites.txt with its hash in the manifest. A later round
 *       and pass 2 need --pilot-dropped to hold exactly the sites of every earlier
 *       round. Pass 2 has one fixed folder, so a second start can't revisit sites.
 *       Pass 3 exists only under Amendment 3, after pass 2 stopped: it has its own fixed
 *       folder, and needs that stopped pass reviewed and pruned, and a pilot round after it.
 *       Rate, order and sub-measures are fixed; no flag changes them. --prior-optouts
 *       must match its frozen hash. --removals is required, may be empty, and only
 *       takes sites out, so its hash is recorded in the manifest, not checked.
 *
 * Reuses the E20 visit (run.mjs) under the strict robots rules: robots.txt at
 * every origin, RFC 9309 for an unreadable file, and the exclusion list on every
 * hop. The grader is unchanged. New per site: stored evidence and response
 * labels (classify.mjs), and DNS read on the listed domain whether or not HTTP
 * worked. Never a way around a bot defense: one honest User-Agent, one address,
 * no browser or TLS imitation, no challenge solving, no retry after a block
 * (Amendment 2). A host on two lists is visited once per pass and counted in both.
 * IPv4 only, so that one published address accounts for every request.
 * raw.jsonl is private; aggregate.json names no site; manifest.json records
 * the code and environment at the start and at the end.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { isIP } from "node:net";
import { chmodSync, readFileSync, readdirSync, renameSync, writeFileSync, mkdirSync, appendFileSync, existsSync, statSync } from "node:fs";
import { Resolver } from "node:dns/promises";
import { homedir, networkInterfaces, platform, release } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Worker } from "node:worker_threads";
import {
  readList, readExclusions, exclusionFor, hostOf, aggregate, ipv4Lookup, sha256, redact, slim, LIMITS, USER_AGENT, OPT_OUT_TOKENS, MIN_GROUP, STUB_DNS, ROBOTS_REDIRECTS, ROBOTS_MAX_BYTES,
} from "./run.mjs";
import { EXCERPT_BYTES, INPUT_CAP_CHARS, PAGE_TEXT_CHARS, scrub, SOFT_MAX_CHARS } from "./classify.mjs";
import { pslSha256, PSL_VERSION, siteKey, siteOrg } from "./psl.mjs";
import { falseFireReviewed, LEGACY_CLASSIFIER_SHA256, MAX_RESOLVER_FAILURES, pageTextMissed, PRIVACY_STOP, purgeState, resolverFailed, sealHash, stopRules } from "./record-checks.mjs";
import { scoreOf } from "../../api/_lib/grade.mjs";
import { dnsChecks } from "../../api/_lib/dns.mjs";
import { isPublicIp } from "../../api/_lib/guard.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const PREREG_R = join(ROOT, "docs", "research", "prereg", "E20r-front-door-replication.md");
export const STUDY_PAGE = join(ROOT, "site", "pages", "research-e20.md");
export const CLASSIFIER = join(ROOT, "bench", "front-door", "classify.mjs");
export const RESULTS = join(ROOT, "bench", "front-door", "results");
export const PASS2_OUT = join(RESULTS, "e20r-pass2");
// Outside results/, so deleting a round's folder can't delete its line. Append only.
export const ROUNDS_LOG = join(homedir(), ".penthera-e20r2-rounds.log");
// Touch this file to stop a run between sites: a complaint, or anything else that can't wait.
export const STOP_FILE = join(homedir(), ".penthera-e20r2-stop");
// Over this share of the sites, a removal list is a mistake, not owners asking.
export const MAX_REMOVED_SHARE = 0.05;
// Pinned: a checkout's `origin` is whatever someone set it to.
export const REMOTE_URL = "https://github.com/danoszz/penthera.git";
const GIT_TIMEOUT_MS = 15_000;
const SECRET = Object.freeze({ mode: 0o600 });
export const VISIT_WORKER = fileURLToPath(new URL("./visit-worker.mjs", import.meta.url));
// The thread's own timers fire first when its event loop is free.
const WORKER_GRACE_MS = 1500;

// § 3: cohort, list file, list format, and the label its hash has in the prereg.
export const R_COHORTS = Object.freeze({
  T1k: { file: "tranco-ZJ8PG-top1000.csv", format: "tranco" },
  "YC-new": { file: "yc-fall2026-summer2026-2026-10-29.csv", format: "yc" },
  "YC-25": { file: "yc-2025.csv", format: "yc" },
  "YC-old": { file: "yc-old.csv", format: "yc" },
  "YC-scale": { file: "yc-scale.csv", format: "yc" },
  T10k: { file: "tranco-ZJ8PG-1k-10k-sample.csv", format: "tranco" },
  T100k: { file: "tranco-ZJ8PG-10k-100k-sample.csv", format: "tranco" },
  Europe: { file: "europe-indexes.csv", format: "yc" },
  ShowHN: { file: "showhn-sample.csv", format: "yc" },
  SP500: { file: "sp500.csv", format: "yc" },
  "NL-Cbw": { file: "nl-cbw.csv", format: "yc", homepageOnly: true },
});
// Pass 1 ran with 2020. Pass 2 keeps the seed § 5 registered for it. The pilot draws its sample and its order from its own.
export const PASS_SEED = Object.freeze({ 1: 2020, 2: 2021, 3: 2021, pilot: 2026 });
export const PILOT_MAX = 50;
export const PILOT_MIN = 50;
// A third live round is a new decision, not a retry.
export const MAX_LIVE_ROUNDS = 2;
// Pass 2 watches its last records, so a fault stops it, not its report.
export const ROLLING_WINDOW = 200;
// Amendment 2: more time per site, so a slow answer is not a lost site. Per-request timeouts stay 6 s and 4 s, and the request rate does not change.
export const V2_LIMITS = Object.freeze({ siteBudgetMs: 15_000, siteHardCapMs: 30_000 });
// Amendment 2: the cohorts claims C1 to C11 use. Pilot sites come from these and leave pass 2.
export const CLAIM_COHORTS = Object.freeze(["T1k", "YC-new", "YC-25", "YC-old", "T100k"]);
export const R_EXCLUSION_LABEL = "E20-R exclusion list";
export const R_HOMEPAGE_LABEL = "E20-R homepage-only list";

export const MX_RULES = Object.freeze([
  ["google", /(^|\.)(google|googlemail)\.com$/i], ["microsoft", /\.outlook\.com$/i], ["proofpoint", /pphosted\.com$/i],
  ["mimecast", /mimecast\.com$/i], ["amazon", /amazonaws\.com$|amazonses\.com$/i], ["zoho", /zoho\./i], ["proton", /protonmail\.ch$/i],
]);
export const NS_RULES = Object.freeze([
  ["cloudflare", /\.ns\.cloudflare\.com$/i], ["route53", /awsdns/i], ["google", /googledomains\.com$|\.google$|google\.com$/i],
  ["vercel", /vercel-dns\.com$/i], ["godaddy", /domaincontrol\.com$/i], ["namecheap", /registrar-servers\.com$/i], ["akamai", /akam\.net$/i],
]);
const providerOf = (host, rules) => rules.find(([, re]) => re.test(host))?.[0] ?? "other";

const defaultResolver = () => new Resolver({ timeout: DNS_TIMEOUT_MS, tries: 2 });
export const DNS_TIMEOUT_MS = 5000;

/** One provider label for a domain's MX and NS records. Only the label is kept. */
export async function dnsProviders(domain, { mx = (d) => defaultResolver().resolveMx(d), ns = (d) => defaultResolver().resolveNs(d) } = {}) {
  const read = async (fn, pick, rules) => {
    try {
      const answers = (await fn(domain)).map(pick).filter(Boolean);
      if (!answers.length) return "none";
      const labels = [...new Set(answers.map((h) => providerOf(String(h).replace(/\.$/, ""), rules)))].sort();
      return labels.join("+");
    } catch (e) {
      return e?.code === "ENODATA" || e?.code === "ENOTFOUND" ? "none" : "unknown";
    }
  };
  return { mx: await read(mx, (r) => r.exchange, MX_RULES), ns: await read(ns, (r) => r, NS_RULES) };
}

/** p, sp and pct of a DMARC record, lower case, or null when absent. */
export function dmarcTags(record) {
  const tag = (name) => { const v = new RegExp(`(?:^|;)\\s*${name}\\s*=\\s*([^;\\s]+)`, "i").exec(String(record))?.[1]?.toLowerCase(); return v === undefined ? null : scrub(v).slice(0, 40); };
  return { p: tag("p"), sp: tag("sp"), pct: tag("pct") };
}

const POLICIES = new Set(["none", "quarantine", "reject"]);

/**
 * One name's DMARC reading, by RFC 7489 (Amendment 2 says why). A record counts
 * only when it is the one v=DMARC1 record and has a known `p`. `inherited` means
 * it came from the organization domain, where `sp` then applies. `declared` reads
 * `p` alone. `enforcing` is the applicable policy with `pct` above 0. `pct` and
 * `sp` stay apart: `partial` and `spNone` report them, and neither fails a domain.
 */
export function dmarcReading(records, { inherited = false } = {}) {
  const found = records.filter((t) => /^v=DMARC1\s*(;|$)/i.test(t.trim()));
  const tags = found.length === 1 ? dmarcTags(found[0]) : { p: null, sp: null, pct: null };
  const valid = found.length === 1 && POLICIES.has(tags.p);
  const policy = valid ? (inherited && POLICIES.has(tags.sp) ? tags.sp : tags.p) : null;
  const n = /^\d{1,3}$/.test(tags.pct ?? "") ? Number(tags.pct) : 100;
  const pct = n > 100 ? 100 : n;
  const strong = policy === "quarantine" || policy === "reject";
  return {
    valid, records: found.length, inherited, policy, pct,
    declared: valid && (tags.p === "quarantine" || tags.p === "reject"),
    enforcing: strong && pct > 0,
    reject: policy === "reject" && pct > 0,
    partial: strong && pct > 0 && pct < 100,
    spNone: tags.sp === "none",
  };
}

/** What one DNS query came back with. Only a resolver failure means "we don't know". */
export function dnsOutcome(e) {
  if (e?.code === "ENOTFOUND" || e?.code === "NXDOMAIN") return "nxdomain";
  if (e?.code === "ENODATA") return "nodata";
  return `resolver-failure:${e?.code || "unknown"}`;
}
const OUTCOME_RANK = (o) => (o === "answer" ? 3 : o?.startsWith("resolver-failure") ? 2 : o === "nodata" ? 1 : 0);
const failedRead = (o) => o?.startsWith("resolver-failure");

/**
 * RFC 8659 § 3: the first name with CAA records decides, from the host up its
 * parents, TLD included, root excluded. `found` is null when the resolver failed
 * before an answer, so unknown is never "no CAA".
 */
export async function caaTree(host, resolveCaa) {
  const labels = String(host).toLowerCase().replace(/\.+$/, "").split(".");
  for (let i = 0; i < Math.min(labels.length, 16); i++) {
    const name = labels.slice(i).join(".");
    try {
      const found = await resolveCaa(name);
      if (found.length) return { found: true, at: name, inherited: i > 0, issuers: found.map((r) => r.issue ?? r.issuewild).filter((v) => v !== undefined).map((v) => scrub(String(v).split(";")[0].trim()).slice(0, 80)).slice(0, 8) };
    } catch (e) {
      const outcome = dnsOutcome(e);
      if (failedRead(outcome)) return { found: null, at: name, outcome };
    }
  }
  return { found: false };
}

const both = (a, b) => (a === null || b === null ? null : a && b);

/**
 * DNS for one name, independent of any HTTP answer. Beside the registered reading
 * (the grader's checks, on its own parser's domain): the SPF record as published,
 * DMARC by `dmarcReading` on the host, then on the organization domain, CAA by
 * `caaTree`, and the MX and NS labels. `outcomes` says per query what came back.
 * A value is null when the resolver failed: that is unknown, never a failed check.
 */
export async function readDomain(host, dns = {}, memo = {}) {
  const r = dns.resolveTxt ? null : defaultResolver();
  const name = String(host).toLowerCase().replace(/\.+$/, "");
  const mailHost = siteKey(name);
  const domain = siteOrg(mailHost);
  const outcomes = {};
  const queries = [];
  // CAA walks up from the host: the strongest outcome over the names decides.
  const note = (key, o) => { if (OUTCOME_RANK(o) >= OUTCOME_RANK(outcomes[key])) outcomes[key] = o; };
  const heard = new Set();
  const watched = (type, keyOf, fn) => {
    const asked = (memo[type] ??= new Map());
    return (query) => {
      if (!asked.has(query)) {
        const entry = { type, name: query, outcome: null, answers: 0 };
        const answer = (async () => {
          try {
            const a = await fn(query);
            entry.outcome = a.length ? "answer" : "nodata";
            entry.answers = a.length;
            return a;
          } catch (e) {
            entry.outcome = dnsOutcome(e);
            throw e;
          }
        })();
        asked.set(query, { entry, answer });
      }
      const hit = asked.get(query);
      if (!heard.has(`${type} ${query}`)) {
        heard.add(`${type} ${query}`);
        queries.push(hit.entry);
        hit.answer.then(() => note(keyOf(query), hit.entry.outcome), () => note(keyOf(query), hit.entry.outcome));
      }
      return hit.answer;
    };
  };
  const txt = watched("TXT", (n) => (n === domain ? "txt" : n === `_dmarc.${domain}` ? "dmarc" : "other"), (n) => (dns.resolveTxt ? dns.resolveTxt(n) : r.resolveTxt(n)));
  const caa = watched("CAA", () => "caa", (n) => (dns.resolveCaa ? dns.resolveCaa(n) : r.resolveCaa(n)));
  const read = async (query) => {
    try {
      return { records: (await txt(query)).map((t) => (Array.isArray(t) ? t.join("") : String(t))) };
    } catch (e) {
      return { records: [], failed: failedRead(dnsOutcome(e)) };
    }
  };
  const checks = await dnsChecks(name, { dns: { resolveTxt: txt, resolveCaa: caa }, dnsTimeout: DNS_TIMEOUT_MS * 3 }).catch(() => []);
  const of = (id) => { const c = checks.find((x) => x.id === id); return !c || c.weight === 0 ? null : c.passed; };
  const spfRead = await read(domain);
  const spfRecords = spfRead.records.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
  const own = mailHost === domain ? null : await read(`_dmarc.${mailHost}`);
  const ownRecord = own && dmarcReading(own.records).records > 0;
  const orgRead = ownRecord ? null : await read(`_dmarc.${domain}`);
  const dmarcFailed = Boolean(own?.failed || orgRead?.failed);
  const dmarcRecords = ownRecord ? own.records : orgRead.records;
  const reading = dmarcReading(dmarcRecords, { inherited: Boolean(own) && !ownRecord });
  const nullable = (v) => (dmarcFailed ? null : v);
  const spfPresent = spfRead.failed ? null : spfRecords.length === 1;
  const spf = of("spf"), dmarc = of("dmarc");
  const providers = await dnsProviders(domain, { mx: watched("MX", () => "mx", dns.mx ?? ((d) => defaultResolver().resolveMx(d))), ns: watched("NS", () => "ns", dns.ns ?? ((d) => defaultResolver().resolveNs(d))) });
  const tree = await caaTree(name, caa);
  for (const q of queries) q.outcome ??= "resolver-failure:timeout";
  for (const key of ["txt", "dmarc", "caa", "mx", "ns"]) outcomes[key] ??= "resolver-failure:timeout";
  return {
    domain, ...providers, outcomes, queries,
    // false only on NXDOMAIN, null when the resolver failed.
    exists: outcomes.ns === "nxdomain" ? false : failedRead(outcomes.ns) ? null : true,
    // The registered reading: the grader's own checks, read here and not in the visit.
    spf, dmarc, caa: of("caa"), "spf+dmarc": both(spf, dmarc), registeredChecks: checks.map(slim),
    // Amendment 2. A record that exists: includes, redirects and lookup limits are not validated.
    spfRecordPresent: spfPresent,
    spfRecord: spfRecords.join(" | ").slice(0, 2048),
    dmarcReading: { ...reading, declared: nullable(reading.declared), enforcing: nullable(reading.enforcing), reject: nullable(reading.reject) },
    "spf-record+dmarc-declared": both(spfPresent, nullable(reading.declared)),
    "spf-record+dmarc-enforcing": both(spfPresent, nullable(reading.enforcing)),
    "spf-record+dmarc-reject": both(spfPresent, nullable(reading.reject)),
    dmarcTags: dmarcRecords.filter((t) => /^v=DMARC1/i.test(t.trim())).length === 1 ? dmarcTags(dmarcRecords.find((t) => /^v=DMARC1/i.test(t.trim()))) : { p: null, sp: null, pct: null },
    dmarcRecord: scrub(redact(dmarcRecords.filter((t) => /^v=DMARC1/i.test(t.trim())).join(" | ").slice(0, 4096))).slice(0, 400),
    caaTree: tree,
  };
}

/** The listed name always, and the final host too when a redirect moved. One organization asks each name once. */
export async function siteDns(host, finalHost, dns = {}) {
  const memo = {};
  const listed = await readDomain(host, dns, memo);
  if (!finalHost || isIP(finalHost.replace(/^\[|\]$/g, "")) || finalHost === host) return { listed };
  const otherOrg = siteOrg(finalHost) !== siteOrg(host);
  return { listed, final: await readDomain(finalHost, dns, otherOrg ? {} : memo), finalOtherOrg: otherOrg };
}

/** mulberry32, so an order can be rebuilt from its seed. */
export function seeded(seed) {
  let t = seed >>> 0;
  return () => {
    t = (t + 0x6d2b79f5) >>> 0;
    let x = Math.imul(t ^ (t >>> 15), 1 | t);
    x = (x + Math.imul(x ^ (x >>> 7), 61 | x)) ^ x;
    return ((x ^ (x >>> 14)) >>> 0) / 2 ** 32;
  };
}

/** § 5: Fisher–Yates over the rows, sorted by host first so the file order cannot matter. */
export function shuffled(rows, seed) {
  const a = [...rows].sort((x, y) => (x.host < y.host ? -1 : x.host > y.host ? 1 : 0));
  const r = seeded(seed);
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(r() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/**
 * One row per site; `cohorts` lists every list it is on, each with its rank and
 * group. example.com and www.example.com are one site: one visit per site.
 */
export function mergeCohorts(lists) {
  const bySite = new Map();
  for (const [cohort, rows] of Object.entries(lists)) {
    for (const { host, rank, group } of rows) {
      const site = siteKey(host);
      if (!bySite.has(site)) bySite.set(site, { host, cohorts: {} });
      bySite.get(site).cohorts[cohort] = { rank, group };
    }
  }
  return [...bySite.values()];
}

/**
 * The pilot: `n` sites, taken in turn from each claim list's own seeded order.
 * Sites the run would not visit are left out first, and that includes earlier
 * pilot sites, so a rerun after a rule change draws other sites.
 */
export function pilotSample(rows, n, { seed = PASS_SEED.pilot, exclude = new Map() } = {}) {
  const usable = rows.filter((r) => !exclusionFor(r.host, exclude));
  const queues = CLAIM_COHORTS.map((c) => shuffled(usable.filter((r) => r.cohorts[c]), seed));
  const picked = new Map();
  for (let i = 0; picked.size < n && queues.some((q) => i < q.length); i++) {
    for (const q of queues) {
      if (i < q.length && picked.size < n) picked.set(q[i].host, q[i]);
    }
  }
  return [...picked.values()];
}

/** The hash the prereg records for a cohort list, or null. */
export function recordedHashR(preregText, label) {
  const esc = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const m = new RegExp(`\\|\\s*${esc} SHA-256\\s*\\|\\s*\`([0-9a-f]{64})\``).exec(preregText);
  return m ? m[1] : null;
}

const PLACEHOLDER = /<[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+[^>]*>/;
export const sourceAddressOf = (preregText) => /^\|\s*Source address\s*\|\s*`([\d.]+)`/m.exec(preregText)?.[1] ?? null;

/** Amendment 3 counts only when its row and its own status line both say so. */
export const amendment3Adopted = (preregText) => {
  const start = preregText.search(/^## Amendment 3\b/m);
  if (start < 0 || !/^\|\s*Amendment 3\s*\|\s*\*\*Adopted\./m.test(preregText)) return false;
  const rest = preregText.slice(start + 1);
  const end = rest.search(/^## /m);
  return /^\*\*Status: adopted\.\*\*/m.test(end < 0 ? rest : rest.slice(0, end));
};

/** Throws unless this pass may leave loopback. */
export function authorizeR({ loopback, registered, pass, listHashes = {}, excludeHash, homepageOnlyHash, preregText, pageText = "", tree = {}, sourceIps = [], removals, priorOptOuts, pilot, classifierHash, pslHash }) {
  if (loopback) return { mode: "loopback" };
  if (registered !== "E20R") throw new Error("Refused: this run would reach other hosts. It needs --registered E20R, after the maintainer registered the protocol (AGENTS.md rule 6).");
  if (pass === 1) throw new Error("Refused: pass 1 ran on 30 October 2026.");
  if (!PASS_SEED[pass]) throw new Error("Refused: use --pass 3, --pass 2 or --pilot <n>.");
  if (pass === 3 && !amendment3Adopted(preregText)) throw new Error("Refused: pass 3 needs Amendment 3 adopted, in its row and its own status line.");
  if (!/^\|\s*Status\s*\|\s*\*\*Registered\./m.test(preregText)) throw new Error("Refused: the E20-R prereg's status is not Registered.");
  if (!/^\|\s*Amendment 2\s*\|\s*\*\*Adopted\./m.test(preregText)) throw new Error("Refused: Amendment 2 is not adopted in the prereg.");
  if (!/^\*\*Status: adopted\.\*\*/m.test(amendmentText(preregText))) throw new Error("Refused: Amendment 2's own status line does not say adopted.");
  for (const [name, text] of [["prereg", preregText], ["study page", pageText]]) {
    const left = PLACEHOLDER.exec(text);
    if (left) throw new Error(`Refused: the ${name} still holds the placeholder ${left[0]}.`);
  }
  if (!pageText) throw new Error("Refused: the study page could not be read.");
  if (!tree.commit) throw new Error("Refused: not a git checkout, so the deployed code would be unknown.");
  if (tree.dirty) throw new Error("Refused: the git tree is dirty. A registered run needs a clean checkout.");
  if (tree.hidden) throw new Error("Refused: git hides a tracked file from status (assume-unchanged or skip-worktree).");
  if (!tree.remoteTip) throw new Error("Refused: could not read the tip of origin main, so the commit can't be checked.");
  if (tree.remoteTip !== tree.commit) throw new Error("Refused: this commit is not the tip of origin main. Pull, and run that commit.");
  const address = sourceAddressOf(preregText);
  if (!address || !pageText.includes(address)) throw new Error("Refused: the study page does not name the registered address.");
  if (sourceIps.length !== 1 || sourceIps[0] !== address) throw new Error(`Refused: this machine needs exactly one public IPv4, the registered ${address}. It has ${sourceIps.length}.`);
  if (removals === undefined) throw new Error("Refused: a registered run needs --removals <file>. It may be empty.");
  if (priorOptOuts === undefined) throw new Error("Refused: a registered run needs --prior-optouts <file>.");
  if (recordedHashR(preregText, "Prior opt-outs") !== sha256(priorOptOuts)) throw new Error("Refused: the prior opt-out list does not match its frozen hash.");
  if ((pass === 2 || pass === 3) && !pilot?.ok) throw new Error(`Refused: ${pilot?.why || `pass ${pass} needs --pilot-dropped and a passed pilot.`}`);
  if (pass === "pilot" && pilot && !pilot.ok) throw new Error(`Refused: ${pilot.why}`);
  const frozen = recordedHashR(preregText, "Frozen classifier");
  if (!frozen || frozen !== classifierHash) throw new Error("Refused: classify.mjs does not match the frozen classifier hash.");
  const psl = recordedHashR(preregText, "Public Suffix List");
  if (!psl || psl !== pslHash) throw new Error("Refused: the Public Suffix List does not match its frozen hash.");
  for (const cohort of Object.keys(R_COHORTS)) {
    const recorded = recordedHashR(preregText, `${cohort} list`);
    if (!recorded) throw new Error(`Refused: the prereg records no ${cohort} list SHA-256.`);
    if (recorded !== listHashes[cohort]) throw new Error(`Refused: the ${cohort} list does not match the prereg.`);
  }
  const ex = recordedHashR(preregText, R_EXCLUSION_LABEL);
  if (!ex) throw new Error(`Refused: the prereg records no ${R_EXCLUSION_LABEL} SHA-256.`);
  if (ex !== excludeHash) throw new Error("Refused: the exclusion list does not match the prereg.");
  const ho = recordedHashR(preregText, R_HOMEPAGE_LABEL);
  if (!ho) throw new Error(`Refused: the prereg records no ${R_HOMEPAGE_LABEL} SHA-256.`);
  if (ho !== homepageOnlyHash) throw new Error("Refused: the homepage-only list does not match the prereg.");
  return { mode: "registered" };
}

/** A host from a list cell, as a URL or a name: lower case, no trailing dot, no www. Throws on anything else. */
export function normalizeHost(cell) {
  const host = siteKey(hostOf(cell));
  if (!/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(host)) throw new Error(`not a host name: "${String(cell).trim()}"`);
  return host;
}

const listLines = (text) => String(text).split(/\r?\n/).map((l) => l.split("#")[0].trim()).filter(Boolean);

/** Domains to skip: one per line, # comments, subdomains included. A line that names no host throws. */
export function readRemovals(text, category = "removed") {
  const out = new Map();
  for (const line of listLines(text)) {
    if (/\s/.test(line)) throw new Error(`expected one host per line, got "${line}"`);
    out.set(normalizeHost(line), category);
  }
  return out;
}

/** The homepage-only list, normalized as a removal list is. */
export const readHostList = (text) => new Set(listLines(text).map(normalizeHost));

/** Entries that match no row: a stale or mistyped entry would silently protect nothing. */
export function unmatchedHosts(entries, rows) {
  const listed = new Set(rows.map((r) => siteKey(r.host)));
  return [...entries].filter((h) => !listed.has(h));
}

/**
 * The commit, whether the tree is clean, whether git hides a file from `status`,
 * and the tip of main on the remote, asked now: a stale `origin/main` would pass.
 */
export function gitState(cwd = ROOT, run = execFileSync, { remote = true } = {}) {
  const git = (...args) => run("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: GIT_TIMEOUT_MS }).trim();
  try {
    const state = {
      commit: git("rev-parse", "HEAD"), dirty: git("status", "--porcelain", "--untracked-files=all").length > 0,
      hidden: git("ls-files", "-v").split("\n").some((l) => /^[a-zS]/.test(l)), remoteUrl: REMOTE_URL, remoteTip: null,
    };
    if (remote) {
      try {
        state.remoteTip = git("ls-remote", REMOTE_URL, "refs/heads/main").split(/\s+/)[0] || null;
      } catch { /* no answer: the lock refuses */ }
    }
    return state;
  } catch {
    return { commit: null, dirty: null, hidden: null, remoteUrl: REMOTE_URL, remoteTip: null };
  }
}

/** True when a raw file still holds text a person could read. */
export function holdsText(rawFile) {
  return readFileSync(rawFile, "utf8").split("\n").filter(Boolean).some((l) => {
    const e = JSON.parse(l).evidence;
    const p = e?.pageExcerpt;
    return Boolean(p?.title || p?.text || p?.noscript || e?.excerpt || e?.others?.some((o) => o.excerpt));
  });
}

/**
 * What pass 2 needs from the pilot. Every round's list is the one its manifest hashed,
 * and its text is deleted, proved by its prune manifest against the raw file now on
 * disk. The last round passed its stop rules on that same raw data, under the code,
 * protocol, suffix list and lists in force now, and nothing changed while it ran.
 */
export function pilotEvidence(dropped, { results = RESULTS, current, allowFixture = false, logged = [] } = {}) {
  const rounds = pilotRounds(results);
  const line = (dir, sha) => `${dir} ${sha}`;
  const onDisk = new Set(rounds.map((r) => line(r.dir, r.listSha256)));
  const inLog = new Set(logged.map((l) => line(l.dir, l.pilotSitesSha256)));
  if ([...inLog].some((l) => !onDisk.has(l)) || [...onDisk].some((l) => !inLog.has(l))) return { ok: false, why: "The pilot rounds on disk do not match the rounds log." };
  const listed = checkPilotDropped(dropped, rounds, { need: true });
  if (!listed.ok) return listed;
  const no = (why) => ({ ok: false, why });
  const read = (dir, f) => { const p = join(results, dir, f); return existsSync(p) ? readFileSync(p) : null; };
  const purged = (dir) => purgeState(join(results, dir)) === "proved";
  // S1: every finished round has a seal, and a failed round isn't simply run again.
  const proofs = [];
  for (const [i, { dir }] of rounds.entries()) {
    const bytes = read(dir, "manifest.json");
    const m = JSON.parse(bytes);
    const seal = read(dir, "pilot-result.json");
    proofs.push({ dir, manifestSha256: sha256(bytes), sealSha256: seal ? sha256(seal) : null });
    if (!m.finishedAt) continue;
    if (!seal) {
      if (purged(dir)) continue;
      return no(`Pilot ${dir} has no sealed report.`);
    }
    const sealed = JSON.parse(seal);
    if (sealed.sealSha256 !== sealHash(sealed)) return no(`Pilot ${dir}: its seal does not match its own hash.`);
    if (sealed.manifestSha256 !== sha256(bytes) || sealed.rawSha256 !== m.rawSha256) return no(`Pilot ${dir}: its sealed report is for another run.`);
    const { lists = {} } = sealed;
    if (lists.exclusionSha256 !== m.exclusionSha256 || lists.removals !== m.removals?.sha256 || lists.priorOptOuts !== m.priorOptOuts?.sha256 || lists.pilotDropped !== (m.pilotDropped?.sha256 ?? null)) return no(`Pilot ${dir}: its report was sealed against other skip lists.`);
    const reportBytes = read(dir, "pilot-report.json");
    if (!reportBytes || sha256(reportBytes) !== sealed.reportSha256) return no(`Pilot ${dir}: its report is not the sealed one.`);
    if (sealed.passed && stopRules(JSON.parse(reportBytes)).length) return no(`Pilot ${dir}: its report does not pass, whatever its seal says.`);
    const next = rounds[i + 1] && JSON.parse(read(rounds[i + 1].dir, "manifest.json"));
    if (next && !JSON.parse(seal).passed && next.codeSha256 === m.codeSha256 && next.protocolSha256 === m.protocolSha256 && !read(dir, "pilot-explanation.txt")?.length) {
      return no(`Pilot ${dir} failed, and the next round changed nothing and explains nothing.`);
    }
  }
  for (const { dir } of rounds) {
    const state = purgeState(join(results, dir));
    if (state === "proved") continue;
    if (state !== "none") return no(`Pilot ${dir}: its purge proof does not hold: ${state}.`);
    const missed = Object.values(JSON.parse(read(dir, "pilot-report.json") ?? "{}").scrubMisses ?? {}).some(Boolean);
    if (missed && !falseFireReviewed(join(results, dir))) return no(`Pilot ${dir} has a privacy scrub miss and no verified purge or reviewed false fire.`);
    const manifest = read(dir, "manifest.json");
    const proof = JSON.parse(read(dir, "prune-manifest.json") ?? "null");
    const raw = join(results, dir, "raw.jsonl");
    if (!proof) return no(`Pilot ${dir} has no proof that its text was deleted.`);
    const recorded = JSON.parse(manifest);
    if (proof.kind !== "pilot" || proof.manifestSha256 !== sha256(manifest) || (recorded.finishedAt && proof.rawSha256Before !== recorded.rawSha256)) return no(`Pilot ${dir}: its prune proof is for another run.`);
    if (!existsSync(raw) || proof.rawSha256After !== sha256(readFileSync(raw))) return no(`Pilot ${dir}: the raw file is not the pruned one.`);
    if (holdsText(raw)) return no(`Pilot ${dir} still holds excerpt text.`);
  }
  const last = rounds.at(-1).dir;
  const manifest = JSON.parse(read(last, "manifest.json"));
  if (manifest.kind !== "pilot") return no(`Pilot ${last}: its manifest is not a pilot's.`);
  if (manifest.loopback !== false && !(allowFixture && manifest.fixture === true)) return no(`Pilot ${last} ran on loopback, so it proves nothing about the study.`);
  if (!manifest.finishedAt || manifest.partial) return no(`Pilot ${last} did not finish. Run the next round.`);
  if (!(manifest.sites >= PILOT_MIN)) return no(`Pilot ${last} has ${manifest.sites} sites. The floor is ${PILOT_MIN}.`);
  const result = JSON.parse(read(last, "pilot-result.json") ?? "null");
  if (!result) return no(`Pilot ${last} has no sealed report.`);
  if (!result.passed) return no(`Pilot ${last} failed: ${result.stop.join("; ")}.`);
  const decision = JSON.parse(read(last, "pilot-decision.json") ?? "null");
  if (decision?.decision !== "go") return no(`Pilot ${last}: no recorded go decision.`);
  if (!String(decision.reviewer ?? "").trim() || Number.isNaN(Date.parse(decision.decidedAt))) return no(`Pilot ${last}: its decision names no reviewer or no valid time.`);
  if (decision.reportSha256 !== sha256(read(last, "pilot-report.json")) || decision.sealSha256 !== result.sealSha256) return no(`Pilot ${last}: its decision is for another report.`);
  if (!manifest.immutableAtFinish?.ok) return no(`Pilot ${last}: something changed while it ran.`);
  for (const [name, now] of Object.entries(current ?? {})) {
    if (JSON.stringify(manifest[name]) !== JSON.stringify(now)) return no(`Pilot ${last} ran under another ${name}.`);
  }
  return { ok: true, why: "", rounds: proofs };
}

export const readRoundsLog = (file = ROUNDS_LOG) => (existsSync(file) ? readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);

/**
 * Every pilot round that started, from its manifest. A round whose list no longer
 * matches the hash in its manifest makes the result fail.
 */
export function pilotRounds(results = RESULTS) {
  const rounds = [];
  if (!existsSync(results)) return rounds;
  const started = (dir) => { const m = join(results, dir, "manifest.json"); return existsSync(m) ? JSON.parse(readFileSync(m, "utf8")).startedAt ?? "" : ""; };
  // In the order they ran: a number can't say which round came last.
  for (const dir of readdirSync(results).filter((d) => /^e20r-pilot-\d+$/.test(d)).sort((a, b) => started(a).localeCompare(started(b)) || a.localeCompare(b))) {
    const m = join(results, dir, "manifest.json");
    const list = join(results, dir, "pilot-sites.txt");
    if (!existsSync(m) || !existsSync(list)) { rounds.push({ dir, ok: false }); continue; }
    const manifest = JSON.parse(readFileSync(m, "utf8"));
    const bytes = readFileSync(list);
    rounds.push({ dir, ok: manifest.pilotSitesSha256 === sha256(bytes), live: manifest.loopback === false, listSha256: manifest.pilotSitesSha256, hosts: [...readRemovals(bytes.toString("utf8"), "pilot").keys()] });
  }
  return rounds;
}

/**
 * Amendment 3: the pass 2 that stopped, and the sites it visited. It counts only as the
 * registered privacy stop of a real, unchanged run, with the frozen detector's finding
 * bound to its original raw file, a named person's review bound to that finding, and a
 * prune proof, since the pruned raw file is what says which sites to leave alone.
 */
export function stoppedPass(results = RESULTS, { allowFixture = false } = {}) {
  const no = (why) => ({ ok: false, why });
  const dir = join(results, "e20r-pass2");
  const file = join(dir, "manifest.json");
  if (!existsSync(file)) return no("there is no stopped pass 2");
  const bytes = readFileSync(file);
  const m = JSON.parse(bytes);
  if (!m.finishedAt || !m.partial) return no("pass 2 has no finished, partial manifest");
  if (purgeState(dir) !== "none") return no("pass 2 was purged, so its sites can't be skipped");
  if (m.kind !== "pass" || m.pass !== 2) return no("this manifest is not pass 2's");
  if (m.loopback !== false && !(allowFixture && m.fixture === true)) return no("pass 2 ran on loopback");
  if (!m.immutableAtFinish?.ok) return no("something changed while pass 2 ran");
  if (m.stoppedFor !== PRIVACY_STOP) return no(`pass 2 stopped for another reason: ${m.stoppedFor}`);
  if (!/^[0-9a-f]{64}$/.test(m.rawSha256 ?? "") || !Number.isInteger(m.records)) return no("pass 2 has no original raw hash and count");
  const json = (name) => { const p = join(dir, name); return existsSync(p) ? readFileSync(p) : null; };
  const legacyBytes = json("legacy-findings.json");
  const legacy = legacyBytes && JSON.parse(legacyBytes);
  if (!legacy) return no("pass 2 has no legacy finding report");
  if (legacy.legacyDetectorSha256 !== LEGACY_CLASSIFIER_SHA256 || legacy.manifestSha256 !== sha256(bytes) || legacy.rawSha256 !== m.rawSha256 || legacy.records !== m.records) return no("its legacy finding report is for another run");
  if (!legacy.findings?.length || !legacy.reproducesStop) return no("its legacy finding report does not reproduce the stop");
  const reviewed = JSON.parse(json("privacy-report.json") ?? "null");
  if (!falseFireReviewed(dir) || reviewed.rawSha256 !== m.rawSha256) return no("pass 2 has no recorded false-fire review");
  if (reviewed.reviewed.legacyFindingsSha256 !== sha256(legacyBytes)) return no("its review is not bound to this legacy finding report");
  const proof = JSON.parse(json("prune-manifest.json") ?? "null");
  if (proof?.kind !== "stopped" || proof.manifestSha256 !== sha256(bytes) || proof.rawSha256Before !== m.rawSha256) return no("pass 2 has no prune proof of its own");
  const raw = join(dir, "raw.jsonl");
  if (!existsSync(raw) || proof.rawSha256After !== sha256(readFileSync(raw))) return no("pass 2's raw file is not the pruned one");
  if (holdsText(raw)) return no("pass 2 still holds excerpt text");
  const hosts = readFileSync(raw, "utf8").split("\n").filter(Boolean).map((l) => siteKey(JSON.parse(l).host));
  if (hosts.length !== m.records) return no("pass 2's raw file doesn't hold every site its manifest counts");
  return { ok: true, why: "", hosts, finishedAt: m.finishedAt, manifestSha256: sha256(bytes), rawSha256: proof.rawSha256After };
}

/** Sites to skip, by list. The stopped pass goes first, so a site's earlier reason survives. */
export const mergeSkips = (visited, ...earlier) => new Map([...visited, ...earlier.flatMap((list) => [...list])]);

/** A later round and pass 2 need the file to hold exactly the sites of every pilot round, finished or not: a killed round still visited them. */
export function checkPilotDropped(dropped, rounds, { need = true } = {}) {
  if (!rounds.length) return need ? { ok: false, why: "No pilot manifest found." } : { ok: true, why: "" };
  const bad = rounds.find((r) => !r.ok);
  if (bad) return { ok: false, why: `Pilot ${bad.dir}: its site list does not match its manifest.` };
  const want = new Set(rounds.flatMap((r) => r.hosts));
  const same = want.size === dropped.size && [...want].every((h) => dropped.has(h));
  return same ? { ok: true, why: "" } : { ok: false, why: "--pilot-dropped does not hold exactly the pilot sites." };
}

/** This machine's public IPv4 addresses. The published address must be the only one. */
export function sourceAddresses(interfaces = networkInterfaces()) {
  return Object.values(interfaces).flat().filter((a) => a.family === "IPv4" && !a.internal && isPublicIp(a.address)).map((a) => a.address);
}
export const sourceAddressCount = (interfaces) => sourceAddresses(interfaces).length;

const fileHash = (path) => (existsSync(path) ? createHash("sha256").update(readFileSync(path)).digest("hex") : null);
const STUDY_ENTRIES = Object.freeze(["bench/front-door/replicate.mjs", "bench/front-door/visit-worker.mjs", "bench/front-door/analyze-r.mjs", "bench/front-door/pilot-report.mjs", "bench/front-door/validation-sample.mjs", "bench/front-door/record-checks.mjs"]);
// Data the code reads at run time, which no import names.
const STUDY_DATA = Object.freeze(["lib/data/retire-jsrepository.json.gz", "lib/data/retire-jsrepository.meta.json", "package-lock.json", "package.json"]);
const IMPORT = /(?:\bfrom\s*|\bimport\s*\(?\s*)["'](\.{1,2}\/[^"']+)["']/g;

/** Every file the study's entry points reach by a relative import, in order. Packages are the lockfile's job. */
export function codeFiles(entries = STUDY_ENTRIES, root = ROOT) {
  const seen = new Set();
  const walk = (file) => {
    if (seen.has(file) || !existsSync(file)) return;
    seen.add(file);
    for (const m of readFileSync(file, "utf8").matchAll(IMPORT)) walk(resolve(dirname(file), m[1]));
  };
  for (const e of entries) walk(join(root, e));
  return [...seen].sort();
}

export const codeHash = () => sha256([...codeFiles(), ...STUDY_DATA.map((f) => join(ROOT, f))].map((f) => `${f.slice(ROOT.length)} ${fileHash(f)}`).join("\n"));

let runtimeSeen = { key: null, hash: null };
/** The node binary's hash, read again only when the file itself changed. */
function runtimeHash() {
  const { size, mtimeMs } = statSync(process.execPath);
  const key = `${size}:${mtimeMs}`;
  if (runtimeSeen.key !== key) runtimeSeen = { key, hash: fileHash(process.execPath) };
  return runtimeSeen.hash;
}

/** The protocol's Amendment 2 section alone, so a later edit elsewhere can be told apart. */
export const amendmentText = (preregText) => { const i = preregText.indexOf("## Amendment 2"); return i < 0 ? "" : preregText.slice(i); };

export const runConfig = () => ({
  limits: V2_LIMITS, visitInThread: true, rollingWindow: ROLLING_WINDOW, maxResolverFailures: MAX_RESOLVER_FAILURES, concurrency: LIMITS.concurrency, delayMs: LIMITS.delayMs, userAgent: USER_AGENT, optOutTokens: OPT_OUT_TOKENS,
  strictRobots: true, appPage: false, robotsRedirects: ROBOTS_REDIRECTS, robotsMaxBytes: ROBOTS_MAX_BYTES, requestTimeoutsMs: { page: 6000, robots: 4000, securityTxt: 4000 },
  dnsTimeoutMs: DNS_TIMEOUT_MS, excerptBytes: EXCERPT_BYTES, pageTextChars: PAGE_TEXT_CHARS, softMaxChars: SOFT_MAX_CHARS, inputCapChars: INPUT_CAP_CHARS, seeds: PASS_SEED, pilotMax: PILOT_MAX,
});

/** Everything a run's behavior or meaning rests on. Read at the start and again at the end. */
export function studyState() {
  const prereg = existsSync(PREREG_R) ? readFileSync(PREREG_R, "utf8") : "";
  return {
    lockfileSha256: fileHash(join(ROOT, "package-lock.json")),
    classifierSha256: fileHash(CLASSIFIER),
    protocolSha256: sha256(prereg), amendmentSha256: sha256(amendmentText(prereg)), studyPageSha256: fileHash(STUDY_PAGE),
    codeSha256: codeHash(), pslSha256: pslSha256(), runtimeSha256: runtimeHash(),
  };
}

/** What ran, where: written at the start of a run and again at the end. */
export function runManifest(extra = {}) {
  return {
    study: "E20-R2", git: gitState(ROOT, execFileSync, { remote: !extra.loopback }),
    ...studyState(),
    node: process.version, os: `${platform()} ${release()}`,
    sourceIpv4Count: sourceAddressCount(),
    psl: { ...PSL_VERSION, sha256: pslSha256() },
    config: runConfig(),
    ...extra,
  };
}

export { ipv4Lookup };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** The per-cohort aggregates. No host in the output, and no group under MIN_GROUP. */
export function aggregateR(records, meta = {}) {
  const cohorts = {};
  for (const cohort of new Set(records.flatMap((r) => Object.keys(r.cohorts)))) {
    const rows = records.filter((r) => r.cohorts[cohort]).map((r) => ({ ...r, rank: r.cohorts[cohort].rank, group: r.cohorts[cohort].group }));
    const ok = rows.filter((r) => r.status === "ok");
    const labels = {}, mx = {}, ns = {};
    for (const r of ok) {
      const l = r.evidence?.class?.label ?? "unknown";
      labels[l] = (labels[l] || 0) + 1;
      if (r.dnsProviders) { mx[r.dnsProviders.mx] = (mx[r.dnsProviders.mx] || 0) + 1; ns[r.dnsProviders.ns] = (ns[r.dnsProviders.ns] || 0) + 1; }
    }
    const floor = (o) => { const out = { other: 0 }; for (const [k, v] of Object.entries(o)) { if (v >= MIN_GROUP) out[k] = v; else out.other += v; } return out; };
    const hosts = {
      graded: ok.length,
      finalHostDiffers: ok.filter((r) => r.redirectClass && r.redirectClass !== "none").length,
      finalOrgDiffers: ok.filter((r) => r.redirectClass === "other-org").length,
    };
    cohorts[cohort] = { ...aggregate(rows, { cohort }, { orgOf: siteOrg }), labels, hosts, mailProviders: floor(mx), dnsProviders: floor(ns) };
  }
  return { experiment: "E20-R", ...meta, cohorts };
}

/**
 * One visit in its own thread, ended at the hard cap. A page can hold a regex for
 * minutes, and no timer on that thread would fire, so the cap is enforced here.
 * The record then keeps the last progress the thread sent.
 */
export function visitInWorker(row, { loopbackPort, exclude = new Map(), budgetMs = V2_LIMITS.siteBudgetMs, hardCapMs = V2_LIMITS.siteHardCapMs, workerFile = VISIT_WORKER } = {}) {
  return new Promise((done) => {
    const at = new Date().toISOString();
    let last = { requests: 0, bytes: 0, redirects: 0, hosts: [] };
    let finished = false;
    const worker = new Worker(workerFile, { workerData: { row, loopbackPort, exclude: [...exclude], budgetMs, hardCapMs } });
    const finish = (record) => {
      if (finished) return;
      finished = true;
      clearTimeout(cap);
      worker.terminate();
      done(record);
    };
    const lost = (error, reason) => ({ ...row, at, status: "error", error, ...(reason ? { reason } : {}), robots: [], counters: { requests: last.requests, bytes: last.bytes, redirects: last.redirects }, hops: last.hosts });
    const cap = setTimeout(() => finish(lost("timeout", "hard_cap")), hardCapMs + WORKER_GRACE_MS);
    worker.on("message", (m) => { if (m.record) finish(m.record); else last = m.progress; });
    worker.on("error", () => finish(lost("internal")));
    worker.on("exit", () => finish(lost("internal")));
  });
}

// A signal reaches its handler in the loop's poll phase. Two turns make sure one has passed.
const letSignalsIn = async () => { for (let i = 0; i < 2; i++) await new Promise((r) => { setImmediate(r); }); };

/** One pass. `rows` come from mergeCohorts. Appends each record to raw.jsonl. */
export async function runPass(rows, { pass, out, loopbackPort, exclude = new Map(), delayMs = LIMITS.delayMs, concurrency = LIMITS.concurrency, dns = {}, meta = {}, manifest = {}, onRecord, onStart, workerFile, recheck = () => ({}), stopCheck = () => null, gitNow = () => gitState(ROOT, execFileSync, { remote: !loopbackPort }), rollingWindow = ROLLING_WINDOW } = {}) {
  if (!loopbackPort) { concurrency = LIMITS.concurrency; delayMs = LIMITS.delayMs; }
  const order = shuffled(rows, PASS_SEED[pass]);
  mkdirSync(out, { recursive: true, mode: 0o700 });
  chmodSync(out, 0o700);
  writeFileSync(join(out, ".gitignore"), "*\n");
  const raw = join(out, "raw.jsonl");
  if ((existsSync(raw) && statSync(raw).size) || existsSync(join(out, "manifest.json"))) throw new Error(`Refused: ${out} already holds a run.`);
  writeFileSync(raw, "", SECRET);
  const pilotList = pass === "pilot" ? order.map((r) => siteKey(r.host)).join("\n") + "\n" : null;
  const started = runManifest({ kind: pass === "pilot" ? "pilot" : "pass", pass, seed: PASS_SEED[pass], loopback: Boolean(loopbackPort), sites: order.length, startedAt: new Date().toISOString(), ...(pilotList ? { pilotSitesSha256: sha256(Buffer.from(pilotList)) } : {}), ...manifest });
  if (pilotList) writeFileSync(join(out, "pilot-sites.txt"), pilotList, SECRET);
  writeFileSync(join(out, "manifest.json"), JSON.stringify(started, null, 2) + "\n", SECRET);
  onStart?.(started);
  // Loopback runs never touch a real resolver.
  const stub = () => Promise.reject(Object.assign(new Error("ENODATA"), { code: "ENODATA" }));
  const dnsAnswers = loopbackPort ? { ...STUB_DNS, mx: stub, ns: stub, ...dns } : dns;
  const records = new Array(order.length);
  let next = 0;
  // Pass 2 stops itself: a scrub miss at once, resolver failures over the rolling window.
  const recent = [];
  let stoppedFor = null;
  const watch = (record) => {
    if (pass === "pilot") return;
    if (pageTextMissed(record)) stoppedFor = PRIVACY_STOP;
    recent.push(resolverFailed(record));
    if (recent.length > rollingWindow) recent.shift();
    if (recent.length === rollingWindow && recent.filter(Boolean).length / rollingWindow > MAX_RESOLVER_FAILURES) stoppedFor ??= "over 20% of recent sites hit a resolver failure";
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, order.length) }, async () => {
    while (next < order.length && !stoppedFor) {
      stoppedFor = stopCheck();
      if (stoppedFor) break;
      const k = next++;
      const row = order[k];
      const category = exclusionFor(row.host, exclude);
      let record;
      if (category) record = { ...row, at: new Date().toISOString(), status: "excluded", reason: "exclusion_list", category };
      else {
        // Amendment 2: no app page, for any site. `appPage` is not passed, and `strict` refuses it anyway.
        record = { ...row, ...(await visitInWorker(row, { loopbackPort, exclude, workerFile })) };
        record.listedHost = row.host;
        record.listedOrg = siteOrg(row.host);
        if (record.finalHost) {
          record.finalOrg = siteOrg(record.finalHost);
          record.redirectClass = record.finalHost === row.host ? "none" : record.finalOrg === record.listedOrg ? "same-org" : "other-org";
        }
        if (readsDns(record)) {
          record.dns = await siteDns(row.host, record.finalHost, dnsAnswers);
          const read = record.dns.final ?? record.dns.listed;
          if (record.status === "ok") {
            record.dnsProviders = { mx: read.mx, ns: read.ns };
            // The score counts the DNS checks, as in pass 1. They run here, so the visit's clock can't touch them.
            record.checks = [...record.checks, ...read.registeredChecks];
            record.score = scoreOf(record.checks);
          }
          delete record.dns.listed.registeredChecks;
          if (record.dns.final) delete record.dns.final.registeredChecks;
        }
      }
      records[k] = record;
      appendFileSync(raw, JSON.stringify({ pass, order: k, ...record }) + "\n");
      watch(record);
      onRecord?.(record, k);
      if (next < order.length && delayMs) await sleep(delayMs);
    }
  }));
  const done = records.filter(Boolean);
  const sum = (k) => done.reduce((n, r) => n + (r.counters?.[k] ?? 0), 0);
  // The steps below block, so a signal waits in the event loop until something yields.
  const end = { ...studyState(), ...recheck() };
  const gitAtFinish = gitNow();
  const { git: gitAtStart, ...begun } = started;
  // A loopback run may share its checkout with other work, so only the commit counts there.
  const gitChanged = (loopbackPort ? ["commit"] : ["commit", "dirty", "hidden"]).some((k) => gitAtFinish[k] !== gitAtStart[k]);
  const changed = [...Object.keys(end).filter((k) => JSON.stringify(end[k]) !== JSON.stringify(started[k])), ...(gitChanged ? ["git"] : [])];
  let agg;
  const writeFinal = () => {
    agg = aggregateR(done, { pass, partial: Boolean(stoppedFor), ...meta, concurrency, delayMs, appPage: false, userAgent: USER_AGENT, order: "seeded shuffle", seed: PASS_SEED[pass] });
    writeFileSync(join(out, "aggregate.json.tmp"), JSON.stringify(agg, null, 2) + "\n", SECRET);
    writeFileSync(join(out, "manifest.json.tmp"), JSON.stringify({
      ...begun, gitAtStart, gitAtFinish, finishedAt: new Date().toISOString(), records: done.length,
      ...(stoppedFor ? { partial: true, stoppedFor } : {}),
      totals: { requests: sum("requests"), bytes: sum("bytes"), redirects: sum("redirects") },
      immutableAtFinish: { ok: changed.length === 0, changed },
      rawSha256: fileHash(raw), aggregateSha256: fileHash(join(out, "aggregate.json.tmp")),
    }, null, 2) + "\n", SECRET);
  };
  await letSignalsIn();
  stoppedFor ??= stopCheck();
  writeFinal();
  await letSignalsIn();
  // The semantic boundary is this last check. Nothing yields from here to the rename, so a
  // signal handled before it makes the run partial, and any later one is post-run.
  if (!stoppedFor) {
    stoppedFor = stopCheck();
    if (stoppedFor) writeFinal();
  }
  renameSync(join(out, "aggregate.json.tmp"), join(out, "aggregate.json"));
  renameSync(join(out, "manifest.json.tmp"), join(out, "manifest.json"));
  return { records: done, aggregate: agg, stoppedFor };
}

// DNS goes to public resolvers, not to the site, but a site that said stop stays out.
export const NO_DNS = Object.freeze(["robots_disallow_all", "not_a_homepage", "exclusion_list", "robots_disallow_path"]);
const readsDns = (r) => r.status !== "opted_out" && !NO_DNS.includes(r.reason);

/** Loopback self-test: three names on two lists, all pinned to the mock server. */
export async function selfTestR({ out } = {}) {
  const { startMockServer } = await import(pathToFileURL(join(ROOT, "tests", "fixtures", "mock-server.js")).href);
  const mock = await startMockServer(0);
  try {
    const rows = mergeCohorts({
      T1k: [{ host: "site-1.e20r-selftest.example.com", rank: 1, group: "com" }, { host: "both.e20r-selftest.example.com", rank: 2, group: "com" }],
      "YC-new": [{ host: "both.e20r-selftest.example.com", rank: 1, group: "Fall 2026" }],
    });
    const stub = () => Promise.reject(Object.assign(new Error("ENODATA"), { code: "ENODATA" }));
    const dir = out || join(ROOT, "bench", "front-door", "results", `e20r-selftest-${Date.now()}`);
    const { records, aggregate: agg } = await runPass(rows, { pass: 2, out: dir, loopbackPort: mock.port, delayMs: 0, dns: { mx: stub, ns: stub }, meta: { selfTest: true } });
    const problems = [];
    if (mock.requests.filter((r) => r.url === "/").length !== 2) problems.push("a host on two lists must be visited once");
    if (records.some((r) => r.status !== "ok")) problems.push("expected every site to be graded");
    if (!records.every((r) => r.evidence?.class?.label && r.evidence?.classRegistered?.label)) problems.push("a record has no label");
    if (!records.every((r) => r.dns?.listed && r.robots?.length && r.counters?.requests && r.listedOrg && r.finalOrg)) problems.push("a record has no DNS, robots, counter or organization field");
    const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
    if (!manifest.finishedAt || !manifest.rawSha256 || !manifest.immutableAtFinish?.ok) problems.push("the manifest has no clean end");
    if (JSON.stringify(agg).includes("e20r-selftest")) problems.push("aggregate names a site");
    return { ok: problems.length === 0, problems, out: dir, aggregate: agg };
  } finally {
    await mock.close();
  }
}

function flag(args, name) {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
}

/**
 * The command. `deps` is for the acceptance run alone: it stands in for what only a real
 * server can supply, so the same path decides there as in a run.
 */
export async function main(args, deps = {}) {
  const say = deps.say ?? console.error;
  const results = deps.results ?? RESULTS;
  const roundsLog = deps.roundsLog ?? ROUNDS_LOG;
  const stopFile = deps.stopFile ?? STOP_FILE;
  const sourceNow = () => deps.sourceNow?.() ?? deps.sourceIps ?? sourceAddresses();
  if (args.includes("--self-test")) {
    const r = await selfTestR({ out: flag(args, "--out") });
    console.log(r.ok ? `E20-R self-test passed, all to 127.0.0.1 (${r.out})` : `E20-R self-test FAILED:\n  ${r.problems.join("\n  ")}`);
    return r.ok ? 0 : 1;
  }
  const dir = flag(args, "--lists");
  const pilot = args.includes("--pilot") ? Number(flag(args, "--pilot")) : null;
  const pass = pilot === null ? Number(flag(args, "--pass")) : "pilot";
  const round = Number(flag(args, "--pilot-round") ?? 1);
  if (!dir) { console.error("Usage: node bench/front-door/replicate.mjs --self-test | (--pass 2 | --pilot <n> [--pilot-round <k>]) --registered E20R --lists <dir> --exclude <file> --homepage-only <file> --removals <file> --prior-optouts <file> --pilot-dropped <file>"); return 2; }
  if (flag(args, "--out")) { console.error("A registered run has one fixed output folder; --out is for no run."); return 2; }
  if (!(Number.isInteger(round) && round >= 1 && round <= 9)) { say("--pilot-round takes 1 to 9."); return 2; }
  if (pilot !== null && !(Number.isInteger(pilot) && pilot >= PILOT_MIN && pilot <= PILOT_MAX)) { say(`--pilot takes exactly ${PILOT_MAX} sites.`); return 2; }
  const excludeBytes = flag(args, "--exclude") ? readFileSync(flag(args, "--exclude")) : null;
  const homepageBytes = flag(args, "--homepage-only") ? readFileSync(flag(args, "--homepage-only")) : null;
  const bytes = Object.fromEntries(Object.entries(R_COHORTS).map(([c, { file }]) => [c, existsSync(join(dir, file)) ? readFileSync(join(dir, file)) : null]));
  const removalsBytes = flag(args, "--removals") ? readFileSync(flag(args, "--removals")) : null;
  const priorBytes = flag(args, "--prior-optouts") ? readFileSync(flag(args, "--prior-optouts")) : null;
  const pilotBytes = flag(args, "--pilot-dropped") ? readFileSync(flag(args, "--pilot-dropped")) : null;
  let lists, exclude, rows, removals, prior, pilotDropped, unmatchedRemovals, pilotProof, stopped;
  try {
    pilotDropped = pilotBytes ? readRemovals(pilotBytes.toString("utf8"), "pilot") : new Map();
    const now = deps.state ?? studyState();
    const known = pilotRounds(results);
    if (existsSync(stopFile)) throw new Error(`Refused: the stop file ${stopFile} exists. Remove it only once its reason is settled.`);
    const prereg = deps.preregText ?? (existsSync(PREREG_R) ? readFileSync(PREREG_R, "utf8") : "");
    const pass2Began = existsSync(join(results, "e20r-pass2", "manifest.json"));
    if (pass2Began && pass !== 2) stopped = stoppedPass(results, { allowFixture: Boolean(deps.fixture) });
    if (pass === 3) {
      if (!pass2Began) throw new Error("Refused: pass 3 follows a stopped pass 2, and there is none.");
      if (!stopped.ok) throw new Error(`Refused: pass 3 needs the stopped pass disposed of: ${stopped.why}.`);
      const lastRound = known.at(-1) && JSON.parse(readFileSync(join(results, known.at(-1).dir, "manifest.json"), "utf8"));
      if (!(lastRound?.startedAt > stopped.finishedAt)) throw new Error("Refused: pass 3 needs a pilot round after the stopped pass, because the code changed.");
    }
    if (pilot !== null) {
      if (existsSync(join(results, "e20r-pass3", "manifest.json"))) throw new Error("Refused: pass 3 has started, so no pilot round can follow it.");
      if (pass2Began && !stopped.ok) throw new Error(`Refused: pass 2 has started, so no pilot round can follow it: ${stopped.why}.`);
      if (pass2Began && !amendment3Adopted(prereg)) throw new Error("Refused: pass 2 has started, so a pilot round needs Amendment 3 adopted.");
      if (Math.max(known.filter((r) => r.live).length, readRoundsLog(roundsLog).filter((l) => l.live).length) >= MAX_LIVE_ROUNDS) throw new Error(`Refused: ${MAX_LIVE_ROUNDS} live pilot rounds ran. A third needs an amendment.`);
      const top = Math.max(0, ...known.map((r) => Number(r.dir.split("-").pop())));
      if (round <= top) throw new Error(`Refused: round ${round} is not after round ${top}. Use a higher --pilot-round.`);
    }
    const listSha256 = Object.fromEntries(Object.entries(bytes).map(([c, b]) => [c, b ? sha256(b) : null]));
    const { classifierSha256, protocolSha256, studyPageSha256, codeSha256, lockfileSha256, runtimeSha256, pslSha256: pslNow } = now;
    const evidence = pilot === null
      ? pilotEvidence(pilotDropped, { results, allowFixture: Boolean(deps.fixture), logged: readRoundsLog(roundsLog), current: { classifierSha256, protocolSha256, studyPageSha256, codeSha256, lockfileSha256, runtimeSha256, pslSha256: pslNow, listSha256 } })
      : checkPilotDropped(pilotDropped, known, { need: false });
    pilotProof = evidence.rounds ?? [];
    authorizeR({
      registered: flag(args, "--registered"), pass,
      listHashes: Object.fromEntries(Object.entries(bytes).map(([c, b]) => [c, b ? sha256(b) : null])),
      excludeHash: excludeBytes ? sha256(excludeBytes) : undefined,
      homepageOnlyHash: homepageBytes ? sha256(homepageBytes) : undefined,
      preregText: prereg,
      pageText: deps.pageText ?? (existsSync(STUDY_PAGE) ? readFileSync(STUDY_PAGE, "utf8") : ""),
      tree: deps.tree ?? gitState(), sourceIps: deps.sourceIps ?? sourceAddresses(),
      removals: removalsBytes ?? undefined, priorOptOuts: priorBytes ?? undefined,
      pilot: evidence,
      classifierHash: deps.classifierHash ?? fileHash(CLASSIFIER), pslHash: deps.pslHash ?? pslSha256(),
    });
    lists = Object.fromEntries(Object.entries(R_COHORTS).map(([c, { format }]) => [c, readList(bytes[c].toString("utf8"), format)]));
    removals = readRemovals(removalsBytes.toString("utf8"));
    prior = readRemovals(priorBytes.toString("utf8"), "opted-out-earlier");
    const visited = new Map((stopped?.ok ? stopped.hosts : []).map((h) => [h, "stopped-pass"]));
    exclude = mergeSkips(visited, readExclusions(excludeBytes.toString("utf8")), pilotDropped, prior, removals);
    const all = mergeCohorts(lists);
    const missing = unmatchedHosts(readHostList(homepageBytes.toString("utf8")), all);
    if (missing.length) throw new Error(`Refused: ${missing.length} homepage-only entries match no listed site.`);
    const removed = all.filter((r) => exclusionFor(r.host, removals)).length;
    say(`Removal list: ${removed} of ${all.length} sites.`);
    if (removed / all.length > MAX_REMOVED_SHARE) throw new Error(`Refused: the removal list takes out ${removed} of ${all.length} sites, over ${MAX_REMOVED_SHARE * 100}%.`);
    unmatchedRemovals = unmatchedHosts(removals.keys(), all).filter((h) => !all.some((r) => exclusionFor(r.host, new Map([[h, "x"]]))));
    if (unmatchedRemovals.length) say(`Warning: ${unmatchedRemovals.length} removal entries match no listed site. Check for a typo.`);
    rows = pilot === null ? all : pilotSample(all, pilot, { exclude });
  } catch (e) {
    say(e.message);
    return 3;
  }
  if (deps.stopBeforeRun) { say("authorized"); return 0; }
  const out = join(results, pilot === null ? `e20r-pass${pass}` : `e20r-pilot-${round}`);
  const listNow = () => ({ listSha256: Object.fromEntries(Object.entries(R_COHORTS).map(([c, { file }]) => [c, fileHash(join(dir, file))])) });
  const inputs = { exclusion: flag(args, "--exclude"), homepageOnly: flag(args, "--homepage-only"), removals: flag(args, "--removals"), priorOptOuts: flag(args, "--prior-optouts"), pilotDropped: flag(args, "--pilot-dropped") };
  const sourceIps = sourceNow();
  // The first signal ends the run between sites, with a manifest. A second one kills it.
  let signal = null;
  const onSignal = (name) => { signal = name; };
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);
  const stopCheck = () => {
    if (signal) return `interrupted by ${signal}`;
    if (existsSync(stopFile)) return "the stop file exists";
    return JSON.stringify(sourceNow()) === JSON.stringify(sourceIps) ? null : "the source address changed";
  };
  const { aggregate: agg, stoppedFor } = await runPass(rows, {
    pass, out, exclude, stopCheck,
    recheck: () => ({ ...(deps.atFinal?.(), listNow()), ...deps.state, sourceIps: sourceNow(), inputFiles: Object.fromEntries(Object.entries(inputs).map(([k, f]) => [k, f ? fileHash(f) : null])) }),
    onStart: (m) => { if (pilot !== null) appendFileSync(roundsLog, `${JSON.stringify({ dir: `e20r-pilot-${round}`, pilotSitesSha256: m.pilotSitesSha256, startedAt: m.startedAt, live: !m.loopback })}\n`, SECRET); },
    ...(deps.loopbackPort ? { loopbackPort: deps.loopbackPort, dns: deps.dns, delayMs: 0, rollingWindow: deps.rollingWindow } : {}),
    manifest: {
      ...deps.state, ...(deps.fixture ? { fixture: true } : {}), sourceIps,
      inputFiles: { exclusion: sha256(excludeBytes), homepageOnly: sha256(homepageBytes), removals: sha256(removalsBytes), priorOptOuts: sha256(priorBytes), pilotDropped: pilotBytes ? sha256(pilotBytes) : null },
      ...(pilot === null ? { pilotRounds: pilotProof } : {}),
      ...(stopped?.ok ? { stoppedPass: { sites: stopped.hosts.length, manifestSha256: stopped.manifestSha256, rawSha256: stopped.rawSha256 } } : {}),
      listSha256: Object.fromEntries(Object.entries(bytes).map(([c, b]) => [c, sha256(b)])), exclusionSha256: sha256(excludeBytes), homepageOnlySha256: sha256(homepageBytes),
      removals: { used: true, count: removals.size, unmatched: unmatchedRemovals.length, sha256: sha256(removalsBytes) },
      priorOptOuts: { used: true, count: prior.size, sha256: sha256(priorBytes) },
      pilotDropped: { used: Boolean(pilotBytes), count: pilotDropped.size, sha256: pilotBytes ? sha256(pilotBytes) : null },
    },
    meta: { listSha256: Object.fromEntries(Object.entries(bytes).map(([c, b]) => [c, sha256(b)])), exclusionSha256: sha256(excludeBytes), startedFrom: process.version },
    onRecord: (r, k) => { deps.afterRecord?.(k, rows.length); if (!deps.say) process.stderr.write(`\r${k + 1}/${rows.length} ${r.status.padEnd(9)}`); },
  });
  process.off("SIGINT", onSignal);
  process.off("SIGTERM", onSignal);
  if (!deps.say) process.stderr.write("\n");
  const finished = JSON.parse(readFileSync(join(out, "manifest.json"), "utf8"));
  const prune = `node bench/front-door/validation-sample.mjs prune ${out}`;
  const skips = [flag(args, "--removals"), flag(args, "--prior-optouts"), flag(args, "--pilot-dropped")].filter(Boolean).map((f) => `--skip ${f}`).join(" ");
  const recovery = pilot === null
    ? `Next: ${prune}`
    : `Next, in order, then see Failure recovery in run-sheet.md:\nnode bench/front-door/pilot-report.mjs ${join(out, "raw.jsonl")} --exclude ${flag(args, "--exclude")} ${skips} --seal\n${prune}`;
  if (stoppedFor) { say(`STOP: ${stoppedFor}. This run is partial: ${finished.records} of ${rows.length} sites. It decides no claim. ${recovery}`); return 5; }
  if (!finished.immutableAtFinish.ok) { say(`STOP: changed during the run: ${finished.immutableAtFinish.changed.join(", ")}. ${recovery}`); return 4; }
  (deps.say ?? console.log)(`E20-R ${pilot === null ? `pass ${pass}` : "pilot"}: ${Object.entries(agg.cohorts).map(([c, a]) => `${c} ${a.sites.visited}/${a.sites.listed}`).join(", ")}. Raw (private): ${join(out, "raw.jsonl")}`);
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}
