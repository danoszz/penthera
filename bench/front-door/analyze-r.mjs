#!/usr/bin/env node
/**
 * E20-R analysis: the claims of the protocol (§ 6, § 7, Amendment 2), from the
 * private raw files of both passes and of E20. Aggregates only; no site is
 * named in the output. Under Amendment 2, --pass1 takes the run the claims are
 * decided on (pass 2) and --pass2 the run it is compared with (pass 1).
 *
 *   node bench/front-door/analyze-r.mjs --pass1 <raw.jsonl> [--pass2 <raw.jsonl>] --e20 <tranco/raw.jsonl> <yc/raw.jsonl> [--e20-excluded <hosts file>] [--industries <csv>] [--out analysis.json]
 *
 * Intervals are a cluster bootstrap over organizations: the final host's for HTTP,
 * the listed one's for DNS, from the pinned suffix list. HTTP claims must hold on
 * both estimands: S (every graded site) and R (sites labeled `candidate-page`).
 * Otherwise they are view-dependent.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { siteKey, siteOrg } from "./psl.mjs";
import { isEligible, selfHashed, unfinishedRun, withheldCounts } from "./record-checks.mjs";
import { PREREG_R, recordedHashR, studyState } from "./replicate.mjs";
import { seeded } from "./replicate.mjs";
import { newcombe } from "./run.mjs";

// Amendment 2: C1 to C11 are the family. The ±10 margin stays because it was registered, not because it is justified.
export const CLAIMS_R = 11;
export const LEVEL = 1 - 0.05 / CLAIMS_R;
export const RESAMPLES = 20_000;
// A kappa over every check is costly, and C14 and C15 only describe, so they use fewer.
export const KAPPA_RESAMPLES = 2000;
// A difference needs this many organizations with a judged response on each side.
export const MIN_SUPPORT = 20;
export const SEED = 2020;
export const SESOI = 0.10;
export const KAPPA_CHECKS = Object.freeze(["https+hsts", "csp", "framing", "nosniff", "referrer", "permissions", "spf+dmarc", "caa", "security-txt"]);
const DNS_CHECKS = new Set(["spf+dmarc", "caa", "spf", "dmarc"]);
const STRATUM_A = new Set(["cloudflare", "akamai"]);

const get = (r, id) => { const c = (r.checks || []).find((x) => x.id === id); return !c || c.weight === 0 ? undefined : Boolean(c.passed); };
/** Pass or fail for a check id, undefined when it could not run. */
export function pass(r, id) {
  if (id === "https+hsts") { const h = get(r, "https"); return h === undefined ? undefined : h && Boolean(get(r, "hsts")); }
  if (id === "spf+dmarc") { const a = get(r, "spf"), b = get(r, "dmarc"); return a === undefined || b === undefined ? undefined : a && b; }
  if (id === "csp-controls-scripts") return r.evidence?.csp ? r.evidence.csp.controlsScripts : undefined;
  return get(r, id);
}
const share = (rows, id) => { let k = 0, n = 0; for (const r of rows) { const p = pass(r, id); if (p !== undefined) { n++; if (p) k++; } } return n ? k / n : NaN; };
const judged = (rows, id) => rows.filter((r) => pass(r, id) !== undefined).length;
// DNS claims cluster on the listed organization, HTTP claims on where the response came from.
const org = (r) => r.clusterOrg ?? siteOrg(r.finalHost || r.host);
const pct = (sorted, q) => sorted[Math.min(sorted.length - 1, Math.max(0, Math.floor(q * sorted.length)))];
const groups = (rows) => Object.values(rows.reduce((m, r) => ((m[org(r)] ||= []).push(r), m), {}));
const orgsJudged = (rows, id) => groups(rows).filter((g) => g.some((r) => pass(r, id) !== undefined)).length;

/**
 * Organizations of two groups, each holding a cell for side A and one for side B. An
 * organization on both sides is one entry, so a resample keeps the covariance. Entries
 * are drawn within their pattern (A only, B only, both), which keeps each side's size.
 */
function jointOrgs(a, b, size, fill) {
  const byOrg = new Map();
  for (const [side, rows] of [[0, a], [1, b]]) {
    for (const r of rows) {
      const o = org(r);
      if (!byOrg.has(o)) byOrg.set(o, { cells: [new Float64Array(size), new Float64Array(size)], on: [false, false] });
      const e = byOrg.get(o);
      e.on[side] = true;
      fill(e.cells[side], r);
    }
  }
  const patterns = { a: [], b: [], both: [] };
  for (const e of byOrg.values()) patterns[e.on[0] && e.on[1] ? "both" : e.on[0] ? "a" : "b"].push(e);
  return Object.values(patterns).filter((p) => p.length);
}

function jointDraw(patterns, size, rng) {
  const x = new Float64Array(size), y = new Float64Array(size);
  for (const p of patterns) {
    for (let i = 0; i < p.length; i++) {
      const e = p[Math.floor(rng() * p.length)];
      for (let k = 0; k < size; k++) { x[k] += e.cells[0][k]; y[k] += e.cells[1][k]; }
    }
  }
  return [x, y];
}

/** B minus A with a cluster-bootstrap interval, resampling organizations jointly. */
export function clusterDiff(a, b, id, { level = LEVEL, resamples = RESAMPLES, seed = SEED } = {}) {
  // Each organization reduced to (passes, judged), so a resample is a sum.
  const patterns = jointOrgs(a, b, 2, (c, r) => { const p = pass(r, id); if (p !== undefined) { c[1]++; if (p) c[0]++; } });
  const rng = seeded(seed), out = [];
  // A draw with nothing judged has no share. It is skipped, and counted.
  let skipped = 0;
  if (a.length && b.length) {
    for (let i = 0; i < resamples; i++) {
      const [x, y] = jointDraw(patterns, 2, rng);
      const d = y[0] / y[1] - x[0] / x[1];
      if (Number.isNaN(d)) skipped++; else out.push(d);
    }
  }
  const sorted = out.sort((x, y) => x - y), tail = (1 - level) / 2;
  return { diff: share(b, id) - share(a, id), ci: sorted.length ? [pct(sorted, tail), pct(sorted, 1 - tail)] : [NaN, NaN], nA: a.length, nB: b.length, judgedA: judged(a, id), judgedB: judged(b, id), orgsA: orgsJudged(a, id), orgsB: orgsJudged(b, id), skipped };
}

/** Two-sided Fisher exact test for [[a, b], [c, d]]: tables no likelier than this one. */
export function fisherExact(a, b, c, d) {
  const n = a + b + c + d;
  const logF = [0];
  for (let i = 1; i <= n; i++) logF.push(logF[i - 1] + Math.log(i));
  const row1 = a + b, col1 = a + c;
  const logP = (x) => logF[row1] + logF[n - row1] + logF[col1] + logF[n - col1] - logF[n] - logF[x] - logF[row1 - x] - logF[col1 - x] - logF[n - row1 - col1 + x];
  const seen = logP(a);
  let p = 0;
  for (let x = Math.max(0, row1 + col1 - n); x <= Math.min(row1, col1); x++) if (logP(x) <= seen + 1e-9) p += Math.exp(logP(x));
  return Math.min(1, p);
}

/** Registered next to the bootstrap: Newcombe's interval, without clustering, and the exact test. */
function rowLevel(a, b, id) {
  const t = (rows) => { let k = 0, n = 0; for (const r of rows) { const p = pass(r, id); if (p !== undefined) { n++; if (p) k++; } } return { k, n }; };
  const x = t(a), y = t(b);
  if (!x.n || !y.n) return { newcombe: { diff: NaN, ci95: [NaN, NaN] }, exactP: NaN };
  return { newcombe: newcombe(y.k, y.n, x.k, x.n), exactP: fisherExact(y.k, y.n - y.k, x.k, x.n - x.k) };
}

/** Two separate readings of one interval: did it leave zero, and did it stay inside the margin. */
export function intervalOutcomes([lo, hi]) {
  const known = Number.isFinite(lo) && Number.isFinite(hi);
  return {
    direction: !known ? "unknown" : lo > 0 ? "above zero" : hi < 0 ? "below zero" : "includes zero",
    equivalence: !known ? "unknown" : lo >= -SESOI && hi <= SESOI ? "within the margin" : "not shown",
  };
}

/** Same rules as E20 § 6.5, with the smallest difference that matters on the interval. */
export function decide([lo, hi], sign) {
  if (!Number.isFinite(lo) || !Number.isFinite(hi)) return "inconclusive";
  if (sign > 0 ? lo > 0 : hi < 0) return "supported";
  if (sign > 0 ? hi < 0 : lo > 0) return "refuted";
  if (lo >= -SESOI && hi <= SESOI) return "no meaningful difference";
  return "inconclusive";
}

/** § 2: an HTTP claim needs S and R to agree. */
export function combine(s, r) {
  if (s === "not estimable" || r === "not estimable") return "not estimable";
  if (s === r) return s;
  return [s, r].some((d) => d === "supported" || d === "refuted") ? "view-dependent" : "inconclusive";
}

/** Cohen's kappa for two paired label arrays. */
export function kappa(x, y) {
  const n = x.length;
  if (!n) return NaN;
  const labels = [...new Set([...x, ...y])];
  let agree = 0;
  for (let i = 0; i < n; i++) if (x[i] === y[i]) agree++;
  const po = agree / n;
  const pe = labels.reduce((s, l) => s + (x.filter((v) => v === l).length / n) * (y.filter((v) => v === l).length / n), 0);
  return pe === 1 ? 1 : (po - pe) / (1 - pe);
}

/** Bootstrap interval for a statistic of paired sites, resampling organizations. */
function bounds(pairs, stat, { level = LEVEL, resamples = RESAMPLES, seed = SEED } = {}) {
  const g = Object.values(pairs.reduce((m, p) => ((m[org(p[0])] ||= []).push(p), m), {})), r = seeded(seed), out = [];
  for (let i = 0; i < resamples; i++) { const s = []; for (let k = 0; k < g.length; k++) s.push(...g[Math.floor(r() * g.length)]); out.push(stat(s)); }
  const finite = out.filter(Number.isFinite).sort((a, b) => a - b);
  return finite.length ? [pct(finite, (1 - level) / 2), pct(finite, 1 - (1 - level) / 2)] : [NaN, NaN];
}

const median = (a) => { const s = [...a].sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const loadAll = (f) => readFileSync(f, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
const load = (f) => loadAll(f).filter((r) => r.status === "ok");
/** One run's records by site, so apex and `www.` find each other. C12 and C13 each pair with their own E20 file. */
export const e20Index = (rows) => new Map(rows.map((r) => [siteKey(r.host), r]));
const inCohort = (rows, ...names) => rows.filter((r) => names.some((n) => r.cohorts?.[n]));
const isPage = (r) => ["page", "candidate-page"].includes(r.evidence?.class?.label);
const isRefused = (r) => ["challenge", "block"].includes(r.evidence?.class?.label);
// One definition across passes: a record from pass 2 carries pass 1's rules next to its own.
const labelForAgreement = (r) => (r.evidence?.classRegistered ?? r.evidence?.class)?.label;

/** One difference claim, on S alone for a DNS check, on S and R otherwise. */
export function diffClaim(id, label, a, b, check, sign, opts) {
  const s = clusterDiff(a, b, check, opts);
  const judge = (x) => (x.orgsA < MIN_SUPPORT || x.orgsB < MIN_SUPPORT ? "not estimable" : decide(x.ci, sign));
  const view = (x, rows, decision) => ({ ...x, ...rowLevel(rows[0], rows[1], check), ...intervalOutcomes(x.ci), decision });
  const sDecision = judge(s);
  if (DNS_CHECKS.has(check)) return { id, label, check, predicted: sign > 0 ? "higher" : "lower", S: view(s, [a, b], sDecision), decision: sDecision };
  const pa = a.filter(isPage), pb = b.filter(isPage);
  const r = clusterDiff(pa, pb, check, opts);
  const rDecision = judge(r);
  return { id, label, check, predicted: sign > 0 ? "higher" : "lower", S: view(s, [a, b], sDecision), R: view(r, [pa, pb], rDecision), decision: combine(sDecision, rDecision) };
}

/** C1 to C11 are the family. C12 to C15 describe reproducibility and decide nothing. `e20` maps host to the E20 record of that site. */
export function claims(p1, p2, e20, opts) {
  const T = inCohort(p1, "T1k"), Y = inCohort(p1, "YC-new"), Rc = inCohort(p1, "YC-new", "YC-25"), H = inCohort(p1, "T100k"), O = inCohort(p1, "YC-old");
  const edge = (rows, a) => rows.filter((r) => STRATUM_A.has(r.platform?.edge) === a);
  const out = [
    diffClaim("C1", "YC-new minus T1k", T, Y, "csp", -1, opts),
    diffClaim("C2", "YC-new minus T1k", T, Y, "spf+dmarc", -1, opts),
    diffClaim("C3", "YC-new minus T1k, Cloudflare and Akamai", edge(T, true), edge(Y, true), "https+hsts", -1, opts),
    diffClaim("C4", "YC-new minus T1k, other edges", edge(T, false), edge(Y, false), "https+hsts", +1, opts),
    diffClaim("C5", "T100k minus T1k", T, H, "csp", -1, opts),
    diffClaim("C6", "T100k minus T1k", T, H, "spf+dmarc", -1, opts),
    diffClaim("C7", "YC-recent minus T100k", H, Rc, "spf+dmarc", +1, opts),
    diffClaim("C8", "YC-recent minus T100k", H, Rc, "https+hsts", +1, opts),
    diffClaim("C9", "YC-recent minus T100k", H, Rc, "csp", -1, opts),
    diffClaim("C10", "YC-old minus YC-new", Y, O, "spf+dmarc", +1, opts),
    diffClaim("C11", "YC-old minus YC-new", Y, O, "csp", +1, opts),
  ];
  // C12, C13: paired on sites graded in E20 and in pass 1; E20 stored only the status. A description, never a decision.
  for (const [id, cohort] of [["C12", "T1k"], ["C13", "YC-new"]]) {
    const seen = e20[cohort] ?? new Map();
    const pairs = inCohort(p1, cohort).filter((r) => seen.has(siteKey(r.host))).map((r) => [r, seen.get(siteKey(r.host))]);
    const refused = ([r]) => ["challenge", "block"].includes(labelForAgreement(r));
    const stat = (s) => s.filter(refused).length / s.length - s.filter(([, e]) => e.httpStatus === 403).length / s.length;
    const ci = pairs.length ? bounds(pairs, stat, { level: 0.95, ...opts }) : [NaN, NaN];
    out.push({ id, label: `server refusals minus E20 403s, ${cohort}`, n: pairs.length, diff: pairs.length ? stat(pairs) : NaN, ci, level: 0.95, decision: "descriptive" });
  }
  // C14, C15: agreement between the passes, on every site graded in both.
  if (!p2) return [...out, { id: "C14", label: "median kappa between passes", decision: "not run" }, { id: "C15", label: "label kappa between passes", decision: "not run" }];
  const byHost = e20Index(p2);
  const pairs = p1.filter((r) => byHost.has(siteKey(r.host))).map((r) => [r, byHost.get(siteKey(r.host))]);
  const checkKappas = (s) => median(KAPPA_CHECKS.map((id) => { const v = s.filter(([a, b]) => pass(a, id) !== undefined && pass(b, id) !== undefined); return kappa(v.map(([a]) => pass(a, id)), v.map(([, b]) => pass(b, id))); }).filter(Number.isFinite));
  const labelKappa = (s) => kappa(s.map(([a]) => labelForAgreement(a)), s.map(([, b]) => labelForAgreement(b)));
  const kOpts = { resamples: KAPPA_RESAMPLES, ...opts, level: 0.95 };
  const lo14 = pairs.length ? bounds(pairs, checkKappas, kOpts)[0] : NaN, lo15 = pairs.length ? bounds(pairs, labelKappa, kOpts)[0] : NaN;
  out.push({ id: "C14", label: "median kappa between passes", n: pairs.length, kappa: pairs.length ? checkKappas(pairs) : NaN, lower: lo14, threshold: 0.8, meetsThreshold: lo14 >= 0.8, decision: "descriptive" });
  out.push({ id: "C15", label: "label kappa between passes", n: pairs.length, kappa: pairs.length ? labelKappa(pairs) : NaN, lower: lo15, threshold: 0.6, meetsThreshold: lo15 >= 0.6, decision: "descriptive" });
  return out;
}

const DNS_MEASURES = Object.freeze({
  registered: { spf: (d) => d.spf, dmarc: (d) => d.dmarc },
  declared: { spf: (d) => d.spfRecordPresent, dmarc: (d) => d.dmarcReading?.declared ?? null },
  enforcing: { spf: (d) => d.spfRecordPresent, dmarc: (d) => d.dmarcReading?.enforcing ?? null },
  reject: { spf: (d) => d.spfRecordPresent, dmarc: (d) => d.dmarcReading?.reject ?? null },
});

/** Sites whose listed domain exists, with checks from their own DNS records, whether or not HTTP worked. */
function dnsRows(records, m) {
  return records.filter((r) => r.dns?.listed?.exists).map((r) => {
    const d = r.dns.listed;
    const check = (id, v) => ({ id, weight: v === null || v === undefined ? 0 : 1, passed: v });
    return { ...r, clusterOrg: r.listedOrg ?? d.domain, checks: [check("spf", m.spf(d)), check("dmarc", m.dmarc(d)), check("caa", d.caa)] };
  });
}

/**
 * Amendment 2: the mail claims on DNS read for the listed domain, for every site
 * whose domain exists, whether or not HTTP worked, clustered on the listed
 * organization. `enforcing` decides. The others are reported beside it.
 */
export function dnsClaims(records, { measure = "enforcing", ...opts } = {}) {
  const rows = dnsRows(records, DNS_MEASURES[measure]);
  const T = inCohort(rows, "T1k"), Y = inCohort(rows, "YC-new"), H = inCohort(rows, "T100k"), Rc = inCohort(rows, "YC-new", "YC-25"), O = inCohort(rows, "YC-old");
  return [
    diffClaim("C2", "YC-new minus T1k", T, Y, "spf+dmarc", -1, opts),
    diffClaim("C6", "T100k minus T1k", T, H, "spf+dmarc", -1, opts),
    diffClaim("C7", "YC-recent minus T100k", H, Rc, "spf+dmarc", +1, opts),
    diffClaim("C10", "YC-old minus YC-new", Y, O, "spf+dmarc", +1, opts),
  ];
}

/** Domains behind each mail claim, by what DNS said. `exists: null` is a resolver failure: unknown, and left out. */
export function dnsCoverage(records) {
  const out = {};
  for (const cohort of ["T1k", "YC-new", "YC-25", "YC-old", "T100k"]) {
    const rows = inCohort(records, cohort).filter((r) => r.dns?.listed);
    out[cohort] = { read: rows.length, exists: rows.filter((r) => r.dns.listed.exists === true).length, nxdomain: rows.filter((r) => r.dns.listed.exists === false).length, unknown: rows.filter((r) => r.dns.listed.exists === null).length };
  }
  return out;
}

export { isEligible };

/** The reported outcome next to "CSP present": C1, C5, C9 and C11 on a policy that controls scripts. */
export function cspValueClaims(rows, opts) {
  const T = inCohort(rows, "T1k"), Y = inCohort(rows, "YC-new"), Rc = inCohort(rows, "YC-new", "YC-25"), H = inCohort(rows, "T100k"), O = inCohort(rows, "YC-old");
  return [
    diffClaim("C1", "YC-new minus T1k", T, Y, "csp-controls-scripts", -1, opts),
    diffClaim("C5", "T100k minus T1k", T, H, "csp-controls-scripts", -1, opts),
    diffClaim("C9", "YC-recent minus T100k", H, Rc, "csp-controls-scripts", -1, opts),
    diffClaim("C11", "YC-old minus YC-new", Y, O, "csp-controls-scripts", +1, opts),
  ];
}

/**
 * Worst-case bounds on B minus A over a whole list: `a` and `b` hold every eligible
 * listed site, and a site with no judged value could be either way.
 */
export function coverageBounds(a, b, id) {
  const t = (rows) => { let k = 0, n = 0; for (const r of rows) { const p = pass(r, id); if (p !== undefined) { n++; if (p) k++; } } return { k, n, N: rows.length }; };
  const x = t(a), y = t(b);
  if (!x.N || !y.N) return { low: NaN, high: NaN, coverageA: NaN, coverageB: NaN };
  return { low: y.k / y.N - (x.k + x.N - x.n) / x.N, high: (y.k + y.N - y.n) / y.N - x.k / x.N, coverageA: x.n / x.N, coverageB: y.n / y.N };
}

const SECONDARY_COHORTS = Object.freeze(["T10k", "Europe", "SP500", "YC-scale", "ShowHN", "NL-Cbw"]);
const EDGE_STRATA = new Set(["cloudflare", "akamai", "cloudfront", "vercel"]);
const edgeStratum = (r) => (EDGE_STRATA.has(r.platform?.edge) ? r.platform.edge : "other");

/**
 * B minus A standardized to the pooled edge mix, on the strata where both sides
 * reach the common-support floor in organizations. A stratum under it is dropped
 * and named. Organizations are resampled jointly.
 */
export function standardizedDiff(a, b, id, { level = 0.95, resamples = RESAMPLES, seed = SEED } = {}) {
  const strata = [...new Set([...a, ...b].map(edgeStratum))].sort();
  const inStratum = (rows, s) => rows.filter((r) => edgeStratum(r) === s);
  const supported = strata.filter((s) => orgsJudged(inStratum(a, s), id) >= MIN_SUPPORT && orgsJudged(inStratum(b, s), id) >= MIN_SUPPORT);
  const dropped = strata.filter((s) => !supported.includes(s));
  if (!supported.length) return { diff: NaN, ci: [NaN, NaN], supported, dropped };
  const index = new Map(supported.map((s, i) => [s, i]));
  const size = supported.length * 2;
  const patterns = jointOrgs(a, b, size, (c, r) => { const i = index.get(edgeStratum(r)); const p = pass(r, id); if (i !== undefined && p !== undefined) { c[i * 2 + 1]++; if (p) c[i * 2]++; } });
  const sum = (side) => { const c = new Float64Array(size); for (const p of patterns) for (const e of p) for (let k = 0; k < size; k++) c[k] += e.cells[side][k]; return c; };
  const totalA = sum(0), totalB = sum(1);
  const pool = supported.map((_, i) => totalA[i * 2 + 1] + totalB[i * 2 + 1]);
  const weight = pool.map((n) => n / pool.reduce((x, y) => x + y, 0));
  const value = (x, y) => { let d = 0; for (let i = 0; i < weight.length; i++) { const p = y[i * 2] / y[i * 2 + 1] - x[i * 2] / x[i * 2 + 1]; if (Number.isNaN(p)) return NaN; d += weight[i] * p; } return d; };
  const rng = seeded(seed), out = [];
  for (let i = 0; i < resamples; i++) { const [x, y] = jointDraw(patterns, size, rng); const d = value(x, y); if (!Number.isNaN(d)) out.push(d); }
  const sorted = out.sort((x, y) => x - y), tail = (1 - level) / 2;
  return { diff: value(totalA, totalB), ci: sorted.length ? [pct(sorted, tail), pct(sorted, 1 - tail)] : [NaN, NaN], supported, dropped };
}

/**
 * Amendment 2, secondary: each secondary cohort against YC-new and T1k on every check.
 * HTTP checks read graded responses. DNS checks read the sites' own DNS records. Intervals
 * are naive row-level, Newcombe with no clustering: reported, they corroborate nothing.
 */
export function secondaryCohorts(graded, all = graded) {
  const dns = dnsRows(all, DNS_MEASURES.enforcing);
  const http = [...new Set(graded.flatMap((r) => (r.checks ?? []).map((c) => c.id)))].filter((id) => !DNS_CHECKS.has(id)).sort();
  const table = [...http.map((check) => [check, graded, "http"]), ...[...DNS_CHECKS].map((check) => [check, dns, "dns"])];
  return SECONDARY_COHORTS.flatMap((cohort) => ["YC-new", "T1k"].flatMap((against) => table.map(([check, rows, source]) => {
    const a = inCohort(rows, against), b = inCohort(rows, cohort);
    const base = { cohort, against, check, source, interval: "naive row-level", judgedA: judged(a, check), judgedB: judged(b, check), orgsA: orgsJudged(a, check), orgsB: orgsJudged(b, check) };
    return base.orgsA >= MIN_SUPPORT && base.orgsB >= MIN_SUPPORT ? { ...base, ...rowLevel(a, b, check) } : { ...base, decision: "not estimable" };
  })));
}

/** Sites this run skipped, per cohort and reason: pilot, stopped pass and the rest. Skipped sites aren't missing at random, so each list shows its own. */
export function skipsByCohort(all) {
  const out = {};
  for (const r of all.filter((x) => x.reason === "exclusion_list")) for (const c of Object.keys(r.cohorts ?? {})) ((out[c] ||= {})[r.category] = (out[c][r.category] ?? 0) + 1);
  return out;
}

/** A Wilson 95% interval, row-level like the table it sits in. */
function wilson(k, n, z = 1.96) {
  const p = k / n, d = 1 + z * z / n, mid = (p + z * z / (2 * n)) / d, half = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d;
  return [Math.max(0, mid - half), Math.min(1, mid + half)];
}

/** The challenge share by edge, among graded responses, for edges with at least 20 sites, with a naive row-level 95% interval. */
export function challengeByEdge(rows) {
  const out = {};
  for (const stratum of new Set(rows.map(edgeStratum))) {
    const here = rows.filter((r) => edgeStratum(r) === stratum);
    const k = here.filter((r) => r.evidence?.class?.label === "challenge").length;
    if (here.length >= MIN_SUPPORT) out[stratum] = { n: here.length, share: k / here.length, ci95: wilson(k, here.length), interval: "naive row-level" };
  }
  return out;
}

/** Amendment 2: refusal share among graded sites. Signature-backed is the primary endpoint. */
export function refusalShares(rows) {
  const n = rows.length;
  const refused = rows.filter(isRefused);
  return { n, all: n ? refused.length / n : NaN, signatureBacked: n ? refused.filter((r) => r.evidence.class.rule !== "unrecognized-403").length / n : NaN, registered: n ? rows.filter((r) => ["challenge", "block"].includes(r.evidence?.classRegistered?.label)).length / n : NaN };
}

/** The primary refusal endpoint with a cluster-bootstrap 95% interval. */
export function primaryRefusal(rows, { resamples = RESAMPLES, seed = SEED } = {}) {
  const hit = (r) => isRefused(r) && r.evidence.class.rule !== "unrecognized-403";
  const t = groups(rows).map((g) => [g.filter(hit).length, g.length]);
  const rng = seeded(seed), out = [];
  for (let i = 0; t.length && i < resamples; i++) { let k = 0, n = 0; for (let j = 0; j < t.length; j++) { const c = t[Math.floor(rng() * t.length)]; k += c[0]; n += c[1]; } out.push(k / n); }
  const sorted = out.sort((x, y) => x - y);
  return { n: rows.length, share: rows.length ? rows.filter(hit).length / rows.length : NaN, ci: sorted.length ? [pct(sorted, 0.025), pct(sorted, 0.975)] : [NaN, NaN] };
}

/** § 7: C1 to C4 without the hosts E20 excluded, so the comparison with E20 is like for like. */
export function replicationAsE20(p1, droppedHosts, opts) {
  const keep = p1.filter((r) => !droppedHosts.has(siteKey(r.host)));
  return claims(keep, keep, {}, opts).filter((c) => ["C1", "C2", "C3", "C4"].includes(c.id));
}

/** § 6, secondary: each check by industry, from a private host-to-industry map. Groups of at least 20 only. */
export function industryTable(rows, industries, checks = KAPPA_CHECKS, min = 20) {
  const by = {};
  for (const r of rows) {
    const i = industries.get(siteKey(r.host));
    if (i) (by[i] ||= []).push(r);
  }
  const out = { suppressedGroups: 0 };
  for (const [i, g] of Object.entries(by)) {
    if (g.length < min) { out.suppressedGroups++; continue; }
    out[i] = { sites: g.length, median: median(g.map((r) => r.score)), shares: Object.fromEntries(checks.map((c) => [c, share(g, c)])) };
  }
  return out;
}

/** § 6, secondary: each check by site trait, within one cohort, groups of at least 20 sites. */
export function traitTable(rows, checks = KAPPA_CHECKS, min = 20) {
  const out = {};
  for (const trait of ["login", "payments", "shop", "securityPage"]) {
    const g = rows.filter((r) => r.evidence?.traits?.[trait] === true);
    if (g.length < min) { out[trait] = { sites: g.length, suppressed: true }; continue; }
    out[trait] = { sites: g.length, shares: Object.fromEntries(checks.map((c) => [c, share(g, c)])) };
  }
  return out;
}

/** § 6, secondary: the trait table for each cohort. */
export function traitsByCohort(rows, checks = KAPPA_CHECKS, min = 20) {
  const cohorts = [...new Set(rows.flatMap((r) => Object.keys(r.cohorts ?? {})))].sort();
  return Object.fromEntries(cohorts.map((c) => [c, traitTable(inCohort(rows, c), checks, min)]));
}

export function main(args, { fail = console.error, preregText } = {}) {
  const at = (n) => args[args.indexOf(n) + 1];
  if (!args.includes("--pass1")) { fail("Usage: analyze-r.mjs --pass1 <raw> [--pass2 <raw>] --e20 <tranco raw> <yc raw> [--out file]"); return 2; }
  const problem = unfinishedRun(dirname(at("--pass1")));
  if (problem) { fail(`Refused: this run can't decide claims: ${problem}.`); return 3; }
  // The gate read raw.jsonl, so nothing else in the folder may stand in for it.
  if (basename(at("--pass1")) !== "raw.jsonl") { fail("Refused: --pass1 takes the run's raw.jsonl, the file the gate checked."); return 3; }
  // The other inputs stay private, so their frozen hashes are what ties a result to them.
  const prereg = preregText ?? readFileSync(PREREG_R, "utf8");
  const given = (flag, offset = 1) => (args.includes(flag) ? args[args.indexOf(flag) + offset] : undefined);
  for (const [label, file] of [["Pass 1 raw", given("--pass2")], ["E20 Tranco raw", given("--e20")], ["E20 YC raw", given("--e20", 2)], ["Industry map", given("--industries")], ["E20 exclusion file", given("--e20-excluded")]]) {
    if (!file || !existsSync(file)) { fail(`Refused: the registered input "${label}" was not given.`); return 3; }
    if (recordedHashR(prereg, label) !== createHash("sha256").update(readFileSync(file)).digest("hex")) { fail(`Refused: ${label} does not match its frozen hash.`); return 3; }
  }
  const i = args.indexOf("--e20");
  const e20 = { T1k: e20Index(load(args[i + 1])), "YC-new": e20Index(load(args[i + 2])) };
  const p1 = load(at("--pass1"));
  const all = loadAll(at("--pass1"));
  const out = { experiment: "E20-R", level: LEVEL, resamples: RESAMPLES, claims: claims(p1, args.includes("--pass2") ? load(at("--pass2")) : null, e20), traits: traitTable(p1), traitsByCohort: traitsByCohort(p1), refusals: refusalShares(p1) };
  const { reviewed, scrubMisses } = JSON.parse(readFileSync(join(dirname(at("--pass1")), "privacy-report.json"), "utf8"));
  if (reviewed) out.privacyDeviation = { ...reviewed, scrubMisses };
  out.primaryRefusal = primaryRefusal(p1);
  const eligible = all.filter(isEligible);
  const edge = (rows, inA) => rows.filter((r) => STRATUM_A.has(r.platform?.edge) === inA);
  const pairs = { C1: ["T1k", ["YC-new"], "csp"], C5: ["T1k", ["T100k"], "csp"], C8: ["T100k", ["YC-new", "YC-25"], "https+hsts"], C9: ["T100k", ["YC-new", "YC-25"], "csp"], C11: ["YC-new", ["YC-old"], "csp"] };
  out.bounds = Object.fromEntries(Object.entries(pairs).map(([id, [a, b, check]]) => [id, coverageBounds(inCohort(eligible, a), inCohort(eligible, ...b), check)]));
  // C3 and C4 are strata of the edge, which only a graded response shows, so their bounds cover graded sites.
  out.bounds.C3 = { ...coverageBounds(edge(inCohort(p1, "T1k"), true), edge(inCohort(p1, "YC-new"), true), "https+hsts"), scope: "graded" };
  out.bounds.C4 = { ...coverageBounds(edge(inCohort(p1, "T1k"), false), edge(inCohort(p1, "YC-new"), false), "https+hsts"), scope: "graded" };
  out.standardized = Object.fromEntries(Object.entries(pairs).map(([id, [a, b, check]]) => [id, standardizedDiff(inCohort(p1, a), inCohort(p1, ...b), check)]));
  out.standardized.C3 = standardizedDiff(edge(inCohort(p1, "T1k"), true), edge(inCohort(p1, "YC-new"), true), "https+hsts");
  out.standardized.C4 = standardizedDiff(edge(inCohort(p1, "T1k"), false), edge(inCohort(p1, "YC-new"), false), "https+hsts");
  // The R view: the same differences among `candidate-page` responses.
  out.standardizedR = Object.fromEntries(Object.entries(pairs).map(([id, [a, b, check]]) => [id, standardizedDiff(inCohort(p1, a).filter(isPage), inCohort(p1, ...b).filter(isPage), check)]));
  out.standardizedR.C3 = standardizedDiff(edge(inCohort(p1, "T1k"), true).filter(isPage), edge(inCohort(p1, "YC-new"), true).filter(isPage), "https+hsts");
  out.standardizedR.C4 = standardizedDiff(edge(inCohort(p1, "T1k"), false).filter(isPage), edge(inCohort(p1, "YC-new"), false).filter(isPage), "https+hsts");
  out.secondaryCohorts = secondaryCohorts(p1, all);
  out.challengeByEdge = challengeByEdge(p1);
  out.skipsByCohort = skipsByCohort(all);
  out.textWithheld = withheldCounts(all);
  out.cspControlsScripts = cspValueClaims(p1);
  if (all.some((r) => r.dns?.listed)) {
    const decided = dnsClaims(all);
    // The graded-only reading on the final host stays beside the decision, and decides nothing.
    out.dnsGradedOnlyReading = out.claims.filter((c) => decided.some((d) => d.id === c.id)).map((c) => ({ ...c, decision: "reported" }));
    out.claims = out.claims.map((c) => decided.find((d) => d.id === c.id) ?? c);
    out.dnsBeside = { registered: dnsClaims(all, { measure: "registered" }), declared: dnsClaims(all, { measure: "declared" }), rejectOnly: dnsClaims(all, { measure: "reject" }) };
    out.dnsCoverage = dnsCoverage(all);
  }
  if (args.includes("--industries")) out.industries = industryTable(p1, new Map(readFileSync(at("--industries"), "utf8").split(/\r?\n/).slice(1).filter(Boolean).map((l) => l.split(",")).map(([h, i]) => [h, i])));
  if (args.includes("--e20-excluded")) out.replicationAsE20 = replicationAsE20(p1, new Set(readFileSync(at("--e20-excluded"), "utf8").split(/\r?\n/).map((l) => l.trim().toLowerCase()).filter(Boolean)));
  // The run this came from and the state it ran under, for the final report to check.
  const sha = (f) => createHash("sha256").update(readFileSync(f)).digest("hex");
  const { codeSha256, protocolSha256, classifierSha256, pslSha256, lockfileSha256 } = studyState();
  out.provenance = { manifestSha256: sha(join(dirname(at("--pass1")), "manifest.json")), rawSha256: sha(at("--pass1")), state: { codeSha256, protocolSha256, classifierSha256, pslSha256, lockfileSha256 } };
  const text = JSON.stringify(selfHashed(JSON.parse(JSON.stringify(out))), null, 2) + "\n";
  if (args.includes("--out")) writeFileSync(at("--out"), text); else process.stdout.write(text);
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main(process.argv.slice(2));
