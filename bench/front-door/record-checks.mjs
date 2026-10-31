/**
 * What one E20-R2 record must not hold, read the same way by the report that seals a
 * pilot and by the watch that can stop pass 2 in flight.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { scrubMisses } from "./classify.mjs";

// Two narrow exceptions, by exact path. A hash is hex by design, and only a real digest
// counts as one. An SPF record lists mail servers by address on purpose, so addresses
// don't count there, and anything else does.
const HASH_PATHS = new Set(["evidence.bodySha256", "evidence.others.bodySha256"]);
const DIGEST = /^[0-9a-f]{64}$/;
const SPF_PATHS = new Set(["dns.listed.spfRecord", "dns.final.spfRecord"]);
const ADDRESS_KINDS = new Set(["ipv4", "ipv6"]);

/** Every string one record stores, object keys too, each with its path. */
function* storedStrings(value, path = "") {
  if (typeof value === "string") yield [path, value, false];
  else if (Array.isArray(value)) for (const v of value) yield* storedStrings(v, path);
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      yield [path, k, true];
      yield* storedStrings(v, path ? `${path}.${k}` : k);
    }
  }
}

/** Every finding of a detector in one record. Takes the detector, so the frozen one can walk the same paths. */
export function eachMiss(r, visit, detector = scrubMisses) {
  for (const [path, text, isKey] of storedStrings(r)) {
    if (!isKey && HASH_PATHS.has(path) && DIGEST.test(text)) continue;
    for (const [kind, n] of Object.entries(detector(text))) if (n && (isKey || !SPF_PATHS.has(path) || !ADDRESS_KINDS.has(kind))) visit(path, isKey, kind, n);
  }
}

/** Every miss in one record, by kind, over all it stores. */
export function recordMisses(r) {
  const out = { ipv4: 0, ipv6: 0, email: 0, query: 0, fragment: 0, jwt: 0, longHex: 0, longNumber: 0 };
  eachMiss(r, (_path, _isKey, kind, n) => { out[kind] += n; });
  return out;
}

/** Where the misses sit, by field and kind, for a person to review. Never the text. A key can be the miss itself, so it isn't named then. */
export function missedFields(records) {
  const out = {};
  for (const r of records) eachMiss(r, (path, isKey, kind, n) => { const at = `${isKey ? `${path || "record"} (a key)` : path} ${kind}`; out[at] = (out[at] ?? 0) + n; });
  return out;
}

// A name that doesn't exist is a finding. A resolver that didn't answer says nothing about the site.
const NO_NAME = new Set(["ENOTFOUND", "ENODATA", "NXDOMAIN"]);
const failedOutcome = (o) => Boolean(o?.startsWith("resolver-failure"));

/** The site's address lookup failed, or any exact DNS query did, for the listed name or the final one. */
export const resolverFailed = (r) => (r.error === "not_found" && r.netCode !== undefined && !NO_NAME.has(r.netCode))
  || [r.dns?.listed, r.dns?.final].filter(Boolean).some((d) => Object.values(d.outcomes ?? {}).some(failedOutcome) || (d.queries ?? []).some((q) => failedOutcome(q.outcome)));

export const MAX_RESOLVER_FAILURES = 0.2;

const DETECTOR_KINDS = new Set(["ipv4", "ipv6", "email", "query", "fragment", "jwt", "longHex", "longNumber"]);
// Amendment 3 covers this stop and no other, as the runner wrote it.
export const PRIVACY_STOP = "a privacy scrub missed something";
// The detector that stopped pass 2. Its file stays in legacy/, and only the finding report reads it.
export const LEGACY_CLASSIFIER_SHA256 = "7023106f7bd73c1e4122d80e9479f63a4a04091f1426327be70621951fe71d3b";
// A pilot round fails past this many withheld records. A pass never stops for them.
export const MAX_PILOT_WITHHELD = 2;
// Rows per audit stratum, frozen in the amendment.
export const STRATA = Object.freeze({
  "candidate-page": 150, challenge: 50, "block-signature": 50, "block-unrecognized-403": 30, "unrecognized-error-response": 20,
});
// Where the in-flight stop looks, so a legacy finding can be shown to be that stop.
export const PAGE_PATHS = Object.freeze(["evidence.excerpt", "evidence.pageExcerpt.title", "evidence.pageExcerpt.text", "evidence.pageExcerpt.noscript", "evidence.others.excerpt"]);

/** Sites a whole-list bound counts. A stop of ours stays in; only an owner's choice or our exclusion leaves. */
const NOT_ELIGIBLE = new Set(["exclusion_list", "robots_disallow_all", "robots_disallow_path", "not_a_homepage"]);
export const isEligible = (r) => r.status !== "opted_out" && !NOT_ELIGIBLE.has(r.reason);

/**
 * Text that came from a page: all the in-flight stop reads. A stop ends pass 2 for good,
 * so it must not fire on what a site legitimately publishes in DNS.
 */
export const pageText = (r) => [
  r.evidence?.excerpt, r.evidence?.pageExcerpt?.title, r.evidence?.pageExcerpt?.text, r.evidence?.pageExcerpt?.noscript,
  ...(r.evidence?.others ?? []).map((o) => o.excerpt),
].filter(Boolean).map((t) => (typeof t === "string" ? t : JSON.stringify(t)));
export const pageTextMissed = (r) => pageText(r).some((t) => Object.values(scrubMisses(t)).some(Boolean));

/** The audit stratum of one record, or null. */
export function stratumOf(r) {
  const c = r.evidence?.class;
  if (!c) return null;
  if (c.label === "block") return c.rule === "unrecognized-403" ? "block-unrecognized-403" : "block-signature";
  return c.label in STRATA ? c.label : null;
}

// Counts are all a marker may hold, so one that came from anywhere else can't carry text through.
const cleanMarker = (m) => {
  const kinds = {};
  for (const [kind, n] of Object.entries(m?.kinds ?? {})) if (DETECTOR_KINDS.has(kind) && Number.isInteger(n) && n > 0) kinds[kind] = n;
  return { kinds, fields: Number.isInteger(m?.fields) && m.fields > 0 ? m.fields : 0 };
};

/**
 * The record with all its page and error text gone. Only those five paths and the marker
 * change, and the marker holds counts alone. The text decides, never a marker already there:
 * whatever is left is scanned and removed, and a record with nothing left comes back as it was.
 */
export function withholdText(r) {
  const left = pageText(r);
  const prior = r.evidence?.textWithheld;
  if (prior && !left.length && JSON.stringify(cleanMarker(prior)) === JSON.stringify(prior)) return r;
  const { kinds, fields: counted } = cleanMarker(prior);
  let fields = counted;
  for (const text of left) {
    const found = Object.entries(scrubMisses(text)).filter(([, n]) => n);
    if (found.length) fields++;
    for (const [kind, n] of found) kinds[kind] = (kinds[kind] ?? 0) + n;
  }
  const { excerpt: _excerpt, ...evidence } = r.evidence;
  if (evidence.pageExcerpt) {
    const { title: _title, text: _text, noscript: _noscript, ...shape } = evidence.pageExcerpt;
    evidence.pageExcerpt = shape;
  }
  if (evidence.others) evidence.others = evidence.others.map(({ excerpt: _other, ...o }) => o);
  return { ...r, evidence: { ...evidence, textWithheld: { kinds, fields } } };
}

/** A record that may leave for a disk: both sides of the worker boundary run this. Nothing that fires ever passes. */
export function safeRecord(r) {
  const out = pageTextMissed(r) || r.evidence?.textWithheld ? withholdText(r) : r;
  if (pageTextMissed(out)) throw new Error("A record still holds flagged text after withholding.");
  return out;
}

// A group under this many sites joins `other`, as nothing in this study quotes a smaller one.
const MIN_REPORTED_GROUP = 20;

/** Withheld records, overall and by group, with each group's total and share. Counts only. */
export function withheldCounts(records) {
  const out = { records: 0, of: 0, kinds: {}, byCohort: {}, byStratum: {}, byLabel: {}, byStatus: {}, byEdge: {} };
  const bump = (into, key, kinds) => {
    const g = (into[key] ??= { records: 0, of: 0, kinds: {} });
    g.of++;
    if (!kinds) return;
    g.records++;
    for (const [kind, n] of Object.entries(kinds)) g.kinds[kind] = (g.kinds[kind] ?? 0) + n;
  };
  for (const r of records) {
    if (!r.evidence) continue;
    const kinds = r.evidence.textWithheld?.kinds;
    out.of++;
    if (kinds) {
      out.records++;
      for (const [kind, n] of Object.entries(kinds)) out.kinds[kind] = (out.kinds[kind] ?? 0) + n;
    }
    for (const c of Object.keys(r.cohorts ?? {})) bump(out.byCohort, c, kinds);
    bump(out.byStratum, stratumOf(r) ?? "none", kinds);
    bump(out.byLabel, r.evidence.class?.label ?? "none", kinds);
    bump(out.byStatus, r.httpStatus ? `${Math.floor(r.httpStatus / 100)}xx` : "none", kinds);
    bump(out.byEdge, r.platform?.edge ?? "unknown", kinds);
  }
  for (const name of ["byCohort", "byStratum", "byLabel", "byStatus", "byEdge"]) out[name] = reported(out[name]);
  out.share = out.of ? out.records / out.of : 0;
  return out;
}

/** Small groups folded into `other`, and each group's share of its own total. */
function reported(groups) {
  const out = {};
  for (const [key, g] of Object.entries(groups)) {
    const into = g.of < MIN_REPORTED_GROUP ? (out.other ??= { records: 0, of: 0, kinds: {} }) : (out[key] = g);
    if (into === g) continue;
    into.records += g.records;
    into.of += g.of;
    for (const [kind, n] of Object.entries(g.kinds)) into.kinds[kind] = (into.kinds[kind] ?? 0) + n;
  }
  for (const g of Object.values(out)) g.share = g.records / g.of;
  return out;
}

// A visit's own budget allows 20 requests; more means the limit failed.
const MAX_REQUESTS_PER_SITE = 20;
// A run that barely reached anything tells nothing about its instrument. Pass 1 graded 84% of what it could.
export const MIN_GRADED_SHARE = 0.5;
// A pilot too small to see these rates can't pass them.
export const MIN_ELIGIBLE = 30;
export const MIN_GRADED = 25;
export const MIN_TWOXX = 10;

/** Amendment 2's stop rules, as counts. Any entry stops the run until it is explained. */
export function stopRules(report, { floors = true } = {}) {
  const stop = [];
  if (Object.values(report.scrubMisses).some(Boolean)) stop.push("a privacy scrub missed something");
  if ((report.outcomes["error:internal"] ?? 0) > 0) stop.push("an internal error");
  // Withheld pages lose their text on purpose, so the rule reads the 2xx responses that could have one.
  const readable = report.evidence.twoxx - (report.evidence.twoxxWithheld ?? 0);
  if (!report.pruned && readable && report.evidence.twoxxWithExcerpt < readable * 0.9) stop.push("under 90% of 2xx responses have an excerpt");
  const eligible = report.sites - Object.entries(report.outcomes).filter(([k]) => /^(opted_out|excluded:(robots_disallow_all|robots_disallow_path|not_a_homepage|exclusion_list))$/.test(k)).reduce((n, [, v]) => n + v, 0);
  if (report.dns.read < eligible) stop.push("a site with no DNS read");
  if (report.counters.maxRequestsPerSite > MAX_REQUESTS_PER_SITE) stop.push(`a site took more than ${MAX_REQUESTS_PER_SITE} requests`);
  if (report.excludedHops) stop.push("a request reached an excluded host");
  if (eligible && report.evidence.graded / eligible < MIN_GRADED_SHARE) stop.push("under half of the eligible sites were graded");
  if (eligible && report.resolverFailures / eligible > MAX_RESOLVER_FAILURES) stop.push("over 20% of sites hit a resolver failure");
  if (eligible && report.evidence.twoxx === 0) stop.push("no site answered with a 2xx");
  else if (floors && eligible && report.evidence.twoxx < MIN_TWOXX) stop.push(`under ${MIN_TWOXX} 2xx responses`);
  if (report.dns.read && report.dns.answered.spf / report.dns.read < 1 - MAX_RESOLVER_FAILURES) stop.push("over 20% of SPF reads got no answer");
  if (report.dns.read && report.dns.answered.dmarc / report.dns.read < 1 - MAX_RESOLVER_FAILURES) stop.push("over 20% of DMARC reads got no answer");
  if ((report.textWithheld?.records ?? 0) > MAX_PILOT_WITHHELD) stop.push(`over ${MAX_PILOT_WITHHELD} records had their text withheld`);
  if (floors && eligible === 0) stop.push("no eligible site");
  else if (floors && eligible < MIN_ELIGIBLE) stop.push(`under ${MIN_ELIGIBLE} eligible sites`);
  if (floors && eligible && report.evidence.graded < MIN_GRADED) stop.push(`under ${MIN_GRADED} graded sites`);
  for (const [cohort, c] of Object.entries(report.coverage ?? {})) if (floors && !(c.graded && c.dnsComplete)) stop.push(`no usable output in ${cohort}`);
  return stop;
}

const hash = (b) => createHash("sha256").update(b).digest("hex");

export const NO_PRIVACY = "no clean privacy report";

const RECORD_FIELDS = new Set(["record", "evidence", "dns", "checks", "app", "hops", "finalHost", "finalOrg", "listedHost", "listedOrg", "host", "cohorts", "robots", "platform", "dnsProviders", "error", "reason", "category", "group"]);
const knownPath = (path) => typeof path === "string" && /^[^\s]+(?: \(a key\))?$/.test(path) && RECORD_FIELDS.has(path.replace(/ \(a key\)$/, "").split(".")[0]);

/**
 * What's wrong with a legacy finding report, or null. Nothing in it is taken on trust:
 * each finding is checked against the raw file's orders, and `reproducesStop` must be
 * what the findings themselves say.
 */
export function legacyProblem(report, orders) {
  if (!Array.isArray(report?.findings)) return "it has no list of findings";
  const seen = new Set();
  for (const f of report.findings) {
    if (!Number.isInteger(f?.order) || !orders.has(f.order)) return "a finding names a record the raw file doesn't hold";
    if (!knownPath(f.path)) return "a finding names an unknown field";
    if (!DETECTOR_KINDS.has(f.kind)) return "a finding names an unknown kind";
    if (!Number.isInteger(f.count) || f.count < 1) return "a finding has no valid count";
    const key = `${f.order} ${f.path} ${f.kind}`;
    if (seen.has(key)) return "a finding appears twice";
    seen.add(key);
  }
  const reproduces = report.findings.some((f) => PAGE_PATHS.includes(f.path));
  if (report.reproducesStop !== reproduces) return "its summary doesn't match its findings";
  return reproduces ? null : "it does not reproduce the stop";
}

/** A JSON artifact that carries the hash of its own fields, so an edit to one field shows. It isn't keyed. */
export const selfHashed = (fields) => ({ ...fields, selfSha256: hash(JSON.stringify(fields)) });
export const selfHashHolds = ({ selfSha256, ...fields }) => selfSha256 === hash(JSON.stringify(fields));

/** The hash a seal carries over its own fields, `passed` among them. */
export const sealHash = ({ sealSha256: _own, ...fields }) => hash(JSON.stringify(fields));

// What a purge deletes. The proof holds only while all of it stays gone.
export const PURGED_FILES = Object.freeze(["raw.jsonl", "raw.jsonl.tmp", "validation-sheet.json", "validation-key.json"]);

const readJson = (file) => (existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null);

export const dispositionOf = (manifest, privacy) => (!manifest.finishedAt ? "crashed" : manifest.partial ? "partial" : privacy && !privacy.clean ? "privacy-failed" : "finished");

/** "none" with no proof, "proved" when it holds in every part, or what's wrong with it. */
export function purgeState(dir) {
  const proof = readJson(join(dir, "purge-manifest.json"));
  if (!proof) return "none";
  const manifestBytes = readFileSync(join(dir, "manifest.json"));
  const m = JSON.parse(manifestBytes);
  const pruned = readJson(join(dir, "prune-manifest.json"));
  if (proof.kind !== "purge") return "it is not a purge proof";
  if (proof.manifestSha256 !== hash(manifestBytes)) return "it is for another run";
  if (!DIGEST.test(proof.rawSha256 ?? "") || (m.rawSha256 && ![m.rawSha256, pruned?.rawSha256After].includes(proof.rawSha256))) return "it names another raw file";
  if (proof.disposition !== dispositionOf(m, readJson(join(dir, "privacy-report.json")))) return "its disposition does not match the run";
  const left = PURGED_FILES.filter((f) => existsSync(join(dir, f)));
  return left.length ? `${left.join(", ")} still there` : "proved";
}

/** A person recorded that every miss in this run was false, for this manifest. */
export function falseFireReviewed(dir) {
  const privacy = readJson(join(dir, "privacy-report.json"));
  return Boolean(privacy?.reviewed?.reviewer) && privacy.manifestSha256 === hash(readFileSync(join(dir, "manifest.json")));
}

/**
 * Why a run can't decide claims, or null: it needs to be a finished, whole pass with
 * nothing changed under it, and the raw file it recorded, pruned or not.
 */
export function unfinishedRun(dir) {
  const file = join(dir, "manifest.json");
  if (!existsSync(file)) return "no run manifest";
  const manifestBytes = readFileSync(file);
  const m = JSON.parse(manifestBytes);
  const purged = purgeState(dir);
  if (purged !== "none") return purged === "proved" ? "the raw file was purged" : `its purge proof does not hold: ${purged}`;
  if (m.kind !== "pass") return "not a pass";
  if (!m.finishedAt) return "the run did not finish";
  if (m.partial) return `the run stopped: ${m.stoppedFor}`;
  if (!m.immutableAtFinish?.ok) return "something changed while it ran";
  const raw = join(dir, "raw.jsonl");
  if (!existsSync(raw)) return "no raw file";
  const read = (name) => (existsSync(join(dir, name)) ? JSON.parse(readFileSync(join(dir, name), "utf8")) : null);
  const now = hash(readFileSync(raw));
  if (now !== m.rawSha256) {
    const proof = read("prune-manifest.json");
    const drawn = proof?.kind === "validation-draw" && proof.manifestSha256 === hash(manifestBytes) && proof.rawSha256Before === m.rawSha256 && proof.rawSha256After === now;
    if (!drawn) return "the raw file is not the one the manifest hashed";
  }
  const privacy = read("privacy-report.json");
  return (privacy?.clean || privacy?.reviewed) && privacy.rawSha256 === m.rawSha256 && privacy.manifestSha256 === hash(manifestBytes) ? null : NO_PRIVACY;
}
