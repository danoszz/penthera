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

// Amendment 3 covers this stop and no other, as the runner wrote it.
export const PRIVACY_STOP = "a privacy scrub missed something";
// The detector that stopped pass 2. Its file stays in legacy/, and only the finding report reads it.
export const LEGACY_CLASSIFIER_SHA256 = "7023106f7bd73c1e4122d80e9479f63a4a04091f1426327be70621951fe71d3b";
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
].filter(Boolean);
export const pageTextMissed = (r) => pageText(r).some((t) => Object.values(scrubMisses(t)).some(Boolean));

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
  if (!report.pruned && report.evidence.twoxx && report.evidence.twoxxWithExcerpt < report.evidence.twoxx * 0.9) stop.push("under 90% of 2xx responses have an excerpt");
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
  if (floors && eligible === 0) stop.push("no eligible site");
  else if (floors && eligible < MIN_ELIGIBLE) stop.push(`under ${MIN_ELIGIBLE} eligible sites`);
  if (floors && eligible && report.evidence.graded < MIN_GRADED) stop.push(`under ${MIN_GRADED} graded sites`);
  for (const [cohort, c] of Object.entries(report.coverage ?? {})) if (floors && !(c.graded && c.dnsComplete)) stop.push(`no usable output in ${cohort}`);
  return stop;
}

const hash = (b) => createHash("sha256").update(b).digest("hex");

export const NO_PRIVACY = "no clean privacy report";

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
