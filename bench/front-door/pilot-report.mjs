#!/usr/bin/env node
/**
 * E20-R pilot report: what a run's raw.jsonl holds, as counts only. No site is
 * named, so the output can be read and pasted anywhere.
 *
 *   node bench/front-door/pilot-report.mjs <raw.jsonl> --exclude <exclusion list> --skip <host list>... [--seal]
 *   node bench/front-door/pilot-report.mjs --privacy <run folder> [--false-fire <note file> --reviewer <who>]
 *   node bench/front-door/pilot-report.mjs --replay <raw.jsonl>
 *   node bench/front-door/pilot-report.mjs --legacy-findings <run folder>
 *   node bench/front-door/pilot-report.mjs --decide <run folder> --decision go|no-go --reviewer <who>
 *
 * --decide records the person's decision on a sealed round, bound to its report and seal.
 * --privacy runs the pilot's scan over every stored field of a finished pass and writes
 * privacy-report.json, which analysis and the audit draw require. Run it before the draw.
 * It prints counts and the code `purge` asks for. Which fields were flagged goes only to
 * that private file. --false-fire records a named person's review that every miss was
 * false, as a note whose hash the analysis reports as a deviation. A clean scan has nothing
 * to review, unless a legacy finding report for this run says the frozen detector fired.
 * --replay runs the scan over a raw file, writes nothing and prints counts only.
 * --legacy-findings runs the frozen detector (legacy-findings.mjs) and prints counts only.
 * Pass the removal, prior opt-out and earlier pilot lists as --skip, so every hop meets all
 * four. Sealing checks each against the run's manifest. This round's own list is not one.
 * --seal writes pilot-result.json next to the raw file, which pass 2 requires. Seal
 * before pruning: the report reads the excerpts that pruning deletes.
 *
 * Exits 1 when a stop rule of Amendment 2 fires, so a miss holds the full run.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isEligible, missedFields, recordMisses, resolverFailed, sealHash, stopRules, MAX_RESOLVER_FAILURES, MIN_ELIGIBLE, MIN_GRADED, MIN_GRADED_SHARE, MIN_TWOXX } from "./record-checks.mjs";
import { legacyFindings } from "./legacy-findings.mjs";
import { CLAIM_COHORTS, readRemovals } from "./replicate.mjs";
import { exclusionFor, readExclusions } from "./run.mjs";

const tally = (items) => {
  const t = {};
  for (const k of items) t[k] = (t[k] || 0) + 1;
  return Object.fromEntries(Object.entries(t).sort(([, a], [, b]) => b - a));
};

/**
 * Counts for one run. `records` come from raw.jsonl; `exclude` is every skip list, to
 * check every hop. `pruned` says the text is gone, so its absence is no failure.
 */
export function pilotReport(records, { exclude = new Map(), pruned = false } = {}) {
  const ok = records.filter((r) => r.status === "ok");
  const dns = records.filter((r) => r.dns?.listed);
  const answered = (id) => dns.filter((r) => r.dns.listed[id] !== null).length;
  const misses = { ipv4: 0, ipv6: 0, email: 0, query: 0, fragment: 0, jwt: 0, longHex: 0, longNumber: 0 };
  for (const r of records) for (const [k, v] of Object.entries(recordMisses(r))) misses[k] += v;
  const sum = (k) => records.reduce((n, r) => n + (r.counters?.[k] ?? 0), 0);
  const twoxx = ok.filter((r) => r.httpStatus >= 200 && r.httpStatus < 300);
  return {
    sites: records.length, pruned,
    coverage: Object.fromEntries(CLAIM_COHORTS.map((c) => {
      const rows = records.filter((r) => r.cohorts?.[c]);
      const graded = rows.filter((r) => r.status === "ok");
      return [c, {
        selected: rows.length, eligible: rows.filter(isEligible).length, graded: graded.length, twoxx: rows.filter((r) => r.httpStatus >= 200 && r.httpStatus < 300).length,
        dnsComplete: rows.filter((r) => r.dns?.listed && !resolverFailed(r)).length, classes: tally(graded.map((r) => r.evidence?.class?.label ?? "none")),
      }];
    })),
    resolverFailures: records.filter(resolverFailed).length,
    outcomes: tally(records.map((r) => (r.status === "error" ? `error:${r.error}` : r.reason ? `${r.status}:${r.reason}` : r.status))),
    labels: tally(ok.map((r) => r.evidence?.class?.label ?? "none")),
    labelsRegistered: tally(ok.map((r) => r.evidence?.classRegistered?.label ?? "none")),
    rules: tally(ok.map((r) => r.evidence?.class?.rule ?? "none")),
    labelChanges: tally(ok.filter((r) => r.evidence?.class?.label !== r.evidence?.classRegistered?.label).map((r) => `${r.evidence?.classRegistered?.label} to ${r.evidence?.class?.label}`)),
    evidence: {
      graded: ok.length,
      withEvidence: ok.filter((r) => r.evidence).length,
      twoxx: twoxx.length,
      twoxxWithExcerpt: twoxx.filter((r) => r.evidence?.pageExcerpt?.text || r.evidence?.pageExcerpt?.title).length,
      outside2xxWithExcerpt: ok.filter((r) => r.evidence?.excerpt).length,
      withBodyHashes: ok.filter((r) => r.evidence?.bodySha256 && (r.evidence?.others ?? []).every((o) => o.bodySha256)).length,
    },
    dns: {
      read: dns.length, ungraded: dns.filter((r) => r.status !== "ok").length, finalDomainToo: dns.filter((r) => r.dns.finalOtherOrg).length,
      domainExists: dns.filter((r) => r.dns.listed.exists).length,
      answered: { spf: answered("spf"), dmarc: answered("dmarc"), caa: answered("caa") },
      withDmarcRecord: dns.filter((r) => r.dns.listed.dmarcRecord).length,
      outcomes: Object.fromEntries(["txt", "dmarc", "caa", "mx", "ns"].map((k) => [k, tally(dns.map((r) => r.dns.listed.outcomes?.[k] ?? "none"))])),
    },
    tls: {
      invalid: records.filter((r) => r.error === "tls_invalid").length,
      reasons: tally(records.map((r) => r.tlsReason ?? r.httpsFailed?.tlsReason).filter(Boolean)),
      fellBackToHttp: records.filter((r) => r.httpsFailed).length,
    },
    robots: {
      outcomes: tally(records.flatMap((r) => r.robots ?? []).map((o) => (o.error ? `error:${o.error}` : `${Math.floor(o.status / 100)}xx`))),
      originsPerSite: tally(records.filter((r) => r.robots).map((r) => r.robots.length)),
    },
    hosts: tally(ok.map((r) => r.redirectClass ?? "none")),
    counters: { requests: sum("requests"), bytes: sum("bytes"), redirects: sum("redirects"), maxRequestsPerSite: Math.max(0, ...records.map((r) => r.counters?.requests ?? 0)) },
    excludedHops: records.flatMap((r) => r.hops ?? []).filter((h) => exclusionFor(h, exclude)).length,
    csp: { present: ok.filter((r) => r.evidence?.csp?.present).length, controlsScripts: ok.filter((r) => r.evidence?.csp?.controlsScripts).length },
    scrubMisses: misses,
  };
}

export { stopRules, MAX_RESOLVER_FAILURES, MIN_ELIGIBLE, MIN_GRADED, MIN_GRADED_SHARE, MIN_TWOXX };

const hash = (b) => createHash("sha256").update(b).digest("hex");

/**
 * The machine-checked result pass 2 reads: pilot-result.json, next to the run, bound to
 * its manifest and raw file. A run that changed under it, or whose raw file isn't
 * the one the manifest hashed, can't pass.
 */
export function sealPilot(dir, { exclude = new Map(), exclusionBytes, skipBytes = [] } = {}) {
  const manifestBytes = readFileSync(join(dir, "manifest.json"));
  const manifest = JSON.parse(manifestBytes);
  const rawBytes = readFileSync(join(dir, "raw.jsonl"));
  const report = pilotReport(rawBytes.toString("utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)), { exclude });
  const stop = stopRules(report);
  if (existsSync(join(dir, "prune-manifest.json"))) stop.push("sealed after pruning: seal first, while the excerpts exist");
  else if (hash(rawBytes) !== manifest.rawSha256) stop.push("the raw file is not the one the manifest hashed");
  if (!manifest.finishedAt) stop.push("the run did not finish");
  if (manifest.partial) stop.push(`the run stopped: ${manifest.stoppedFor}`);
  if (!manifest.immutableAtFinish?.ok) stop.push("something changed while it ran");
  // The hop check is only as good as its lists, so they must be this run's own.
  const lists = { exclusionSha256: manifest.exclusionSha256 ?? null, removals: manifest.removals?.sha256 ?? null, priorOptOuts: manifest.priorOptOuts?.sha256 ?? null, pilotDropped: manifest.pilotDropped?.sha256 ?? null };
  const given = skipBytes.map(hash);
  if (!exclusionBytes || hash(exclusionBytes) !== lists.exclusionSha256) stop.push("--exclude is not the list this run used");
  for (const name of ["removals", "priorOptOuts", "pilotDropped"]) if (lists[name] && !given.includes(lists[name])) stop.push(`--skip is missing the run's ${name} list`);
  if (given.some((h) => ![lists.removals, lists.priorOptOuts, lists.pilotDropped].includes(h))) stop.push("a --skip file is not one of this run's lists");
  const reportText = `${JSON.stringify(report, null, 2)}\n`;
  writeFileSync(join(dir, "pilot-report.json"), reportText, { mode: 0o600 });
  const fields = { passed: stop.length === 0, stop, manifestSha256: hash(manifestBytes), rawSha256: manifest.rawSha256 ?? null, reportSha256: hash(reportText), lists, sealedAt: new Date().toISOString() };
  const result = { ...fields, sealSha256: sealHash(fields) };
  writeFileSync(join(dir, "pilot-result.json"), JSON.stringify(result, null, 2) + "\n", { mode: 0o600 });
  return { ...result, report };
}

/** The pilot's scan over a finished pass, bound to its manifest and raw file. */
export function privacyReport(dir, { falseFire, reviewer } = {}) {
  const manifestBytes = readFileSync(join(dir, "manifest.json"));
  const manifest = JSON.parse(manifestBytes);
  const rawBytes = readFileSync(join(dir, "raw.jsonl"));
  const rawSha256 = manifest.rawSha256 ?? hash(rawBytes);
  if (hash(rawBytes) !== rawSha256) throw new Error("Refused: the raw file is not the one the manifest hashed. Run this before the audit draw.");
  const rows = rawBytes.toString("utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const { sites: records, scrubMisses } = pilotReport(rows);
  const clean = !Object.values(scrubMisses).some(Boolean);
  if (falseFire?.length === 0) throw new Error("Refused: the false-fire note is empty.");
  if (falseFire && !String(reviewer ?? "").trim()) throw new Error("Refused: a false-fire review needs --reviewer.");
  const legacyFile = join(dir, "legacy-findings.json");
  const legacyBytes = falseFire && existsSync(legacyFile) ? readFileSync(legacyFile) : null;
  const legacy = legacyBytes && JSON.parse(legacyBytes);
  const legacyHolds = legacy?.findings?.length > 0 && legacy.manifestSha256 === hash(manifestBytes) && legacy.rawSha256 === rawSha256;
  if (falseFire && clean && !legacyHolds) throw new Error("Refused: this scan is clean, so there is nothing to call a false fire. It needs a legacy finding report for this run.");
  const report = {
    manifestSha256: hash(manifestBytes), rawSha256, purgeConfirm: rawSha256.slice(0, 12), records, scrubMisses, clean, flaggedFields: missedFields(rows),
    ...(falseFire ? { reviewed: { noteSha256: hash(falseFire), reviewer, reviewedAt: new Date().toISOString(), ...(legacyHolds ? { legacyFindingsSha256: hash(legacyBytes) } : {}) } } : {}), writtenAt: new Date().toISOString(),
  };
  writeFileSync(join(dir, "privacy-report.json"), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  return report;
}

/** The scan over one raw file, as counts alone: no site, no field and no text. */
export function replayRaw(file) {
  const rows = readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const flagged = rows.filter((r) => Object.values(recordMisses(r)).some(Boolean)).length;
  return { records: rows.length, flagged, scrubMisses: pilotReport(rows).scrubMisses };
}

/** The person's go or no-go on a sealed round. A failed round can't be a go. */
export function decidePilot(dir, { decision, reviewer }) {
  if (!["go", "no-go"].includes(decision) || !reviewer) throw new Error("Refused: --decide needs --decision go|no-go and --reviewer.");
  if (!existsSync(join(dir, "pilot-result.json"))) throw new Error("Refused: seal the round first.");
  const seal = JSON.parse(readFileSync(join(dir, "pilot-result.json"), "utf8"));
  if (decision === "go" && !seal.passed) throw new Error("Refused: a failed round can't be a go.");
  const record = { decision, reportSha256: hash(readFileSync(join(dir, "pilot-report.json"))), sealSha256: seal.sealSha256, reviewer, decidedAt: new Date().toISOString() };
  writeFileSync(join(dir, "pilot-decision.json"), `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
  return record;
}

export function main(args, { log = console.log, fail = console.error } = {}) {
  if (args[0] === "--decide") {
    try {
      const value = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
      log(JSON.stringify(decidePilot(args[1], { decision: value("--decision"), reviewer: value("--reviewer") })));
      return 0;
    } catch (e) {
      fail(e.message);
      return 3;
    }
  }
  if (args[0] === "--legacy-findings") {
    if (!args[1]) { fail("Usage: pilot-report.mjs --legacy-findings <run folder>"); return 2; }
    try {
      const { findings, reproducesStop, records, purgeConfirm } = legacyFindings(args[1]);
      log(JSON.stringify({ records, findings: findings.length, reproducesStop, purgeConfirm }, null, 2));
      return reproducesStop ? 0 : 1;
    } catch (e) {
      fail(e.message);
      return 3;
    }
  }
  if (args[0] === "--replay") {
    if (!args[1]) { fail("Usage: pilot-report.mjs --replay <raw.jsonl>"); return 2; }
    const report = replayRaw(args[1]);
    log(JSON.stringify(report, null, 2));
    return report.flagged ? 1 : 0;
  }
  if (args[0] === "--privacy") {
    if (!args[1]) { fail("Usage: pilot-report.mjs --privacy <run folder> [--false-fire <note file> --reviewer <who>]"); return 2; }
    try {
      const value = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
      const { flaggedFields: _private, ...report } = privacyReport(args[1], args.includes("--false-fire") ? { falseFire: readFileSync(value("--false-fire")), reviewer: value("--reviewer") } : {});
      log(JSON.stringify(report, null, 2));
      return report.clean || report.reviewed ? 0 : 1;
    } catch (e) {
      fail(e.message);
      return 3;
    }
  }
  const i = args.indexOf("--exclude");
  const file = args.find((a, k) => !a.startsWith("--") && !["--exclude", "--skip"].includes(args[k - 1]));
  if (!file || i < 0) { fail("Usage: pilot-report.mjs <raw.jsonl> --exclude <exclusion list> --skip <host list>... [--seal]"); return 2; }
  const skips = args.flatMap((a, k) => (a === "--skip" ? [args[k + 1]] : []));
  if (args.includes("--seal") && !skips.length) { fail("--seal needs --skip for the removal, prior opt-out and earlier pilot lists."); return 2; }
  const exclusionBytes = readFileSync(args[i + 1]);
  const skipBytes = skips.map((f) => readFileSync(f));
  const exclude = new Map([...readExclusions(exclusionBytes.toString("utf8")), ...skipBytes.flatMap((b) => [...readRemovals(b.toString("utf8"), "skip")])]);
  if (args.includes("--seal")) {
    if (!existsSync(join(dirname(file), "manifest.json"))) { fail("--seal needs the run's manifest.json next to the raw file."); return 2; }
    const { report, ...result } = sealPilot(dirname(file), { exclude, exclusionBytes, skipBytes });
    log(JSON.stringify({ ...report, ...result }, null, 2));
    return result.passed ? 0 : 1;
  }
  const records = readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const report = pilotReport(records, { exclude, pruned: existsSync(join(dirname(file), "prune-manifest.json")) });
  const stop = stopRules(report);
  log(JSON.stringify({ ...report, stop }, null, 2));
  return stop.length ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main(process.argv.slice(2));
