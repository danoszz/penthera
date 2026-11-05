/**
 * Read-only views over memory events, plus the two pure helpers scans use:
 * rankFindings() re-orders, isSuppressed() hides. Neither can add a finding,
 * change a severity, or run anything: memory content is only ever compared and
 * counted. Every field read from an event is type-checked, so a malformed or
 * hostile event degrades to "ignored", never to behaviour.
 */
import { fingerprintFinding } from "../audit-loop.js";
import { sha256 } from "./store.js";

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const MAX_STR = 500;

/** Short, stable id for a finding: sha256 of the audit-loop fingerprint. */
export function findingId(f) {
  return sha256(fingerprintFinding(f)).slice(0, 16);
}

const str = (x) => (typeof x === "string" && x.length > 0 && x.length <= MAX_STR ? x : null);
const int = (x) => (Number.isInteger(x) && x >= 0 ? x : null);
const time = (x) => { const t = Date.parse(x); return Number.isNaN(t) ? null : t; };
const key = (x) => (str(x) ? x.toLowerCase() : "unknown");

function median(nums) {
  if (!nums.length) return null;
  const s = [...nums].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

/**
 * Build the views from a verified event list.
 * @param {object[]} events  parsed events from openMemory().events()
 * @param {{ now?: string }} opts  `now` decides which suppressions have expired
 */
export function buildViews(events, { now = new Date().toISOString() } = {}) {
  const nowMs = time(now) ?? Date.now();
  const recipes = new Map();      // `${framework}\0${recipe}` -> stats
  const lastApplied = new Map();  // finding id -> { recipe, framework, category, ts }
  const firstSeen = new Map();    // finding id -> ms
  const seenCount = new Map();    // finding id -> scans it appeared in
  const fixDurations = [];
  const suppressions = new Map(); // finding id -> latest suppression
  const probes = new Map();       // `${stack}\0${probe}` -> stats
  let scans = 0;

  const recipeStats = (framework, recipe) => {
    const k = `${framework}\0${recipe}`;
    if (!recipes.has(k)) recipes.set(k, { framework, recipe, applied: 0, verified: 0, failed: 0, categories: new Set() });
    return recipes.get(k);
  };

  for (const ev of events || []) {
    const d = ev?.data;
    if (!d || typeof d !== "object") continue;
    const ts = time(ev.ts);
    switch (ev.type) {
      case "scan": {
        scans++;
        const ids = Array.isArray(d.ids) ? d.ids.filter(str) : [];
        for (const id of ids) {
          if (!firstSeen.has(id) && ts != null) firstSeen.set(id, ts);
          seenCount.set(id, (seenCount.get(id) || 0) + 1);
        }
        break;
      }
      case "fix_applied": {
        const id = str(d.id) || str(d.fingerprint);
        const recipe = str(d.recipe);
        if (!recipe) break;
        const framework = key(d.framework);
        const s = recipeStats(framework, recipe);
        s.applied++;
        if (str(d.category)) s.categories.add(d.category);
        if (id) lastApplied.set(id, { recipe, framework, category: str(d.category), ts });
        break;
      }
      case "fix_verified":
      case "fix_failed": {
        const id = str(d.id) || str(d.fingerprint);
        const prior = id ? lastApplied.get(id) : null;
        const recipe = str(d.recipe) || prior?.recipe;
        if (!recipe) break;
        const framework = str(d.framework) ? key(d.framework) : (prior?.framework || "unknown");
        const s = recipeStats(framework, recipe);
        if (ev.type === "fix_verified") {
          s.verified++;
          if (id && ts != null && firstSeen.has(id)) fixDurations.push(Math.max(0, ts - firstSeen.get(id)));
        } else {
          s.failed++;
        }
        break;
      }
      case "fp_suppressed": {
        const id = str(d.id) || (str(d.fingerprint) ? sha256(d.fingerprint).slice(0, 16) : null);
        const reason = str(d.reason);
        if (!id || !reason) break; // a suppression without a reason is ignored
        const expires = str(d.expires);
        if (expires && (time(expires) == null || time(expires) <= nowMs)) { suppressions.delete(id); break; }
        suppressions.set(id, {
          id, reason, actor: str(d.actor) || "unknown", since: ev.ts, expires: expires || null, source: "memory",
          severity: suppressSeverity(d.severity),
        });
        break;
      }
      case "probe_yield": {
        const probe = str(d.probe);
        const findings = int(d.findings);
        if (!probe || findings == null) break;
        const stack = key(d.stack);
        const k = `${stack}\0${probe}`;
        if (!probes.has(k)) probes.set(k, { stack, probe, runs: 0, findings: 0 });
        const p = probes.get(k);
        p.runs++;
        p.findings += findings;
        break;
      }
      default:
        break;
    }
  }

  const recipeSuccess = [...recipes.values()].map((s) => {
    const decided = s.verified + s.failed;
    return {
      framework: s.framework, recipe: s.recipe, applied: s.applied, verified: s.verified, failed: s.failed,
      rate: decided ? s.verified / decided : null, categories: [...s.categories].sort(),
    };
  }).sort((a, b) => a.framework.localeCompare(b.framework) || (b.rate ?? -1) - (a.rate ?? -1) || a.recipe.localeCompare(b.recipe));

  const probeRanking = {};
  for (const p of probes.values()) {
    (probeRanking[p.stack] ||= []).push({ probe: p.probe, runs: p.runs, findings: p.findings, yield: p.findings / p.runs });
  }
  for (const list of Object.values(probeRanking)) {
    list.sort((a, b) => b.yield - a.yield || b.findings - a.findings || a.probe.localeCompare(b.probe));
  }

  const med = median(fixDurations);
  return {
    scans,
    recipeSuccess,
    suppressions: [...suppressions.values()],
    probeRanking,
    medianTimeToFixMs: med,
    medianTimeToFixDays: med == null ? null : Math.round((med / 86_400_000) * 10) / 10,
    seen: Object.fromEntries(seenCount),
  };
}

/**
 * Add repo-file suppressions to a views object. They keep their own source so
 * reports can say "suppressed by repo file". A local-memory suppression for the
 * same id wins (the user decided it, not the repo).
 */
export function withRepoSuppressions(views, repoEntries) {
  const have = new Set((views?.suppressions || []).map((s) => s.id));
  const extra = (repoEntries || []).filter((s) => !have.has(s.id)).map((s) => ({ ...s, source: "repo-file" }));
  return { ...(views || {}), suppressions: [...(views?.suppressions || []), ...extra] };
}

/** A suppression's severity cap as stored: a known severity, or null. */
export function suppressSeverity(x) {
  return typeof x === "string" && Object.hasOwn(SEV_ORDER, x) ? x : null;
}

/**
 * The most severe finding an entry without a severity still covers. Entries
 * written before 2.3.2 have none; they keep working up to medium, and a
 * finding that is now high or critical shows again.
 */
export const LEGACY_SUPPRESS_CAP = "medium";

/**
 * Does this suppression still cover the finding at its current severity? A
 * suppression covers the severity it was given and below. The finding id
 * leaves severity out, so a low that became critical has the same id: without
 * this check the old suppression hid it (Vercel review, B04). A finding with
 * an unknown severity is never covered.
 */
export function suppressionCovers(suppression, finding) {
  const cap = suppressSeverity(suppression?.severity) || LEGACY_SUPPRESS_CAP;
  const now = SEV_ORDER[finding?.severity];
  return now !== undefined && now >= SEV_ORDER[cap];
}

/**
 * Is this finding suppressed? Returns the suppression record or null.
 * Matches on the finding's id (or its full fingerprint, for repo files), and
 * only while the finding is no more severe than the suppression allows.
 */
export function isSuppressed(finding, views) {
  const list = views?.suppressions;
  if (!list?.length) return null;
  const fp = fingerprintFinding(finding);
  const id = sha256(fp).slice(0, 16);
  return list.find((s) => (s.id === id || (s.fingerprint && s.fingerprint === fp)) && suppressionCovers(s, finding)) || null;
}

/**
 * Re-order findings using what memory learned. Severity always comes first and
 * is never changed. Within a severity:
 *   1. findings whose category has a recipe with a proven fix rate (quick wins),
 *   2. findings seen in more past scans (persistent problems),
 *   3. then the original order (the sort is stable).
 * Returns a new array with exactly the same findings.
 */
export function rankFindings(findings, views, { framework = null } = {}) {
  const fw = framework ? String(framework).toLowerCase() : null;
  const bestRate = new Map(); // category -> best verified rate
  for (const r of views?.recipeSuccess || []) {
    if (r.rate == null || (fw && r.framework !== fw && r.framework !== "unknown")) continue;
    for (const c of r.categories || []) bestRate.set(c, Math.max(bestRate.get(c) ?? 0, r.rate));
  }
  const seen = views?.seen || {};
  return (findings || [])
    .map((f, i) => ({
      f, i,
      sev: SEV_ORDER[f.severity] ?? 5,
      fix: bestRate.get(f.category) ?? 0,
      seen: seen[findingId(f)] || 0,
    }))
    .sort((a, b) => a.sev - b.sev || b.fix - a.fix || b.seen - a.seen || a.i - b.i)
    .map((x) => x.f);
}
