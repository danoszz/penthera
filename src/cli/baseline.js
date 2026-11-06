/**
 * Compare scan findings against a previous JSON report.
 */
import { readFileSync } from "node:fs";
import { fingerprintFinding } from "../../lib/audit-loop.js";
import { tagSalt, useTagSalt } from "../../lib/secret-tags.js";

// Shared with dedupe and the audit loop so one finding has one identity
// everywhere. It excludes severity: a finding whose severity is re-rated is
// the same finding, and keying on it made every re-rating show up as one
// resolved plus one new.
const findingKey = fingerprintFinding;

const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
// An unknown severity counts as the most severe: never unchanged by accident.
const rank = (s) => RANK[s] ?? -1;

const isSecret = (f) => f.source === "secret-scan";
const isSink = (f) => f.source === "static-analysis" && f.category === "code-pattern" && !!f.pattern;

/**
 * What one finding holds beyond its key: for a secret, the masked value
 * reports show, how many lines hold it and the salted tags of every value it
 * holds (`valueTags`, lib/secret-tags.js); for an eval or exec sink, the
 * calls it lists (line numbers dropped, so an edit above them is no change).
 * One rule's secrets in one file, and one kind of sink in one file, are one
 * finding, so a second key or a second call would otherwise hide behind the
 * first (Vercel review, B03).
 */
function sitesOf(f) {
  if (isSecret(f)) {
    const value = /Possible secret in `[^`]*`: `([^`]*)`/.exec(String(f.description || ""))?.[1] ?? "";
    const tags = Array.isArray(f.valueTags) ? f.valueTags.map(String) : null;
    return { count: Array.isArray(f.lines) && f.lines.length ? f.lines.length : 1, values: [value], tags };
  }
  if (isSink(f)) {
    const calls = [...String(f.description || "").matchAll(/(?<![\w.$])([\w.$]+) on line \d+((?: \([^)]*\))?)/g)].map((m) => `${m[1]}${m[2]}`);
    return { count: Math.max(1, calls.length), values: calls };
  }
  return null;
}

/**
 * Before a scan with --baseline: take the baseline's tag salt, so this run's
 * secret tags compare with the baseline's. A baseline without one (written
 * before 2.3.2, or unreadable: compareWithBaseline says so) changes nothing.
 */
export function useBaselineSalt(baselinePath) {
  try {
    return useTagSalt(JSON.parse(readFileSync(baselinePath, "utf-8"))?.secretTagSalt);
  } catch {
    return false;
  }
}

export function compareWithBaseline(currentFindings, baselinePath) {
  let baseline;
  try {
    baseline = JSON.parse(readFileSync(baselinePath, "utf-8"));
  } catch (e) {
    throw new Error(`Cannot read baseline report: ${baselinePath} (${e.message})`);
  }

  const prev = baseline.findings || [];
  // Tags compare only when both runs used one salt; else the masked value and count decide, as before.
  const tagged = typeof baseline.secretTagSalt === "string" && baseline.secretTagSalt === tagSalt();
  // Per key: the most severe baseline severity, and what the findings held.
  const before = new Map();
  for (const f of prev) {
    const k = findingKey(f);
    const b = before.get(k) || { rank: Infinity, count: 0, values: new Set(), tags: null };
    b.rank = Math.min(b.rank, rank(f.severity));
    const s = sitesOf(f);
    if (s) {
      b.count = Math.max(b.count, s.count);
      for (const v of s.values) b.values.add(v);
      if (tagged && s.tags) {
        b.tags ??= new Set();
        for (const t of s.tags) b.tags.add(t);
      }
    }
    before.set(k, b);
  }
  const currKeys = new Set((currentFindings || []).map(findingKey));

  // New: a key the baseline lacks, a severity above the baseline's for that
  // key (a low that became critical is not "unchanged"), or a secret or sink
  // finding that now holds more than it did.
  const isNew = (f) => {
    const b = before.get(findingKey(f));
    if (!b) return true;
    if (rank(f.severity) < b.rank) return true;
    const s = sitesOf(f);
    if (!s) return false;
    if (s.count > b.count) return true;
    // A secret with tags on both sides: new when it holds a value the baseline did not.
    if (b.tags && s.tags) return s.tags.some((t) => !b.tags.has(t));
    return s.values.some((v) => !b.values.has(v));
  };

  const newFindings = [];
  const unchangedFindings = [];
  for (const f of currentFindings || []) (isNew(f) ? newFindings : unchangedFindings).push(f);
  const resolvedFindings = prev.filter((f) => !currKeys.has(findingKey(f)));

  return {
    newFindings,
    resolvedFindings,
    unchangedFindings,
    stats: {
      path: baselinePath,
      newCount: newFindings.length,
      resolvedCount: resolvedFindings.length,
      unchangedCount: unchangedFindings.length,
    },
  };
}
