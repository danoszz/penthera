/**
 * Local learning store (v1.4 "local loop", workstream W2). Public API:
 *
 *   openMemory(projectId)      -> { append(event), verify(), events(), forget() }
 *   views(memory)              -> recipe success, suppressions, probe ranking, time-to-fix
 *   rankFindings(findings, v)  -> same findings, re-ordered
 *   isSuppressed(finding, v)   -> suppression record or null
 *
 * See docs/local-loop.md for the threat model.
 */
import { existsSync } from "node:fs";
import { join } from "node:path";
import { openMemory, projectIdFor, memoryRoot, forgetAll, EVENT_TYPES } from "./store.js";
import { buildViews, rankFindings, isSuppressed, withRepoSuppressions, findingId } from "./views.js";
import { loadRepoSuppressions, REPO_SUPPRESS_FILE } from "./repo-suppress.js";
import { buildHistory } from "./history.js";

export {
  openMemory, projectIdFor, memoryRoot, forgetAll, EVENT_TYPES,
  buildViews, rankFindings, isSuppressed, withRepoSuppressions, findingId,
  loadRepoSuppressions, REPO_SUPPRESS_FILE, buildHistory,
};

/**
 * Views for an opened memory. Returns null when the chain does not verify:
 * a tampered log must not steer a scan, so callers fall back to no memory.
 */
export function views(memory, opts = {}) {
  if (!memory.verify().ok) return null;
  return buildViews(memory.events(), opts);
}

/** Lower-cased framework name for the scanned target, or "unknown". */
export function detectStack(result) {
  const fw = result?.fingerprint?.framework || result?.attackSurface?.find?.((r) => r?.framework)?.framework;
  return typeof fw === "string" && fw ? fw.toLowerCase().slice(0, 64) : "unknown";
}

/** Findings per probe: executed probes count from 0, finding sources add to them. */
export function probeYields(result) {
  const counts = new Map();
  for (const p of result?.executedProbes || []) if (typeof p === "string") counts.set(p, 0);
  for (const f of result?.findings || []) {
    const probe = typeof f.source === "string" && f.source ? f.source : "unknown";
    counts.set(probe, (counts.get(probe) || 0) + 1);
  }
  return [...counts].map(([probe, findings]) => ({ probe, findings }));
}

/**
 * The `--memory` scan hook. Mutates `merged`:
 *   merged.findings   -> unsuppressed findings, ranked
 *   merged.suppressed -> suppressed findings, each with .suppression { source, reason, actor }
 *   merged.memory     -> { projectId, chain: "ok" | "broken", ... }
 * then appends `scan` and `probe_yield` events. Returns { warnings }.
 *
 * Fail-closed: if the chain is broken, memory suppressions and ranking are not
 * applied and nothing is appended (the repo file, which is labelled, still is).
 */
/**
 * How many of a plain scan's findings a --memory scan would suppress. A plain
 * scan applies none, so a CI run stays strict, but it says so. Reads only.
 * @returns {number}
 */
export function suppressedElsewhere(findings, { repo = null, url = null, root } = {}) {
  let v = { suppressions: [] };
  try {
    const { id } = projectIdFor({ repo, url });
    if (existsSync(join(root || memoryRoot(), id))) v = buildViews(openMemory(id, { root }).events());
  } catch { /* an unreadable store only costs the hint */ }
  if (repo) v = withRepoSuppressions(v, loadRepoSuppressions(repo).entries);
  return findings.filter((f) => isSuppressed(f, v)).length;
}

export function applyMemoryToScan(merged, { repo = null, url = null, now = new Date().toISOString(), root } = {}) {
  const warnings = [];
  const { id: projectId, label } = projectIdFor({ repo, url });
  const mem = openMemory(projectId, { root, label, now: () => now });
  const check = mem.verify();
  const stack = detectStack(merged);

  let v = { suppressions: [], recipeSuccess: [], seen: {} };
  if (check.ok) {
    v = buildViews(mem.events(), { now });
  } else {
    warnings.push(`memory chain broken at line ${check.brokenAt} (${check.reason}); memory not applied. Run \`penthera memory verify\`.`);
  }

  if (repo) {
    const rs = loadRepoSuppressions(repo, { now });
    warnings.push(...rs.warnings);
    v = withRepoSuppressions(v, rs.entries);
  }

  const all = merged.findings || [];
  const kept = [];
  const suppressed = [];
  for (const f of all) {
    const fid = findingId(f);
    const s = isSuppressed(f, v);
    if (s) suppressed.push({ ...f, fid, suppression: { source: s.source, reason: s.reason, actor: s.actor, expires: s.expires || null } });
    else kept.push({ ...f, fid });
  }
  merged.findings = check.ok ? rankFindings(kept, v, { framework: stack }) : kept;
  merged.suppressed = suppressed;
  merged.memory = { projectId, stack, chain: check.ok ? "ok" : "broken", events: check.count };

  if (check.ok) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of all) if (counts[f.severity] != null) counts[f.severity]++;
    mem.append({
      type: "scan",
      ts: now,
      data: {
        stack,
        modes: merged.modes || (merged.mode ? [merged.mode] : []),
        counts: { ...counts, total: all.length, suppressed: suppressed.length },
        ids: all.filter((f) => f.severity !== "info").map(findingId),
      },
    });
    for (const p of probeYields({ executedProbes: merged.executedProbes, findings: all })) {
      mem.append({ type: "probe_yield", ts: now, data: { probe: p.probe, stack, findings: p.findings } });
    }
    merged.memory.events = mem.verify().count;
    merged.memory.history = buildHistory(mem.events());
  }
  return { warnings, projectId };
}
