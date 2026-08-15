/**
 * Remediation throughput / audit-loop tracking (NIS2 measure f).
 *
 * More findings is not more security — what matters is closing them. This module
 * turns repeated scans into an audit-loop artifact: time-to-fix, ageing of open
 * items, and drift since last scan. It persists a small history keyed by a
 * STABLE finding fingerprint (severity- and count-independent) so a re-worded or
 * re-counted finding isn't seen as "resolved + new" churn.
 *
 * Pure functions take `now` (ISO string) so they're deterministic and testable.
 */

const DAY_MS = 24 * 3600 * 1000;

/**
 * Stable fingerprint for a finding: source + category + normalized url + title,
 * with digit runs collapsed so ids/counts (e.g. "5 active params", "/users/1")
 * don't create spurious new/resolved churn. Severity is intentionally excluded.
 */
export function fingerprintFinding(f) {
  const norm = (s) => String(s || "").toLowerCase().replace(/\d+/g, "#").replace(/\s+/g, " ").trim();
  return [f.source || "", f.category || "", norm(f.url), norm(f.title)].join("|");
}

/** A fresh, empty history store. */
export function emptyHistory() {
  return { version: 1, findings: {}, scans: [] };
}

/**
 * Fold the current findings into the history. Returns a new history object.
 * - a finding seen now that wasn't open before → firstSeen = now
 * - a finding previously resolved but seen again → reopened (resolvedAt cleared)
 * - a tracked finding not seen now → resolvedAt = now
 */
export function updateHistory(history, findings, now) {
  const h = {
    version: 1,
    findings: { ...(history?.findings || {}) },
    scans: [...(history?.scans || [])],
  };
  const current = new Map();
  for (const f of findings || []) {
    if (f.severity === "info") continue; // track actionable findings only
    current.set(fingerprintFinding(f), f);
  }

  let newCount = 0;
  let reopened = 0;
  for (const [fp, f] of current) {
    const rec = h.findings[fp];
    if (!rec) {
      h.findings[fp] = {
        firstSeen: now, lastSeen: now, resolvedAt: null,
        severity: f.severity, title: f.title, url: f.url || null, category: f.category || null,
      };
      newCount++;
    } else {
      rec.lastSeen = now;
      rec.severity = f.severity; // keep latest severity
      if (rec.resolvedAt) { rec.resolvedAt = null; reopened++; } // reappeared
    }
  }

  let resolvedCount = 0;
  for (const [fp, rec] of Object.entries(h.findings)) {
    if (!current.has(fp) && !rec.resolvedAt) {
      rec.resolvedAt = now;
      resolvedCount++;
    }
  }

  const open = Object.values(h.findings).filter((r) => !r.resolvedAt).length;
  h.scans.push({ at: now, open, new: newCount, resolved: resolvedCount, reopened });
  return h;
}

function daysBetween(aIso, bIso) {
  const a = new Date(aIso).getTime();
  const b = new Date(bIso).getTime();
  if (Number.isNaN(a) || Number.isNaN(b)) return null;
  return Math.max(0, Math.round((b - a) / DAY_MS));
}

function median(nums) {
  if (!nums.length) return null;
  const s = [...nums].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : Math.round((s[mid - 1] + s[mid]) / 2);
}

/** Compute the audit-loop artifact from a history store. */
export function buildAuditLoop(history, now) {
  const recs = Object.values(history?.findings || {});
  const open = recs.filter((r) => !r.resolvedAt);
  const resolved = recs.filter((r) => r.resolvedAt);

  const openBySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const r of open) if (openBySeverity[r.severity] != null) openBySeverity[r.severity]++;

  const ageOf = (r) => daysBetween(r.firstSeen, now);
  const ttf = resolved.map((r) => daysBetween(r.firstSeen, r.resolvedAt)).filter((n) => n != null);

  const ageing = { "0-7": 0, "8-30": 0, "31-90": 0, "90+": 0 };
  for (const r of open) {
    const d = ageOf(r) ?? 0;
    if (d <= 7) ageing["0-7"]++;
    else if (d <= 30) ageing["8-30"]++;
    else if (d <= 90) ageing["31-90"]++;
    else ageing["90+"]++;
  }

  const openList = open
    .map((r) => ({ title: r.title, url: r.url, severity: r.severity, ageDays: ageOf(r), firstSeen: r.firstSeen }))
    .sort((a, b) => (b.ageDays ?? 0) - (a.ageDays ?? 0));

  return {
    generated_at: now,
    scansRecorded: (history?.scans || []).length,
    openCount: open.length,
    resolvedCount: resolved.length,
    openBySeverity,
    medianTimeToFixDays: median(ttf),
    oldestOpenDays: openList.length ? (openList[0].ageDays ?? 0) : 0,
    ageing,
    open: openList,
    lastScan: (history?.scans || []).slice(-1)[0] || null,
  };
}

/** Render the audit loop as a Markdown section. */
export function formatAuditLoopMarkdown(a) {
  if (!a) return "";
  const L = [];
  L.push("## Remediation & audit loop (measure f)");
  L.push("");
  L.push(`Across **${a.scansRecorded}** recorded scan${a.scansRecorded === 1 ? "" : "s"}: **${a.openCount}** open · **${a.resolvedCount}** resolved.`);
  L.push("");
  L.push(`- **Open by severity:** ${a.openBySeverity.critical} critical · ${a.openBySeverity.high} high · ${a.openBySeverity.medium} medium · ${a.openBySeverity.low} low`);
  L.push(`- **Median time-to-fix:** ${a.medianTimeToFixDays == null ? "—" : `${a.medianTimeToFixDays} day(s)`}`);
  L.push(`- **Oldest open finding:** ${a.oldestOpenDays} day(s)`);
  L.push(`- **Ageing of open items:** 0–7d: ${a.ageing["0-7"]} · 8–30d: ${a.ageing["8-30"]} · 31–90d: ${a.ageing["31-90"]} · 90d+: ${a.ageing["90+"]}`);
  if (a.lastScan) L.push(`- **Since last scan:** ${a.lastScan.new} new · ${a.lastScan.resolved} resolved${a.lastScan.reopened ? ` · ${a.lastScan.reopened} reopened` : ""}`);
  L.push("");
  if (a.open.length) {
    L.push("| Open finding | Severity | Age (days) |");
    L.push("|--------------|----------|-----------|");
    for (const o of a.open.slice(0, 20)) {
      L.push(`| ${o.title}${o.url ? ` (${o.url})` : ""} | ${o.severity} | ${o.ageDays ?? "—"} |`);
    }
    L.push("");
  }
  L.push("> Measure f is about closing the loop, not lengthening the backlog. Track time-to-fix and ageing over time; re-run on a cadence.");
  L.push("");
  return L.join("\n");
}
