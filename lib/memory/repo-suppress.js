/**
 * Optional repo file `penthera.suppress.json`. This is the ONLY thing Penthera
 * reads from a scanned repo that changes what a report shows, so it is held to
 * a strict, data-only shape and every effect is labelled in the report as
 * "suppressed by repo file" with its reason. A PR that adds an entry is visible
 * in review, and so is the suppressed finding in the report.
 *
 *   {
 *     "version": 1,
 *     "suppress": [
 *       { "id": "3f9a0c1d2b4e5f60", "reason": "test fixture key", "severity": "critical", "expires": "2027-01-01" },
 *       { "fingerprint": "repo-secret|secret|...|...", "reason": "..." }
 *     ]
 *   }
 */
import { existsSync, statSync } from "node:fs";
import { readRepoFile, isRefused } from "../fs-safe.js";
import { join } from "node:path";
import { parseJson } from "../json-text.js";

export const REPO_SUPPRESS_FILE = "penthera.suppress.json";
const MAX_BYTES = 64 * 1024;
const MAX_ENTRIES = 500;
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

/**
 * Load and validate the repo file. Returns { entries, warnings }. Invalid
 * entries are dropped with a warning, never guessed at.
 */
export function loadRepoSuppressions(repoPath, { now = new Date().toISOString() } = {}) {
  const path = join(repoPath, REPO_SUPPRESS_FILE);
  if (!existsSync(path)) return { entries: [], warnings: [], path: null };
  const st = statSync(path);
  if (!st.isFile()) return { entries: [], warnings: [`${REPO_SUPPRESS_FILE} is not a regular file, ignored`], path };
  if (st.size > MAX_BYTES) return { entries: [], warnings: [`${REPO_SUPPRESS_FILE} is larger than 64 KB, ignored`], path };
  let buf;
  try {
    buf = readRepoFile(path, { root: repoPath, encoding: null, maxBytes: MAX_BYTES, label: REPO_SUPPRESS_FILE });
  } catch (e) {
    if (isRefused(e)) return { entries: [], warnings: [`${e.message}, ignored`], path };
    throw e;
  }
  return parseRepoSuppressions(buf, { now, path });
}

/**
 * Validate the file's bytes (from disk, or from the git index for the
 * pre-commit hook). Same rules and result shape as loadRepoSuppressions().
 */
export function parseRepoSuppressions(buf, { now = new Date().toISOString(), path = REPO_SUPPRESS_FILE } = {}) {
  const warnings = [];
  if (buf.length > MAX_BYTES) return { entries: [], warnings: [`${REPO_SUPPRESS_FILE} is larger than 64 KB, ignored`], path };
  let doc;
  try { doc = parseJson(buf.toString("utf-8")); } catch (e) {
    return { entries: [], warnings: [`${REPO_SUPPRESS_FILE} is not valid JSON (${e.message}), ignored`], path };
  }
  if (!doc || typeof doc !== "object" || doc.version !== 1 || !Array.isArray(doc.suppress)) {
    return { entries: [], warnings: [`${REPO_SUPPRESS_FILE} needs { "version": 1, "suppress": [...] }, ignored`], path };
  }

  const nowMs = Date.parse(now);
  const entries = [];
  doc.suppress.slice(0, MAX_ENTRIES).forEach((e, i) => {
    const where = `${REPO_SUPPRESS_FILE} entry ${i + 1}`;
    if (!e || typeof e !== "object") { warnings.push(`${where}: not an object, ignored`); return; }
    const id = typeof e.id === "string" && /^[0-9a-f]{16}$/.test(e.id) ? e.id : null;
    const fingerprint = typeof e.fingerprint === "string" && e.fingerprint.length <= 2000 ? e.fingerprint : null;
    if (!id && !fingerprint) { warnings.push(`${where}: needs "id" (16 hex chars) or "fingerprint", ignored`); return; }
    const reason = typeof e.reason === "string" ? e.reason.trim() : "";
    if (!reason || reason.length > 500) { warnings.push(`${where}: needs a "reason" (1-500 chars), ignored`); return; }
    let expires = null;
    if (e.expires != null) {
      const t = Date.parse(e.expires);
      if (typeof e.expires !== "string" || Number.isNaN(t)) { warnings.push(`${where}: "expires" is not a date, ignored`); return; }
      if (t <= nowMs) { warnings.push(`${where}: expired on ${e.expires}, not applied`); return; }
      expires = e.expires;
    }
    // The most severe finding this entry covers. Without one it covers up to
    // medium (entries from before 2.3.2), so a finding that escalates shows.
    let severity = null;
    if (e.severity != null) {
      if (!SEVERITIES.includes(e.severity)) { warnings.push(`${where}: "severity" must be one of ${SEVERITIES.join(", ")}, ignored`); return; }
      severity = e.severity;
    }
    entries.push({ id, fingerprint, reason, expires, actor: "repo", severity });
  });
  if (doc.suppress.length > MAX_ENTRIES) warnings.push(`${REPO_SUPPRESS_FILE}: only the first ${MAX_ENTRIES} entries are read`);
  return { entries, warnings, path };
}
