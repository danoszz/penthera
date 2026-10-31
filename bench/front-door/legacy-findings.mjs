/**
 * Amendment 3: what the frozen detector found in the stopped pass 2. The detector was
 * fixed after the stop, so only the old one can show which record a person must review.
 * This is its one use. It scans the original raw file, before any prune, and writes
 * legacy-findings.json next to it: record order and field path, never text. That file
 * is private and stays on the server. The review is bound to its hash.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { scrubMisses as frozenDetector } from "./legacy/classify-7023106f.mjs";
import { eachMiss, LEGACY_CLASSIFIER_SHA256, PAGE_PATHS } from "./record-checks.mjs";

const FROZEN_FILE = new URL("./legacy/classify-7023106f.mjs", import.meta.url);
const hash = (b) => createHash("sha256").update(b).digest("hex");

/** What the frozen detector finds in this run's original raw file. Writes nothing. */
export function scanLegacy(dir) {
  if (hash(readFileSync(FROZEN_FILE)) !== LEGACY_CLASSIFIER_SHA256) throw new Error("Refused: the frozen detector does not match its hash.");
  const manifestBytes = readFileSync(join(dir, "manifest.json"));
  const manifest = JSON.parse(manifestBytes);
  const rawBytes = readFileSync(join(dir, "raw.jsonl"));
  if (!manifest.rawSha256 || hash(rawBytes) !== manifest.rawSha256) throw new Error("Refused: this needs the original raw file, before any prune.");
  const rows = rawBytes.toString("utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const findings = [];
  for (const r of rows) eachMiss(r, (path, isKey, kind, count) => findings.push({ order: r.order, path: isKey ? `${path || "record"} (a key)` : path, kind, count }), frozenDetector);
  return {
    legacyDetectorSha256: LEGACY_CLASSIFIER_SHA256, manifestSha256: hash(manifestBytes), rawSha256: manifest.rawSha256, records: rows.length, findings,
    reproducesStop: findings.some((f) => PAGE_PATHS.includes(f.path)), purgeConfirm: manifest.rawSha256.slice(0, 12),
  };
}

export function legacyFindings(dir) {
  const report = { ...scanLegacy(dir), writtenAt: new Date().toISOString() };
  writeFileSync(join(dir, "legacy-findings.json"), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  return report;
}
