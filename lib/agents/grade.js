/**
 * The A-F grade for a list of findings, shared by `penthera agents`, the
 * dashboard and `penthera init`. Problems to act on count (the buckets every
 * surface uses, src/report/counts.js), and so does every critical or high
 * finding wherever it is, since it fails the run (exit 1). A medium or low
 * finding to check first, or likely noise, does not lower the grade (Daan,
 * 9 Nov); the card says how many there are to check.
 */
import { bucketOf } from "../../src/report/counts.js";

const WEIGHT = { critical: 30, high: 15, medium: 5, low: 1, info: 0 };

/** A–F grade. Any critical finding is an F; otherwise score bands. */
export function gradeFindings(findings, { skillTarget = false } = {}) {
  const act = (findings || []).filter((f) => f && (f.severity === "critical" || f.severity === "high" || bucketOf(f, { skillTarget }).bucket === "act"));
  let score = 100;
  for (const f of act) score -= WEIGHT[f.severity] ?? 0;
  score = Math.max(0, score);
  const critical = act.some((f) => f.severity === "critical");
  const grade = critical ? "F" : score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  return { grade, score };
}
