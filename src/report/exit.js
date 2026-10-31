/**
 * The scan's exit code, and the reason for it in words. Every surface reads it
 * from here (CLI, brief, terminal report, Markdown, SARIF), so none can call a
 * failing run clean.
 */
import { cleanText } from "../mcp/results.js";
import { giantsGate } from "../../lib/giants/index.js";

const MAX_NAMED = 3;

export const isSevere = (f) => f.severity === "critical" || f.severity === "high";

/**
 * 2: a tool the policy requires did not run. 1: a critical or high finding,
 * wherever it sits, or other tools' unless the policy says giants.failOn: never.
 * A bucket says how likely a finding is to matter; it does not pass a run, so a
 * live-format key in a fixture still fails.
 */
export function exitCodeOf(result) {
  if (result.giants?.requiredNotRun?.length) return 2;
  return (result.findings || []).some(isSevere) || giantsGate(result) ? 1 : 0;
}

function namedFinding(f) {
  const where = f.file || f.url;
  const place = where ? ` in ${where}${f.line ? `:${f.line}` : ""}` : "";
  return cleanText(`${f.foundBy?.[0] || f.sources?.[0]?.tool || "other tool"}: ${f.title || "finding"}${place}`, 200);
}

/**
 * The reason, for reports that list Penthera's own findings: only when those do
 * not explain the exit code already.
 */
export function exitNote(result) {
  const explained = exitCodeOf(result) === 1 && (result.findings || []).some(isSevere);
  return explained ? null : exitReason(result);
}

/** Why a result fails, in one line, or null when it does not. Takes one result or several. */
export function exitReason(results) {
  const list = [results].flat().filter(Boolean);
  const code = Math.max(0, ...list.map(exitCodeOf));
  if (code === 0) return null;
  if (code === 2) {
    const tools = [...new Set(list.flatMap((r) => r.giants?.requiredNotRun || []))].map((t) => cleanText(t, 60));
    return `The CLI exits 2 on this: the policy requires ${tools.join(", ")}, which did not run.`;
  }
  const own = list.flatMap((r) => r.findings || []).filter(isSevere).length;
  const others = list.flatMap((r) => (giantsGate(r) ? r.giants.findings.filter(isSevere) : []));
  const parts = [];
  if (own) parts.push(`${own} critical or high finding${own === 1 ? "" : "s"} outside Act on`);
  if (others.length) {
    const named = others.slice(0, MAX_NAMED).map(namedFinding).join("; ");
    const more = others.length > MAX_NAMED ? `; ${others.length - MAX_NAMED} more in the full report` : "";
    parts.push(`${others.length} critical or high finding${others.length === 1 ? "" : "s"} from other tools (${named}${more})`);
  }
  const it = own + others.length === 1 ? "it" : "them";
  return `The CLI exits 1 on this: ${parts.join(" and ")}. Fix ${it}, or write down why you accept ${it}.`;
}
