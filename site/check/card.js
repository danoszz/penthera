/**
 * The result card's rules, shared by the page (ui.js renders your result) and
 * the build (site/build.mjs renders the example from a real check of the test
 * server), so the example and your result show the same rows the same way.
 */

export const SEV = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export const TAG = { critical: "Crit", high: "High", medium: "Med", low: "Low", info: "Info" };

const bySeverity = (a, b) => (SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9);

/** Failed checks, most severe first. */
export const failedChecks = (report) => report.checks.filter((c) => !c.passed).sort(bySeverity);

/**
 * The rows on the card: the most severe failed checks, or, for a clean
 * result, what passed. `withPassed` adds one passed row after the failures,
 * so the example shows both kinds.
 */
export function cardRows(report, { n = 3, withPassed = false } = {}) {
  const failed = failedChecks(report);
  const passed = report.checks.filter((c) => c.passed);
  if (!failed.length) return passed.slice(0, n);
  return [...failed.slice(0, n), ...(withPassed ? passed.slice(0, 1) : [])];
}

/** The tag before a row: its severity, or OK. */
export const rowTag = (c) => (c.passed ? "OK" : TAG[c.severity] || c.severity);

/** The headline next to a result, above the hand-off. */
export function handoffTitle(report) {
  const n = failedChecks(report).length;
  if (!n) return "Nothing to fix from the outside.";
  return n === 1 ? "1 thing to fix. Your coding agent can help." : `${n} things to fix. Your coding agent can help.`;
}

/**
 * The report as Markdown, for the visitor to keep. Built in the page from what
 * is already on screen; nothing is sent anywhere.
 */
export function reportMarkdown(report, date = new Date().toISOString().slice(0, 10)) {
  const failed = failedChecks(report);
  const passed = report.checks.filter((c) => c.passed);
  const lines = [`# Penthera quick check: ${report.url}`, "", `${report.score}/100. ${report.verdict}. Checked ${date}.`, "", report.scope, ""];
  if (failed.length) lines.push(`## ${failed.length} to fix, most severe first`, "");
  for (const c of failed) {
    lines.push(`### ${c.title} (${c.severity})`, "");
    if (c.evidence) lines.push(`Evidence: ${c.evidence}`, "");
    if (c.fix) lines.push(`Fix: ${c.fix}`, "");
    if (c.verify) lines.push(`Verify: \`${c.verify}\``, "");
  }
  if (passed.length) lines.push(`## ${passed.length} passed`, "", ...passed.map((c) => `- ${c.title}`), "");
  lines.push(`Full scan on your own machine: \`npx penthera ${report.url}\``, "");
  return lines.join("\n");
}
