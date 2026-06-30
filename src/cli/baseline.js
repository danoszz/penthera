/**
 * Compare scan findings against a previous JSON report.
 */
import { readFileSync } from "node:fs";

function findingKey(f) {
  return `${f.severity}::${f.title}::${f.url || ""}::${f.source || ""}`;
}

export function compareWithBaseline(currentFindings, baselinePath) {
  let baseline;
  try {
    baseline = JSON.parse(readFileSync(baselinePath, "utf-8"));
  } catch (e) {
    throw new Error(`Cannot read baseline report: ${baselinePath} (${e.message})`);
  }

  const prev = baseline.findings || [];
  const prevKeys = new Set(prev.map(findingKey));
  const currKeys = new Set((currentFindings || []).map(findingKey));

  const newFindings = (currentFindings || []).filter((f) => !prevKeys.has(findingKey(f)));
  const resolvedFindings = prev.filter((f) => !currKeys.has(findingKey(f)));
  const unchangedFindings = (currentFindings || []).filter((f) => prevKeys.has(findingKey(f)));

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
