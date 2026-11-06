/**
 * The tools --giants runs, in report order, and the areas they cover.
 * Each adapter (lib/giants/adapters/<tool>.js) says how to run its tool, how
 * to read its output, its minimum version and the versions with a recorded
 * fixture (tests/fixtures/giants/<tool>/<version>/).
 */
import gitleaks from "./adapters/gitleaks.js";
import trufflehog from "./adapters/trufflehog.js";
import semgrep from "./adapters/semgrep.js";
import codeql from "./adapters/codeql.js";
import osvScanner from "./adapters/osv-scanner.js";
import pipAudit from "./adapters/pip-audit.js";
import trivy from "./adapters/trivy.js";
import checkov from "./adapters/checkov.js";
import nuclei from "./adapters/nuclei.js";
import zap from "./adapters/zap.js";

export const TOOLS = [gitleaks, trufflehog, semgrep, codeql, osvScanner, pipAudit, trivy, checkov, nuclei, zap];
export const TOOL_IDS = TOOLS.map((t) => t.id);
export const toolById = (id) => TOOLS.find((t) => t.id === id) || null;

/** The areas of a first pass, with Penthera's own checks for each. */
export const AREAS = [
  { id: "secrets", label: "Secrets", mode: "repo", penthera: "secret rules" },
  { id: "code", label: "Code", mode: "repo", penthera: "code patterns, library mode" },
  { id: "dependencies", label: "Dependencies", mode: "repo", penthera: "penthera deps (capabilities, malware, licences)" },
  { id: "infrastructure", label: "Infrastructure", mode: "repo", penthera: "runtime versions in Dockerfiles and version files" },
  { id: "live", label: "Live app", mode: "url", penthera: "passive checks, templates, --deep probes" },
];

/** The areas a tool covers, as a list. */
export const areasOf = (tool) => (Array.isArray(tool.area) ? tool.area : [tool.area]);

/** Compare dotted versions numerically: -1, 0 or 1. Missing parts count as 0. */
export function compareVersions(a, b) {
  const pa = String(a).split(/[.+-]/).map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split(/[.+-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length, 3); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

/** The first x.y.z in a tool's --version output, or null. */
export function parseVersion(text) {
  const m = /(?<![\d.])(\d+\.\d+\.\d+)/.exec(String(text || ""));
  return m ? m[1] : null;
}

/**
 * How a found version stands against the adapter: "below-minimum",
 * "untested" (newer or other than any recorded fixture: runs with a warning,
 * spec decision 7), "tested", or "unknown".
 */
export function versionStatus(tool, version) {
  if (!version) return "unknown";
  if (compareVersions(version, tool.minVersion) < 0) return "below-minimum";
  return tool.tested.includes(version) ? "tested" : "untested";
}

/** The install hint for this platform. */
export function installHint(tool, platform = process.platform) {
  return tool.install[platform] || tool.install.other;
}
