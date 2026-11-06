/**
 * gitleaks (MIT): secrets in the files of the scanned folder.
 *
 * `gitleaks dir` replaces `gitleaks detect --no-git` (confirmed on 8.30.1:
 * `detect` is no longer listed in --help). `--redact` keeps the secret out of
 * the report file, so the secret's value for the merge key is read back from
 * the scanned file at the reported line and columns.
 */
import { makeFinding, readLine, secretHash, where } from "../finding.js";
import { readSarif, sarifResults } from "../sarif.js";
import { trimEndChars, trimStartChars } from "../../linear-text.js";

/** Tokens in a span that can be a secret's value: 8+ characters, with a digit or 20+ long. */
export function secretTokens(span) {
  return [...String(span || "").matchAll(/[A-Za-z0-9+/_\-.=~]{8,}/g)].map((m) => trimStartChars(trimEndChars(m[0], "=."), "=."))
    .filter((t) => t.length >= 8 && (/\d/.test(t) || t.length >= 20));
}

export default {
  id: "gitleaks",
  area: "secrets",
  mode: "repo",
  licence: "MIT",
  homepage: "https://github.com/gitleaks/gitleaks",
  minVersion: "8.30.0",
  tested: ["8.30.1"],
  bins: ["gitleaks"],
  versionArgs: ["version"],
  network: "none",
  install: { darwin: "brew install gitleaks", linux: "Download a release from https://github.com/gitleaks/gitleaks/releases", other: "https://github.com/gitleaks/gitleaks/releases" },
  // No severity in gitleaks' output: a committed secret is high.
  severity: "high",

  command({ root, tmp }) {
    const out = `${tmp}/gitleaks.sarif`;
    return { args: ["dir", root, "--report-format", "sarif", "--report-path", out, "--redact", "--exit-code", "0", "--no-banner", "--log-level", "error"], output: out };
  },
  exitOk: (code) => code === 0,

  parse(text, { root, tool }) {
    const doc = readSarif(text);
    return sarifResults(doc, root).map((r) => {
      const lineText = readLine(root, r.file, r.line);
      const span = lineText != null && r.startColumn
        ? lineText.slice(Math.max(0, r.startColumn - 2), (r.endColumn || lineText.length) + 1)
        : null;
      const hashes = span ? [...new Set(secretTokens(span).map(secretHash))] : [];
      return makeFinding({
        tool, ruleId: r.ruleId, ruleUrl: "https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml",
        category: "secret", severity: this.severity,
        title: `Secret (${r.ruleId}) in ${where(r.file, r.line)}`,
        description: `gitleaks rule ${r.ruleId} matched in \`${r.file}\`${r.line ? ` on line ${r.line}` : ""}. The value is not shown.`,
        file: r.file, line: r.line,
        key: { secretHashes: hashes },
        remediation: "Remove the secret from the code, rotate it, and load it from the environment or a secret manager.",
      });
    });
  },
};
