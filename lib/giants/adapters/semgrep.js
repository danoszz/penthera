/**
 * Semgrep (LGPL-2.1 engine; rules under their own licence): code patterns,
 * with a local rules folder only. Registry configs (`auto`, `p/…`, `r/…`, a
 * URL) download rules at scan time, so they are refused; no local rules
 * means Semgrep is skipped with that reason.
 */
import { existsSync, statSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { clean, makeFinding, severityFromScore, severityFromWord, where } from "../finding.js";
import { cwesOf, readSarif, sarifResults } from "../sarif.js";
import { trimEndChars, trimStartChars } from "../../linear-text.js";

/** The rules folder or file to use, or `{ skip }` with the reason. */
export function semgrepRules(value) {
  if (!value) return { skip: "no local rules: set PENTHERA_SEMGREP_RULES or giants.semgrepRules to a rules folder (for example a clone of https://github.com/semgrep/semgrep-rules)" };
  const v = String(value);
  if (/^(?:auto$|p\/|r\/|s\/|https?:)/i.test(v)) return { skip: `"${v}" downloads rules from the Semgrep registry at scan time; give a local folder` };
  const path = isAbsolute(v) ? v : resolve(v);
  if (!existsSync(path)) return { skip: `the rules path ${path} does not exist` };
  return { path, dir: statSync(path).isDirectory() };
}

/** Semgrep prefixes rule ids with the rules folder's path, dotted; take it off. */
export function shortRuleId(ruleId, rulesPath) {
  const prefix = trimEndChars(trimStartChars(String(rulesPath || ""), "/"), "/").split("/").join(".") + ".";
  return ruleId.startsWith(prefix) ? ruleId.slice(prefix.length) : ruleId;
}

export default {
  id: "semgrep",
  area: "code",
  mode: "repo",
  licence: "LGPL-2.1 (engine); rules under their own licence, e.g. the Semgrep Rules License v1.0",
  homepage: "https://github.com/semgrep/semgrep",
  minVersion: "1.100.0",
  tested: ["1.180.0"],
  bins: ["semgrep"],
  versionArgs: ["--version"],
  network: "none",
  env: { SEMGREP_SEND_METRICS: "off", SEMGREP_ENABLE_VERSION_CHECK: "0" },
  install: { darwin: "brew install semgrep, then clone rules: git clone https://github.com/semgrep/semgrep-rules", linux: "pipx install semgrep, then clone rules: git clone https://github.com/semgrep/semgrep-rules", other: "https://semgrep.dev/docs/getting-started/" },

  command({ root, tmp, settings }) {
    const rules = semgrepRules(settings.semgrepRules);
    if (rules.skip) return { skip: rules.skip };
    const out = `${tmp}/semgrep.sarif`;
    return { args: ["scan", "--config", rules.path, "--metrics", "off", "--disable-version-check", "--sarif", "--output", out, "--quiet", root], output: out };
  },
  // 0: scan done; 1: findings with --error (not used here). 2 and up are errors.
  exitOk: (code) => code === 0 || code === 1,

  parse(text, { root, tool, settings }) {
    const doc = readSarif(text);
    const rulesPath = settings.semgrepRules ? resolve(settings.semgrepRules) : "";
    return sarifResults(doc, root).map((r) => {
      const id = shortRuleId(r.ruleId, rulesPath);
      const name = id.split(".").pop();
      const props = r.rule?.properties || {};
      const severity = severityFromScore(props["security-severity"]) || severityFromWord(r.level) || "medium";
      const cwe = cwesOf(props.tags, props.cwe);
      return makeFinding({
        tool, ruleId: id, ruleUrl: r.rule?.helpUri || null,
        category: "code", severity,
        title: `${clean(name, 120)} in ${where(r.file, r.line)}`,
        description: r.message || r.rule?.fullDescription?.text || id,
        file: r.file, line: r.line,
        key: { cwe },
      });
    });
  },
};
