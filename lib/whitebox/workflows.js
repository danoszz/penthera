/**
 * GitHub Actions workflow checks: the CI files GitHub runs, at
 * <repo>/.github/workflows/*.yml.
 *
 * Three rules, from GitHub's own guidance on securing workflows (GitHub
 * Security Lab, "Keeping your GitHub Actions and workflows secure", parts 1
 * and 2) and the Actions security hardening docs:
 *   - gha-pwn-request: a pull_request_target or workflow_run workflow checks
 *     out the pull request's code. That code then runs with the base
 *     repository's token and secrets.
 *   - gha-script-injection: text an outsider controls (a PR title, an issue
 *     body, a branch name) is expanded with ${{ }} inside a `run:` script,
 *     where it becomes shell code.
 *   - gha-unpinned-action: a third-party action referenced by a tag or
 *     branch, which its owner can move, instead of a full commit SHA.
 * Line-based on purpose: it reads the text, runs nothing, and reports the line.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

export const WORKFLOW_RULES = {
  "gha-pwn-request": "config",
  "gha-script-injection": "injection",
  "gha-unpinned-action": "config",
};

const PRIVILEGED_TRIGGER = /^\s*(pull_request_target|workflow_run)\s*:|^\s*on\s*:\s*\[?[^\n#]*\b(pull_request_target|workflow_run)\b|^\s*-\s*(pull_request_target|workflow_run)\s*$/m;
const HEAD_REF = /github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|github\.event\.workflow_run\.head_(sha|branch)|refs\/pull\//;
// Context fields an outsider can write (GitHub's "untrusted input" list).
const UNTRUSTED = /\$\{\{\s*[^}]*\b(github\.head_ref|github\.event\.(issue|pull_request|comment|review|review_comment|discussion|discussion_comment|pages|head_commit|commits|workflow_run)\b[\w.[\]*]*\.(title|body|head_ref|ref|label|message|name|email|default_branch|page_name|head_branch))\b[^}]*\}\}/;
const USES = /^\s*-?\s*uses:\s*["']?([^\s"'#]+)/;

const indentOf = (line) => line.match(/^\s*/)[0].length;

/** Findings for one workflow's text; `file` is its path relative to the repo. */
export function checkWorkflow(text, file) {
  const findings = [];
  const lines = text.split(/\r?\n/);
  const privileged = PRIVILEGED_TRIGGER.test(text);

  // gha-pwn-request: a checkout step whose ref points at the PR's head.
  if (privileged) {
    lines.forEach((line, i) => {
      if (!/uses:\s*["']?actions\/checkout@/.test(line)) return;
      const stepIndent = indentOf(line.replace(/-\s*/, "  "));
      for (let j = i + 1; j < lines.length && (lines[j].trim() === "" || indentOf(lines[j]) >= stepIndent); j++) {
        if (/^\s*ref\s*:/.test(lines[j]) && HEAD_REF.test(lines[j])) {
          findings.push(finding("gha-pwn-request", "high", file, j + 1,
            "A pull_request_target or workflow_run workflow checks out the pull request's code",
            `\`${file}\` runs on a privileged trigger and checks out the pull request's head (line ${j + 1}). Anything that code runs next (a build, a test, an install script) runs with this repository's token and secrets, so a fork can take them.`,
            "Use the plain pull_request trigger for jobs that build or test PR code. If you need pull_request_target (to label or comment), don't check out the PR's code in it, or read it only as data and never run it.",
          ));
          break;
        }
      }
    });
  }

  // gha-script-injection: untrusted ${{ }} inside a run: block.
  let runIndent = -1;
  lines.forEach((line, i) => {
    if (runIndent >= 0 && line.trim() !== "" && indentOf(line) <= runIndent) runIndent = -1;
    const run = line.match(/^(\s*)-?\s*run\s*:\s*(.*)$/);
    if (run) {
      runIndent = indentOf(line);
      if (!/^[|>]/.test(run[2].trim()) && UNTRUSTED.test(run[2])) report(i);
      return;
    }
    if (runIndent >= 0 && UNTRUSTED.test(line)) report(i);
  });
  function report(i) {
    const expr = lines[i].match(UNTRUSTED)[1];
    findings.push(finding("gha-script-injection", "high", file, i + 1,
      "Untrusted text is expanded inside a workflow's shell script",
      `\`${file}\` line ${i + 1} puts \`${expr}\` straight into a \`run:\` script. Whoever writes that text (a PR title, an issue body, a branch name) can end the string and run their own commands in CI.`,
      "Pass the value through an environment variable (env: TITLE: ${{ ... }}) and use \"$TITLE\" in the script, quoted. Then the shell treats it as data.",
    ));
  }

  // gha-unpinned-action: third-party action not pinned to a full commit SHA.
  lines.forEach((line, i) => {
    const m = line.match(USES);
    if (!m) return;
    const ref = m[1];
    if (ref.startsWith("./") || ref.startsWith("docker://")) return;
    const at = ref.lastIndexOf("@");
    if (at < 0 || /^[0-9a-f]{40}$/.test(ref.slice(at + 1))) return;
    const owner = ref.split("/")[0];
    const firstParty = owner === "actions" || owner === "github";
    findings.push(finding("gha-unpinned-action", firstParty ? "low" : "medium", file, i + 1,
      `Action \`${ref}\` is pinned to a tag, not a commit`,
      `\`${file}\` line ${i + 1} uses \`${ref}\`. A tag or branch can be moved to new code by whoever controls that action${firstParty ? "" : ", a third party"}, and the next run uses it with this workflow's permissions.`,
      "Pin the action to its full commit SHA and keep the tag as a comment (uses: owner/action@<40-char sha> # v1.2.3). Dependabot can keep the SHA up to date.",
    ));
  });

  return findings;
}

function finding(rule, severity, file, line, title, description, remediation) {
  return {
    severity, title, description, remediation,
    url: file, file, line,
    templateId: rule,
    category: WORKFLOW_RULES[rule],
    source: "static-analysis",
    confidence: rule === "gha-unpinned-action" ? "confirmed" : "likely",
  };
}

/** Every workflow GitHub would run for this repo. */
export function scanWorkflows(repoPath) {
  const dir = join(repoPath, ".github", "workflows");
  if (!existsSync(dir)) return [];
  const out = [];
  for (const name of readdirSync(dir).filter((f) => /\.ya?ml$/.test(f)).sort()) {
    let text;
    try { text = readFileSync(join(dir, name), "utf-8"); } catch { continue; }
    out.push(...checkWorkflow(text, `.github/workflows/${name}`));
  }
  return out;
}
