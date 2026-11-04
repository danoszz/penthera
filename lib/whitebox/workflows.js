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
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readSync } from "node:fs";
import { join } from "node:path";

export const WORKFLOW_RULES = {
  "gha-pwn-request": "config",
  "gha-script-injection": "injection",
  "gha-unpinned-action": "config",
};

// Every pattern below runs on one line at a time, after the indentation and an
// optional "- " list marker are split off with plain string code, so no
// pattern has two whitespace runs next to each other (a crafted workflow can't
// make matching quadratic). A line longer than any real workflow line is skipped.
const MAX_LINE = 2000;
const TRIGGER = /^(pull_request_target|workflow_run)\b/;
const HEAD_REF = /github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|github\.event\.workflow_run\.head_(sha|branch)|refs\/pull\//;
// Context fields an outsider can write (GitHub's "untrusted input" list), tested on the text inside one ${{ }}.
const UNTRUSTED = /\b(github\.head_ref|github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|discussion_comment|pages|head_commit|commits|workflow_run)\b[\w.[\]*]{0,80}?\.(?:title|body|head_ref|ref|label|message|name|email|default_branch|page_name|head_branch))\b/;

/** A line split into its indentation, whether it starts a list item, and the rest. */
export function splitLine(line) {
  if (line.length > MAX_LINE) return { indent: 0, dash: false, rest: "", skip: true };
  const rest0 = line.trimStart();
  const indent = line.length - rest0.length;
  const dash = rest0.startsWith("-") && (rest0.length === 1 || rest0[1] === " " || rest0[1] === "\t");
  return { indent, dash, rest: dash ? rest0.slice(1).trimStart() : rest0, skip: false };
}

/** The text after "key:" when the line's key is `key`, else null. */
function valueOf(rest, key) {
  if (!rest.startsWith(key)) return null;
  const after = rest.slice(key.length).trimStart();
  return after.startsWith(":") ? after.slice(1).trim() : null;
}

/** The first untrusted expression inside a ${{ }} on this text, or null. */
function untrustedExpr(text) {
  let at = 0;
  while ((at = text.indexOf("${{", at)) !== -1) {
    const close = text.indexOf("}}", at + 3);
    if (close === -1) return null;
    const m = text.slice(at + 3, close).match(UNTRUSTED);
    if (m) return m[1];
    at = close + 2;
  }
  return null;
}

/** Findings for one workflow's text; `file` is its path relative to the repo. */
export function checkWorkflow(text, file) {
  const findings = [];
  const lines = text.split(/\r?\n/).map(splitLine);
  const privileged = lines.some(({ rest }) => TRIGGER.test(rest) || (valueOf(rest, "on") !== null && /\b(pull_request_target|workflow_run)\b/.test(rest)));

  // gha-pwn-request: a checkout step whose ref points at the PR's head.
  if (privileged) {
    lines.forEach((l, i) => {
      const uses = valueOf(l.rest, "uses");
      if (uses === null || !uses.replace(/^["']/, "").startsWith("actions/checkout@")) return;
      const stepIndent = l.dash ? l.indent + 2 : l.indent;
      for (let j = i + 1; j < lines.length && (lines[j].rest === "" || lines[j].indent >= stepIndent); j++) {
        const ref = valueOf(lines[j].rest, "ref");
        if (ref !== null && HEAD_REF.test(ref)) {
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
  lines.forEach((l, i) => {
    if (runIndent >= 0 && l.rest !== "" && l.indent <= runIndent) runIndent = -1;
    const run = valueOf(l.rest, "run");
    if (run !== null) {
      runIndent = l.indent;
      if (!/^[|>]/.test(run)) report(i, untrustedExpr(run));
      return;
    }
    if (runIndent >= 0) report(i, untrustedExpr(l.rest));
  });
  function report(i, expr) {
    if (!expr) return;
    findings.push(finding("gha-script-injection", "high", file, i + 1,
      "Untrusted text is expanded inside a workflow's shell script",
      `\`${file}\` line ${i + 1} puts \`${expr}\` straight into a \`run:\` script. Whoever writes that text (a PR title, an issue body, a branch name) can end the string and run their own commands in CI.`,
      "Pass the value through an environment variable (env: TITLE: ${{ ... }}) and use \"$TITLE\" in the script, quoted. Then the shell treats it as data.",
    ));
  }

  // gha-unpinned-action: third-party action not pinned to a full commit SHA.
  lines.forEach((l, i) => {
    const uses = valueOf(l.rest, "uses");
    if (uses === null) return;
    const ref = uses.replace(/^["']/, "").split(/[\s"'#]/)[0];
    if (!ref || ref.startsWith("./") || ref.startsWith("docker://")) return;
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

// A real workflow is a few KB; anything far larger isn't one.
const MAX_WORKFLOW_BYTES = 256 * 1024;

/** A real directory, not a symlink a scanned repo planted. */
function isRealDir(path) {
  try { return lstatSync(path).isDirectory(); } catch { return false; }
}

/**
 * Read a workflow only if it's a regular file under the size cap. The repo is
 * untrusted: a symlink can point at /dev/zero or outside the repo, and a FIFO
 * would block the read. O_NOFOLLOW refuses a link swapped in after the check,
 * O_NONBLOCK stops a FIFO from blocking open, and fstat checks what was opened.
 */
function readWorkflow(path) {
  let fd;
  try {
    if (!lstatSync(path).isFile()) return null;
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0) | (constants.O_NONBLOCK || 0));
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > MAX_WORKFLOW_BYTES) return null;
    const buf = Buffer.alloc(st.size);
    const n = readSync(fd, buf, 0, st.size, 0);
    return buf.subarray(0, n).toString("utf-8");
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/** Every workflow GitHub would run for this repo. */
export function scanWorkflows(repoPath) {
  const github = join(repoPath, ".github");
  const dir = join(github, "workflows");
  if (!isRealDir(github) || !isRealDir(dir)) return [];
  const out = [];
  for (const name of readdirSync(dir).filter((f) => /\.ya?ml$/.test(f)).sort()) {
    const text = readWorkflow(join(dir, name));
    if (text === null) continue;
    out.push(...checkWorkflow(text, `.github/workflows/${name}`));
  }
  return out;
}
