/**
 * Triage for pull requests from forks, before anyone approves CI.
 *
 *   node scripts/ci/pr-triage.mjs <owner/repo> <pr-number> <out-dir>
 *
 * Reads the PR's changed files through the GitHub API as data: nothing from
 * the PR is checked out, installed or run. It writes those files under
 * <out-dir>/files, runs this checkout's Penthera (repo and agents scans) on
 * them, and writes <out-dir>/triage.json and <out-dir>/comment.md. A PR that
 * touches CI, install or agent config gets `needs-maintainer-review`; any
 * other gets `standard-paths`. Needs `gh` with GH_TOKEN (read-only is enough).
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const MAX_FILES = 100;
const MAX_BYTES = 512 * 1024;

/** Agent config: skills, MCP servers, hooks and instruction files. */
const AGENT = /(^|\/)(\.claude|\.cursor|\.codex|skills)\/|(^|\/)\.mcp\.json$|(^|\/)(CLAUDE|AGENTS)\.md$/;

/** Paths that can change what runs in CI, on install or in an agent session. */
const SENSITIVE = [
  /^\.github\//,
  /(^|\/)package(-lock)?\.json$/,
  /(^|\/)npm-shrinkwrap\.json$/,
  /(^|\/)\.npmrc$/,
  /(^|\/)scripts\//,
  /^bin\//,
  /(^|\/)Dockerfile$/,
  /^\.husky\//,
  /^action\.ya?ml$/,
  /(^|\/)(vitest|eslint|rolldown)\.config\./,
  /^\.vscode\//,
  AGENT,
];

/**
 * Files our workflows run directly (`bash x.sh`, `node scripts/x.mjs`),
 * read from the base branch, so a new one is covered without editing SENSITIVE.
 */
export function workflowRunPaths(yamlTexts) {
  const out = new Set();
  for (const text of yamlTexts) {
    for (const m of text.matchAll(/\b(?:bash|sh|node|python3?)\s+(?:-\S+\s+)*([\w./-]+\.(?:sh|m?js|cjs|py))\b/g)) {
      out.add(m[1].replace(/^\.\//, ""));
    }
  }
  return out;
}

/** Which of the changed paths are sensitive. */
export function sensitivePaths(paths, runPaths = new Set()) {
  return paths.filter((p) => runPaths.has(p) || SENSITIVE.some((re) => re.test(p)));
}

function baseWorkflows() {
  const dir = join(ROOT, ".github", "workflows");
  try {
    return readdirSync(dir).filter((f) => /\.ya?ml$/.test(f)).map((f) => readFileSync(join(dir, f), "utf-8"));
  } catch {
    return [];
  }
}

/** A changed path is written only if it stays inside the output folder. */
export function safeRelative(p) {
  const n = normalize(p);
  return !n.startsWith("..") && !n.startsWith("/") && !n.includes("\0");
}

const gh = (...args) => execFileSync("gh", args, { encoding: "utf-8", maxBuffer: 64 * 1024 * 1024 });

function penthera(args) {
  try {
    return execFileSync(process.execPath, [join(ROOT, "bin", "penthera.js"), ...args, "--brief"], {
      encoding: "utf-8",
      env: { ...process.env, PENTHERA_NO_ONBOARDING: "1", NO_COLOR: "1" },
      timeout: 120_000,
    });
  } catch (e) {
    return e.stdout || `Penthera stopped: ${e.message.split("\n")[0]}`;
  }
}

/** Keep quoted file text from pinging people or closing our code block. */
const tidy = (s) => s.replace(/@(?=\w)/g, "@​").replace(/```/g, "'''").slice(0, 6000);

async function main() {
  const [repo, pr, out] = process.argv.slice(2);
  if (!repo || !/^\d+$/.test(pr || "") || !out) {
    console.error("usage: pr-triage.mjs <owner/repo> <pr-number> <out-dir>");
    process.exit(2);
  }
  const info = JSON.parse(gh("api", `repos/${repo}/pulls/${pr}`));
  const head = info.head.sha;
  const files = JSON.parse(gh("api", "--paginate", "--slurp", `repos/${repo}/pulls/${pr}/files?per_page=100`)).flat();
  const changed = files.filter((f) => f.status !== "removed").map((f) => f.filename);
  const sensitive = sensitivePaths(files.map((f) => f.filename), workflowRunPaths(baseWorkflows()));

  const dir = join(out, "files");
  mkdirSync(dir, { recursive: true });
  let written = 0;
  const skipped = [];
  for (const path of changed.slice(0, MAX_FILES)) {
    if (!safeRelative(path)) { skipped.push(path); continue; }
    try {
      const body = execFileSync("gh", ["api", "-H", "Accept: application/vnd.github.raw", `repos/${info.head.repo.full_name}/contents/${encodeURI(path)}?ref=${head}`], { maxBuffer: MAX_BYTES * 2 });
      if (body.length > MAX_BYTES || body.includes(0)) { skipped.push(path); continue; }
      mkdirSync(dirname(join(dir, path)), { recursive: true });
      writeFileSync(join(dir, path), body);
      written++;
    } catch {
      skipped.push(path);
    }
  }
  if (changed.length > MAX_FILES) skipped.push(`${changed.length - MAX_FILES} more files`);

  // The brief's "Next" section suggests commands for a local repo; it doesn't apply here.
  const brief = (args) => penthera(args).split(/\n### Next\b/)[0].replaceAll(dir, "<changed files>");
  const repoBrief = brief(["--repo", dir, "--no-library"]);
  const agentFiles = changed.some((p) => AGENT.test(p));
  const agentsBrief = agentFiles ? brief(["agents", dir]) : "";
  const label = sensitive.length ? "needs-maintainer-review" : "standard-paths";

  const comment = [
    "<!-- penthera-triage -->",
    "## Checked by Penthera before CI",
    "",
    `**${label === "standard-paths" ? "Standard paths" : "Needs maintainer review"}.** ${written} changed file${written === 1 ? "" : "s"} read as data at \`${head.slice(0, 7)}\`. Nothing from this PR was installed or run.${label === "standard-paths" ? " No CI, install or agent files changed; source and tests still run in CI once approved, so read the diff." : ""}`,
    sensitive.length ? `\nThis PR touches files that change what CI, an install or an agent runs:\n${sensitive.slice(0, 20).map((p) => `- \`${tidy(p)}\``).join("\n")}` : "",
    skipped.length ? `\nNot read: ${skipped.slice(0, 10).map((p) => `\`${tidy(p)}\``).join(", ")}.` : "",
    "",
    "<details><summary>Penthera on the changed files</summary>",
    "",
    "```",
    tidy(repoBrief.trim()),
    "```",
    ...(agentsBrief ? ["", "```", tidy(agentsBrief.trim()), "```"] : []),
    "</details>",
    "",
    "<sub>Static checks on the changed files only, with this repository's own Penthera. A maintainer approves CI after reading this.</sub>",
  ].join("\n");

  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, "triage.json"), JSON.stringify({ pr: Number(pr), head, label, sensitive, written, skipped }, null, 2));
  writeFileSync(join(out, "comment.md"), comment);
  console.log(`PR ${pr}: ${label}, ${written} files read, ${sensitive.length} sensitive.`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
