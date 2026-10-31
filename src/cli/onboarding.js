/**
 * PostHog-style interactive onboarding, simple defaults, advanced hidden.
 *
 * `penthera` (no arguments, in a terminal) and `penthera init` run the setup
 * wizard: detect what the project has, ask what to check, run it offline, show
 * one summary, then offer the hook, the GitHub workflow, .gitignore, the fix
 * loop and the dashboard, each a yes/no. Nothing is committed or pushed, and
 * nothing is written outside the project. `penthera-scan` keeps the URL-first
 * wizard (runScanWizard).
 */
import { existsSync, mkdirSync, writeFileSync, appendFileSync, lstatSync, realpathSync } from "node:fs";
import { resolve, join, relative, isAbsolute, sep, dirname } from "node:path";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { initPrompt, closePrompt, ask, choose, confirm, checklist, normalizeUrlInput } from "./prompt.js";
import { banner, logo, box, bold, dim, cyan, green, yellow, red, hr, brand } from "./ansi.js";
import { executeScan, writeScanReports } from "./run-scan.js";
import { confirmActiveScan } from "./active-gate.js";
import { detectProject, portsFromEnv } from "./detect.js";
import { mdInline } from "../report/md-escape.js";
import { mergeResults } from "./merge-results.js";
import { resolveLicensePolicy } from "./deps.js";
import { isPrivateHost } from "../utils/url.js";
import { printError, writeJsonReport } from "../reporter.js";
import { writeMarkdownReport } from "../report/markdown.js";
import { buildActionPlan } from "../../lib/remediation/index.js";
import { gradeFindings } from "../../lib/agents/grade.js";
import { uncheckedDeps } from "../../lib/deps/report.js";
import { installHook } from "../../lib/hook/index.js";

const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf-8"));

function countFindings(findings) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings || []) c[f.severity] = (c[f.severity] || 0) + 1;
  return c;
}

function summarize(findings) {
  const c = countFindings(findings);
  const parts = [];
  if (c.critical) parts.push(`${c.critical} critical`);
  if (c.high) parts.push(`${c.high} high`);
  if (c.medium) parts.push(`${c.medium} medium`);
  if (c.low) parts.push(`${c.low} low`);
  if (parts.length === 0) return green("No issues found, looking good!");
  return yellow(parts.join(" · "));
}

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function topFindings(findings, limit = 3) {
  return [...(findings || [])]
    .filter((f) => f.severity !== "info")
    .sort((a, b) => (SEV_RANK[a.severity] ?? 5) - (SEV_RANK[b.severity] ?? 5))
    .slice(0, limit);
}

function printTopFixes(findings) {
  const top = topFindings(findings);
  if (top.length === 0) return;
  process.stdout.write(`\n  ${bold("Start here")}\n`);
  top.forEach((f, i) => {
    process.stdout.write(`  ${i + 1}. ${f.title} ${dim(`(${f.severity})`)}\n`);
  });
}

async function runSimpleScan(config) {
  process.stdout.write(`\n  ${dim("Scanning")}${dim("...")}\n\n`);
  const result = await executeScan({ ...config, version: pkg.version });
  const paths = writeScanReports(
    { merged: result.merged },
    result.paths,
    result.mdOpts,
    { verbose: false, quiet: true, writeSarif: true },
  );
  return { ...result, paths };
}

/** The CLI's active-scan gate, asked through the wizard's prompt. */
function confirmWizardActive(url, modes) {
  return confirmActiveScan({
    url, modes, interactive: true, ask,
    write: (t) => process.stdout.write(t),
  });
}

function printScanFailure(url, err) {
  if (/unreachable/i.test(err.message)) {
    printError(`Couldn't reach ${url}. Is your app running?`);
    process.stdout.write(
      `\n  ${dim("Tip:")} start your dev server, then run ${bold("penthera")} again.\n\n`,
    );
    return;
  }
  printError(err.message);
}

/** `penthera-scan`: the URL-first wizard (asks for a URL, scans it, offers a deeper scan). */
export async function runScanWizard() {
  await initPrompt();

  process.stdout.write(banner());
  process.stdout.write(box("Welcome", [
    "Shipped something you vibecoded? Pressure-test it before attackers do.",
    "Penthera checks your live app + repo for the gaps that get apps owned, ",
    "exposed APIs, missing headers, weak auth, leaked secrets.",
    "",
    dim("Only scan apps you own or have permission to test."),
  ]));
  process.stdout.write(
    `  ${dim("Expert?")} ${dim("skip the wizard with")} ${brand("penthera <url> --profile deep")} ${dim("· see")} ${brand("penthera --help")}\n\n`,
  );

  // ── Step 1: URL (required) ─────────────────────────────────────────────
  process.stdout.write(`  ${bold("Step 1")}  ${dim("Where is your app running?")}\n\n`);
  const urlRaw = await ask(`  ${cyan(">")} URL ${dim("(e.g. https://myapp.com or localhost:3000)")}: `);
  const url = normalizeUrlInput(urlRaw);

  if (!url) {
    printError("A URL is required. Example: localhost:3000 or https://staging.myapp.com");
    closePrompt();
    process.exit(2);
  }

  // ── Step 2: Source code (optional, default yes if package.json) ────────
  const hasProject = existsSync(resolve("package.json"));
  let repo = null;

  if (hasProject) {
    process.stdout.write(`\n  ${bold("Step 2")}  ${dim("Scan your source code too?")}\n`);
    process.stdout.write(`  ${dim("Finds hardcoded secrets and risky API routes in this folder.")}\n\n`);
    const scanRepo = await confirm(`  ${cyan(">")} Scan ./`, true);
    if (scanRepo) repo = ".";
  } else {
    process.stdout.write(`\n  ${dim("Step 2 skipped, no package.json in current folder.")}\n`);
  }

  // ── Permission check for remote targets ────────────────────────────────
  if (!isPrivateHost(url)) {
    process.stdout.write(`\n  ${yellow("Note")}  ${dim("We'll send safe checks to")} ${cyan(url)}\n`);
    process.stdout.write(`  ${dim("No attack payloads in the default scan.")}\n\n`);
    // Default to "no": for a security tool the safe default is to not scan a
    // remote host unless the user explicitly affirms authorization.
    const ok = await confirm(`  ${cyan(">")} You have permission to scan this URL`, false);
    if (!ok) {
      process.stdout.write(`\n  ${dim("Aborted.")}\n\n`);
      closePrompt();
      process.exit(0);
    }
  }

  closePrompt();

  // ── Run default scan (standard profile) ────────────────────────────────
  let scanResult;
  try {
    scanResult = await runSimpleScan({ url, repo, profile: "standard" });
  } catch (e) {
    printScanFailure(url, e);
    process.exit(2);
  }

  const { merged, paths, hasSevere } = scanResult;

  process.stdout.write(`\n  ${hr()}\n`);
  process.stdout.write(`  ${green("Done!")}  ${summarize(merged.findings)}\n`);
  printTopFixes(merged.findings);
  process.stdout.write(`\n  ${bold("Read your report")}\n`);
  process.stdout.write(`  ${cyan(paths.markdown)}  ${dim("← start here (plain English)")}\n`);
  process.stdout.write(`  ${dim(paths.json)}  ${dim("(machine-readable)")}\n`);
  process.stdout.write(`\n  ${hr()}\n`);

  // ── Post-scan menu (re-open prompt) ────────────────────────────────────
  await initPrompt();

  const next = await choose("What next?", [
    { id: "done", label: "Looks good, I'm done" },
    { id: "deeper", label: "Run a deeper scan (sends test payloads, needs permission)" },
    { id: "custom", label: "Custom setup (profiles, auth tokens, advanced flags)" },
  ]);

  if (next === "done") {
    closePrompt();
    process.stdout.write(`\n  ${dim("Tip:")} re-run anytime with ${bold("penthera")} or ${bold("penthera <url>")}\n\n`);
    process.exit(hasSevere ? 1 : 0);
  }

  if (next === "deeper") {
    process.stdout.write(`\n  ${yellow("Deep scan")} sends SQLi, XSS, and fuzz payloads.\n`);
    const consent = await confirmWizardActive(url, ["deep", "fuzz"]);
    closePrompt();
    if (!consent.ok) {
      process.stdout.write(`\n  ${dim("Skipped deep scan.")}\n\n`);
      process.exit(hasSevere ? 1 : 0);
    }

    try {
      const deep = await runSimpleScan({ url, repo, profile: "deep", activeConfirmed: true });
      process.stdout.write(`\n  ${green("Deep scan complete.")}  ${summarize(deep.merged.findings)}\n`);
      process.stdout.write(`  ${cyan(deep.paths.markdown)}\n\n`);
      process.exit(deep.hasSevere ? 1 : 0);
    } catch (e) {
      printScanFailure(url, e);
      process.exit(2);
    }
  }

  // ── Custom setup (hidden power-user path) ──────────────────────────────
  process.stdout.write(box("Custom setup", [
    "Power-user options. Most people never need this.",
    dim("Press enter to keep defaults shown in [brackets]."),
  ]));

  const profileAns = await ask(`  Profile ${dim("[standard]")} quick | standard | deep: `);
  const profile = ["quick", "standard", "deep"].includes(profileAns) ? profileAns : "standard";

  const repoAns = await ask(`  Repo path ${dim("[.]")}: `);
  const customRepo = repoAns || repo || null;

  const bearer = await ask(`  Bearer token ${dim("(optional, for logged-in routes)")}: `);
  const cookie = await ask(`  Session cookie ${dim("(optional)")}: `);

  const customUrl = await ask(`  URL ${dim(`[${url}]`)}: `);
  const target = normalizeUrlInput(customUrl) || url;
  let activeConfirmed = false;
  if (profile === "deep") {
    const consent = await confirmWizardActive(target, ["deep", "fuzz"]);
    if (!consent.ok) {
      closePrompt();
      process.stdout.write(`\n  ${dim("Skipped deep scan.")}\n\n`);
      process.exit(0);
    }
    activeConfirmed = true;
  }
  closePrompt();

  try {
    const custom = await runSimpleScan({
      url: target,
      repo: customRepo,
      profile,
      activeConfirmed,
      authBearer: bearer || null,
      authCookie: cookie || null,
    });
    process.stdout.write(`\n  ${green("Custom scan complete.")}  ${summarize(custom.merged.findings)}\n`);
    process.stdout.write(`  ${cyan(custom.paths.markdown)}\n\n`);
    process.stdout.write(`  ${dim("Expert mode:")} penthera --help\n\n`);
    process.exit(custom.hasSevere ? 1 : 0);
  } catch (e) {
    printScanFailure(target, e);
    process.exit(2);
  }
}

// ── `penthera init`: the setup wizard ─────────────────────────────────────

/**
 * The release the generated workflow pins, by commit SHA: the newest stable
 * release before this version. Update after each release is tagged:
 * git rev-parse vX.Y.Z^{commit}. tests/init.test.js fails when it falls behind.
 */
export const ACTION_PIN = Object.freeze({ tag: "v2.1.1", sha: "4dc8ac8f84985bf694ccee750bb4cdb67a0458f2" });

export const WORKFLOW_PATH = ".github/workflows/penthera.yml";
export const AGENTS_WORKFLOW_PATH = ".github/workflows/penthera-agents.yml";
const BIN = fileURLToPath(new URL("../../bin/penthera.js", import.meta.url));
const WORKFLOW_EXAMPLE = new URL("../../docs/examples/pr-dependency-review.yml", import.meta.url);
const AGENTS_WORKFLOW_EXAMPLE = new URL("../../docs/examples/github-actions-agents.yml", import.meta.url);

const INIT_HELP = `
  ${bold("penthera init")} — set up Penthera in this project in one command

  ${dim("Usage")}
    $ penthera                 In a terminal with no arguments: the same wizard
    $ penthera init            Detect, ask what to check, run it, offer setup steps
    $ penthera init --yes      Accept every safe default, ask nothing
    $ penthera init --dry-run  Show what would run and be written; change nothing

  ${dim("Options")}
    -y, --yes        Non-interactive. Runs the code, dependency and AI tooling checks
                     that apply, offline. Never scans a URL, never runs the fix loop,
                     never opens the dashboard
        --dry-run    Print the checks and file writes instead of doing them
    -h, --help       Show this help

  Reports go to reports/penthera-<date>/. The hook goes in .git/hooks, the workflows
  in ${WORKFLOW_PATH} and ${AGENTS_WORKFLOW_PATH}, and nothing is committed or pushed.
`;

const AREAS = {
  code: { label: "Code", cmd: (c) => `penthera --repo .${c.offline ? " --offline" : ""}` },
  deps: { label: "Dependencies", cmd: (c) => `penthera deps${c.offline ? "" : " --online"}` },
  agents: { label: "AI tooling", cmd: (c) => `penthera agents${c.home ? " --home" : ""}` },
  app: { label: "Running app", cmd: (c) => `penthera ${c.url}${c.offline ? " --offline" : ""}` },
};
const EFFORT_RANK = { quick: 0, moderate: 1, significant: 2 };

const noop = () => {};
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;
const out = (s = "") => process.stdout.write(s + "\n");

/** Local calendar date, YYYY-MM-DD: one report folder per day. */
function today(now = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  return `${now.getFullYear()}-${p(now.getMonth() + 1)}-${p(now.getDate())}`;
}

/**
 * Refuse any write that would land outside the project root. Both sides are
 * resolved first, so a root in another spelling (git prints D:/a/app on
 * Windows) still compares equal. `p` is the path module (path.win32 in tests).
 */
/**
 * Is anything at `p`, a dangling symlink included? existsSync follows the
 * link and says no for a dangling one, and a write would then create the
 * link's target wherever it points.
 */
export function entryExists(p) {
  try { lstatSync(p); return true; } catch { return false; }
}

/** Is `p` a symlink (dangling or not)? */
function isSymlink(p) {
  try { return lstatSync(p).isSymbolicLink(); } catch { return false; }
}

/**
 * Create a new file inside the project: never through a symlink (a dangling
 * one included, `wx` refuses any existing entry) and never into a folder that
 * resolves outside the project. Returns an error message, or null when written.
 */
export function writeNewFile(root, full, content) {
  const OUTSIDE = "its folder resolves outside the project";
  try {
    const realRoot = realpathSync(root);
    const within = (d) => d === realRoot || d.startsWith(realRoot.endsWith(sep) ? realRoot : realRoot + sep);
    // Check the nearest folder that already exists (a symlink counts, even a
    // dangling one) before creating anything, so a `.github` symlink to
    // another place never gets a `workflows` folder made inside it.
    let existing = dirname(full);
    while (!entryExists(existing) && dirname(existing) !== existing) existing = dirname(existing);
    let realExisting;
    try { realExisting = realpathSync(existing); } catch { return OUTSIDE; }
    if (!within(realExisting)) return OUTSIDE;
    mkdirSync(dirname(full), { recursive: true });
    if (!within(realpathSync(dirname(full)))) return OUTSIDE;
    writeFileSync(full, content, { flag: "wx" });
    return null;
  } catch (e) {
    return e?.code === "EEXIST" ? "a file or symlink is already there" : String(e?.message || e);
  }
}

export function inside(root, path, p = { resolve, relative, isAbsolute, sep }) {
  const base = p.resolve(root);
  const full = p.resolve(base, path);
  const rel = p.relative(base, full);
  if (rel === ".." || rel.startsWith(`..${p.sep}`) || p.isAbsolute(rel)) throw new Error(`Refusing to write outside the project: ${full}`);
  return full;
}

function countLine(findings, un = null) {
  if (un?.nothing) return "nothing found to assess";
  if (un?.none) return `not checked: 0 of ${un.total} packages installed or cached`;
  const c = countFindings(findings);
  const parts = ["critical", "high", "medium", "low"].filter((s) => c[s]).map((s) => `${c[s]} ${s}`);
  const line = parts.length ? parts.join(" · ") : "no issues";
  return un ? `${line} in what was read, ${un.missing} of ${un.total} packages not read` : line;
}

/** A grade for what was read; "–" when nothing was, so nothing unread reads as an A. */
function gradeArea(r) {
  Object.assign(r, gradeFindings(r.merged.findings));
  r.unchecked = r.merged.agents?.grade === null
    ? { none: true, nothing: true, what: "No agent config at the paths Penthera reads, so there is nothing to grade.", fix: "If this project uses AI tooling, its config sits somewhere Penthera does not read yet." }
    : uncheckedDeps(r.merged.deps);
  if (r.unchecked?.none) Object.assign(r, { grade: "–", score: null });
}

/** Word-wrap `text` to the terminal (max 80 columns), each line prefixed by `indent`. */
function wrap(text, indent) {
  const width = Math.min(process.stdout.columns || 80, 80) - indent.length;
  const lines = [];
  let line = "";
  for (const word of text.split(/\s+/)) {
    if (line && line.length + 1 + word.length > width) { lines.push(line); line = word; }
    else line = line ? `${line} ${word}` : word;
  }
  if (line) lines.push(line);
  return lines.map((l) => indent + l).join("\n");
}

function gradeColor(g) {
  return g === "A" ? green(g) : g === "B" || g === "C" || g === "–" ? yellow(g) : red(g);
}

/** The generated workflow: the PR dependency review example, pinned to ACTION_PIN. */
export function workflowYaml(pin = ACTION_PIN) {
  const example = readFileSync(WORKFLOW_EXAMPLE, "utf-8");
  const body = example.slice(example.indexOf("\nname:") + 1);
  const pinned = body.replace(/danoszz\/penthera@[0-9a-f]{40} # .*$/m, `danoszz/penthera@${pin.sha} # ${pin.tag}`);
  if (pinned === body) throw new Error("docs/examples/pr-dependency-review.yml no longer has a pinned `uses: danoszz/penthera@<sha>` line");
  return [
    "# Added by `penthera init`. Review it, then commit it yourself.",
    "#",
    "# Comments a dependency capability diff on every PR that changes the lockfile",
    "# (new packages, or packages that gained network, shell, install-script or",
    "# dynamic-code capabilities) and uploads SARIF to code scanning. Penthera runs",
    "# offline from the action's own checkout. The action is pinned to the",
    `# ${pin.tag} release commit. Do not switch this to \`pull_request_target\`: that`,
    "# would run with write access next to untrusted code.",
    "",
    pinned,
  ].join("\n");
}

/** The generated agent config workflow: the agents example, pinned to ACTION_PIN's npm version. */
export function agentsWorkflowYaml(pin = ACTION_PIN) {
  const example = readFileSync(AGENTS_WORKFLOW_EXAMPLE, "utf-8");
  const body = example.slice(example.indexOf("\nname:") + 1);
  const version = pin.tag.replace(/^v/, "");
  const pinned = body.replace(/npx --yes penthera@\d+\.\d+\.\d+ agents/, `npx --yes penthera@${version} agents`);
  if (pinned === body && !body.includes(`npx --yes penthera@${version} agents`)) {
    throw new Error("docs/examples/github-actions-agents.yml no longer runs `npx --yes penthera@<version> agents`");
  }
  return [
    "# Added by `penthera init`. Review it, then commit it yourself.",
    "#",
    "# Checks the repo's skills, MCP servers, hooks and agent instructions on every",
    "# pull request and push to main, offline, and uploads SARIF to code scanning.",
    `# Report-only. \`npx\` fetches Penthera ${version} from npm, from the runner's`,
    "# temp folder. Do not switch this to `pull_request_target`: that would run with",
    "# write access next to untrusted code.",
    "",
    pinned,
  ].join("\n");
}

/** Whether a Penthera workflow under .github/workflows already runs the agents check. */
function hasAgentsWorkflow(root, workflows) {
  return workflows.some((f) => {
    try { return /penthera@\S+\s+agents\b|penthera\.js\s+agents\b|mode:\s*["']?agents\b/.test(readFileSync(join(root, f), "utf-8")); } catch { return false; }
  });
}

/** A new-file unified diff, for showing the workflow before it is written. */
export function newFileDiff(path, content) {
  const lines = content.replace(/\n$/, "").split("\n");
  return [dim("--- /dev/null"), dim(`+++ b/${path}`), dim(`@@ -0,0 +1,${lines.length} @@`), ...lines.map((l) => green(`+${l}`))].join("\n");
}

/** The checklist offered after detection, with defaults from what was found. */
export function checkItems(found) {
  const items = [
    { id: "code", label: "Code: secrets and risky API routes in ./", hint: "penthera --repo .", checked: found.code || found.git },
    { id: "deps", label: "Dependencies: what your npm and Python packages can do", hint: "penthera deps", checked: found.lockfiles.npm.length + found.lockfiles.python.length > 0 },
    { id: "agents", label: "AI tooling: skills, MCP servers, hooks, agent instructions", hint: "penthera agents", checked: found.agentConfig.length > 0 },
  ];
  if (found.devServer) items.push({ id: "app", label: `The running app at ${found.devServer}`, hint: "only if it is yours", checked: false });
  items.push({ id: "offline", label: "Offline mode: nothing leaves this machine", hint: "recommended", checked: true });
  return items;
}

function printFound(f, cwd) {
  const yes = (s) => `${green("✓")} ${s}`;
  const no = (s) => `${dim("·")} ${dim(s)}`;
  const rel = relative(cwd, f.root) || ".";
  out(`  ${bold("Found")}  ${dim(rel === "." ? "in this folder" : `in ${rel}`)}`);
  out(`    ${f.git ? yes(`git repository${f.branch ? ` (branch ${f.branch})` : ""}`) : no("not a git repository (hook and workflow steps are skipped)")}`);
  out(`    ${f.framework ? yes(`framework: ${f.framework}`) : no("no web framework detected")}`);
  const locks = [...f.lockfiles.npm, ...f.lockfiles.python];
  out(`    ${locks.length ? yes(`lockfiles: ${locks.join(", ")}`) : no("no npm or Python lockfile")}`);
  out(`    ${f.agentConfig.length ? yes(`agent config: ${f.agentConfig.join(", ")}`) : no("no agent config (.mcp.json, .claude/, .cursor/, CLAUDE.md, AGENTS.md, skills/)")}`);
  out(`    ${f.devServer ? yes(`dev server: ${f.devServer}`) : no("no dev server on localhost:3000, 5173, 8000 or 8080")}`);
  if (f.git) out(`    ${f.hook ? yes("Penthera pre-commit hook installed") : no("no Penthera pre-commit hook")}`);
  out(`    ${f.workflows.length ? yes(`Penthera workflow: ${f.workflows.join(", ")}`) : no("no Penthera GitHub workflow")}`);
  out();
}

/** Run one check and return its merged result (findings + actionPlan). */
async function runCheck(id, ctx) {
  const { root, offline, version } = ctx;
  if (id === "code") return (await executeScan({ repo: root, offline, json: true, version, onPhase: noop })).merged;
  if (id === "app") return (await executeScan({ url: ctx.url, offline, json: true, version, onPhase: noop })).merged;
  let result;
  if (id === "deps") {
    const { scanDeps } = await import("../../lib/deps/index.js");
    result = await scanDeps(root, { licensePolicy: await resolveLicensePolicy(root), online: !offline, onPhase: noop });
  } else {
    const { scanAgents } = await import("../../lib/agents/index.js");
    result = await scanAgents(root, { home: ctx.home, onPhase: noop });
  }
  const merged = mergeResults([result]);
  merged.actionPlan = buildActionPlan(merged.findings);
  return merged;
}

/** The three actions to do first, across every area. */
export function fixFirst(results, limit = 3) {
  const SEV = { critical: 0, high: 1, medium: 2, low: 3 };
  return results
    .flatMap((r) => (r.merged?.actionPlan || []).map((a) => ({ ...a, area: r.label })))
    .sort((a, b) => (SEV[a.severity] ?? 5) - (SEV[b.severity] ?? 5) || (EFFORT_RANK[a.effort] ?? 3) - (EFFORT_RANK[b.effort] ?? 3))
    .slice(0, limit)
    .map((a) => ({ action: a.action, area: a.area, severity: a.severity, why: (a.why || "").split(/(?<=\.)\s/)[0], findings: a.findings.length }));
}

function summaryMarkdown(results, top, ctx) {
  const L = [`# Penthera summary, ${ctx.date}`, "", `Penthera ${ctx.version}, ${ctx.offline ? "offline" : "online"}.`, "", "| Area | Grade | Findings | Report |", "| --- | --- | --- | --- |"];
  for (const r of results) {
    L.push(r.error
      ? `| ${r.label} | n/a | could not run: ${mdInline(r.error)} | |`
      : `| ${mdInline(r.label)} | ${r.grade} | ${countLine(r.merged.findings, r.unchecked)} | [${r.id}.md](${r.id}.md) |`);
  }
  if (top.length) {
    L.push("", "## Fix first", "");
    top.forEach((a, i) => L.push(`${i + 1}. **${mdInline(a.action)}** (${mdInline(a.area)}, ${a.severity}). ${mdInline(a.why)}`));
  }
  L.push("", "## Rerun", "", ...results.map((r) => `- ${r.label}: \`${r.command}\``), "");
  return L.join("\n");
}

/**
 * `penthera init [--yes] [--dry-run]`.
 * @returns {Promise<number>} exit code: 0 done, 2 bad usage
 */
export async function runInit(argv, { version = pkg.version } = {}) {
  let opts;
  try {
    opts = parseArgs({
      args: argv,
      allowPositionals: false,
      options: {
        yes: { type: "boolean", short: "y", default: false },
        "dry-run": { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
    }).values;
  } catch (e) {
    printError(e.message);
    return 2;
  }
  if (opts.help) { console.log(INIT_HELP); return 0; }

  const auto = opts.yes;
  const dry = opts["dry-run"];
  const cwd = process.cwd();
  if (!auto) await initPrompt();
  const yesNo = (q, def) => (auto ? Promise.resolve(def) : confirm(`  ${cyan(">")} ${q}`, def));

  out(logo("set up Penthera in this project: detect, check, set up"));
  if (dry) out(`  ${yellow("Dry run")}  ${dim("nothing is scanned, written or started.")}\n`);
  if (auto) out(`  ${dim("--yes: accepting the safe defaults. No URL scan, no fix loop, no dashboard.")}\n`);

  // ── 1. Detect ──────────────────────────────────────────────────────────
  const found = await detectProject(cwd, { ports: portsFromEnv() });
  const root = found.root;
  printFound(found, cwd);

  // ── 2. What to check ───────────────────────────────────────────────────
  const items = checkItems(found);
  let picked;
  if (auto) {
    picked = new Set(items.filter((i) => i.checked && i.id !== "app").map((i) => i.id));
  } else {
    picked = await checklist(bold("What should Penthera check?"), items);
    out();
  }
  const ctx = { root, version, offline: picked.has("offline"), home: false, url: null, date: today() };
  if (picked.has("agents") && !auto) {
    ctx.home = await yesNo("Also check ~/.claude and ~/.cursor (your user-level agent config)?", false);
  }
  if (picked.has("app")) {
    out(`  ${yellow("Note")}  ${dim("The app check sends safe requests (no attack payloads) to")} ${cyan(found.devServer)}`);
    const owned = await yesNo(`Is ${found.devServer} your app (you own it or may test it)?`, false);
    if (owned) ctx.url = found.devServer;
    else { picked.delete("app"); out(`  ${dim("Skipping the app check.")}`); }
  }
  const checks = ["code", "deps", "agents", "app"].filter((id) => picked.has(id));
  const dir = inside(root, join("reports", `penthera-${ctx.date}`));
  const relDir = relative(cwd, dir) || ".";

  // ── 3. Run ─────────────────────────────────────────────────────────────
  const results = [];
  if (!checks.length) {
    out(`  ${dim("Nothing selected to check.")}`);
  } else if (dry) {
    out(`  ${bold("Would run")}  ${dim(ctx.offline ? "(offline)" : "(online)")}`);
    for (const id of checks) out(`    ${AREAS[id].label.padEnd(13)} ${cyan(AREAS[id].cmd(ctx))}  ${dim(`→ ${join(relDir, `${id}.json`)}, ${id}.md`)}`);
    out(`    ${"Summary".padEnd(13)} ${dim(`→ ${join(relDir, "summary.md")}, summary.json`)}`);
  } else {
    out(`  ${bold(`Running ${plural(checks.length, "check")}`)}  ${dim(ctx.offline ? "(offline)" : "(online)")}`);
    mkdirSync(dir, { recursive: true });
    for (const id of checks) {
      const label = AREAS[id].label;
      const r = { id, label, command: AREAS[id].cmd(ctx) };
      if (process.stdout.isTTY) process.stdout.write(`    ${dim("…")} ${label.padEnd(13)} ${dim(r.command)}`);
      const t0 = Date.now();
      try {
        r.merged = await runCheck(id, ctx);
        gradeArea(r);
        writeJsonReport(r.merged, join(dir, `${id}.json`));
        writeMarkdownReport(r.merged, join(dir, `${id}.md`), { version });
      } catch (e) {
        r.error = e.message.split("\n")[0];
      }
      const secs = dim(`${((Date.now() - t0) / 1000).toFixed(1)}s`);
      if (process.stdout.isTTY) process.stdout.write("\r\x1b[2K");
      out(r.error
        ? `    ${yellow("!")} ${label.padEnd(13)} ${dim("could not run:")} ${r.error}`
        : `    ${r.unchecked ? yellow("!") : green("✓")} ${label.padEnd(13)} ${gradeColor(r.grade)}  ${countLine(r.merged.findings, r.unchecked)}  ${secs}`);
      results.push(r);
    }

    const top = fixFirst(results);
    writeFileSync(join(dir, "summary.md"), summaryMarkdown(results, top, ctx));
    writeFileSync(join(dir, "summary.json"), JSON.stringify({
      generatedAt: new Date().toISOString(),
      version,
      offline: ctx.offline,
      checks: results.map((r) => ({
        id: r.id, label: r.label, command: r.command,
        ...(r.error ? { error: r.error } : { grade: r.grade, score: r.score, counts: countFindings(r.merged.findings), ...(r.unchecked && !r.unchecked.nothing ? { notRead: { packages: r.unchecked.missing, of: r.unchecked.total } } : {}), report: { json: `${r.id}.json`, markdown: `${r.id}.md` } }),
      })),
      fixFirst: top,
    }, null, 2) + "\n");

    out(`\n  ${hr()}`);
    out(`  ${bold("Summary")}`);
    for (const r of results) out(`    ${r.label.padEnd(13)} ${r.error ? dim("n/a") : `${gradeColor(r.grade)}  ${countLine(r.merged.findings, r.unchecked)}`}`);
    for (const r of results.filter((x) => x.unchecked)) out(`\n  ${yellow(r.label)}  ${r.unchecked.what}\n  ${dim(r.unchecked.fix)}`);
    if (top.length) {
      out(`\n  ${bold("Fix first")}`);
      top.forEach((a, i) => {
        out(`    ${i + 1}. ${a.action} ${dim(`(${a.area}, ${a.severity})`)}`);
        if (a.why) out(dim(wrap(a.why, "       ")));
      });
    } else if (results.some((r) => !r.error && !r.unchecked?.none)) {
      out(`\n  ${green("Nothing to fix first")} ${dim("in what was checked.")}`);
    }
    out(`\n  ${bold("Report")}  ${cyan(join(relDir, "summary.md"))}  ${dim(`(+ JSON and Markdown per area in ${relDir}/)`)}`);
    out(`  ${hr()}\n`);
  }

  // ── 4. Set up ──────────────────────────────────────────────────────────
  out(`  ${bold("Set up")}  ${dim(dry ? "(dry run: answers are shown, nothing is written)" : "nothing is committed or pushed")}`);
  const did = (s) => out(`    ${dry ? yellow("would") : green("✓")} ${s}`);
  const skip = (s) => out(`    ${dim("·")} ${dim(s)}`);

  // Pre-commit hook
  if (!found.git) skip("Pre-commit hook: not a git repository");
  else if (found.hook) skip("Pre-commit hook: already installed");
  else if (await yesNo("Install the pre-commit hook? It blocks staged secrets, risky agent config and lockfile changes", true)) {
    if (dry) did("install .git/hooks/pre-commit (penthera hook install)");
    else {
      try {
        const r = installHook(root);
        did(`Installed ${relative(cwd, r.path) || r.path}${r.chained ? dim(" (your existing hook runs first)") : ""}`);
      } catch (e) {
        out(`    ${yellow("!")} Hook not installed: ${e.message}`);
      }
    }
  }

  // GitHub workflow
  const wfFull = inside(root, WORKFLOW_PATH);
  if (!found.git) skip("GitHub workflow: not a git repository");
  else if (found.workflows.length) skip(`GitHub workflow: already present (${found.workflows.join(", ")})`);
  else if (entryExists(wfFull)) skip(`GitHub workflow: ${WORKFLOW_PATH} exists, left as is`);
  else if (!found.lockfiles.npm.length) skip("GitHub workflow: the PR dependency review reads package-lock.json, none here");
  else {
    const yaml = workflowYaml();
    out(`\n  ${dim(`The PR dependency review workflow, pinned to the ${ACTION_PIN.tag} release commit:`)}\n`);
    out(newFileDiff(WORKFLOW_PATH, yaml).split("\n").map((l) => `    ${l}`).join("\n"));
    out();
    if (await yesNo(`Write ${WORKFLOW_PATH}? It is not committed`, true)) {
      const err = dry ? null : writeNewFile(root, wfFull, yaml);
      if (err) skip(`${WORKFLOW_PATH}: not written, ${err}`);
      else did(`${dry ? "write " : "Wrote "}${WORKFLOW_PATH}${dry ? "" : dim(" (review and commit it yourself)")}`);
    }
  }

  // GitHub workflow: the agent config check
  const awFull = inside(root, AGENTS_WORKFLOW_PATH);
  if (!found.git) skip("Agent config workflow: not a git repository");
  else if (!found.agentConfig.length) skip("Agent config workflow: no agent config here");
  else if (hasAgentsWorkflow(root, found.workflows)) skip("Agent config workflow: already present");
  else if (entryExists(awFull)) skip(`Agent config workflow: ${AGENTS_WORKFLOW_PATH} exists, left as is`);
  else {
    const yaml = agentsWorkflowYaml();
    out(`\n  ${dim(`The agent config check on every pull request, Penthera ${ACTION_PIN.tag.slice(1)} from npm:`)}\n`);
    out(newFileDiff(AGENTS_WORKFLOW_PATH, yaml).split("\n").map((l) => `    ${l}`).join("\n"));
    out();
    if (await yesNo(`Write ${AGENTS_WORKFLOW_PATH}? It is not committed`, true)) {
      const err = dry ? null : writeNewFile(root, awFull, yaml);
      if (err) skip(`${AGENTS_WORKFLOW_PATH}: not written, ${err}`);
      else did(`${dry ? "write " : "Wrote "}${AGENTS_WORKFLOW_PATH}${dry ? "" : dim(" (review and commit it yourself)")}`);
    }
  }

  // .gitignore
  if (found.reportsIgnored) skip(".gitignore: reports/ is already ignored");
  else if (isSymlink(inside(root, ".gitignore"))) skip(".gitignore: it is a symlink, left as is");
  else if (await yesNo("Add reports/ to .gitignore so scan output is never committed?", true)) {
    if (!dry) {
      const gi = inside(root, ".gitignore");
      const prev = existsSync(gi) ? readFileSync(gi, "utf-8") : "";
      appendFileSync(gi, `${prev && !prev.endsWith("\n") ? "\n" : ""}${prev ? "\n" : ""}# Penthera scan reports\nreports/\n`);
    }
    did(`${dry ? "add" : "Added"} reports/ to .gitignore`);
  }

  // Fix loop (never in --yes)
  let loop = false;
  if (auto) skip("Fix loop: not run with --yes (penthera agent --loop)");
  else if (!found.git) skip("Fix loop: needs a git repository");
  else if (!picked.has("code")) skip("Fix loop: the code check was not selected");
  else loop = await yesNo("Run the fix loop now on a local branch? It shows each diff and asks before applying", false);
  if (loop) {
    if (dry) did("run penthera agent --loop (local branch penthera/fix-<date>, nothing pushed)");
    else {
      // The only uncommitted changes are ours (.gitignore, the workflow, reports/)
      // when the tree was clean; the loop never patches changed files.
      const args = [BIN, "agent", "--loop", "--repo", root, ...(found.clean && found.branch ? ["--allow-dirty"] : [])];
      out();
      closePrompt();
      // Ctrl-C belongs to the child while it runs.
      process.on("SIGINT", noop);
      spawnSync(process.execPath, args, { stdio: "inherit" });
      process.off("SIGINT", noop);
      await initPrompt();
    }
  }

  // Dashboard (never in --yes: it runs until Ctrl-C)
  let dashboard = false;
  if (auto) skip("Dashboard: not opened with --yes (penthera ui --open)");
  // Default yes only on a terminal: piped answers that run out must not start
  // something that runs until Ctrl-C (and opens a browser).
  else dashboard = await yesNo("Open the dashboard (penthera ui --open)?", process.stdin.isTTY === true);

  // ── 5. What next ───────────────────────────────────────────────────────
  out(`\n  ${bold("What next")}`);
  const next = [
    ["penthera", "this wizard again"],
    ...checks.map((id) => [AREAS[id].cmd(ctx), AREAS[id].label.toLowerCase()]),
    ...(found.git ? [["penthera hook run", "check what is staged now"], ["penthera agent --loop", "fix findings on a local branch"]] : []),
    ["penthera ui --open", "the dashboard"],
    ["penthera --help", "every command"],
  ];
  const w = Math.max(...next.map(([c]) => c.length));
  for (const [c, why] of next) out(`    ${cyan(c.padEnd(w))}  ${dim(why)}`);
  out();

  closePrompt();
  if (dashboard) {
    if (dry) did("start penthera ui --open (127.0.0.1 only)");
    else {
      process.on("SIGINT", noop);
      // The dashboard reads top-level report JSON, so point it at this run's folder.
      const reports = results.some((r) => !r.error) ? ["--reports", dir] : [];
      spawnSync(process.execPath, [BIN, "ui", "--open", "--project", root, ...reports], { stdio: "inherit" });
      process.off("SIGINT", noop);
    }
  }
  return 0;
}
