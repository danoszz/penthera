/**
 * Two Penthera checks per commit, instead of a long list of jobs.
 *
 *   node scripts/ci/penthera-checks.mjs <owner/repo> <head-sha>
 *
 * Reads every GitHub Actions job that ran on the commit, sorts them into
 * "Penthera: security" (triage, self-scan, dependency review, CodeQL) and
 * "Penthera: safe build" (tests, lint, provenance, install matrix, site), and
 * creates or updates one check run for each, with a table of what ran. It
 * reads results only; it never checks out or runs the commit's code.
 * Needs `gh` with GH_TOKEN allowed to write checks (the Penthera app's token).
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

/** Which summary a job belongs to, by its workflow and job name. */
export function groupOf(workflow, job) {
  if (/^(CodeQL|Dependency review|PR triage)$/.test(workflow)) return "security";
  if (workflow === "CI" && job === "scan") return "security";
  if (/^(CI|Install matrix)$/.test(workflow)) return "build";
  return null;
}

/** The check's state from its jobs: any still running wins, then any failure. */
export function summarize(jobs) {
  if (jobs.some((j) => j.status !== "completed")) return { status: "in_progress" };
  const failed = jobs.filter((j) => ["failure", "cancelled", "timed_out", "action_required"].includes(j.conclusion));
  return { status: "completed", conclusion: failed.length ? "failure" : "success", failed };
}

const ICON = { success: "✅", skipped: "➖", failure: "❌", cancelled: "⛔", timed_out: "⏱", neutral: "➖" };

export function table(jobs) {
  const rows = jobs.map((j) => `| ${j.status === "completed" ? (ICON[j.conclusion] || "•") : "⏳"} | ${j.workflow} | ${j.name.replace(/\|/g, "/")} |`);
  return ["| | Workflow | Job |", "|---|---|---|", ...rows].join("\n");
}

const NAMES = { security: "Penthera: security", build: "Penthera: safe build" };
const ABOUT = {
  security: "Checked by Penthera on this commit: the fork PR triage, Penthera's scan of itself, the dependency capability diff and CodeQL.",
  build: "Built and tested safely: tests on Node 22 and 24, lint, provenance and docs gates, the install matrix from the packed tarball, and the site build.",
};

const gh = (...args) => JSON.parse(execFileSync("gh", args, { encoding: "utf-8", maxBuffer: 32 * 1024 * 1024 }) || "null");

async function main() {
  const [repo, sha] = process.argv.slice(2);
  if (!repo || !/^[0-9a-f]{40}$/.test(sha || "")) {
    console.error("usage: penthera-checks.mjs <owner/repo> <head-sha>");
    process.exit(2);
  }
  const runs = gh("api", `repos/${repo}/actions/runs?head_sha=${sha}&per_page=100`).workflow_runs;
  // A workflow can run more than once on a commit (a re-run); keep the newest.
  const latest = new Map();
  for (const r of runs) if (!latest.has(r.name) || r.run_number > latest.get(r.name).run_number) latest.set(r.name, r);

  const groups = { security: [], build: [] };
  for (const run of latest.values()) {
    if (!/^(CI|Install matrix|CodeQL|Dependency review|PR triage)$/.test(run.name)) continue;
    const jobs = gh("api", `repos/${repo}/actions/runs/${run.id}/jobs?per_page=100`).jobs;
    for (const j of jobs) {
      const g = groupOf(run.name, j.name);
      if (g) groups[g].push({ workflow: run.name, name: j.name, status: j.status, conclusion: j.conclusion });
    }
  }

  const existing = gh("api", `repos/${repo}/commits/${sha}/check-runs?per_page=100`).check_runs;
  for (const key of ["security", "build"]) {
    const jobs = groups[key];
    if (!jobs.length) continue;
    const s = summarize(jobs);
    const summary = `${ABOUT[key]}\n\n${table(jobs)}`;
    const title = s.status !== "completed" ? "Running" : s.conclusion === "success" ? `All ${jobs.length} passed` : `${s.failed.length} of ${jobs.length} failed`;
    const body = { name: NAMES[key], status: s.status, output: { title, summary: summary.slice(0, 60000) } };
    if (s.conclusion) body.conclusion = s.conclusion;
    // Update our own earlier check: the app's, or the workflow token's (CHECK_APP_SLUG=github-actions) when it falls back.
    const own = process.env.CHECK_APP_SLUG;
    const prev = existing.find((c) => c.name === NAMES[key] && (own ? c.app?.slug === own : c.app?.slug !== "github-actions"));
    const input = JSON.stringify(prev ? body : { ...body, head_sha: sha });
    execFileSync("gh", ["api", "-X", prev ? "PATCH" : "POST", prev ? `repos/${repo}/check-runs/${prev.id}` : `repos/${repo}/check-runs`, "--input", "-"], { input, stdio: ["pipe", "ignore", "inherit"] });
    console.log(`${NAMES[key]}: ${title}`);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
