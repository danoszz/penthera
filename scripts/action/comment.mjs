#!/usr/bin/env node
/**
 * Helpers for the Penthera GitHub Action (action.yml at the repo root).
 *
 *   node scripts/action/comment.mjs comment --body-file <md> [--repo o/r] [--pr n]
 *   node scripts/action/comment.mjs gate --report <json> --fail-on none|high|critical
 *
 * `comment` upserts one PR comment identified by a hidden marker, so every push
 * updates the same comment instead of adding a new one. On fork PRs (read-only
 * token) it skips the comment cleanly. The body always goes to the job summary.
 *
 * The GitHub client is injected, so the body builder and the upsert logic are
 * unit-tested without GitHub (tests/action.test.js). The real client shells out
 * to `gh api` with the default GITHUB_TOKEN; nothing else is contacted.
 */
import { readFileSync, appendFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";

export const MARKER = "<!-- penthera-deps -->";
// GitHub rejects comment bodies over 65,536 characters.
export const MAX_BODY = 65536;

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/**
 * Build the final comment body from `penthera deps --pr-comment` output: the
 * marker first (exactly once), a short provenance line, and truncation that
 * keeps the result under GitHub's limit.
 */
export function buildCommentBody(markdown, { sha, runUrl, marker = MARKER, max = MAX_BODY } = {}) {
  let text = String(markdown ?? "").split(marker).join("").trim();
  if (!text) text = "## Dependency capability diff\n\nPenthera produced no output for this change.";
  const meta = [];
  if (sha) meta.push(`commit \`${String(sha).slice(0, 7)}\``);
  if (runUrl) meta.push(`[workflow run](${runUrl})`);
  const footer = meta.length ? `\n\n<sub>Updated for ${meta.join(" · ")}. This comment is edited in place on every push.</sub>` : "";
  const head = `${marker}\n`;
  const cut = "\n\n_…truncated. The full report is in the job summary and the SARIF upload._";
  const room = max - head.length - footer.length - 1; // trailing newline
  if (text.length > room) text = text.slice(0, Math.max(0, room - cut.length)) + cut;
  return `${head}${text}${footer}\n`;
}

/** The account GITHUB_TOKEN posts as. Only its comments are ever edited. */
export const ACTIONS_BOT = "github-actions[bot]";

/**
 * Create or update the single marker comment on an issue or PR.
 * @param {{ listComments(issue: number): Promise<Array<{id: number, body: string, login?: string, userType?: string}>>,
 *           createComment(issue: number, body: string): Promise<{id: number}>,
 *           updateComment(id: number, body: string): Promise<{id: number}> }} api
 * @returns {Promise<{ action: "created" | "updated" | "unchanged", id: number }>}
 */
export async function upsertComment(api, { issue, body, marker = MARKER, botLogin = ACTIONS_BOT }) {
  if (!body.includes(marker)) throw new Error("Comment body is missing the marker; refusing to post an untracked comment.");
  // Only our own comments count: a person, or another bot or app, quoting the
  // marker must not have its comment edited by us.
  const existing = (await api.listComments(issue)).find((c) =>
    typeof c.body === "string" && c.body.includes(marker) && c.login === botLogin && c.userType === "Bot");
  if (!existing) return { action: "created", id: (await api.createComment(issue, body)).id };
  if (existing.body === body) return { action: "unchanged", id: existing.id };
  return { action: "updated", id: (await api.updateComment(existing.id, body)).id };
}

/** True when the PR comes from a fork, where GITHUB_TOKEN is read-only. */
export function isForkPullRequest(event) {
  const pr = event?.pull_request;
  if (!pr) return false;
  const head = pr.head?.repo?.full_name;
  const base = pr.base?.repo?.full_name ?? event.repository?.full_name;
  return !head || !base || head !== base;
}

/** Findings at or above the fail-on threshold. "none" never fails. */
export function gate(findings, failOn = "none") {
  if (!["none", "high", "critical"].includes(failOn)) throw new Error(`fail-on must be none, high or critical, got: ${failOn}`);
  if (failOn === "none") return { fail: false, count: 0 };
  const min = SEVERITY_RANK[failOn];
  const count = (findings || []).filter((f) => (SEVERITY_RANK[f.severity] ?? 0) >= min).length;
  return { fail: count > 0, count };
}

/** API client backed by `gh api`; GH_TOKEN comes from the environment. */
export function ghClient(repo, { run = spawnSync } = {}) {
  const gh = (args, input) => {
    const r = run("gh", ["api", ...args], { encoding: "utf-8", input, maxBuffer: 64 * 1024 * 1024 });
    if (r.error) throw r.error;
    if (r.status !== 0) {
      const err = new Error(`gh api ${args[0]} failed: ${(r.stderr || r.stdout || "").trim()}`);
      err.forbidden = /\b(403|Resource not accessible)/i.test(`${r.stderr}${r.stdout}`);
      throw err;
    }
    return r.stdout;
  };
  return {
    async listComments(issue) {
      const out = gh(["--paginate", `repos/${repo}/issues/${issue}/comments?per_page=100`, "--jq", ".[] | {id, body, login: .user.login, userType: .user.type}"]);
      return out.split("\n").filter(Boolean).map((l) => JSON.parse(l));
    },
    async createComment(issue, body) {
      return JSON.parse(gh(["--method", "POST", `repos/${repo}/issues/${issue}/comments`, "--input", "-"], JSON.stringify({ body })));
    },
    async updateComment(id, body) {
      return JSON.parse(gh(["--method", "PATCH", `repos/${repo}/issues/comments/${id}`, "--input", "-"], JSON.stringify({ body })));
    },
  };
}

function readEvent(env) {
  try { return env.GITHUB_EVENT_PATH ? JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, "utf-8")) : {}; } catch { return {}; }
}

function setOutput(env, key, value) {
  if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, `${key}=${value}\n`);
}

export async function runComment(opts, env = process.env, api = null) {
  const event = readEvent(env);
  const repo = opts.repo || env.GITHUB_REPOSITORY;
  const issue = Number(opts.pr || event.pull_request?.number);
  const runUrl = env.GITHUB_RUN_ID ? `${env.GITHUB_SERVER_URL || "https://github.com"}/${repo}/actions/runs/${env.GITHUB_RUN_ID}` : null;
  const body = buildCommentBody(readFileSync(opts["body-file"], "utf-8"), {
    sha: event.pull_request?.head?.sha || env.GITHUB_SHA,
    runUrl,
  });
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, body.replace(MARKER, "").trimStart() + "\n");

  const skip = (why) => { console.log(`penthera: ${why}; the diff is in the job summary.`); setOutput(env, "comment-action", "skipped"); return { action: "skipped" }; };
  if (!issue) return skip("not a pull request, no comment posted");
  if (isForkPullRequest(event)) return skip("fork pull request (read-only token), comment skipped");
  try {
    const res = await upsertComment(api || ghClient(repo), { issue, body });
    console.log(`penthera: PR comment ${res.action} (id ${res.id})`);
    setOutput(env, "comment-action", res.action);
    setOutput(env, "comment-id", res.id);
    return res;
  } catch (e) {
    if (e.forbidden) return skip("token cannot write PR comments (grant pull-requests: write)");
    throw e;
  }
}

export function runGate(opts) {
  const report = JSON.parse(readFileSync(opts.report, "utf-8"));
  const res = gate(report.findings, opts["fail-on"] || "none");
  // A green job must not read as a check of a site nobody read.
  if (report.challenge || report.reachable === false) console.log("::warning::Site not read: Penthera couldn't read the site, so this job says nothing about it.");
  if (res.fail) console.error(`penthera: ${res.count} finding(s) at or above ${opts["fail-on"]}; failing as requested by fail-on.`);
  return res;
}

async function main(argv) {
  const [cmd, ...rest] = argv;
  const { values } = parseArgs({
    args: rest,
    options: { "body-file": { type: "string" }, repo: { type: "string" }, pr: { type: "string" }, report: { type: "string" }, "fail-on": { type: "string" } },
  });
  if (cmd === "comment" && values["body-file"]) { await runComment(values); return 0; }
  if (cmd === "gate" && values.report) return runGate(values).fail ? 1 : 0;
  console.error("usage: comment.mjs comment --body-file <md> | gate --report <json> --fail-on none|high|critical");
  return 2;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => { console.error(`penthera: ${e.message}`); process.exitCode = 2; });
}
