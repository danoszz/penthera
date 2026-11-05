#!/usr/bin/env node
/**
 * Moves the `plugin-claude-live` branch, which Anthropic's plugin directory follows,
 * to the newest commit on main whose plugin pins the version npm serves as
 * `latest`. A release PR bumps the pin before the maintainer approves the
 * version on npm, so main can point at a version that doesn't exist yet; this
 * branch never does. It only moves forward (a fast-forward), never rewrites.
 *
 *   node scripts/ci/plugin-live.mjs            find the target and push it
 *   node scripts/ci/plugin-live.mjs --dry-run  print what it would do
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const BRANCH = "plugin-claude-live";
const MCP = "plugin/.mcp.json";
// How far back on main to look for a commit with the published pin.
const MAX_COMMITS = 500;

/** The penthera version a plugin .mcp.json pins, or null. */
export function pinOf(text) {
  let json;
  try { json = JSON.parse(text); } catch { return null; }
  const args = json?.mcpServers?.penthera?.args;
  if (!Array.isArray(args)) return null;
  for (const a of args) {
    const m = /^penthera@(\d+\.\d+\.\d+)$/.exec(String(a));
    if (m) return m[1];
  }
  return null;
}

/**
 * The newest commit (commits come newest first) whose pin is `latest`, or
 * null. Release candidates never match: `latest` is a plain x.y.z.
 */
export function chooseTarget(commits, latest) {
  if (!/^\d+\.\d+\.\d+$/.test(latest)) return null;
  return commits.find((c) => c.pin === latest)?.sha ?? null;
}

const git = (...args) => execFileSync("git", args, { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] }).trim();

/**
 * Commits on `ref`'s first-parent line, newest first, with their plugin pin,
 * stopping at the first that pins `latest`. First parent only: a merge's side
 * branch holds a contributor's intermediate commits, which nobody reviewed as
 * a snapshot, so a plugin that a PR added and then removed is never a candidate.
 */
export function candidates(ref, latest, run = git) {
  const shas = run("rev-list", "--first-parent", `--max-count=${MAX_COMMITS}`, ref).split("\n").filter(Boolean);
  const commits = [];
  for (const sha of shas) {
    let text = "";
    try { text = run("show", `${sha}:${MCP}`); } catch { /* no plugin folder in this commit */ }
    commits.push({ sha, pin: pinOf(text) });
    if (commits.at(-1).pin === latest) break;
  }
  return commits;
}

function main() {
  const dry = process.argv.includes("--dry-run");
  const latest = execFileSync("npm", ["view", "penthera", "version"], { encoding: "utf-8" }).trim();
  const target = chooseTarget(candidates("origin/main", latest), latest);
  if (!target) {
    console.error(`No commit in the last ${MAX_COMMITS} on main's first-parent line pins penthera@${latest}; ${BRANCH} stays where it is.`);
    process.exit(1);
  }
  let current = null;
  try { current = git("rev-parse", `origin/${BRANCH}`); } catch { /* the branch doesn't exist yet */ }
  if (current === target) {
    console.log(`${BRANCH} is at ${target.slice(0, 7)} (penthera@${latest}); nothing to do.`);
    return;
  }
  if (current) {
    try { git("merge-base", "--is-ancestor", current, target); } catch {
      console.error(`${target.slice(0, 7)} is not ahead of ${BRANCH} (${current.slice(0, 7)}); refusing to move it backwards or sideways.`);
      process.exit(1);
    }
  }
  console.log(`${dry ? "Would move" : "Moving"} ${BRANCH} ${current ? current.slice(0, 7) : "(new)"} → ${target.slice(0, 7)} (penthera@${latest}).`);
  if (!dry) git("push", "origin", `${target}:refs/heads/${BRANCH}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
