/**
 * Dependabot's own pin bumps, for the PR checks (scripts/ci/provenance.mjs and
 * scripts/ci/docs-gate.mjs). Its commits carry no AI-Assisted trailer and no
 * changelog fragment, so those checks let a pull request through only when all
 * of this holds, and stay strict otherwise:
 *
 * - GitHub says the pull request was opened by dependabot[bot] (PR_AUTHOR, set
 *   by the workflow from the event, not from anything in the branch).
 * - Every commit has Dependabot's author address and GitHub as its committer,
 *   and GitHub's API reports its signature as verified.
 * - The change touches only dependency pins: workflows, action.yml, the
 *   example workflows, package.json and the lockfile.
 *
 * Without a token or the API, nothing is exempt.
 */
import { execFileSync } from "node:child_process";

const AUTHOR = "dependabot[bot]";
const AUTHOR_EMAIL = "49699333+dependabot[bot]@users.noreply.github.com";
const COMMITTER_EMAIL = "noreply@github.com";
const PINS = /^(?:\.github\/workflows\/[^/]+\.ya?ml|action\.yml|docs\/examples\/[^/]+\.ya?ml|package(?:-lock)?\.json)$/;

/**
 * @param {{author: string, commits: {sha: string, authorEmail: string, committerEmail: string, verified: boolean|null, files: string[]}[]}} pr
 * @returns {{ok: boolean, reason: string}}
 */
export function dependabotOnly({ author, commits }) {
  if (author !== AUTHOR) return { ok: false, reason: "not opened by Dependabot" };
  if (!commits.length) return { ok: false, reason: "no commits" };
  for (const c of commits) {
    const sha = c.sha.slice(0, 7);
    if (c.authorEmail !== AUTHOR_EMAIL || c.committerEmail !== COMMITTER_EMAIL) return { ok: false, reason: `${sha} is not Dependabot's own commit` };
    if (c.verified !== true) return { ok: false, reason: `${sha} is not verified by GitHub` };
    const other = c.files.find((f) => !PINS.test(f));
    if (other) return { ok: false, reason: `${sha} changes ${other}, which is not a dependency pin` };
  }
  return { ok: true, reason: `${commits.length} verified Dependabot commit(s), dependency pins only` };
}

/** Reads the pull request from git and GitHub's API. @returns {Promise<{ok: boolean, reason: string}>} */
export async function dependabotPr(base, head, env = process.env) {
  if (env.PR_AUTHOR !== AUTHOR) return { ok: false, reason: "not opened by Dependabot" };
  if (!env.GITHUB_TOKEN || !env.GITHUB_REPOSITORY) return { ok: false, reason: "no token to ask GitHub whether the commits are verified" };
  const git = (...args) => execFileSync("git", args, { encoding: "utf-8" });
  const shas = git("rev-list", "--no-merges", `${base}..${head}`).split("\n").filter(Boolean);
  const commits = [];
  for (const sha of shas) {
    const [authorEmail, committerEmail] = git("show", "-s", "--format=%ae%n%ce", sha).trim().split("\n");
    const files = git("show", "--name-only", "--format=", sha).split("\n").filter(Boolean);
    let verified = null;
    try {
      const res = await fetch(`https://api.github.com/repos/${env.GITHUB_REPOSITORY}/commits/${sha}`, {
        headers: { Authorization: `Bearer ${env.GITHUB_TOKEN}`, Accept: "application/vnd.github+json" },
      });
      if (res.ok) verified = (await res.json())?.commit?.verification?.verified === true;
    } catch { /* stays null: not exempt */ }
    commits.push({ sha, authorEmail, committerEmail, verified, files });
  }
  return dependabotOnly({ author: env.PR_AUTHOR, commits });
}
