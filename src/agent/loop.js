/**
 * `penthera agent --loop`: scan → triage → plan → patch → verify → learn, locally.
 *
 * One iteration scans the repo (and the URL, if given), drops suppressed
 * findings, ranks the rest with memory, plans fixes (recipes first, a local
 * model only with --fix-model), then takes the plans one at a time: show the
 * diff and ask, apply it on the fix branch, re-scan (plus the project's tests
 * with --run-tests), commit it if it verified, revert it if it did not, and
 * write what happened to memory. It repeats until nothing fixable is left,
 * --max-iterations is reached, or the user stops it.
 *
 * Guarantees (each has a test in tests/agent.test.js):
 * - Git goes through ./git.js only: local subcommands, no hooks, no transports.
 *   Nothing is pushed, fetched or opened as a pull request.
 * - Everything runs in one egress context limited to the URL target, always
 *   offline. Loopback is added only with --fix-model, for Ollama.
 * - A dirty tree or a detached HEAD is refused unless allowDirty is set, or the only changes are the wizard's files. A fix
 *   that touches a file with uncommitted changes (checked right before writing),
 *   an untracked file or a git-ignored path is never applied.
 * - A revert puts back the bytes each file had before the fix, and only while
 *   the file still holds exactly what the fix wrote; a commit includes only the
 *   fix's files, and only while they still hold what the fix wrote. Anything
 *   edited meanwhile is left alone and the fix is reported as a conflict.
 * - Every diff is approved by `ask` unless --auto low and memory shows the
 *   recipe verified at least 3 times on this framework with no failures.
 * - When `signal` aborts, the fix in flight is verified and committed or
 *   reverted before the loop returns; the branch holds only verified commits.
 * - The judge stays as it was: no fix may edit tests, test config or
 *   Penthera's own files (applyDiff refuses with PROTECTED), and a fix is not
 *   verified if any of them changed since the run began.
 * - A finding that failed once in a run is given up (event gave_up, with the
 *   reason) and not retried in that run. A give-up never counts against a
 *   recipe in memory.
 */
import { randomUUID, createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { scanRepo as defaultScanRepo } from "../scan-repo.js";
import { isProblem } from "../report/counts.js";
import { scanUrl as defaultScanUrl } from "../scan-url.js";
import { createEgressContext, runWithEgress, request } from "../utils/http.js";
import {
  planFixes, applyDiff, restoreFiles, redactPlan, findingKey, createModelFixer, parsePatch,
} from "../../lib/fix/index.js";
import { assertLocalModelUrl } from "../../lib/fix/model.js";
import { protectedReason } from "../../lib/fix/apply.js";
import { detectFramework } from "../../lib/fix/util.js";
import {
  openMemory, projectIdFor, buildViews, rankFindings, isSuppressed, withRepoSuppressions,
  findingId, loadRepoSuppressions,
} from "../../lib/memory/index.js";
import { createGit, isOwnReport, parseStatusZ } from "./git.js";
import { hasTestScript, runProjectTests } from "./tests.js";
import { siteUnread, SITE_NOT_READ } from "../report/unread.js";

export const LOOP_RUN_SCHEMA = "penthera.loopRun/1";
export const AUTO_MIN_VERIFIED = 3;

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const OLLAMA_HOST = "127.0.0.1";

export { parseStatusZ };

/** A file the setup wizard writes and doesn't commit. */
export const isWizardFile = (path) => path === ".gitignore" || path === ".github/workflows/penthera.yml";

export class LoopError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "LoopError";
    this.code = code;
  }
}

/** `penthera/fix-<yyyymmdd-hhmm>` in local time. */
export function fixBranchName(date = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  return `penthera/fix-${date.getFullYear()}${p(date.getMonth() + 1)}${p(date.getDate())}-${p(date.getHours())}${p(date.getMinutes())}`;
}

/**
 * The loop's egress context: only the URL target, always offline. Loopback is
 * allowed only when a fix model is set (Ollama listens on 127.0.0.1:11434).
 */
export function loopEgressContext({ url = null, fixModel = null } = {}) {
  return createEgressContext({ target: url || undefined, offline: true, allowHosts: fixModel ? [OLLAMA_HOST] : [] });
}

/** fetch for lib/fix/model.js that goes through the egress-guarded client. */
export function localModelFetch(url, init = {}) {
  assertLocalModelUrl(url);
  const { redirect: _ignored, ...rest } = init;
  return request(url, { ...rest, probe: "fix-model", timeout: 120_000 });
}

const sevOf = (f) => SEV_ORDER[f?.severity] ?? 5;
const brief = (f) => ({ fid: findingId(f), title: f.title, severity: f.severity, category: f.category || null });
const keysOf = (list) => new Set(list.map(findingKey));
const actionable = (list) => list.filter((f) => f.severity !== "info");
const sha256 = (s) => createHash("sha256").update(s).digest("hex");

function dedupe(findings) {
  const seen = new Set();
  return findings.filter((f) => {
    if (!f || (f.severity === "info" && f.category === "config")) return false;
    const k = findingKey(f);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/** Record a timed step on `list`. */
async function timed(list, step, fn) {
  const startedAt = new Date().toISOString();
  const t0 = Date.now();
  try {
    return await fn();
  } finally {
    list.push({ step, startedAt, durationMs: Date.now() - t0 });
  }
}

function clean(obj) {
  return JSON.parse(JSON.stringify(obj)); // drops undefined so memory's canonical JSON accepts it
}

/**
 * Run the loop.
 *
 * @param {object} opts
 * @param {string} opts.repo - repo to fix (required)
 * @param {string} [opts.url] - live target to scan as well
 * @param {number} [opts.maxIterations=5]
 * @param {"off"|"low"} [opts.auto="off"]
 * @param {boolean} [opts.runTests=false]
 * @param {string} [opts.fixModel] - local Ollama model name
 * @param {boolean} [opts.allowDirty=false]
 * @param {(req: object) => Promise<"y"|"n"|"skip"|"quit">} [opts.ask] - approval prompt; required unless every plan is auto-approved
 * @param {(line: string) => void} [opts.log]
 * @param {AbortSignal} [opts.signal]
 * @param {string} [opts.memoryRoot] - memory root (default ~/.penthera/memory)
 * @param {{ scanRepo?: Function, scanUrl?: Function, runTests?: Function, model?: object }} [opts.deps] - injectable for tests
 * @param {{ revertPending?: () => void }} [opts.handle] - filled with an emergency revert for a second Ctrl-C
 * @returns {Promise<object>} loopRun
 */
export async function runLoop(opts = {}) {
  if (!opts.repo) throw new LoopError("agent --loop needs a repo to fix (--repo <path>)", "NO_REPO");
  const repo = resolve(opts.repo);
  const url = opts.url || null;
  const maxIterations = Math.max(1, Number.isInteger(opts.maxIterations) ? opts.maxIterations : 5);
  const auto = opts.auto === "low" ? "low" : "off";
  const log = opts.log || (() => {});
  const deps = opts.deps || {};
  const scanRepoFn = deps.scanRepo || defaultScanRepo;
  const scanUrlFn = deps.scanUrl || defaultScanUrl;
  const log0 = opts.log || (() => {});
  const testsFn = (dir) => (deps.runTests || runProjectTests)(dir, { onProgress: (ms) => log0(`    tests still running after ${Math.round(ms / 1000)} s`) });
  const stopped = () => Boolean(opts.signal?.aborted);

  // ── Preflight: a git work tree on a branch, clean unless --allow-dirty ──
  const gitExec = deps.gitExec ? { exec: deps.gitExec } : {};
  let git = createGit(repo, gitExec);
  if (git.tryRun("rev-parse", "--is-inside-work-tree")?.trim() !== "true") {
    throw new LoopError(`${repo} is not a git work tree. The loop commits each fix, so run git init and commit once, then try again.`, "NOT_GIT");
  }
  const baseSha = git.tryRun("rev-parse", "--verify", "--quiet", "HEAD")?.trim();
  if (!baseSha) throw new LoopError(`${repo} has no commits yet. Commit once, then run the loop.`, "NO_HEAD");
  const base = git.tryRun("symbolic-ref", "--quiet", "--short", "HEAD")?.trim() || null;
  if (!base && !opts.allowDirty) {
    throw new LoopError("HEAD is detached. Check out a branch first (the fix branch starts from it), or pass --allow-dirty.", "DETACHED");
  }
  const prefix = git.run("rev-parse", "--show-prefix").replace(/\n$/, "");
  const statusNow = () => parseStatusZ(git.run("status", "--porcelain=v1", "-z", "--untracked-files=all", "--", "."), prefix);
  const dirtyFiles = new Set(statusNow().filter((e) => !isOwnReport(e)).map((e) => e.path));
  // The wizard writes these and leaves them for you to commit, so they can't stop the fix it offers.
  const allowDirty = Boolean(opts.allowDirty) || (Boolean(base) && dirtyFiles.size > 0 && [...dirtyFiles].every(isWizardFile));
  if (dirtyFiles.size && !allowDirty) {
    throw new LoopError(`${repo} has uncommitted changes (${[...dirtyFiles].slice(0, 5).join(", ")}${dirtyFiles.size > 5 ? ", ..." : ""}). Commit or stash them first, or pass --allow-dirty.`, "DIRTY");
  }
  if (!git.tryRun("config", "--get", "user.email")?.trim()) {
    // No identity configured: commit as the agent rather than failing after a verified fix.
    git = createGit(repo, {
      ...gitExec,
      env: {
        ...process.env,
        GIT_AUTHOR_NAME: "penthera agent", GIT_AUTHOR_EMAIL: "penthera-agent@localhost",
        GIT_COMMITTER_NAME: "penthera agent", GIT_COMMITTER_EMAIL: "penthera-agent@localhost",
      },
    });
  }

  // ── Memory: fail closed on a broken chain (no ranking, no auto, no writes) ──
  const { id: projectId, label } = projectIdFor({ repo });
  const mem = openMemory(projectId, { root: opts.memoryRoot, label });
  const chainOk = mem.verify().ok;
  let views = chainOk ? buildViews(mem.events()) : { suppressions: [], recipeSuccess: [], seen: {} };
  const repoSupp = loadRepoSuppressions(repo);
  views = withRepoSuppressions(views, repoSupp.entries);
  let eventsAppended = 0;
  const remember = (type, data) => {
    if (!chainOk) return;
    try {
      mem.append({ type, data: clean(data) });
      eventsAppended++;
    } catch (e) {
      log(`  memory: could not record ${type} (${e.message})`);
    }
  };
  const recipeStats = (framework, recipe) =>
    views.recipeSuccess?.find((r) => r.framework === String(framework || "unknown").toLowerCase() && r.recipe === recipe) || null;
  const stack = detectFramework(repo) || "unknown";

  let model = null;
  if (opts.fixModel) model = deps.model || createModelFixer({ model: opts.fixModel, fetch: localModelFetch });

  const startedAt = new Date().toISOString();
  const t0 = Date.now();
  const loopRun = {
    schema: LOOP_RUN_SCHEMA,
    id: randomUUID(),
    startedAt,
    finishedAt: null,
    durationMs: 0,
    target: { repo, url },
    branch: { base, baseSha, fix: null },
    options: {
      maxIterations, auto, runTests: Boolean(opts.runTests), fixModel: opts.fixModel || null,
      offline: true, allowDirty,
    },
    stopReason: null,
    error: null,
    gaveUp: [],
    findings: { initial: null, final: null, left: null, suppressed: 0 },
    totals: { iterations: 0, planned: 0, applied: 0, verified: 0, failed: 0, conflicts: 0, declined: 0, skipped: 0, commits: [] },
    memory: { projectId, chain: chainOk ? "ok" : "broken", eventsAppended: 0 },
    iterations: [],
  };
  if (!chainOk) log("  memory chain is broken: ranking and --auto are off, nothing is recorded. Run `penthera memory verify`.");
  for (const w of repoSupp.warnings || []) log(`  ${w}`);

  if (opts.runTests && !hasTestScript(repo)) log("  --run-tests: this project has no test script, so fixes are checked by re-scan only");

  // ── The fix branch, from the current HEAD ──
  const continuing = /^penthera\/fix-/.test(base || "");
  let branch = continuing ? base : fixBranchName();
  if (continuing) {
    log(`  continuing on ${branch}: this is already a fix branch`);
  } else {
    for (let i = 2; git.tryRun("show-ref", "--verify", "--quiet", `refs/heads/${branch}`) !== null; i++) {
      branch = `${fixBranchName()}-${i}`;
    }
    git.run("checkout", "-b", branch);
    log(`  on ${branch} (from ${base || baseSha.slice(0, 12)})`);
  }
  loopRun.branch.fix = branch;

  /**
   * Why a plan must not be applied right now, or null. Run immediately before
   * writing: files with uncommitted changes (including ones saved while the
   * prompt was open), untracked files and git-ignored paths are all off limits,
   * since the loop could neither revert nor commit them cleanly.
   */
  const guardFiles = (files) => {
    const status = statusNow();
    const set = new Set(files);
    const untracked = status.filter((e) => e.xy === "??" && set.has(e.path)).map((e) => e.path);
    const dirty = status.filter((e) => e.xy !== "??" && set.has(e.path)).map((e) => e.path);
    if (dirty.length) return `touches files with uncommitted changes (${dirty.join(", ")}); fix them by hand`;
    if (untracked.length) return `touches untracked files (${untracked.join(", ")}); commit them first or fix them by hand`;
    // One file per call: the exit code is the answer, so no quoted path output to parse.
    const ignored = files.filter((f) => {
      try {
        git.run("check-ignore", "-q", "--", `./${f}`);
        return true;
      } catch (e) {
        if (e?.status === 1) return false; // not ignored
        throw e;
      }
    });
    if (ignored.length) return `touches git-ignored files (${ignored.join(", ")}), which git can neither commit nor restore; fix them by hand`;
    return null;
  };

  // The fix in flight ({ files: applyDiff's result, staged }), so a second Ctrl-C can put the files back.
  let pending = null;
  /** Restore every file of a fix from its saved bytes; never throws, reports what it could not do. */
  const revert = (fix) => {
    const r = restoreFiles(repo, fix.files);
    if (fix.staged && r.restored.length) {
      try {
        git.run("reset", "-q", "--", ...r.restored);
      } catch (e) {
        r.errors.push({ path: r.restored.join(", "), message: `could not unstage: ${e.message}` });
      }
    }
    return r;
  };
  const revertProblems = (r) => [
    ...(r.conflicts.length ? [`left as they are because they changed after the fix was written: ${r.conflicts.join(", ")}`] : []),
    ...r.errors.map((e) => `could not restore ${e.path}: ${e.message}`),
  ].join("; ");
  const currentSha = (file) => {
    try {
      return sha256(readFileSync(join(repo, file)));
    } catch {
      return null;
    }
  };
  // Protected files (the judge) that differ from the base commit, with their hashes; must not change during the run.
  const judgeState = () => [...new Set([
    ...git.run("diff", "--name-only", "-z", "--relative", baseSha, "--", ".").split("\0"),
    ...statusNow().filter((e) => e.xy === "??").map((e) => e.path),
  ])].filter((f) => f && protectedReason(f)).sort().map((f) => `${f} ${currentSha(f)}`).join("\n");
  const judgeAtStart = judgeState();

  if (opts.handle) {
    opts.handle.revertPending = () => {
      const r = pending ? revert(pending) : null;
      pending = null;
      return r;
    };
  }

  const ctx = loopEgressContext({ url, fixModel: opts.fixModel });
  const scanOpts = { offline: true, allowHosts: [...ctx.allowHosts], timeout: opts.scanTimeout || 10_000 };

  async function scan() {
    const repoResult = await scanRepoFn(repo, {});
    // The repo scan runs the recipes' static checks, so this is the same set the scan and the fix plan count.
    const stat = dedupe(repoResult?.findings || []);
    let live = [];
    if (url) {
      const r = await scanUrlFn(url, scanOpts);
      live = dedupe(r?.findings || []);
      loopRun.siteUnread = siteUnread(r)?.text || null;
    }
    return { static: stat, live, all: dedupe([...stat, ...live]) };
  }

  function recordScan(s) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of s.all) if (counts[f.severity] != null) counts[f.severity]++;
    remember("scan", {
      stack, modes: url ? ["repo", "url", "agent"] : ["repo", "agent"],
      counts: { ...counts, total: s.all.length, suppressed: 0 },
      ids: actionable(s.all).map(findingId),
    });
  }

  function triage(s) {
    const kept = [];
    let suppressed = 0;
    for (const f of s.all) {
      if (isSuppressed(f, views)) suppressed++;
      else kept.push(f);
    }
    return { ranked: chainOk ? rankFindings(kept, views, { framework: stack }) : kept, suppressed };
  }

  let heldBack = 0; // plans and findings left out of the last plan() because they were declined or given up
  const tried = new Set(); // plan keys declined or failed in this run: never proposed again
  const gaveUp = new Set(); // finding keys the loop could not fix in this run: never retried
  /** The safe exit: record that the loop could not fix these findings, and why. Never a recipe failure. */
  const giveUp = (findings, reason, source) => {
    for (const f of findings) {
      if (gaveUp.has(findingKey(f))) continue;
      gaveUp.add(findingKey(f));
      loopRun.gaveUp.push({ fid: findingId(f), title: f.title, reason });
      remember("gave_up", { id: findingId(f), reason: String(reason).slice(0, 1_000), source: source || null, loop: loopRun.id });
    }
  };
  const planKey = (p) => (p.source === "recipe" ? `recipe:${p.recipe}` : `model:${p.findings.map(findingKey).sort().join("|")}`);

  async function plan(ranked) {
    const open = ranked.filter((f) => !gaveUp.has(findingKey(f)));
    const byKey = new Map(open.map((f) => [findingKey(f), f]));
    const { plans, unmatched, refused } = await planFixes(repo, open, { model });
    for (const r of refused) giveUp([r.finding], r.reason, "local-model");
    if (model) giveUp(actionable(unmatched), "no recipe matched and the local model gave no usable fix", "local-model");
    const order = new Map(open.map((f, i) => [findingKey(f), i]));
    heldBack = plans.filter((p) => tried.has(planKey(p))).length + ranked.filter((f) => gaveUp.has(findingKey(f))).length;
    return plans
      .filter((p) => !tried.has(planKey(p)))
      .map((p) => {
        const stats = p.source === "recipe" ? recipeStats(p.framework, p.recipe) : null;
        return {
          plan: p,
          originals: p.findings.map((b) => byKey.get(findingKey(b)) || b),
          sev: Math.min(...p.findings.map(sevOf)),
          rate: stats?.rate ?? null,
          rank: Math.min(...p.findings.map((b) => order.get(findingKey(b)) ?? Infinity)),
          stats,
        };
      })
      // Severity first (memory never changes it), then the recipe's verified rate, then memory's finding rank.
      .sort((a, b) => a.sev - b.sev || (b.rate ?? 0.5) - (a.rate ?? 0.5) || a.rank - b.rank);
  }

  const autoOk = (p, stats) => auto === "low" && chainOk && p.source === "recipe" && p.confidence !== "needs-human-review"
    && stats && stats.verified >= AUTO_MIN_VERIFIED && stats.failed === 0;

  function commitMessage(p, entry, decision) {
    const lines = p.findings.map((f) => `- [${f.severity || "?"}] ${f.title}${f.url ? ` (${f.url})` : ""}`);
    const tests = entry.verify?.tests ? (entry.verify.tests.ok ? "project tests passed" : "project tests failed") : "project tests not run";
    return [
      `fix(security): ${p.title}${p.framework ? ` (${p.framework})` : ""}`,
      [
        "Fixes:", ...lines, "",
        `Recipe: ${p.recipe} (${p.source}, confidence ${p.confidence}), plan ${p.id}`,
        `Verified: re-scan no longer reports the fixed findings and shows no new ones; ${tests}.`,
        `Applied by penthera agent --loop (${decision === "auto" ? "auto-approved from memory" : "approved"}). Nothing was pushed.`,
      ].join("\n"),
    ];
  }

  let current = null; // last scan, kept in sync as fixes land
  let stopReason = null;

  const body = async () => {
    if (opts.runTests && hasTestScript(repo) && !stopped()) {
      log("  tests: running them once before any fix");
      const r = await testsFn(repo);
      loopRun.testsBefore = { ok: r.ok, exitCode: r.exitCode };
      if (!r.ok && !stopped()) log("  tests already fail before any fix, so fixes are judged by re-scan only");
    }

    for (let n = 1; n <= maxIterations && !stopReason; n++) {
      if (stopped()) { stopReason = "interrupted"; break; }
      const it = { n, startedAt: new Date().toISOString(), durationMs: 0, findings: null, steps: [], fixes: [] };
      loopRun.iterations.push(it);
      const itStart = Date.now();
      log(`\n  iteration ${n}/${maxIterations}`);

      current = await timed(it.steps, "scan", scan);
      recordScan(current);
      if (loopRun.findings.initial == null) loopRun.findings.initial = actionable(current.all).length;
      const { ranked, suppressed } = await timed(it.steps, "triage", async () => triage(current));
      const candidates = await timed(it.steps, "plan", () => plan(ranked));
      // Problems in the words every surface uses (src/report/counts.js); suppressed ones are not counted.
      const problems = ranked.filter((f) => isProblem(f)).length;
      it.findings = { total: current.all.length, problems, suppressed, fixable: candidates.length };
      loopRun.totals.planned += candidates.length;
      log(`  scan: ${problems} problem${problems === 1 ? "" : "s"} (${suppressed} suppressed), ${candidates.length} fix${candidates.length === 1 ? "" : "es"} planned`);

      if (!candidates.length) {
        stopReason = heldBack ? "declined-or-failed-left" : "no-fixable-findings";
        it.durationMs = Date.now() - itStart;
        break;
      }

      let appliedHere = 0;
      for (let i = 0; i < candidates.length; i++) {
        if (stopped()) { stopReason = "interrupted"; break; }
        let { plan: p, originals, stats } = candidates[i];
        const entry = {
          planId: p.id, recipe: p.recipe, title: p.title, framework: p.framework || null, source: p.source,
          confidence: p.confidence, files: p.files, findings: originals.map(brief), ownerActions: p.ownerActions || [],
          memory: stats ? { verified: stats.verified, failed: stats.failed } : null,
          decision: null, status: "not-applied", reason: null, commit: null, verify: null, steps: [],
        };
        it.fixes.push(entry);

        // Earlier fixes in this iteration may have changed the same files: re-plan against the tree.
        if (i > 0) {
          const fresh = (await planFixes(repo, originals, { model })).plans.find((q) => planKey(q) === planKey(p));
          if (!fresh) {
            entry.decision = "obsolete";
            entry.reason = "an earlier fix in this iteration already covered it";
            continue;
          }
          p = fresh;
          Object.assign(entry, { planId: p.id, files: p.files });
        }

        const { contextDiff, ...shown } = redactPlan(p, { context: Boolean(opts.approvalContext) });
        let answer;
        if (autoOk(p, stats)) {
          answer = "auto";
          log(`  [${i + 1}/${candidates.length}] ${p.title}: auto-approved (memory: ${stats.verified} verified, 0 failed on ${p.framework})`);
        } else {
          if (!opts.ask) throw new LoopError("No approval prompt: every diff needs a y/n answer unless --auto low applies", "NO_PROMPT");
          answer = await timed(entry.steps, "approve", () => opts.ask({
            plan: shown, ...(contextDiff ? { contextDiff } : {}), iteration: n, index: i + 1, total: candidates.length,
            memory: entry.memory, signal: opts.signal,
          }));
        }
        if (stopped()) { entry.decision = "quit"; stopReason = "interrupted"; break; }
        if (answer === "quit") { entry.decision = "quit"; stopReason = "user-quit"; break; }
        if (answer === "n") { entry.decision = "declined"; tried.add(planKey(p)); loopRun.totals.declined++; continue; }
        if (answer !== "y" && answer !== "auto") { entry.decision = "skipped"; loopRun.totals.skipped++; continue; }
        entry.decision = answer === "auto" ? "auto" : "approved";

        // ── Patch: re-check the files right before writing (the prompt may have been open a while) ──
        let applied;
        try {
          applied = await timed(entry.steps, "patch", async () => {
            const targets = [...new Set([...p.files, ...parsePatch(p.diff).map((f) => f.newPath).filter(Boolean)])];
            const refused = guardFiles(targets);
            if (refused) return { refused };
            return applyDiff(repo, p.diff, { allowDirty });
          });
        } catch (e) {
          if (e?.name === "GitPolicyError") throw e;
          // The tree is the problem, so every later fix would fail the same way: stop now, not after more approvals.
          if (e?.code === "DIRTY" || e?.code === "NOT_GIT") {
            entry.reason = e.message;
            throw new LoopError(e.message, e.code);
          }
          applied = { refused: `did not apply: ${e.message}` };
        }
        if (applied.refused) {
          entry.reason = applied.refused;
          tried.add(planKey(p));
          giveUp(originals, entry.reason, p.source);
          log(`    not applied: ${entry.reason}`);
          continue;
        }
        const files = applied.files.map((f) => f.path);
        const created = applied.files.filter((f) => f.created).map((f) => f.path);
        pending = { files: applied.files, staged: false };
        loopRun.totals.applied++;
        appliedHere++;
        const primary = originals[0];
        const learnData = {
          id: findingId(primary), recipe: p.recipe, framework: p.framework || stack, category: primary.category || null,
          diff_sha256: sha256(p.diff), plan: p.id, ids: originals.map(findingId), source: p.source, loop: loopRun.id,
        };
        await timed(entry.steps, "learn", async () => remember("fix_applied", learnData));

        // ── Verify: re-scan, then the project's tests ──
        const before = current;
        const verdict = await timed(entry.steps, "verify", async () => {
          const after = await scan();
          const staticNow = keysOf(after.static);
          const liveNow = keysOf(after.live);
          const beforeKeys = keysOf(before.all);
          const targetedRemaining = p.findings.filter((f) => staticNow.has(findingKey(f))).length;
          const liveRemaining = p.findings.filter((f) => liveNow.has(findingKey(f))).length;
          const introduced = actionable(after.all).filter((f) => !beforeKeys.has(findingKey(f)));
          // The judge must be the one the run began with, before and after the tests run.
          let judgeOk = judgeState() === judgeAtStart;
          let tests = null;
          if (judgeOk && opts.runTests && hasTestScript(repo) && loopRun.testsBefore?.ok !== false) {
            const r = await testsFn(repo);
            tests = { ok: r.ok, exitCode: r.exitCode, durationMs: r.durationMs };
            if (!r.ok) entry.testOutput = r.output?.slice(-2_000);
          }
          judgeOk &&= judgeState() === judgeAtStart;
          const reasons = [];
          if (!judgeOk) reasons.push("tests, test config or Penthera's own files changed during the run, so the fix was not verified");
          if (targetedRemaining) reasons.push(`${targetedRemaining} targeted finding(s) still reported`);
          if (introduced.length) reasons.push(`new finding(s): ${introduced.slice(0, 3).map((f) => f.title).join("; ")}`);
          if (tests && !tests.ok) reasons.push(`project tests failed (exit ${tests.exitCode})`);
          return { after, ok: reasons.length === 0, reasons, summary: { targetedRemaining, newFindings: introduced.length, liveRemaining, tests } };
        });
        entry.verify = verdict.summary;

        // Files edited by someone else since the fix was written: neither commit nor revert them.
        const changed = applied.files.filter((f) => currentSha(f.path) !== f.sha256).map((f) => f.path);
        if (verdict.ok && changed.length) {
          pending = null;
          entry.status = "conflict";
          entry.reason = `verified, but ${changed.join(", ")} changed while it was being verified; left as they are and nothing was committed`;
          tried.add(planKey(p));
          loopRun.totals.conflicts++;
          log(`    not committed: ${entry.reason}`);
        } else if (verdict.ok) {
          const [subject, msg] = commitMessage(p, entry, entry.decision);
          await timed(entry.steps, "commit", async () => {
            if (created.length) {
              pending.staged = true;
              git.run("add", "--", ...created);
            }
            // --only: the fix's files as they are on disk, nothing else that happens to be staged.
            git.run("commit", "-q", "--only", "-m", subject, "-m", msg, "--", ...files);
          });
          pending = null;
          entry.commit = git.run("rev-parse", "HEAD").trim();
          entry.status = "verified";
          loopRun.totals.verified++;
          loopRun.totals.commits.push(entry.commit);
          current = verdict.after;
          await timed(entry.steps, "learn", async () => remember("fix_verified", { ...learnData, commit: entry.commit }));
          const live = entry.verify.liveRemaining ? `; ${entry.verify.liveRemaining} still served by the running app until it restarts` : "";
          log(`    verified and committed ${entry.commit.slice(0, 10)}${live}`);
        } else if (stopped()) {
          // The run was stopped, so nothing was learned about this fix: not a failure, and not one to remember.
          await timed(entry.steps, "revert", async () => revert(pending));
          pending = null;
          entry.status = "interrupted";
          log("    stopped, fix reverted");
        } else {
          const r = await timed(entry.steps, "revert", async () => revert(pending));
          pending = null;
          entry.status = r.conflicts.length ? "conflict" : "failed";
          entry.reason = verdict.reasons.join("; ");
          const problems = revertProblems(r);
          if (problems) entry.reason += `; revert: ${problems}`;
          tried.add(planKey(p));
          loopRun.totals.failed++;
          if (r.conflicts.length) loopRun.totals.conflicts++;
          await timed(entry.steps, "learn", async () => {
            remember("fix_failed", { ...learnData, reason: entry.reason });
            giveUp(originals, entry.reason, p.source);
          });
          log(`    failed verification, ${problems ? "not fully reverted" : "reverted"}: ${entry.reason}`);
        }
        if (stopped()) { stopReason = "interrupted"; break; }
      }
      it.durationMs = Date.now() - itStart;
      if (!stopReason && appliedHere === 0 && it.fixes.every((f) => f.decision !== "skipped")) {
        stopReason = "declined-or-failed-left";
      }
    }

    if (!stopReason) {
      // The last iteration may have fixed everything: check before saying we ran out of iterations.
      const s = await scan();
      current = s;
      const left = await plan(triage(s).ranked);
      stopReason = left.length ? "max-iterations" : heldBack ? "declined-or-failed-left" : "no-fixable-findings";
    }
  };

  try {
    await runWithEgress(ctx, body);
  } catch (e) {
    let problems = "";
    if (pending) {
      problems = revertProblems(revert(pending));
      pending = null;
    }
    stopReason = "error";
    loopRun.error = problems ? `${e.message}; revert: ${problems}` : e.message;
  }

  loopRun.stopReason = stopReason;
  // No commit, no reason to stay: an empty fix branch only hides where you were.
  if (!loopRun.totals.commits.length && base && base !== branch && git.tryRun("checkout", "-q", base) !== null) {
    loopRun.branch.left = true;
    loopRun.branch.removed = git.tryRun("branch", "-d", branch) !== null;
  }
  if (current) {
    const open = actionable(triage(current).ranked).length;
    loopRun.findings.final = open;
    loopRun.findings.suppressed = actionable(current.all).length - open;
    // Suppressed findings stay in: a plain scan counts them, and the loop's exit code matches it.
    loopRun.findings.left = countBySeverity(current.all);
  }
  loopRun.totals.iterations = loopRun.iterations.length;
  loopRun.finishedAt = new Date().toISOString();
  loopRun.durationMs = Date.now() - t0;
  remember("loop_run", summarizeForMemory(loopRun));
  loopRun.memory.eventsAppended = eventsAppended;
  return loopRun;
}

function countBySeverity(findings) {
  const left = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) if (left[f.severity] != null) left[f.severity]++;
  return left;
}

/**
 * How a run really ended, in one line, for the CLI and the dashboard. A run is
 * clean only if it finished and its last scan left no critical or high
 * finding: the same bar as a scan's exit code.
 * The headline is plain words, for the dashboard too; a command goes in next.
 * @returns {{ clean: boolean, headline: string, next: string|null }}
 */
export function loopVerdict(run) {
  const left = run.findings?.left;
  const passed = (run.totals.declined || 0) + (run.totals.skipped || 0);
  const fixed = `${run.totals.verified} fixed${passed ? `, ${passed} skipped` : ""}`;
  if (!left) return { clean: false, headline: `${fixed}. The run ended before a final scan.` };
  const serious = left.critical + left.high;
  const lower = left.medium + left.low;
  const open = serious
    ? [left.critical && `${left.critical} critical`, left.high && `${left.high} high`].filter(Boolean).join(", ") + " left"
    : `no critical or high left${lower ? `, ${lower} lower` : ""}`;
  const finished = run.stopReason !== "error" && run.stopReason !== "interrupted" && run.stopReason !== "user-quit";
  const hidden = run.findings.suppressed;
  const review = hidden ? ` (${hidden} suppressed by you).` : ".";
  const site = run.siteUnread ? ` ${SITE_NOT_READ} ${run.siteUnread}` : "";
  const red = run.testsBefore?.ok === false ? " Your tests were already failing before any fix, so fixes were judged by re-scan only." : "";
  return {
    clean: run.stopReason === "no-fixable-findings" && serious === 0 && !site,
    headline: `${finished ? "" : "Stopped early: "}${fixed}, ${open}${review}${site}${red}`,
    next: [
      hidden && "Review them with penthera memory show --repo . and penthera.suppress.json.",
      run.totals.verified && "These counts include checks only penthera fix runs, so they differ from a scan's.",
      run.totals.verified && !run.target?.url && "Findings from a live scan stay until you scan the URL again.",
    ].filter(Boolean).join(" ") || null,
  };
}

/** The loopRun as stored in memory: no test output, bounded size. */
export function summarizeForMemory(loopRun) {
  const { iterations, ...rest } = loopRun;
  return clean({
    ...rest,
    iterations: iterations.map((it) => ({
      ...it,
      fixes: it.fixes.map(({ testOutput, findings, ...f }) => ({ ...f, findings: findings.map((x) => x.fid) })),
    })),
  });
}
