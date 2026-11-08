/**
 * Live runs started from the dashboard: `agent --loop` and plain scans.
 *
 * A run goes through the same functions as the CLI (runLoop, executeScan),
 * with the same rules: the loop is always offline and limited to its URL
 * target, every diff waits for a decision, nothing is pushed. On top of that:
 *
 * - The repo must be inside a project folder the dashboard was started with.
 * - A URL that is not on this machine needs its hostname typed back as
 *   confirmation (the CLI's authorization gate, made explicit).
 * - One run at a time.
 *
 * Output is an append-only event list per run, streamed over SSE. Events are
 * plain data; the frontend renders them as text.
 */
import { randomBytes, createHash } from "node:crypto";
import { normalizeBaseUrl, urlToFilename } from "../../utils/url.js";
import { confineDir } from "./data.js";
import { projectKey } from "./summarize.js";
import { nothingClaim, notRead } from "../../report/unread.js";
import { CONSENT_TEXT_VERSION, CLOUD_HOST, logConsent, readConsentLog } from "../../../lib/ai/consent.js";
import { parseBudget } from "../../../lib/ai/hunt.js";
import { loadPolicy } from "../../../lib/install/policy.js";

const MAX_EVENTS = 5000;
const MAX_FINISHED = 20; // finished runs kept for replay; older ones are dropped
export const MAX_DIFF = 60000;
const LOCAL_HOST = /^(localhost|127\.\d+\.\d+\.\d+|\[::1\]|[a-z0-9-]+\.localhost)$/i;
const ANSI = /\x1b\[[0-9;?]*[ -/]*[@-~]/g;
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;

export class RunError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

export const cleanLine = (s) => String(s ?? "").replace(ANSI, "").replace(CONTROL, "").slice(0, 4000);

export const diffSha256 = (s) => createHash("sha256").update(String(s), "utf-8").digest("hex");

/** A CLI flag means nothing on this page, so an error that offers one doesn't. */
const forDashboard = (message) => (message ? String(message).replace(/, or pass --allow-dirty\.$/, ".") : message);

export function isLocalHost(hostname) {
  return LOCAL_HOST.test(hostname);
}

/**
 * Validate a run request. Returns { kind, repo, url } or throws RunError.
 * @param {object} body  { kind, repo, url, confirm, maxIterations, runTests }
 * @param {string[]} projectRoots
 */
export function validateRunRequest(body, projectRoots, confine = confineDir) {
  if (!body || typeof body !== "object") throw new RunError("Expected a JSON body.");
  const kind = ["scan", "loop", "deps", "agents"].includes(body.kind) ? body.kind : null;
  if (!kind) throw new RunError('kind must be "scan", "deps", "agents" or "loop".');

  let url = null;
  if (body.url != null && String(body.url).trim()) {
    const raw = String(body.url).trim();
    let parsed;
    try { parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`); } catch { throw new RunError(`Not a URL: ${raw.slice(0, 200)}`); }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new RunError("Only http and https URLs can be scanned.");
    if (parsed.username || parsed.password) throw new RunError("Leave credentials out of the URL.");
    url = normalizeBaseUrl(parsed.href);
    if (!isLocalHost(parsed.hostname)) {
      const confirm = typeof body.confirm === "string" ? body.confirm.trim().toLowerCase() : "";
      if (confirm !== parsed.hostname.toLowerCase()) {
        throw new RunError(`${parsed.hostname} is not on this machine. Type the hostname to confirm you own it or have written permission to test it.`, 428);
      }
    }
  }

  let repo = null;
  if (body.repo != null && String(body.repo).trim()) {
    try { repo = confine(String(body.repo), projectRoots); } catch (e) { throw new RunError(e.message); }
  }
  if (kind === "loop" && !repo) throw new RunError("The agent loop fixes a repo: enter a project folder.");
  if ((kind === "deps" || kind === "agents") && !repo) throw new RunError(`${kind === "deps" ? "The dependency check reads package-lock.json" : "The AI tooling audit reads agent config"} in a project folder: enter one.`);
  if ((kind === "deps" || kind === "agents") && url) throw new RunError("This check reads files only; leave the URL empty.");
  if (kind === "scan" && !repo && !url) throw new RunError("Enter a project folder, a URL, or both.");

  let ai = null;
  if (body.ai != null) {
    if (kind !== "scan" || !repo) throw new RunError("AI mode reads source code: it runs with a scan of a project folder.");
    const a = body.ai;
    if (typeof a !== "object" || typeof a.model !== "string" || !a.model.trim() || a.model.length > 200) throw new RunError("AI mode needs a model.");
    if (a.consent !== true) throw new RunError("AI mode needs your consent: open the AI mode sheet and choose the model.", 428);
    if (a.textVersion !== CONSENT_TEXT_VERSION) throw new RunError("What AI mode does has changed since this page loaded. Reload and open the AI mode sheet again.", 409);
    ai = { model: a.model.trim(), confirmHost: typeof a.confirmHost === "string" ? a.confirmHost.trim().toLowerCase() : "" };
  }

  const maxIterations = body.maxIterations == null ? 5 : Number(body.maxIterations);
  if (!Number.isInteger(maxIterations) || maxIterations < 1 || maxIterations > 50) throw new RunError("Max iterations must be a whole number from 1 to 50.");
  return { kind, repo, url, maxIterations, runTests: body.runTests === true, ai };
}

/**
 * The run manager.
 * @param {object} deps
 * @param {Function} deps.runLoop       src/agent/loop.js runLoop (injectable for tests and --demo)
 * @param {Function} deps.executeScan   src/cli/run-scan.js executeScan
 * @param {Function} deps.writeReport   (merged, base) => file name
 * @param {Function} deps.saveLoopRun   (loopRun) => file name
 * @param {() => { offline: boolean }} deps.settings
 * @param {string[]} deps.projectRoots
 * @param {Function} [deps.confineDir]  folder check override (--demo has no real folders)
 */
export function createRunManager(deps) {
  const runs = new Map();
  let active = null;

  function emit(run, type, data = {}) {
    // Ids keep counting after the buffer drops old events, so a reconnect
    // with Last-Event-ID replays exactly what it missed.
    const ev = { seq: ++run.nextSeq, type, ts: new Date().toISOString(), data };
    run.events.push(ev);
    if (run.events.length > MAX_EVENTS) run.events.splice(0, run.events.length - MAX_EVENTS);
    for (const fn of run.listeners) fn(ev);
  }

  /** The diff an approval showed stays in the run's event log only until the decision: it can hold context lines. */
  function forgetDiff(run, approvalId) {
    for (const ev of run.events) if (ev.type === "approval" && ev.data?.approvalId === approvalId) ev.data = { ...ev.data, plan: { ...ev.data.plan, diff: "" } };
  }

  function publicRun(run) {
    return {
      id: run.id, kind: run.kind, status: run.status, repo: run.repo, url: run.url,
      startedAt: run.startedAt, pending: run.pending ? run.pending.request : null, summary: run.summary,
      ai: run.ai ? { model: run.ai.model.name, route: run.ai.model.route } : null,
    };
  }

  async function execute(run, req) {
    const log = (line) => {
      const text = cleanLine(line);
      emit(run, "log", { text });
      const m = text.match(/^\s*iteration (\d+)\/(\d+)/);
      if (m) emit(run, "iteration", { n: Number(m[1]), of: Number(m[2]) });
      // The loop's line, in the words every surface uses (src/report/counts.js).
      const s = text.match(/^\s*scan: (\d+) problems? \((\d+) suppressed\), (\d+) fix(?:es)? planned/);
      if (s) emit(run, "scanned", { problems: Number(s[1]), suppressed: Number(s[2]), fixes: Number(s[3]) });
      if (/verified and committed/.test(text)) emit(run, "fix", { status: "verified", text });
      else if (/failed verification, reverted/.test(text)) emit(run, "fix", { status: "failed", text });
      else if (/^\s*not applied:/.test(text)) emit(run, "fix", { status: "not-applied", text });
    };

    if (req.kind === "loop") {
      emit(run, "log", { text: `penthera agent --loop ${req.repo}${req.url ? ` + ${req.url}` : ""}` });
      emit(run, "log", { text: `local only: egress limited to ${req.url ? new URL(req.url).host : "no hosts (repo scan only)"}; nothing is pushed` });
      const loopRun = await deps.runLoop({
        repo: req.repo, url: req.url, maxIterations: req.maxIterations, auto: "off", runTests: req.runTests, approvalContext: true,
        log, signal: run.controller.signal,
        ask: (q) => new Promise((resolveAnswer) => {
          const approvalId = randomBytes(8).toString("hex");
          const p = q.plan || {};
          // The page shows at most MAX_DIFF characters. It says so (truncated,
          // fullLength), and an approval names the SHA-256 of what it showed.
          const fullDiff = String(q.contextDiff || p.diff || "");
          const diff = fullDiff.slice(0, MAX_DIFF);
          const request = {
            approvalId, iteration: q.iteration, index: q.index, total: q.total, memory: q.memory || null,
            plan: {
              title: cleanLine(p.title), recipe: cleanLine(p.recipe), framework: p.framework ? cleanLine(p.framework) : null,
              confidence: cleanLine(p.confidence), source: cleanLine(p.source),
              files: (p.files || []).map(cleanLine), diff, truncated: diff.length < fullDiff.length, fullLength: fullDiff.length,
              findings: (p.findings || []).map((f) => ({ title: cleanLine(f.title), severity: cleanLine(f.severity) })),
              ownerActions: (p.ownerActions || []).map(cleanLine), redacted: Boolean(p.redacted),
            },
          };
          run.pending = { request, resolve: resolveAnswer, diffSha256: diffSha256(diff), truncated: diff.length < fullDiff.length };
          emit(run, "approval", request);
        }),
      });
      run.summary = {
        stopReason: loopRun.stopReason, error: forDashboard(loopRun.error), totals: loopRun.totals, findings: loopRun.findings,
        verdict: deps.loopVerdict?.(loopRun) || null,
        ownerActions: [...new Set(loopRun.iterations.flatMap((it) => it.fixes.filter((f) => f.status === "verified").flatMap((f) => f.ownerActions || [])))].map(cleanLine),
        // A merge needs fixes to bring and another branch to bring them to.
        mergeBase: !loopRun.totals?.verified || loopRun.branch?.removed || loopRun.branch?.base === loopRun.branch?.fix ? null : loopRun.branch?.base || null,
        branch: loopRun.branch?.removed ? null : loopRun.branch?.fix || null, durationMs: loopRun.durationMs,
        liveRemaining: loopRun.iterations.reduce((n, it) => n + it.fixes.reduce((m, f) => m + (f.verify?.liveRemaining || 0), 0), 0),
        iterations: loopRun.iterations.map((it) => ({
          n: it.n, durationMs: it.durationMs, findings: it.findings,
          fixes: it.fixes.map((f) => ({ title: f.title, recipe: f.recipe, decision: f.decision, status: f.status, commit: f.commit })),
        })),
      };
      const file = deps.saveLoopRun?.(loopRun);
      if (file) emit(run, "log", { text: `loopRun written to ${file}` });
      emit(run, "log", { text: run.summary.branch ? `branch ${run.summary.branch}: nothing was pushed. Merge it yourself when you are happy with it.` : "No fix was kept, so the fix branch was removed. Nothing was pushed." });
      // Project views read the newest report, so the fixes show there and not only in this run.
      if (loopRun.totals.verified && !run.controller.signal.aborted) {
        try {
          // The same targets as the check it follows, so the result lands on the same project.
          const r = await deps.executeScan({ url: req.url, repo: req.repo, profile: "standard", offline: deps.settings().offline, json: true, onPhase: () => {} });
          const file = deps.writeReport(r.merged, `${req.url ? urlToFilename(req.url) : "repo"}_${new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-")}.json`);
          run.summary.project = projectKey(r.merged.target);
          if (file) emit(run, "log", { text: `rescan written to ${file}` });
        } catch (e) {
          emit(run, "log", { text: `rescan failed: ${cleanLine(e.message)}` });
        }
      }
    } else if (req.kind === "deps" || req.kind === "agents") {
      const stamp = new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-");
      emit(run, "log", { text: req.kind === "deps" ? `penthera deps ${req.repo} (offline)` : `penthera agents ${req.repo} (offline, read-only)` });
      const result = req.kind === "deps"
        ? await deps.scanDeps(req.repo, { onPhase: (m) => log(m) })
        : await deps.scanAgents(req.repo, { onPhase: (m) => log(m) });
      const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const f of result.findings || []) if (c[f.severity] != null) c[f.severity]++;
      const file = deps.writeReport({ ...result, folder: req.repo }, `${req.kind}_${stamp}.json`);
      run.summary = { counts: c, total: (result.findings || []).length, file, grade: result.agents?.grade || null, claim: nothingClaim(result) };
      log(`${req.kind === "deps" ? "deps" : "agents"} done: ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low${result.agents ? `, ${result.agents.grade ? `grade ${result.agents.grade}` : "nothing to assess"}` : ""}`);
      if (file) log(`report written to ${file}`);
    } else {
      const offline = deps.settings().offline;
      emit(run, "log", { text: `penthera${req.url ? ` ${req.url}` : ""}${req.repo ? ` --repo ${req.repo}` : ""} --profile standard${offline ? " --offline" : ""}` });
      const r = await deps.executeScan({ url: req.url, repo: req.repo, profile: "standard", offline, json: true, onPhase: (m) => log(m) });
      if (run.ai && !run.controller.signal.aborted) await runAi(run, req, r, log);
      const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const f of r.merged.findings) if (c[f.severity] != null) c[f.severity]++;
      const base = `${req.url ? urlToFilename(req.url) : "repo"}_${new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-")}.json`;
      const file = deps.writeReport(r.merged, base);
      run.summary = { counts: c, total: r.merged.findings.length, file, ai: aiSummary(r.merged.ai), project: projectKey(r.merged.target), unread: notRead(r.merged), claim: nothingClaim(r.merged) };
      log(`scan done: ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low, ${c.info} info`);
      if (run.summary.unread) log(`${run.summary.unread.title} ${run.summary.unread.text}`);
      if (file) log(`report written to ${file}`);
    }
  }

  /** AI mode after the rules, as the CLI does it; model findings stay in merged.ai. */
  async function runAi(run, req, r, log) {
    const { model } = run.ai;
    log(model.route === "local" ? `AI: ${model.name} on this computer · nothing sent off it` : `AI: ${model.name} on ${CLOUD_HOST} · code sent there through your local Ollama`);
    const repoResult = r.results?.find((x) => x.mode === "repo") || r.merged;
    const ai = await deps.runAiMode({
      repoPath: req.repo,
      scanResult: { ...repoResult, findings: r.merged.findings },
      model,
      ollama: deps.ollama,
      budget: parseBudget(),
      consent: { via: "dashboard" },
      signal: run.controller.signal,
      onUnit: (u, i, n) => { if (i === 1 || i === n || i % 10 === 0) log(`   AI ${i}/${n} ${u.id}`); },
    });
    r.merged.ai = ai;
    r.merged.findings = deps.attachProposals(r.merged.findings, ai);
    log(`AI done: ${ai.counts["confirmed-by-rule"]} confirmed by a rule, ${ai.counts.unverified} model-proposed and unverified${ai.partial ? ` (partial: ${ai.stopReason})` : ""}`);
  }

  /**
   * Check an AI request against Ollama and the repo's policy, server side:
   * the route comes from Ollama, never from the page. Logs the consent.
   */
  async function checkAi(req) {
    if (!deps.ollama || !deps.runAiMode) throw new RunError("AI mode is not available here (it is off in the demo).", 400);
    let models;
    try { models = await deps.ollama.models(); } catch (e) { throw new RunError(cleanLine(e.message), 503); }
    const model = models.find((m) => m.name === req.ai.model || m.name === `${req.ai.model}:latest`);
    if (!model) throw new RunError(`Ollama has no model named ${cleanLine(req.ai.model)}.`, 400);
    let allow = null;
    let loaded;
    try { loaded = loadPolicy(req.repo); } catch (e) { throw new RunError(cleanLine(e.message)); }
    if (loaded.warning) throw new RunError(cleanLine(`${loaded.warning.replace(/ The scan used the default policy.*$/, "")} AI mode does not run until it can be read.`));
    allow = loaded.policy.ai?.allow ?? null;
    if (allow && allow.length === 0) throw new RunError("penthera.policy.json turns AI mode off for this project.", 403);
    if (model.route === "ollama-cloud" && req.ai.confirmHost !== CLOUD_HOST) {
      throw new RunError(`This model runs on ${CLOUD_HOST}. Type ${CLOUD_HOST} in the AI mode sheet to send your code there.`, 428);
    }
    logConsent({ project: req.repo, route: model.route, model: model.name, digest: model.digest, via: "dashboard" }, deps.env || process.env);
    return { model };
  }

  const head = {
    list: () => [...runs.values()].map(publicRun).reverse(),

    /** Ollama's models with their route, for the AI mode sheet. */
    async aiModels() {
      if (!deps.ollama) return { models: [], error: "AI mode is not available here (it is off in the demo)." };
      try { return { models: await deps.ollama.models(), textVersion: CONSENT_TEXT_VERSION }; } catch (e) { return { models: [], error: cleanLine(e.message), textVersion: CONSENT_TEXT_VERSION }; }
    },
    aiConsentLog: () => ({ log: readConsentLog(deps.env || process.env).slice(-100) }),
    get: (id) => runs.get(id) || null,
    publicRun,

    /** Start a run. Synchronous, except an AI run: Ollama is asked first, so that one returns a promise. */
    start(body) {
      if (active && active.status === "running") throw new RunError("A run is already in progress. Stop it first.", 409);
      const req = validateRunRequest(body, deps.projectRoots, deps.confineDir);
      if (req.ai) return checkAi(req).then((ai) => begin(req, ai));
      return begin(req, null);
    },
  };

  /** Create the run and start it; the caller has checked the request (and AI consent). */
  function begin(req, ai) {
    if (active && active.status === "running") throw new RunError("A run is already in progress. Stop it first.", 409);
    const finished = [...runs.values()].filter((r) => r.status !== "running");
    for (const old of finished.slice(0, Math.max(0, finished.length - MAX_FINISHED + 1))) runs.delete(old.id);
    const run = {
      id: randomBytes(8).toString("hex"), kind: req.kind, repo: req.repo, url: req.url, status: "running",
      startedAt: new Date().toISOString(), events: [], nextSeq: 0, listeners: new Set(), pending: null, summary: null,
      controller: new AbortController(), ai,
    };
    runs.set(run.id, run);
    active = run;
    emit(run, "status", { status: "running" });
    execute(run, req)
      .then(() => { run.status = run.controller.signal.aborted ? "stopped" : "done"; })
      .catch((e) => {
        run.status = "error";
        const error = forDashboard(cleanLine(e.message));
        run.summary = { ...run.summary, error };
        emit(run, "log", { text: `error: ${error}` });
      })
      .finally(() => {
        if (run.pending) { forgetDiff(run, run.pending.request.approvalId); run.pending.resolve("quit"); run.pending = null; }
        emit(run, "status", { status: run.status, summary: run.summary });
        for (const fn of run.listeners) fn(null);
        run.listeners.clear();
      });
    return publicRun(run);
  }

  const manager = {
    /**
     * An approval must name the SHA-256 of the diff the page showed
     * (`diffSha256`), and for a diff cut at MAX_DIFF characters also
     * `acknowledgeTruncated: true`. Skip and stop need neither.
     */
    decide(id, { approvalId, answer, diffSha256: shown, acknowledgeTruncated } = {}) {
      const run = runs.get(id);
      if (!run) throw new RunError("No such run.", 404);
      if (!run.pending || run.pending.request.approvalId !== approvalId) throw new RunError("Nothing is waiting for that decision.", 409);
      const map = { approve: "y", y: "y", skip: "n", n: "n", later: "skip", stop: "quit", quit: "quit" };
      const a = typeof answer === "string" && Object.hasOwn(map, answer) ? map[answer] : null;
      if (!a) throw new RunError("answer must be approve, skip or stop.");
      if (a === "y") {
        if (typeof shown !== "string" || shown.toLowerCase() !== run.pending.diffSha256) {
          throw new RunError("This approval does not match the diff on offer. Reload the run and review the diff again.", 409);
        }
        if (run.pending.truncated && acknowledgeTruncated !== true) {
          throw new RunError(`The diff is ${run.pending.request.plan.fullLength} characters and only the first ${MAX_DIFF} were shown. Acknowledge that to apply it, or skip it and review the change in the repo.`, 409);
        }
      }
      const { resolve: done } = run.pending;
      run.pending = null;
      forgetDiff(run, approvalId);
      emit(run, "decision", { approvalId, answer: a });
      if (a === "quit") run.controller.abort();
      done(a);
      return publicRun(run);
    },

    stop(id) {
      const run = runs.get(id);
      if (!run) throw new RunError("No such run.", 404);
      if (run.status !== "running") return publicRun(run);
      emit(run, "log", { text: "stopping after the current step" });
      run.controller.abort();
      if (run.pending) { const { request, resolve: done } = run.pending; run.pending = null; forgetDiff(run, request.approvalId); done("quit"); }
      return publicRun(run);
    },

    /** Subscribe: replays events after `afterSeq`, then live ones. `fn(null)` means the run ended. */
    subscribe(id, afterSeq, fn) {
      const run = runs.get(id);
      if (!run) return null;
      for (const ev of run.events) if (ev.seq > afterSeq) fn(ev);
      if (run.status !== "running") { fn(null); return () => {}; }
      run.listeners.add(fn);
      return () => run.listeners.delete(fn);
    },
  };

  return { ...head, ...manager };
}

/** What the page shows after an AI run: counts, and the unverified proposals by title. */
function aiSummary(ai) {
  if (!ai || ai.ran === false) return null;
  return {
    route: ai.route, model: ai.model.name, confirmed: ai.counts["confirmed-by-rule"], unverified: ai.counts.unverified,
    partial: ai.partial, stopReason: ai.stopReason, read: ai.units.examined, of: ai.units.units,
    findings: ai.findings.slice(0, 50).map((f) => ({ title: cleanLine(f.title), file: cleanLine(f.url), line: f.line, class: f.class, severity: f.severity })),
  };
}
