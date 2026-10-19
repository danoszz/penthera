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
import { randomBytes } from "node:crypto";
import { normalizeBaseUrl, urlToFilename } from "../../utils/url.js";
import { confineDir } from "./data.js";

const MAX_EVENTS = 5000;
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

  const maxIterations = body.maxIterations == null ? 5 : Number(body.maxIterations);
  if (!Number.isInteger(maxIterations) || maxIterations < 1 || maxIterations > 50) throw new RunError("Max iterations must be a whole number from 1 to 50.");
  return { kind, repo, url, maxIterations, runTests: body.runTests === true };
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
    const ev = { seq: run.events.length + 1, type, ts: new Date().toISOString(), data };
    run.events.push(ev);
    if (run.events.length > MAX_EVENTS) run.events.splice(0, run.events.length - MAX_EVENTS);
    for (const fn of run.listeners) fn(ev);
  }

  function publicRun(run) {
    return {
      id: run.id, kind: run.kind, status: run.status, repo: run.repo, url: run.url,
      startedAt: run.startedAt, pending: run.pending ? run.pending.request : null, summary: run.summary,
    };
  }

  async function execute(run, req) {
    const log = (line) => {
      const text = cleanLine(line);
      emit(run, "log", { text });
      const m = text.match(/^\s*iteration (\d+)\/(\d+)/);
      if (m) emit(run, "iteration", { n: Number(m[1]), of: Number(m[2]) });
      const s = text.match(/^\s*scan: (\d+) findings \((\d+) suppressed\), (\d+) fixable/);
      if (s) emit(run, "scanned", { findings: Number(s[1]), suppressed: Number(s[2]), fixable: Number(s[3]) });
      if (/verified and committed/.test(text)) emit(run, "fix", { status: "verified", text });
      else if (/failed verification, reverted/.test(text)) emit(run, "fix", { status: "failed", text });
      else if (/^\s*not applied:/.test(text)) emit(run, "fix", { status: "not-applied", text });
    };

    if (req.kind === "loop") {
      emit(run, "log", { text: `penthera agent --loop ${req.repo}${req.url ? ` + ${req.url}` : ""}` });
      emit(run, "log", { text: `local only: egress limited to ${req.url ? new URL(req.url).host : "no hosts (repo scan only)"}; nothing is pushed` });
      const loopRun = await deps.runLoop({
        repo: req.repo, url: req.url, maxIterations: req.maxIterations, auto: "off", runTests: req.runTests,
        log, signal: run.controller.signal,
        ask: (q) => new Promise((resolveAnswer) => {
          const approvalId = randomBytes(8).toString("hex");
          const p = q.plan || {};
          const request = {
            approvalId, iteration: q.iteration, index: q.index, total: q.total, memory: q.memory || null,
            plan: {
              title: cleanLine(p.title), recipe: cleanLine(p.recipe), framework: p.framework ? cleanLine(p.framework) : null,
              confidence: cleanLine(p.confidence), source: cleanLine(p.source),
              files: (p.files || []).map(cleanLine), diff: String(p.diff || "").slice(0, 60000),
              findings: (p.findings || []).map((f) => ({ title: cleanLine(f.title), severity: cleanLine(f.severity) })),
              ownerActions: (p.ownerActions || []).map(cleanLine), redacted: Boolean(p.redacted),
            },
          };
          run.pending = { request, resolve: resolveAnswer };
          emit(run, "approval", request);
        }),
      });
      run.summary = {
        stopReason: loopRun.stopReason, error: loopRun.error, totals: loopRun.totals, findings: loopRun.findings,
        branch: loopRun.branch?.fix || null, durationMs: loopRun.durationMs,
        iterations: loopRun.iterations.map((it) => ({
          n: it.n, durationMs: it.durationMs, findings: it.findings,
          fixes: it.fixes.map((f) => ({ title: f.title, recipe: f.recipe, decision: f.decision, status: f.status, commit: f.commit })),
        })),
      };
      const file = deps.saveLoopRun?.(loopRun);
      if (file) emit(run, "log", { text: `loopRun written to ${file}` });
      emit(run, "log", { text: `branch ${run.summary.branch}: nothing was pushed. Merge it yourself when you are happy with it.` });
    } else if (req.kind === "deps" || req.kind === "agents") {
      const stamp = new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-");
      emit(run, "log", { text: req.kind === "deps" ? `penthera deps ${req.repo} (offline)` : `penthera agents ${req.repo} (offline, read-only)` });
      const result = req.kind === "deps"
        ? await deps.scanDeps(req.repo, { onPhase: (m) => log(m) })
        : await deps.scanAgents(req.repo, { onPhase: (m) => log(m) });
      const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const f of result.findings || []) if (c[f.severity] != null) c[f.severity]++;
      const file = deps.writeReport(result, `${req.kind}_${stamp}.json`);
      run.summary = { counts: c, total: (result.findings || []).length, file, grade: result.agents?.grade || null };
      log(`${req.kind === "deps" ? "deps" : "agents"} done: ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low${result.agents ? `, grade ${result.agents.grade}` : ""}`);
      if (file) log(`report written to ${file}`);
    } else {
      const offline = deps.settings().offline;
      emit(run, "log", { text: `penthera${req.url ? ` ${req.url}` : ""}${req.repo ? ` --repo ${req.repo}` : ""} --profile standard${offline ? " --offline" : ""}` });
      const r = await deps.executeScan({ url: req.url, repo: req.repo, profile: "standard", offline, json: true, onPhase: (m) => log(m) });
      const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const f of r.merged.findings) if (c[f.severity] != null) c[f.severity]++;
      const base = `${req.url ? urlToFilename(req.url) : "repo"}_${new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-")}.json`;
      const file = deps.writeReport(r.merged, base);
      run.summary = { counts: c, total: r.merged.findings.length, file };
      log(`scan done: ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low, ${c.info} info`);
      if (file) log(`report written to ${file}`);
    }
  }

  return {
    list: () => [...runs.values()].map(publicRun).reverse(),
    get: (id) => runs.get(id) || null,
    publicRun,

    start(body) {
      if (active && active.status === "running") throw new RunError("A run is already in progress. Stop it first.", 409);
      const req = validateRunRequest(body, deps.projectRoots, deps.confineDir);
      const run = {
        id: randomBytes(8).toString("hex"), kind: req.kind, repo: req.repo, url: req.url, status: "running",
        startedAt: new Date().toISOString(), events: [], listeners: new Set(), pending: null, summary: null,
        controller: new AbortController(),
      };
      runs.set(run.id, run);
      active = run;
      emit(run, "status", { status: "running" });
      execute(run, req)
        .then(() => { run.status = run.controller.signal.aborted ? "stopped" : "done"; })
        .catch((e) => { run.status = "error"; emit(run, "log", { text: `error: ${cleanLine(e.message)}` }); })
        .finally(() => {
          if (run.pending) { run.pending.resolve("quit"); run.pending = null; }
          emit(run, "status", { status: run.status, summary: run.summary });
          for (const fn of run.listeners) fn(null);
          run.listeners.clear();
        });
      return publicRun(run);
    },

    decide(id, { approvalId, answer } = {}) {
      const run = runs.get(id);
      if (!run) throw new RunError("No such run.", 404);
      if (!run.pending || run.pending.request.approvalId !== approvalId) throw new RunError("Nothing is waiting for that decision.", 409);
      const map = { approve: "y", y: "y", skip: "n", n: "n", later: "skip", stop: "quit", quit: "quit" };
      const a = map[answer];
      if (!a) throw new RunError("answer must be approve, skip or stop.");
      const { resolve: done } = run.pending;
      run.pending = null;
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
      if (run.pending) { const { resolve: done } = run.pending; run.pending = null; done("quit"); }
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
}
