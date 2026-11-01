/**
 * `penthera ui`: the local dashboard server.
 *
 * node:http only, bound to 127.0.0.1, random port by default. Static files
 * come from an allowlist built at startup (no path from a request ever
 * reaches the filesystem), the API is JSON plus SSE for live runs, and every
 * request goes through the gate in ./security.js first.
 */
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { readdirSync, readFileSync, lstatSync, mkdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, relative, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import {
  SECURITY_HEADERS, createSession, createAuthLimiter, hostAllowed, originAllowed, isStateChanging,
} from "./security.js";
import { createApi, sendJson, readJson } from "./api/routes.js";
import { RunError } from "./api/runs.js";
import { createRunManager } from "./api/runs.js";
import { createDataSource } from "./api/data.js";
import { memoryRoot as defaultMemoryRoot } from "../../lib/memory/index.js";

export const STATIC_DIR = fileURLToPath(new URL("./static/", import.meta.url));

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".txt": "text/plain; charset=utf-8",
};

/** Map of URL path -> { body, type } for every file under the static dir, read once. */
export function loadStatic(dir = STATIC_DIR) {
  const files = new Map();
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile() && TYPES[extname(e.name)]) {
        files.set(`/${relative(dir, p).split("\\").join("/")}`, { body: readFileSync(p), type: TYPES[extname(e.name)] });
      }
    }
  };
  walk(dir);
  files.set("/", files.get("/index.html"));
  return files;
}

function plain(res, status, text, headers = {}) {
  res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8", ...headers });
  res.end(`${text}\n`);
}

/** The Settings screen's state. Offline is on by default in the dashboard. */
// A finished owner step: a hash, so the file still says nothing about a project.
const DONE_ID = /^[0-9a-f]{16}$/;
const MAX_DONE = 500;

export function createSettings(initial = {}) {
  const state = { offline: initial.offline !== false, memoryRoot: initial.memoryRoot, reportsDir: initial.reportsDir };
  // The port is random, so the browser's storage starts empty on every restart.
  // The mode lives in the data folder instead: one word, no paths, nothing about a project.
  const file = initial.file;
  if (file) try {
    const saved = JSON.parse(readFileSync(file, "utf8"));
    state.ux = validUx(saved.ux);
    state.done = (Array.isArray(saved.done) ? saved.done : []).filter((id) => DONE_ID.test(id));
  } catch { /* first run, or an unreadable file: setup runs */ }
  state.done ||= [];
  return {
    get: () => ({ ...state }),
    update(body) {
      if (body && typeof body.offline === "boolean") state.offline = body.offline;
      const ux = validUx(body?.ux);
      const done = DONE_ID.test(body?.doneAction) && !state.done.includes(body.doneAction) ? body.doneAction : null;
      if (ux || done) {
        if (ux) state.ux = ux;
        if (done) state.done = [...state.done, done].slice(-MAX_DONE);
        if (file) try {
          mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
          // Written beside it and renamed, so a symlink at `file` is replaced, never followed.
          const next = `${file}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
          writeFileSync(next, `${JSON.stringify({ ux: state.ux, ...(state.done.length ? { done: state.done } : {}) })}\n`, { mode: 0o600, flag: "wx" });
          renameSync(next, file);
        } catch { /* read-only data folder: this session only */ }
      }
      return { ...state };
    },
  };
}

const validUx = (ux) => (ux === "simple" || ux === "advanced" ? ux : undefined);

/**
 * Start the dashboard.
 * @param {object} opts
 * @param {number} [opts.port=0]
 * @param {string[]} [opts.projects]   folders the dashboard may read and run in (default: cwd)
 * @param {string} [opts.reportsDir]   report JSON folder (default: <first project>/reports, which
 *                                     must not be a symlink; an explicit folder may be one)
 * @param {boolean} [opts.demo]        seed realistic fake data, no disk reads
 * @param {string} [opts.version]
 * @param {object} [opts.source]       data source override (tests)
 * @param {object} [opts.runDeps]      run manager deps override (tests)
 * @param {{ request?: number, idle?: number }} [opts.timeouts]  ms; the event stream is exempt from idle
 * @returns {Promise<{ server, port, url, origin, session, close }>}
 */
export async function startUiServer(opts = {}) {
  const projects = (opts.projects?.length ? opts.projects : [process.cwd()]).map((p) => resolve(p));
  const reportsDir = resolve(opts.reportsDir || join(projects[0], "reports"));
  // A cloned repo can ship `reports -> ../elsewhere`. The default folder is
  // taken only when it is a real folder (or missing); --reports is the user's
  // own choice and may point anywhere.
  if (!opts.reportsDir && !opts.demo && !opts.source) {
    let st = null;
    try { st = lstatSync(reportsDir); } catch { /* missing: created on first write */ }
    if (st?.isSymbolicLink()) throw new Error(`${reportsDir} is a symlink. Pass --reports <dir> to use it on purpose.`);
  }
  const home = process.env.PENTHERA_HOME ? resolve(process.env.PENTHERA_HOME) : join(homedir(), ".penthera");
  const memoryRoot = opts.memoryRoot || defaultMemoryRoot();
  const settings = createSettings({ offline: true, memoryRoot, reportsDir, file: opts.demo || opts.source ? null : join(dirname(memoryRoot), "ui.json") });

  let source = opts.source;
  let runDeps = opts.runDeps;
  if (!source && opts.demo) {
    const demo = await import("./api/demo.js");
    source = demo.createDemoSource({ settings, version: opts.version });
    runDeps = runDeps || demo.demoRunDeps();
  }
  if (!source) source = createDataSource({ projects, reportsDir, home, memoryRoot, settings, version: opts.version });
  if (!runDeps) {
    const [{ runLoop, loopVerdict }, { executeScan }, { scanDeps }, { scanAgents }, { createOllama }, { runAiMode, attachProposals }] = await Promise.all([
      import("../agent/loop.js"), import("../cli/run-scan.js"),
      import("../../lib/deps/index.js"), import("../../lib/agents/index.js"),
      import("../../lib/ai/ollama.js"), import("../../lib/ai/index.js"),
    ]);
    runDeps = {
      runLoop,
      loopVerdict,
      executeScan,
      scanDeps,
      scanAgents,
      // AI mode (docs/ai-mode.md): Ollama on 127.0.0.1 only. Absent in --demo.
      ollama: createOllama(),
      runAiMode,
      attachProposals,
      saveLoopRun: (l) => source.saveLoopRun?.(l),
      writeReport: (result, name) => source.writeReport(name, result),
    };
  }
  const runs = createRunManager({ ...runDeps, settings: settings.get, projectRoots: source.projectRoots || projects });
  const api = createApi({ source, runs, version: opts.version || "dev", settings });
  const files = loadStatic(opts.staticDir);
  const session = createSession();
  const limiter = createAuthLimiter(opts.limits);
  let port = 0;
  const tooMany = (res, wait) => {
    res.writeHead(429, { "Content-Type": "text/plain; charset=utf-8", "Retry-After": String(wait) });
    res.end("Too many requests without a session. Rate limit exceeded.\n");
  };

  const server = createServer(async (req, res) => {
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
    try {
      // 1. Host: blocks DNS rebinding. Before anything else, including the token.
      if (!hostAllowed(req.headers.host, port)) return plain(res, 421, "Host not allowed. Open the dashboard at http://127.0.0.1 with the URL penthera ui printed.");

      // No dot segments, encoded slashes or dots, backslashes or NULs: the URL
      // parser would normalise some of them, and none has a legitimate use here.
      const rawPath = String(req.url || "/").split("?")[0];
      if (!rawPath.startsWith("/") || /(^|\/)\.\.?(\/|$)|%2e|%2f|%5c|%00|\\|\/\//i.test(rawPath)) return plain(res, 400, "Bad path.");
      const url = new URL(req.url, `http://127.0.0.1:${port}`);
      if (req.method === "OPTIONS") return plain(res, 405, "Method not allowed.", { Allow: "GET, POST" });

      // Static files: the page and its scripts hold no data, so they need no
      // session (there is no cookie to carry one). Everything under /api does.
      if (!url.pathname.startsWith("/api/")) {
        if (req.method !== "GET" && req.method !== "HEAD") return plain(res, 405, "Method not allowed.", { Allow: "GET" });
        const file = files.get(url.pathname);
        if (!file) return plain(res, 404, "Not found.");
        res.writeHead(200, { "Content-Type": file.type, "Content-Length": file.body.length });
        return res.end(req.method === "HEAD" ? undefined : file.body);
      }

      // 3. Origin on anything that changes state, the sign-in included.
      if (isStateChanging(req.method) && !originAllowed(req, port)) {
        const wait = session.check(req.headers.authorization) ? 0 : limiter.hit(req.method);
        if (wait) return tooMany(res, wait);
        return sendJson(res, 403, { error: "Cross-origin request refused." });
      }

      // 2. Session: the page posts the one-time token from the URL fragment
      // and gets the session id back, once.
      if (url.pathname === "/api/session" && req.method === "POST") {
        let body;
        try { body = await readJson(req); } catch (e) { return sendJson(res, e instanceof RunError ? e.status : 400, { error: e.message }, e.close ? { Connection: "close" } : undefined); }
        const sid = session.redeem(typeof body?.token === "string" ? body.token : "");
        if (!sid) {
          const wait = limiter.hit(req.method);
          if (wait) return tooMany(res, wait);
          return sendJson(res, 403, { error: "This link was already used or is wrong. Restart penthera ui for a new one." });
        }
        return sendJson(res, 200, { session: sid });
      }
      if (!session.check(req.headers.authorization)) {
        const wait = limiter.hit(req.method);
        if (wait) return tooMany(res, wait);
        return sendJson(res, 401, { error: "Not signed in. Open the one-time URL printed by penthera ui." });
      }

      if (await api(req, res, url.pathname, url.searchParams)) return;
      return sendJson(res, 404, { error: "Not found." });
    } catch (e) {
      process.stderr.write(`  penthera ui: ${e.stack || e.message}\n`);
      if (!res.headersSent) plain(res, 500, "Internal error.");
      else res.end();
    }
  });
  // Bounded request reads and idle sockets; the run event stream turns the
  // idle timeout off for its own socket (routes.js) and keeps itself alive.
  server.headersTimeout = 20_000;
  server.requestTimeout = opts.timeouts?.request ?? 30_000;
  server.timeout = opts.timeouts?.idle ?? 120_000;
  if (server.requestTimeout) server.headersTimeout = Math.min(server.headersTimeout, server.requestTimeout);

  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(opts.port ?? 0, "127.0.0.1", () => { server.off("error", reject); resolveListen(); });
  });
  port = server.address().port;
  const origin = `http://127.0.0.1:${port}`;
  return {
    server,
    port,
    origin,
    url: `${origin}/#t=${session.bootstrap}`,
    session,
    runs,
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }),
  };
}
