/**
 * `penthera ui`: the local dashboard server.
 *
 * node:http only, bound to 127.0.0.1, random port by default. Static files
 * come from an allowlist built at startup (no path from a request ever
 * reaches the filesystem), the API is JSON plus SSE for live runs, and every
 * request goes through the gate in ./security.js first.
 */
import { createServer } from "node:http";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import {
  SECURITY_HEADERS, createSession, createAuthLimiter, hostAllowed, originAllowed, isStateChanging,
} from "./security.js";
import { createApi, sendJson } from "./api/routes.js";
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
export function createSettings(initial = {}) {
  const state = { offline: initial.offline !== false, memoryRoot: initial.memoryRoot, reportsDir: initial.reportsDir };
  return {
    get: () => ({ ...state }),
    update(body) {
      if (body && typeof body.offline === "boolean") state.offline = body.offline;
      return { ...state };
    },
  };
}

/**
 * Start the dashboard.
 * @param {object} opts
 * @param {number} [opts.port=0]
 * @param {string[]} [opts.projects]   folders the dashboard may read and run in (default: cwd)
 * @param {string} [opts.reportsDir]   report JSON folder (default: <first project>/reports)
 * @param {boolean} [opts.demo]        seed realistic fake data, no disk reads
 * @param {string} [opts.version]
 * @param {object} [opts.source]       data source override (tests)
 * @param {object} [opts.runDeps]      run manager deps override (tests)
 * @returns {Promise<{ server, port, url, origin, session, close }>}
 */
export async function startUiServer(opts = {}) {
  const projects = (opts.projects?.length ? opts.projects : [process.cwd()]).map((p) => resolve(p));
  const reportsDir = resolve(opts.reportsDir || join(projects[0], "reports"));
  const home = process.env.PENTHERA_HOME ? resolve(process.env.PENTHERA_HOME) : join(homedir(), ".penthera");
  const memoryRoot = opts.memoryRoot || defaultMemoryRoot();
  const settings = createSettings({ offline: true, memoryRoot, reportsDir });

  let source = opts.source;
  let runDeps = opts.runDeps;
  if (!source && opts.demo) {
    const demo = await import("./api/demo.js");
    source = demo.createDemoSource({ settings, version: opts.version });
    runDeps = runDeps || demo.demoRunDeps();
  }
  if (!source) source = createDataSource({ projects, reportsDir, home, memoryRoot, settings, version: opts.version });
  if (!runDeps) {
    const [{ runLoop }, { executeScan }, { scanDeps }, { scanAgents }] = await Promise.all([
      import("../agent/loop.js"), import("../cli/run-scan.js"),
      import("../../lib/deps/index.js"), import("../../lib/agents/index.js"),
    ]);
    runDeps = {
      runLoop,
      executeScan,
      scanDeps,
      scanAgents,
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

      // 2. Session: the one-time URL token becomes an HttpOnly cookie.
      const token = url.searchParams.get("token");
      if (token != null && req.method === "GET" && url.pathname === "/") {
        const sid = session.redeem(token);
        if (!sid) { const wait = limiter.hit(req.method); if (wait) return tooMany(res, wait); }
        if (!sid) return plain(res, 403, "This link was already used or is wrong. Restart `penthera ui` for a new one.");
        res.writeHead(303, { "Set-Cookie": session.cookie(sid), Location: "/" });
        return res.end();
      }
      if (!session.check(req.headers.cookie)) {
        const wait = limiter.hit(req.method);
        if (wait) return tooMany(res, wait);
        return url.pathname.startsWith("/api/")
          ? sendJson(res, 401, { error: "Not signed in. Open the one-time URL printed by penthera ui." })
          : plain(res, 401, "Open the one-time URL printed by `penthera ui` in the terminal.");
      }

      // 3. Origin on anything that changes state.
      if (isStateChanging(req.method) && !originAllowed(req, port)) {
        return sendJson(res, 403, { error: "Cross-origin request refused." });
      }

      if (await api(req, res, url.pathname, url.searchParams)) return;

      if (req.method !== "GET" && req.method !== "HEAD") return plain(res, 405, "Method not allowed.", { Allow: "GET" });
      const file = files.get(url.pathname);
      if (!file) return plain(res, 404, "Not found.");
      res.writeHead(200, { "Content-Type": file.type, "Content-Length": file.body.length });
      res.end(req.method === "HEAD" ? undefined : file.body);
    } catch (e) {
      process.stderr.write(`  penthera ui: ${e.stack || e.message}\n`);
      if (!res.headersSent) plain(res, 500, "Internal error.");
      else res.end();
    }
  });
  server.headersTimeout = 20_000;
  server.requestTimeout = 0; // SSE streams stay open

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
    url: `${origin}/?token=${session.bootstrap}`,
    session,
    runs,
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }),
  };
}
