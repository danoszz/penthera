/**
 * JSON API for the dashboard. Every route here runs after the gate in
 * ../security.js (Host, Origin, bearer session), so handlers only validate
 * their own input.
 */
import { RunError } from "./runs.js";

const MAX_BODY = 64 * 1024;
const MAX_STREAMS = 16;
const ID = /^[0-9a-f]{16}$/;

export function sendJson(res, status, body, headers = {}) {
  const buf = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": buf.length, ...headers });
  res.end(buf);
}

/** A 413 that the client can read: the rest of the body is not read, and the connection closes after the answer. */
function tooLarge() {
  const e = new RunError("Request body too large.", 413);
  e.close = true;
  return e;
}

export function readJson(req) {
  return new Promise((resolve, reject) => {
    const type = String(req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
    if (type !== "application/json") { reject(new RunError("Send JSON (Content-Type: application/json).", 415)); return; }
    if (Number(req.headers["content-length"]) > MAX_BODY) { reject(tooLarge()); return; }
    let size = 0;
    let over = false;
    const chunks = [];
    req.on("data", (c) => {
      if (over) return;
      size += c.length;
      if (size > MAX_BODY) { over = true; chunks.length = 0; reject(tooLarge()); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      if (over) return;
      if (!size) { resolve({}); return; }
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf-8"))); } catch { reject(new RunError("Body is not valid JSON.")); }
    });
    // A client that hangs up (or an idle socket the server times out) is not an internal error.
    req.on("error", () => reject(new RunError("The request body did not arrive.", 400)));
  });
}

export function stream(req, res, runs, id, onEnd = () => {}) {
  const last = Number(req.headers["last-event-id"]) || 0;
  // The stream is long-lived by design: no idle timeout on its socket. The
  // keep-alive comment below keeps proxies and the browser from giving up.
  req.socket?.setTimeout?.(0);
  res.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-store",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.write(": penthera\n\n");
  const beat = setInterval(() => res.write(": keep-alive\n\n"), 15_000);
  // subscribe() replays history synchronously and calls fn(null) at once for a
  // run that already finished, so end() can run before subscribe() returns.
  let unsubscribe = null;
  let ended = false;
  const end = () => {
    if (ended) return;
    ended = true;
    clearInterval(beat);
    unsubscribe?.();
    onEnd();
    if (!res.writableEnded) res.end();
  };
  unsubscribe = runs.subscribe(id, last, (ev) => {
    if (ended) return;
    if (!ev) { res.write("event: end\ndata: {}\n\n"); end(); return; }
    res.write(`id: ${ev.seq}\nevent: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`);
  });
  if (ended) unsubscribe?.();
  req.on("close", end);
}

/**
 * @returns {(req, res, path: string, query: URLSearchParams) => Promise<boolean>} true when handled
 */
export function createApi({ source, runs, version, settings, maxStreams = MAX_STREAMS }) {
  let streams = 0;
  const routes = [
    ["GET", /^\/api\/meta$/, () => ({ version, demo: source.demo, ...source.meta(), settings: settings.get() })],
    ["GET", /^\/api\/overview$/, () => source.overview()],
    ["GET", /^\/api\/findings$/, () => ({ findings: source.findings(), giants: source.giants ? source.giants() : [] })],
    ["GET", /^\/api\/findings\/([0-9a-f]{16})$/, async (m, q) => {
      const f = await source.finding(m[1], q.get("project") || null);
      if (!f) throw new RunError("No finding with that id in the latest reports.", 404);
      return f;
    }],
    ["GET", /^\/api\/history$/, (_m, q) => {
      const n = (k) => (q.get(k) == null || q.get(k) === "" ? null : Number(q.get(k)));
      const h = source.history(String(q.get("project") || ""), n("a"), n("b"));
      if (!h) throw new RunError("No scans for that project in the reports folder.", 404);
      return h;
    }],
    ["POST", /^\/api\/evidence\/create$/, async (_m, _q, body) => {
      const r = await source.createEvidence(String(body.project || ""));
      if (!r) throw new RunError("No scan report for that project yet. Run a scan first.", 404);
      return r;
    }],
    ["GET", /^\/api\/env$/, (_m, q) => source.env(String(q.get("project") || ""))],
    ["GET", /^\/api\/deps$/, (_m, q) => source.deps(q.get("project") || undefined)],
    ["GET", /^\/api\/ai$/, (_m, q) => source.ai(q.get("project") || undefined)],
    ["GET", /^\/api\/memory$/, () => ({ projects: source.memory() })],
    ["GET", /^\/api\/evidence$/, () => ({ bundles: source.evidence() })],
    ["POST", /^\/api\/evidence\/verify$/, async (_m, _q, body) => {
      if (!ID.test(String(body.id))) throw new RunError("Unknown bundle id.");
      const r = await source.verifyEvidence(body.id);
      if (!r) throw new RunError("No bundle with that id.", 404);
      return r;
    }],
    ["GET", /^\/api\/settings$/, () => settings.get()],
    ["POST", /^\/api\/settings$/, (_m, _q, body) => settings.update(body)],
    ["GET", /^\/api\/runs$/, () => ({ live: runs.list(), past: source.runs() })],
    ["GET", /^\/api\/ai-mode\/models$/, () => runs.aiModels()],
    ["GET", /^\/api\/ai-mode\/consent$/, () => runs.aiConsentLog()],
    ["POST", /^\/api\/runs$/, (_m, _q, body) => runs.start(body)],
    ["POST", /^\/api\/runs\/([0-9a-f]{16})\/decision$/, (m, _q, body) => runs.decide(m[1], body)],
    ["POST", /^\/api\/runs\/([0-9a-f]{16})\/stop$/, (m) => runs.stop(m[1])],
  ];

  return async function handle(req, res, path, query) {
    if (!path.startsWith("/api/")) return false;
    if (path === "/api/report" && req.method === "GET") {
      const project = String(query.get("project") || "");
      const audience = String(query.get("audience") || "auditor");
      const md = source.audienceReport(project, audience);
      if (!md) { sendJson(res, 404, { error: "No report for that project and audience." }); return true; }
      const name = `penthera-${audience}-${project.replace(/^https?:\/\//, "").replace(/[^a-z0-9]+/gi, "-").slice(-40)}.md`;
      const buf = Buffer.from(md);
      res.writeHead(200, { "Content-Type": "text/markdown; charset=utf-8", "Content-Disposition": `attachment; filename="${name}"`, "Content-Length": buf.length });
      res.end(buf);
      return true;
    }
    const sse = path.match(/^\/api\/runs\/([0-9a-f]{16})\/stream$/);
    if (sse && req.method === "GET") {
      if (!runs.get(sse[1])) { sendJson(res, 404, { error: "No such run." }); return true; }
      if (streams >= maxStreams) { sendJson(res, 429, { error: "Too many open run streams. Close a dashboard tab." }, { "Retry-After": "5" }); return true; }
      streams++;
      let counted = true;
      stream(req, res, runs, sse[1], () => { if (counted) { counted = false; streams--; } });
      return true;
    }
    const matching = routes.filter(([, re]) => re.test(path));
    if (!matching.length) { sendJson(res, 404, { error: "Not found." }); return true; }
    const route = matching.find(([method]) => method === req.method);
    if (!route) {
      res.setHeader("Allow", [...new Set(matching.map(([m]) => m))].join(", "));
      sendJson(res, 405, { error: "Method not allowed." });
      return true;
    }
    try {
      const body = req.method === "POST" ? await readJson(req) : null;
      const out = await route[2](path.match(route[1]), query, body || {});
      sendJson(res, 200, out);
    } catch (e) {
      const status = e instanceof RunError ? e.status : 500;
      sendJson(res, status, { error: status === 500 ? "Internal error. Check the terminal running penthera ui." : e.message }, e.close ? { Connection: "close" } : {});
      if (status === 500) process.stderr.write(`  penthera ui: ${e.stack || e.message}\n`);
    }
    return true;
  };
}
