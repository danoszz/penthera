/**
 * JSON API for the dashboard. Every route here runs after the gate in
 * ../security.js (Host, session cookie, Origin), so handlers only validate
 * their own input.
 */
import { RunError } from "./runs.js";

const MAX_BODY = 64 * 1024;
const ID = /^[0-9a-f]{16}$/;

export function sendJson(res, status, body) {
  const buf = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": buf.length });
  res.end(buf);
}

export function readJson(req) {
  return new Promise((resolve, reject) => {
    const type = String(req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
    if (type !== "application/json") { reject(new RunError("Send JSON (Content-Type: application/json).", 415)); return; }
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new RunError("Request body too large.", 413)); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      if (!size) { resolve({}); return; }
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf-8"))); } catch { reject(new RunError("Body is not valid JSON.")); }
    });
    req.on("error", reject);
  });
}

function stream(req, res, runs, id) {
  const last = Number(req.headers["last-event-id"]) || 0;
  res.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-store",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.write(": penthera\n\n");
  const beat = setInterval(() => res.write(": keep-alive\n\n"), 15_000);
  const end = () => { clearInterval(beat); unsubscribe?.(); if (!res.writableEnded) res.end(); };
  const unsubscribe = runs.subscribe(id, last, (ev) => {
    if (!ev) { res.write("event: end\ndata: {}\n\n"); end(); return; }
    res.write(`id: ${ev.seq}\nevent: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`);
  });
  req.on("close", end);
}

/**
 * @returns {(req, res, path: string, query: URLSearchParams) => Promise<boolean>} true when handled
 */
export function createApi({ source, runs, version, settings }) {
  const routes = [
    ["GET", /^\/api\/meta$/, () => ({ version, demo: source.demo, ...source.meta(), settings: settings.get() })],
    ["GET", /^\/api\/overview$/, () => source.overview()],
    ["GET", /^\/api\/findings$/, () => ({ findings: source.findings() })],
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
    ["GET", /^\/api\/deps$/, () => source.deps()],
    ["GET", /^\/api\/ai$/, () => source.ai()],
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
      stream(req, res, runs, sse[1]);
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
      sendJson(res, status, { error: status === 500 ? "Internal error. Check the terminal running penthera ui." : e.message });
      if (status === 500) process.stderr.write(`  penthera ui: ${e.stack || e.message}\n`);
    }
    return true;
  };
}
