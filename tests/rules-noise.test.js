/**
 * Noise at the top of the agent brief (E9): four rules that put a hint or a
 * comment in "Act on", each fixed without dropping a real finding.
 *
 *   1. Supabase `auth.getSession()` reads the cookie unverified, so it is not an
 *      auth check (Server Actions, route records); `getUser()` and `getClaims()` are.
 *   2. The route RISK patterns read code with comments blanked and strings kept.
 *   3. A route-level command-injection whose every shell call runs fixed text is
 *      medium, potential; anything unresolved stays critical.
 *   4. Rate-limit and timing-compare hints are low.
 */
import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { callsAuth, uncheckedActions } from "../lib/whitebox/server-actions.js";
import { routeRecord } from "../lib/attack-surface.js";
import { SESSION_CHECK_RE, SHELL_EXEC_RE, riskPatterns, discoverFrameworkRoutes } from "../lib/whitebox/frameworks.js";
import { codeMatcher } from "../lib/whitebox/js-lex.js";
import { probeRateLimit } from "../lib/fix/recipes/rate-limit.js";
import { scanRepo } from "../src/scan-repo.js";
import { isSevere } from "../src/report/exit.js";

const temps = [];
afterAll(() => temps.forEach((d) => rmSync(d, { recursive: true, force: true })));
function repo(files) {
  const dir = mkdtempSync(join(tmpdir(), "penthera-rules-noise-"));
  temps.push(dir);
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}
const risks = (src) => routeRecord("/api/x", "app/api/x/route.ts", src, ["GET"]).securityPatterns.filter((p) => p.startsWith("RISK:"));
const authOf = (src) => routeRecord("/api/x", "app/api/x/route.ts", src, ["GET"]).auth;

// ── 1. Supabase getSession ──────────────────────────────────────────────

const ACTION = (check) => `"use server";\nimport { createClient } from "@/utils/supabase/server";\nexport async function addTodo(text) {\n  const supabase = await createClient();\n  ${check}\n  await supabase.from("todos").insert({ text });\n}\n`;
const unchecked = (src) => uncheckedActions(src).hits.map((h) => h.name);

describe("Supabase auth.getSession() is not an auth check", () => {
  it("reports a Server Action that only calls supabase.auth.getSession()", () => {
    expect(unchecked(ACTION("const { data: { session } } = await supabase.auth.getSession();"))).toEqual(["addTodo"]);
  });
  it("reports it in every spelling: optional chaining, a line break, a comment between", () => {
    expect(unchecked(ACTION("await supabase?.auth?.getSession();"))).toEqual(["addTodo"]);
    expect(unchecked(ACTION("await supabase.auth\n    .getSession();"))).toEqual(["addTodo"]);
    expect(unchecked(ACTION("await supabase.auth /* cookie */ .getSession();"))).toEqual(["addTodo"]);
    expect(unchecked(ACTION("const { auth } = supabase; await auth.getSession();"))).toEqual(["addTodo"]);
  });
  it("accepts supabase.auth.getUser() and getClaims()", () => {
    expect(unchecked(ACTION("const { data: { user } } = await supabase.auth.getUser();"))).toEqual([]);
    expect(unchecked(ACTION("const { data } = await supabase.auth.getClaims();"))).toEqual([]);
  });
  it("leaves next-auth's bare getSession and other session helpers as they were", () => {
    expect(unchecked(ACTION("const session = await getSession();"))).toEqual([]);
    expect(callsAuth("await auth.api.getSession({ headers: await headers() })")).toBe(true); // better-auth verifies on the server
    expect(callsAuth("await sessionStore.getSession(id)")).toBe(true);
    expect(callsAuth("await oauth.getSession()")).toBe(true);
  });
  it("route records: getSession() from Supabase is public, getUser() and next-auth's getSession() are user", () => {
    expect(authOf("export async function GET(){ const { data } = await supabase.auth.getSession(); }")).toEqual(["public"]);
    expect(authOf("export async function GET(){ const { data } = await supabase.auth.getUser(); }")).toEqual(["user"]);
    expect(authOf("export async function GET(){ const { data } = await supabase.auth.getClaims(); }")).toEqual(["user"]);
    expect(authOf("export async function GET(){ const session = await getSession(); }")).toEqual(["user"]);
    expect(authOf("export async function GET(){ const s = await getSessionUser(req); }")).toEqual(["user"]);
  });
  it("framework routes read the same session check", () => {
    const dir = repo({
      "routes/a.js": "const express = require('express'); const router = express.Router();\nrouter.get('/a', async (req, res) => { const { data } = await supabase.auth.getSession(); res.json(data); });\nmodule.exports = router;\n",
      "routes/b.js": "const express = require('express'); const router = express.Router();\nrouter.get('/b', async (req, res) => { const s = await getSession(req); res.json(s); });\nmodule.exports = router;\n",
    });
    expect(discoverFrameworkRoutes(dir).map((r) => [r.url, r.auth.join("+")])).toEqual([["/a", "public"], ["/b", "user"]]);
  });
  it("matches getSession linearly, whatever whitespace stands before it", () => {
    const pad = " ".repeat(200000);
    const s = Date.now();
    expect(SESSION_CHECK_RE.test(`auth.${pad}getSession(`.repeat(5) + `${pad}x`)).toBe(false);
    expect(Date.now() - s).toBeLessThan(2000);
  });
});

// ── 2. RISK patterns and comments ───────────────────────────────────────

describe("route RISK patterns: low hints skip comments, serious sinks never do", () => {
  it("a low hint in a comment is no finding", () => {
    expect(risks("// never send err.message, origin || \"*\" here\nexport async function GET(){ return Response.json({ ok: 1 }) }\n")).toEqual([]);
    expect(risks("export async function POST(req){ const b = JSON.parse(await req.text()); } // add .catch later\n")).toEqual(["RISK:json-parse-unguarded"]);
  });
  it("eval, innerHTML and exec match the raw text, comments included (Vercel 01M77P03MJR568HXT0BKQZ1ZTE)", () => {
    expect(risks("// eval( innerHTML exec(\nexport function GET(){}\n")).toEqual(["RISK:eval", "RISK:innerHTML", "RISK:command-injection"]);
    expect(riskPatterns("// eval( innerHTML exec(\nrouter.get('/x', h);\n")).toEqual(["RISK:eval", "RISK:innerHTML", "RISK:command-injection"]);
  });
  it("real use is a finding, a property named by a string too", () => {
    expect(risks("export function GET(){ el.innerHTML = x; }")).toEqual(["RISK:innerHTML"]);
    expect(risks("export function GET(){ el[\"innerHTML\"] = x; }")).toEqual(["RISK:innerHTML"]);
    expect(risks("export async function GET(){ try {} catch (err) { return Response.json({ e: err.message }) } }")).toEqual(["RISK:error-leak"]);
    expect(risks("export function GET(req){ return eval/* x */(req.url) }")).toEqual(["RISK:eval"]);
  });
  it("a lexer trick that fakes a comment can't hide an exec: a quote-bearing regex after a block, then a continued string", () => {
    const src = "import { exec } from 'child_process';\nif (a) {}\n/[\"']/.test(s);\nconst t = 'x\\\n/* ';\nexport async function POST(req) { exec((await req.json()).cmd); }\n";
    expect(risks(src)).toContain("RISK:command-injection");
  });
  it("end of input, and linear on a file full of comments", () => {
    expect(risks("")).toEqual([]);
    const re = new RegExp(SHELL_EXEC_RE.source, "g");
    const gen = (n) => "// exec( innerHTML\n".repeat(n);
    const ms = (n) => { const src = gen(n); codeMatcher(src).has(re); const t = process.hrtime.bigint(); for (let k = 0; k < 3; k++) { codeMatcher(src).has(re); riskPatterns(src); } return Number(process.hrtime.bigint() - t) / 1e6; };
    const small = Math.max(ms(4000), 0.5);
    expect(ms(32000) / small).toBeLessThan(24);
  });
});

// ── 3. command-injection in a route stays critical ─────────────────────

describe("command-injection in a route stays critical: no fixed-text downgrade", () => {
  const routeFinding = (r) => r.findings.find((f) => f.source === "static-analysis" && f.pattern === "command-injection");
  const failsRun = async (files) => { const r = await scanRepo(repo(files)); const f = routeFinding(r); expect(f).toMatchObject({ severity: "critical" }); expect(isSevere(f)).toBe(true); expect(f.confidence).toBeUndefined(); return f; };
  it("a route that runs only fixed text: still critical (a downgrade was bypassed three times)", async () => {
    await failsRun({ "app/api/version/route.ts": "import { execSync } from 'node:child_process';\nexport function GET() {\n  return Response.json({ sha: execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim() });\n}\n" });
  });
  it("Vercel 01M77J8S704B4DF7BQ5H3Q3EA7: request data inside a template, then a literal call", async () => {
    await failsRun({ "app/api/run/route.ts": "import { exec } from 'child_process';\nexport async function GET(request) {\n  const q = new URL(request.url).searchParams.get('q');\n  const out = `${exec(q)}`;\n  exec('git status');\n  return Response.json({ out });\n}\n" });
  });
  it("Vercel 01M77J94SK530Y7RAV4E3MZ06Q: a fixed interpreter fed request data through options.input", async () => {
    await failsRun({ "app/api/run/route.ts": "import { execSync } from 'child_process';\nexport async function POST(req) {\n  const { code } = await req.json();\n  return Response.json({ out: execSync('python3', { input: code }).toString() });\n}\n" });
  });
  it("Vercel 01M77P23YCTXMXYHJ8HR737R59: a destructured, renamed request body piped to a spawned interpreter", async () => {
    await failsRun({ "app/api/run/route.ts": "import { spawn } from 'child_process';\nimport { Readable } from 'stream';\nexport async function POST({ body: inputStream }) {\n  const p = spawn('sh');\n  Readable.fromWeb(inputStream).pipe(p.stdin);\n  return new Response('ok');\n}\n" });
  });
  it("an Express route the sink scan finds tainted: one critical finding, the sink's", async () => {
    const r = await scanRepo(repo({ "routes/run.js": "const express = require('express');\nconst { exec } = require('child_process');\nconst router = express.Router();\nrouter.post('/run', (req, res) => { exec('git log ' + req.body.ref, () => res.end()); });\nmodule.exports = router;\n" }));
    const all = r.findings.filter((f) => f.category === "code-pattern" && f.pattern === "command-injection");
    expect(all).toHaveLength(1);
    expect(all[0]).toMatchObject({ severity: "critical", source: "static-analysis" });
  });
});

// ── 4. hardening hints are low ──────────────────────────────────────────

describe("rate-limit hints are low", () => {
  it("a public route that calls a paid API with no rate limit", async () => {
    const r = await scanRepo(repo({ "app/api/chat/route.ts": "import OpenAI from 'openai';\nconst openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });\nexport async function POST(req) { return Response.json(await openai.responses.create({ model: 'x', input: 'hi' })); }\n" }));
    const f = r.findings.find((x) => x.category === "rate-limiting" && /Public endpoint/.test(x.title));
    expect(f).toMatchObject({ severity: "low" });
    expect(isSevere(f)).toBe(false);
  });
  it("a login route with no rate limit", () => {
    const [f] = probeRateLimit("server.js", "const express = require('express');\nconst app = express();\napp.post('/login', (req, res) => res.json({}));\n", "express");
    expect(f).toMatchObject({ severity: "low", category: "rate-limiting" });
  });
});
