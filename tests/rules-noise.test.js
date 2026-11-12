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
import { SESSION_CHECK_RE, SHELL_EXEC_RE, riskPatterns, commandsConstant, discoverFrameworkRoutes } from "../lib/whitebox/frameworks.js";
import { constantCommands } from "../lib/whitebox/code-sinks.js";
import { codeMatcher } from "../lib/whitebox/js-lex.js";
import { probeRateLimit } from "../lib/fix/recipes/rate-limit.js";
import { scanRepo } from "../src/scan-repo.js";
import { bucketOf } from "../src/report/counts.js";
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

describe("route RISK patterns skip comments, not code", () => {
  it("a word in a comment is no finding", () => {
    expect(risks("// never send err.message or set innerHTML, never eval( or exec( here\n/* spawn( execSync origin || \"*\" */\nexport async function GET(){ return Response.json({ ok: 1 }) }\n")).toEqual([]);
    expect(risks("/**\n * Uses innerHTML and execSync for nothing.\n */\nexport function GET(){}\n")).toEqual([]);
  });
  it("real use is still a finding", () => {
    expect(risks("export function GET(){ el.innerHTML = x; }")).toEqual(["RISK:innerHTML"]);
    expect(risks("export async function GET(){ try {} catch (err) { return Response.json({ e: err.message }) } }")).toEqual(["RISK:error-leak"]);
    expect(risks("export function GET(req){ return eval(req.url) }")).toEqual(["RISK:eval"]);
    expect(risks("export function GET(req){ const origin = req.headers.get('origin'); const allow = origin || \"*\"; }")).toEqual(["RISK:cors-wildcard"]);
  });
  it("a property named by a string still matches: strings are never masked", () => {
    expect(risks("export function GET(){ el[\"innerHTML\"] = x; }")).toEqual(["RISK:innerHTML"]);
    expect(risks("export function GET(){ el['innerHTML'] = x; }")).toEqual(["RISK:innerHTML"]);
    expect(risks("export function GET(){ el[`innerHTML`] = x; }")).toEqual(["RISK:innerHTML"]);
  });
  it("a comment padded into the call still matches (comments blank to spaces)", () => {
    expect(risks("export function GET(req){ return eval/* x */(req.url) }")).toEqual(["RISK:eval"]);
  });
  it("a comment the lexer may have misread keeps the match: a regex literal after a block", () => {
    // The lexer reads `/a\/*/` after `}` as a division, then `/*` as a comment opener.
    expect(risks("function f(){}\n/a\\/*/.test(s); el.innerHTML = x;\nexport function GET(){}\n")).toEqual(["RISK:innerHTML"]);
    expect(risks("if (a) {}\n/[//]/.test(s); el.innerHTML = x;\nexport function GET(){}\n")).toEqual(["RISK:innerHTML"]);
  });
  it("a comment after a `/` on its line keeps the match (the safe side)", () => {
    expect(risks("const u = \"https://x\"; // err.message\nexport function GET(){}\n")).toEqual(["RISK:error-leak"]);
  });
  it("end of input: a last comment line with no newline, an unclosed comment, an unclosed string", () => {
    expect(risks("export function GET(){}\n// innerHTML")).toEqual([]);
    expect(risks("export function GET(){}\n/* innerHTML")).toEqual([]);
    expect(risks("")).toEqual([]);
    expect(risks("x = \"/* innerHTML")).toEqual(["RISK:innerHTML"]);
  });
  it("a .catch in a comment does not guard JSON.parse", () => {
    expect(risks("export async function POST(req){ const b = JSON.parse(await req.text()); } // add .catch later\n")).toEqual(["RISK:json-parse-unguarded"]);
    expect(risks("export async function POST(req){ const b = await req.json().catch(() => ({})); JSON.parse(b.x); }")).toEqual([]);
  });
  it("framework routes skip comments too", () => {
    expect(riskPatterns("// eval( innerHTML exec(\nrouter.get('/x', h);\n")).toEqual([]);
    expect(riskPatterns("router.get('/x', (req, res) => { el['innerHTML'] = req.query.x; });\n")).toEqual(["RISK:innerHTML"]);
  });
  it("stays linear on a file full of commented matches", () => {
    const re = new RegExp(SHELL_EXEC_RE.source, "g");
    const gen = (n) => "// exec( innerHTML\n".repeat(n);
    const ms = (n) => { const src = gen(n); codeMatcher(src).has(re); const s = process.hrtime.bigint(); for (let k = 0; k < 3; k++) codeMatcher(src).has(re); return Number(process.hrtime.bigint() - s) / 1e6; };
    const small = Math.max(ms(4000), 0.5);
    expect(ms(32000) / small).toBeLessThan(24);
  });
});

// ── 3. command-injection with fixed text ────────────────────────────────

const CONST_EXEC = "import { execSync } from \"node:child_process\";\nexport function GET() {\n  const sha = execSync(\"git rev-parse HEAD\", { encoding: \"utf8\" }).trim();\n  return Response.json({ sha });\n}\n";
const shellFixed = (src) => constantCommands(src, new RegExp(SHELL_EXEC_RE.source, "g"));

describe("constantCommands: is every shell call fixed text?", () => {
  it("yes for literals, literal argument lists, options objects and callbacks", () => {
    expect(shellFixed(CONST_EXEC)).toBe(true);
    expect(shellFixed("import { spawn } from 'child_process';\nspawn('git', ['status'], { stdio: 'inherit' });\n")).toBe(true);
    expect(shellFixed("const { exec } = require('child_process');\nexec('ls -la', (err, out) => {});\n")).toBe(true);
    expect(shellFixed("import * as cp from 'child_process';\ncp.execSync(`git log -1`, { env: { ...process.env, A: '1' } });\n")).toBe(true);
  });
  it("no for any command that is not a literal", () => {
    expect(shellFixed("import { execSync } from 'child_process';\nexport async function POST(req){ const { cmd } = await req.json(); execSync(cmd) }\n")).toBe(false);
    expect(shellFixed("import { execSync } from 'child_process';\nexport async function POST(req){ const b = await req.json(); execSync(`git log ${b.ref}`) }\n")).toBe(false);
    expect(shellFixed("import { execSync } from 'child_process';\nexecSync('git log ' + ref);\n")).toBe(false);
    expect(shellFixed("import { spawn } from 'child_process';\nspawn('git', ['log', ref]);\n")).toBe(false);
    expect(shellFixed("import { spawn } from 'child_process';\nspawn('git', args);\n")).toBe(false);
    expect(shellFixed("import { execSync } from 'child_process';\nexecSync('ls', opts);\n")).toBe(false);
    expect(shellFixed("import { execSync } from 'child_process';\nexecSync('ls', { ...body });\n")).toBe(false);
  });
  // An attacker who wants a real injection read as fixed text would hide the
  // tainted call next to a constant one. Every way to reach exec that the
  // check cannot read as a direct call says "no", so the finding stays critical.
  it("no when an exec function is aliased, renamed, picked by a string or passed as a value", () => {
    const tail = "\nexport async function POST(req){ execSync('git status'); run((await req.json()).x) }\n";
    expect(shellFixed("import { exec, execSync } from 'child_process';\nconst run = exec;" + tail)).toBe(false);
    expect(shellFixed("import { execSync, exec as run } from 'child_process';" + tail)).toBe(false);
    expect(shellFixed("const { exec: run, execSync } = require('child_process');" + tail)).toBe(false);
    expect(shellFixed("import { exec, execSync } from 'child_process'; import { promisify } from 'util';\nconst run = promisify(exec);" + tail)).toBe(false);
    expect(shellFixed("import { exec, exec as run, execSync } from '@/lib/sh';" + tail)).toBe(false);
    expect(shellFixed("import * as cp from 'child_process';\ncp.execSync('ls'); cp['exec']((await req.json()).x);\n")).toBe(false);
    expect(shellFixed("import * as cp from 'child_process';\nconst x = cp; cp.execSync('ls'); x.exec(cmd);\n")).toBe(false);
    expect(shellFixed("import { execSync } from 'child_process';\nwrap({ execSync }); execSync('ls');\n")).toBe(false);
  });
  it("no for a call in a string, an unclosed call, or no call at all", () => {
    expect(shellFixed("import { execSync } from 'child_process';\nconst s = `${execSync(cmd)}`; execSync('ls');\n")).toBe(false);
    expect(shellFixed("import { execSync } from 'child_process';\nexecSync('ls'\n")).toBe(false);
    expect(shellFixed("const help = 'call execSync(x)';\n")).toBe(false);
  });
  it("no when a regex literal after a block hides a call in a false comment", () => {
    expect(shellFixed("import { execSync } from 'child_process';\nexecSync('ls');\nif (a) {}\n/a\\/*/.test(s); execSync(cmd);\n")).toBe(false);
  });
  it("a RegExp exec in the same file is an unknown call: no", () => {
    expect(shellFixed("import { execSync } from 'child_process';\nexecSync('ls'); /v(\\d)/.exec(v);\n")).toBe(false);
  });
  it("route records carry the answer", () => {
    expect(routeRecord("/api/x", "app/api/x/route.ts", CONST_EXEC, ["GET"]).commandsConstant).toBe(true);
    expect(routeRecord("/api/x", "app/api/x/route.ts", "export function GET(){}", ["GET"]).commandsConstant).toBeUndefined();
    expect(commandsConstant("import { execSync } from 'child_process';\nexecSync(cmd);\n")).toBe(false);
  });
  it("stays bounded on deeply nested option objects", () => {
    const gen = (n) => `import { execSync } from 'child_process';\n${"execSync('ls', { cwd: ".repeat(n)}1${" })".repeat(n)};\n`;
    const ms = (n) => { const src = gen(n); shellFixed(src); const s = process.hrtime.bigint(); for (let k = 0; k < 3; k++) shellFixed(src); return Number(process.hrtime.bigint() - s) / 1e6; };
    const small = Math.max(ms(500), 0.5);
    expect(ms(4000) / small).toBeLessThan(24);
  });
});

describe("command-injection in a route: fixed text is a check, the rest stays critical", () => {
  const routeFinding = (r) => r.findings.find((f) => f.source === "static-analysis" && f.pattern === "command-injection");
  it("a Next.js route that runs only fixed text: medium, potential, Check first, no CI failure", async () => {
    const r = await scanRepo(repo({ "app/api/version/route.ts": CONST_EXEC, "package.json": "{\"dependencies\":{\"next\":\"15.5.9\"}}" }));
    const f = routeFinding(r);
    expect(f).toMatchObject({ severity: "medium", confidence: "potential" });
    expect(f.description).toMatch(/fixed text/);
    expect(bucketOf(f).bucket).toBe("check");
    expect(isSevere(f)).toBe(false);
  });
  it("a Next.js route that runs request data: critical", async () => {
    const r = await scanRepo(repo({ "app/api/run/route.ts": "import { execSync } from 'child_process';\nexport async function POST(req) {\n  const { cmd } = await req.json();\n  return Response.json({ out: execSync(cmd).toString() });\n}\n" }));
    expect(routeFinding(r)).toMatchObject({ severity: "critical" });
    expect(routeFinding(r).confidence).toBeUndefined();
  });
  it("a Next.js route with a constant call and an aliased one: critical", async () => {
    const r = await scanRepo(repo({ "app/api/run/route.ts": "import { exec, execSync } from 'child_process';\nconst run = exec;\nexport async function POST(req) {\n  execSync('git status');\n  run((await req.json()).cmd);\n}\n" }));
    expect(routeFinding(r)).toMatchObject({ severity: "critical" });
  });
  // Vercel 01M77J8S704B4DF7BQ5H3Q3EA7: a request-derived call inside template interpolation, then a literal call.
  it("an imported bare exec with request data in a template, then a literal call: critical, fails the run", async () => {
    const src = "import { exec } from 'child_process';\nexport async function GET(request) {\n  const q = new URL(request.url).searchParams.get('q');\n  const out = `${exec(q)}`;\n  exec('git status');\n  return Response.json({ out });\n}\n";
    const r = await scanRepo(repo({ "app/api/run/route.ts": src, "package.json": "{\"dependencies\":{\"next\":\"15.5.9\"}}" }));
    expect(routeFinding(r)).toMatchObject({ severity: "critical" });
    expect(isSevere(routeFinding(r))).toBe(true);
    expect(commandsConstant(src)).toBe(false);
  });
  it("the same, with no request-reading names, still fails: the shared regex cursor no longer skips the first call", () => {
    const src = "import { exec } from 'child_process';\nexport async function GET() {\n  const out = `${exec(process.argv[2])}`;\n  exec('git status');\n}\n";
    const shared = new RegExp(SHELL_EXEC_RE.source, "g");
    shared.test(src); // leave the cursor past the first call, as codeMatcher did
    expect(constantCommands(src, shared)).toBe(false);
  });
  // Vercel 01M77J94SK530Y7RAV4E3MZ06Q: a fixed interpreter fed request data on stdin.
  it("a fixed interpreter with request data through options.input: critical, fails the run", async () => {
    const src = "import { execSync } from 'child_process';\nexport async function POST(req) {\n  const { code } = await req.json();\n  return Response.json({ out: execSync('python3', { input: code }).toString() });\n}\n";
    const r = await scanRepo(repo({ "app/api/run/route.ts": src }));
    expect(routeFinding(r)).toMatchObject({ severity: "critical" });
    expect(isSevere(routeFinding(r))).toBe(true);
  });
  it("options are constant only with literal values", () => {
    const run = (opts) => shellFixed(`import { execSync } from 'child_process';\nexport function GET() { execSync('python3', ${opts}); }\n`);
    expect(run("{ encoding: 'utf8', timeout: 5000, windowsHide: true }")).toBe(true);
    expect(run("{ env: { ...process.env, NODE_ENV: 'production' } }")).toBe(true);
    expect(run("{ ...process.env }")).toBe(true);
    for (const opts of ["{ input: code }", "{ input }", "{ shell: sh }", "{ cwd: dir }", "{ input: `${x}` }", "{ input: get() }", "{ env: { X: y } }"]) expect(run(opts), opts).toBe(false);
  });
  it("an Express route with fixed text: medium, potential", async () => {
    const r = await scanRepo(repo({ "routes/v.js": "const express = require('express');\nconst { execSync } = require('child_process');\nconst router = express.Router();\nrouter.get('/version', (req, res) => res.json({ sha: execSync('git rev-parse HEAD').toString() }));\nmodule.exports = router;\n" }));
    expect(routeFinding(r)).toMatchObject({ severity: "medium", confidence: "potential" });
  });
  it("an Express route the sink scan finds tainted: the sink's critical finding stands in", async () => {
    const r = await scanRepo(repo({ "routes/run.js": "const express = require('express');\nconst { exec } = require('child_process');\nconst router = express.Router();\nrouter.post('/run', (req, res) => { exec('git log ' + req.body.ref, () => res.end()); });\nmodule.exports = router;\n" }));
    const all = r.findings.filter((f) => f.category === "code-pattern" && f.pattern === "command-injection");
    expect(all).toHaveLength(1);
    expect(all[0]).toMatchObject({ severity: "critical", confidence: "likely", source: "static-analysis" });
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
