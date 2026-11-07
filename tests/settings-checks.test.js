/**
 * The fix planner's static checks (headers, cookies, CORS, login rate limits)
 * now run in every repo scan, so they are decision code on untrusted input.
 * These tests are the bypass checklist's rows for them (docs/team/BYPASS-CHECKLIST.md):
 * bounded time on a crafted file at the size cap, the worst kept under the
 * per-file cap, refused and linked files counted, the rewrite of the CORS
 * fallback regex checked against the old regex, and nothing the scan found
 * before lost.
 */
import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync, realpathSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { probeRepoDetailed, planFixes, findingKey } from "../lib/fix/index.js";
import { fallbackSites, probeCors } from "../lib/fix/recipes/cors.js";
import { probeCookies } from "../lib/fix/recipes/cookies.js";
import { PROBE_CAP } from "../lib/fix/probe-cap.js";
import { scanRepo } from "../src/scan-repo.js";
import { mulberry32 } from "../bench/prng.js";

const temps = [];
afterAll(() => temps.forEach((d) => rmSync(d, { recursive: true, force: true })));

function repo(files) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "penthera-settings-")));
  temps.push(root);
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return root;
}

const NEXT = { "package.json": JSON.stringify({ dependencies: { next: "15.0.0" } }) };
const EXPRESS = { "package.json": JSON.stringify({ dependencies: { express: "4.0.0" } }) };

describe("the CORS fallback finder (row 16: a rewrite is checked against the old check)", () => {
  // The regex it replaces, as it stood in lib/fix/recipes/cors.js.
  const OLD = /([\w$.]+(?:\.get\(\s*['"]origin['"]\s*\))?)\s*\|\|\s*(['"])\*\2/g;
  const old = (s) => [...s.matchAll(OLD)].map((m) => ({ index: m.index, length: m[0].length, expr: m[1] }));
  const PIECES = ["a", "b", "$", ".", "_", "1", " ", "\n", "\t", "|", "||", "'", "\"", "*", "\"*\"", "'*'", "(", ")", ".get(", "\"origin\"", "'origin'", "origin", "x.get(\"origin\")", "headers", "=", ";", ",", "-"];

  it("finds the same sites as the old regex on 20,000 random inputs", () => {
    const rand = mulberry32(0x0c0de);
    for (let n = 0; n < 20_000; n++) {
      let s = "";
      const len = 1 + Math.floor(rand() * 24);
      for (let i = 0; i < len; i++) s += PIECES[Math.floor(rand() * PIECES.length)];
      expect(fallbackSites(s), JSON.stringify(s)).toEqual(old(s));
    }
  });

  it("finds the same sites on the shapes real code has", () => {
    for (const s of [
      'const o = request.headers.get("origin") || "*";',
      "headers: { 'Access-Control-Allow-Origin': origin || '*' }",
      'x.get( "origin" ) || "*"',
      'a||"*"b||"*"',
      'a || "*" || "*"',
      '|| "*"',
    ]) expect(fallbackSites(s)).toEqual(old(s));
  });

  it("takes linear time: 5 MiB of letters, where the old regex needed hours (row 15)", () => {
    const t = Date.now();
    fallbackSites(`${"a".repeat(5 * 1024 * 1024)} || "*"`);
    expect(Date.now() - t).toBeLessThan(2000);
  });
});

describe("work per file is bounded at the size cap (rows 4, 15)", () => {
  const MiB = 1024 * 1024;
  const cases = {
    "a run of word characters (the old CORS regex)": "a".repeat(5 * MiB - 16),
    "cookie calls on one long line": 'a.cookie("s", v '.repeat(Math.floor((5 * MiB - 16) / 16)),
    "origin: true on one long line, with cors imported": `import cors from "cors";${" origin: true,".repeat(Math.floor((5 * MiB - 64) / 14))}`,
    "many cookies() stores": "const s1 = cookies();\n".repeat(Math.floor((5 * MiB - 16) / 22)),
    "wildcard fallbacks on every line": 'h(origin || "*");\n'.repeat(Math.floor((5 * MiB - 16) / 18)),
  };
  for (const [name, text] of Object.entries(cases)) {
    it(`${name}: scanned in bounded time, findings capped`, () => {
      const root = repo({ ...EXPRESS, "server.js": text });
      const t = Date.now();
      const { findings, coverage } = probeRepoDetailed(root);
      expect(Date.now() - t).toBeLessThan(15_000);
      expect(coverage.examined).toContain("server.js");
      const perRecipe = new Map();
      for (const f of findings) perRecipe.set(f.source, (perRecipe.get(f.source) || 0) + 1);
      for (const n of perRecipe.values()) expect(n).toBeLessThanOrEqual(PROBE_CAP + 6);
    }, 60_000);
  }
});

describe("the per-file cap keeps the worst (row 13)", () => {
  it("a session cookie after 100 harmless ones is still reported", () => {
    const decoys = Array.from({ length: 100 }, (_, i) => `res.cookie("pref${i}", v);`).join("\n");
    const found = probeCookies("app.js", `${decoys}\nres.cookie("session", token);\n`);
    expect(found).toHaveLength(PROBE_CAP);
    expect(found[0]).toMatchObject({ title: expect.stringContaining('"session"'), severity: "medium", line: 101 });
    expect(found.at(-1).description).toMatch(/76 more like these in app\.js are not listed/);
  });

  it("reads origin: true on the first line, a middle line and a last line with no newline (row 12)", () => {
    const src = 'import cors from "cors"; app.use(cors({ origin: true }));\nconst o = { origin: true };\napp.use(cors({ origin: "*" }))';
    expect(probeCors("a.js", src).map((f) => f.line)).toEqual([1, 3]);
    expect(probeCors("b.js", `${src}\n`).map((f) => f.line)).toEqual([1, 3]);
  });

  it("a short list is left as it is", () => {
    expect(probeCors("a.js", 'const o = origin || "*";')).toEqual([expect.objectContaining({ file: "a.js", line: 1 })]);
  });
});

describe("refused and linked files (row 2)", () => {
  it("counts a FIFO, a file over the limit and files past the walk's cap; never follows a link", () => {
    const root = repo({ ...EXPRESS, "big.js": "x".repeat(5 * 1024 * 1024 + 1), "app.js": 'res.cookie("sid", v);\n' });
    execFileSync("mkfifo", [join(root, "pipe.js")]);
    const outside = repo({ "secret.js": 'res.cookie("token", v);\n' });
    symlinkSync(join(outside, "secret.js"), join(root, "link.js"));
    symlinkSync(outside, join(root, "linked-dir"));
    const { findings, coverage } = probeRepoDetailed(root);
    expect(coverage.skipped).toEqual({ "too-large": 1, refused: 1 });
    expect(coverage.examined).toEqual(["app.js"]);
    // Nothing from the linked file or folder; the header findings name no file (no entry file here).
    expect(findings.filter((f) => f.category !== "headers").map((f) => f.file)).toEqual(["app.js"]);
  });

  it("puts what it did not read in the scan's coverage, so the brief names it", async () => {
    const root = repo({ ...EXPRESS, "big.js": "x".repeat(5 * 1024 * 1024 + 1) });
    const r = await scanRepo(root);
    const fam = r.coverage.families.find((f) => f.id === "app-settings");
    expect(fam.skipped["too-large"]).toBe(1);
  });

  it("counts code files past the 2,000-file walk", () => {
    const files = { ...EXPRESS };
    for (let i = 0; i < 2003; i++) files[`src/f${String(i).padStart(4, "0")}.js`] = "";
    const { coverage } = probeRepoDetailed(repo(files));
    expect(coverage.over).toBe(3);
    expect(coverage.examined).toHaveLength(2000);
  });
});

describe("headers set where a host or framework sets them", () => {
  it("reads vercel.json, so a Next.js app that sets its headers there gets no missing-header finding", () => {
    const vercel = { headers: [{ source: "/(.*)", headers: ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security", "Referrer-Policy"].map((key) => ({ key, value: "x" })) }] };
    const root = repo({ ...NEXT, "vercel.json": JSON.stringify(vercel, null, 2), "next.config.mjs": "export default {};\n" });
    expect(probeRepoDetailed(root).findings.filter((f) => f.category === "headers")).toEqual([]);
  });

  it("marks headers read from code as potential, with the file to change", () => {
    const root = repo({ ...NEXT, "next.config.mjs": "export default {};\n" });
    const csp = probeRepoDetailed(root).findings.find((f) => /Content-Security-Policy/.test(f.title));
    expect(csp).toMatchObject({ confidence: "potential", file: "next.config.mjs", severity: "medium" });
  });

  it("gathers an Express app's headers on the same walk, from any file", () => {
    const root = repo({ ...EXPRESS, "server.js": "const express = require('express');\nconst app = express();\napp.listen(3000);\n", "lib/h.js": "const helmet = require('helmet');\napp.use(helmet());\n" });
    expect(probeRepoDetailed(root).findings.filter((f) => f.category === "headers").map((f) => f.title)).toEqual([]);
  });
});

describe("nothing the scan found before is lost, and the fix plan sees the scan's set", () => {
  it("the scan's findings are the fix plan's findings", async () => {
    const root = repo({
      ...NEXT,
      "next.config.mjs": "export default {};\n",
      "app/api/login/route.ts": 'const sessionSecret = "q7Vt2Lm9Xp4Rk8Wz";\nexport async function POST(request: Request) {\n  const store = await cookies();\n  store.set("session", "x");\n  return Response.json({ ok: true });\n}\n',
      "app/api/session/route.ts": 'export async function GET(request: Request) {\n  const origin = request.headers.get("origin");\n  return new Response("{}", { headers: { "Access-Control-Allow-Origin": origin || "*" } });\n}\n',
    });
    const scan = await scanRepo(root);
    const keys = new Set(scan.findings.map(findingKey));
    const { plans } = await planFixes(root, scan.findings);
    for (const p of plans) for (const f of p.findings) expect(keys.has(findingKey(f)), f.title).toBe(true);
    // The route scan's own CORS finding stands; the settings check's copy of it is dropped.
    const cors = scan.findings.filter((f) => /cors/i.test(f.title));
    expect(cors).toEqual([expect.objectContaining({ category: "code-pattern", pattern: "cors-wildcard" })]);
    expect(plans.map((p) => p.recipe).sort()).toEqual(["auth-rate-limit", "cookie-flags", "cors-allowlist", "secret-to-env", "security-headers"]);
  });

  it("a CORS wildcard only the settings check sees (a bare cors()) is reported once", async () => {
    const root = repo({ ...EXPRESS, "server.js": "const cors = require('cors');\nconst express = require('express');\nconst app = express();\napp.use(cors());\napp.listen(3000);\n" });
    const scan = await scanRepo(root);
    expect(scan.findings.filter((f) => f.category === "cors")).toHaveLength(1);
  });
});
