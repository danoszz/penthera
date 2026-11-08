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
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync, realpathSync, readFileSync, chmodSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import { join, dirname, resolve } from "node:path";
import { tmpdir } from "node:os";
import { probeRepoDetailed, planFixes, findingKey } from "../lib/fix/index.js";
import { fallbackSites, probeCors } from "../lib/fix/recipes/cors.js";
import { probeCookies } from "../lib/fix/recipes/cookies.js";
import { PROBE_CAP, keepWorst, worstKeeper } from "../lib/fix/probe-cap.js";
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
  const PIECES = ["a", "b", "$", ".", "_", "1", " ", "\n", "\t", "|", "||", "'", "\"", "*", "\"*\"", "'*'", "(", ")", ".get(", "\"origin\"", "'origin'", "origin", "x.get(\"origin\")", "headers", "=", ";", ",", "-", " ".repeat(20), "\n\t ".repeat(9)];

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
      `res.set("Access-Control-Allow-Origin", req.get(${" ".repeat(20)}"origin") || "*")`,
      `req.get(${" ".repeat(40)}'origin'${"\n".repeat(40)}) || '*'`,
      '.get("origin") || "*"',
      'a||"*"b||"*"',
      'a || "*" || "*"',
      '|| "*"',
    ]) expect(fallbackSites(s)).toEqual(old(s));
  });

  it("reads any number of blanks inside .get( \"origin\" ), as the old regex did (review, 7 Nov)", () => {
    const src = `res.set("Access-Control-Allow-Origin", req.get(${" ".repeat(20)}"origin") || "*");`;
    expect(fallbackSites(src)).toEqual([expect.objectContaining({ expr: `req.get(${" ".repeat(20)}"origin")` })]);
    expect(probeCors("a.js", src)).toHaveLength(1);
  });

  it("takes linear time on blanks inside .get( ... ) too", () => {
    const t = Date.now();
    const src = `x.get(${" ".repeat(1024 * 1024)}"origin") || "*" `.repeat(4);
    expect(fallbackSites(src)).toHaveLength(4);
    expect(Date.now() - t).toBeLessThan(2000);
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

describe("memory per file is bounded (row 4; review, 7 Nov)", () => {
  // 5 MiB of one hit per line: the checks used to collect every hit (about
  // 200,000) before keeping 25, and peaked at 350 to 460 MB. Run in a child
  // with a 128 MB heap: collecting them all runs out of memory there.
  const run = (code) => spawnSync(process.execPath, ["--max-old-space-size=128", "--input-type=module", "-e", code], { encoding: "utf-8", timeout: 60_000 });
  const lib = (f) => JSON.stringify(resolve("lib/fix/recipes", f));
  const MiB = 1024 * 1024;
  it("a cookie-dense 5 MiB file", () => {
    const r = run(`const { probeCookies } = await import(${lib("cookies.js")}); console.log(probeCookies("a.js", 'res.cookie("session", v);\\n'.repeat(${Math.floor((5 * MiB) / 26)})).length);`);
    expect(r.stderr).not.toMatch(/heap out of memory/);
    expect(r.stdout.trim()).toBe(String(PROBE_CAP));
  }, 60_000);
  it("a 5 MiB file of wildcard fallbacks", () => {
    const r = run(`const { probeCors } = await import(${lib("cors.js")}); console.log(probeCors("a.js", 'a || "*";\\n'.repeat(${Math.floor((5 * MiB) / 10)})).length);`);
    expect(r.stderr).not.toMatch(/heap out of memory/);
    expect(r.stdout.trim()).toBe(String(PROBE_CAP));
  }, 60_000);
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

  it("a cookie set through a 21st cookies() store is still reported (review, 7 Nov: no cap on stores)", () => {
    const decl = Array.from({ length: 20 }, (_, i) => `const s${i} = cookies();`).join("\n");
    const found = probeCookies("app.ts", `${decl}\nconst jar = cookies();\njar.set("session", token);\n`);
    expect(found).toEqual([expect.objectContaining({ title: 'Cookie "session" missing HttpOnly, missing Secure, missing SameSite', line: 22 })]);
    // Any number of stores, and a .set( on a name that is not a store is not a cookie.
    const many = Array.from({ length: 500 }, (_, i) => `const s${i} = await cookies();`).join("\n");
    expect(probeCookies("b.ts", `${many}\nmap.set("session", 1);\ns499.set("sid", v);\n`).map((f) => f.title)).toEqual(['Cookie "sid" missing HttpOnly, missing Secure, missing SameSite']);
  });

  it("a store named cookieStore is reported once, and its fix edits the call once", async () => {
    const src = 'const cookieStore = await cookies();\ncookieStore.set("session", t);\n';
    expect(probeCookies("a.ts", src)).toHaveLength(1);
    const root = repo({ ...NEXT, "app/api/login/route.ts": src });
    const { plans } = await planFixes(root, probeRepoDetailed(root).findings.filter((f) => f.category === "cookie"));
    const diff = plans.find((p) => p.recipe === "cookie-flags").diff;
    expect(diff.match(/^\+.*httpOnly/gm)).toHaveLength(1);
    expect(diff).toContain('cookieStore.set("session", t, { httpOnly: true, secure: true, sameSite: "lax" });');
  });

  it("the running keeper keeps what keepWorst keeps, in the same order", () => {
    const rand = mulberry32(0xbeef);
    const sevs = ["critical", "high", "medium", "low", "info"];
    for (let n = 0; n < 500; n++) {
      const len = Math.floor(rand() * 60);
      const fs = Array.from({ length: len }, (_, i) => ({ severity: sevs[Math.floor(rand() * 5)], title: `t${i}`, description: "d" }));
      const w = worstKeeper("f.js");
      // Added out of order, as the cookie and CORS checks add them: the order key decides ties.
      const order = fs.map((_, i) => i).sort(() => rand() - 0.5);
      for (const i of order) w.add(fs[i], i);
      expect(w.result()).toEqual(keepWorst(fs, "f.js"));
    }
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
    const { findings, coverage, notRead } = probeRepoDetailed(root);
    // The FIFO, the linked file (its target is outside) and the linked folder (outside) are refused and named.
    expect(coverage.skipped).toEqual({ "too-large": 1, refused: 3 });
    expect(notRead.map((n) => n.file).sort()).toEqual(["big.js", "link.js", "linked-dir", "pipe.js"]);
    expect(coverage.examined).toEqual(["app.js"]);
    // Nothing from the linked file or folder; the header findings name no file (no entry file here).
    expect(findings.filter((f) => f.category !== "headers").map((f) => f.file)).toEqual(["app.js"]);
  });

  it("puts what it did not read in the scan's coverage, and makes the scan incomplete (exit 2)", async () => {
    const root = repo({ ...EXPRESS, "big.js": "x".repeat(5 * 1024 * 1024 + 1) });
    const r = await scanRepo(root);
    const fam = r.coverage.families.find((f) => f.id === "app-settings");
    expect(fam.skipped["too-large"]).toBe(1);
    // Named once, by whichever check refused it first (the secret scan's limit is 4 MiB).
    expect(r.incomplete).toEqual([{ file: "big.js", reason: expect.stringMatching(/over the .*limit/) }]);
    expect(r.findings).toContainEqual(expect.objectContaining({ title: "File not read: big.js", severity: "info" }));
  });

  it("a FIFO among the code files makes the scan incomplete; a file two checks refuse is named once", async () => {
    const root = repo({ ...EXPRESS, "server.js": "const express = require('express');\nconst app = express();\napp.listen(3000);\n" });
    execFileSync("mkfifo", [join(root, "pipe.js")]);
    const r = await scanRepo(root);
    expect(r.incomplete.filter((x) => x.file === "pipe.js")).toHaveLength(1);
    expect(r.findings.filter((f) => f.title === "File not read: pipe.js")).toHaveLength(1);
  });

  it.skipIf(process.getuid?.() === 0)("a folder or file it cannot read is named; an unreadable file makes the scan incomplete", async () => {
    const root = repo({ ...EXPRESS, "locked/server.js": 'res.cookie("session", v);\n', "secret.js": 'res.cookie("sid", v);\n' });
    chmodSync(join(root, "secret.js"), 0o000);
    chmodSync(join(root, "locked"), 0o000);
    try {
      const { notRead, coverage } = probeRepoDetailed(root);
      expect(notRead).toEqual([
        { file: "locked", reason: expect.stringMatching(/folder that could not be read \(EACCES\)/) },
        { file: "secret.js", reason: expect.stringMatching(/could not be read \(EACCES\)/) },
      ]);
      expect(coverage.skipped).toEqual({ unreadable: 2 });
      // The scan as a whole (its sink check lists folders too) on the unreadable file alone.
      chmodSync(join(root, "locked"), 0o755);
      const r = await scanRepo(root);
      expect(r.incomplete).toEqual([{ file: "secret.js", reason: expect.stringMatching(/could not be read|EACCES/) }]);
    } finally {
      chmodSync(join(root, "locked"), 0o755);
      chmodSync(join(root, "secret.js"), 0o644);
    }
  });

  it("a file whose cookie calls were not all read (the read budget) makes the scan incomplete", async () => {
    const root = repo({ ...NEXT, "app/a.ts": `const s = cookies();\n${"s.set(".repeat(400_000)}\n` });
    const t = Date.now();
    const r = await scanRepo(root);
    expect(Date.now() - t).toBeLessThan(20_000);
    expect(r.incomplete).toContainEqual({ file: "app/a.ts", reason: "not all cookie calls read" });
    expect(r.findings).toContainEqual(expect.objectContaining({ title: "Cookie calls not all checked: app/a.ts", severity: "info" }));
  }, 60_000);

  it("5,000 decoy files ahead of the real server: incomplete, exit 2, and the first file not read is named (review, 7 Nov)", () => {
    const files = { ...EXPRESS };
    for (let i = 0; i < 5001; i++) files[`aaa/f${String(i).padStart(4, "0")}.js`] = "";
    files["zserver.js"] = 'const cors = require("cors");\napp.use(cors({ origin: "*" }));\nres.cookie("session", "x");\n';
    const root = repo(files);
    const report = join(root, "..", `${root.split("/").pop()}.json`);
    temps.push(report);
    const out = spawnSync(process.execPath, [resolve("bin/penthera.js"), "--repo", root, "-o", report], { encoding: "utf-8", env: { ...process.env, HOME: root, NO_COLOR: "1", CI: "1" }, timeout: 120_000 });
    expect(out.status).toBe(2);
    expect(out.stdout + out.stderr).toMatch(/aaa\/f5000\.js/);
    const json = JSON.parse(readFileSync(report, "utf-8"));
    expect(json.incomplete).toContainEqual({ file: "aaa/f5000.js", reason: "past the settings check's 5000-file limit (2 not read)" });
    expect(json.findings).toContainEqual(expect.objectContaining({ title: "Settings check stopped at 5,000 code files", severity: "info" }));
  }, 120_000);

  it("counts code files past the 5,000-file walk", () => {
    const files = { ...EXPRESS };
    for (let i = 0; i < 5003; i++) files[`src/f${String(i).padStart(4, "0")}.js`] = "";
    const { coverage } = probeRepoDetailed(repo(files));
    expect(coverage.over).toBe(3);
    expect(coverage.firstOver).toBe("src/f5000.js");
    expect(coverage.examined).toHaveLength(5000);
  });

  it("generated and git-ignored folders do not count toward the cap (review re-check, 9 Nov)", async () => {
    const files = { ...NEXT, ".gitignore": "local/\n" };
    for (let i = 0; i < 800; i++) files[`src/m${i}.ts`] = "";
    for (let i = 0; i < 4300; i++) files[`out/_next/c${i}.js`] = "";
    for (let i = 0; i < 300; i++) files[`local/x${i}.js`] = "";
    const root = repo(files);
    execFileSync("git", ["init", "-q"], { cwd: root });
    const r = await scanRepo(root);
    expect(r.incomplete ?? []).toEqual([]);
    expect(r.coverage.families.find((f) => f.id === "app-settings").skipped).not.toHaveProperty("settings-file-cap");
  }, 120_000);

  it("a linked code file inside the project is read; one outside it is named and the scan is incomplete", async () => {
    const root = repo({ ...EXPRESS, "lib/real.js": 'res.cookie("session", v);\n' });
    symlinkSync(join(root, "lib/real.js"), join(root, "server.js"));
    const outside = repo({ "x.js": 'res.cookie("token", v);\n' });
    const inner = probeRepoDetailed(root);
    // Listed once, by its real path, so a fix edits the real file.
    expect(inner.findings.filter((f) => f.category === "cookie").map((f) => f.file)).toEqual(["lib/real.js"]);
    symlinkSync(join(outside, "x.js"), join(root, "out-link.js"));
    const r = await scanRepo(root);
    expect(r.incomplete).toContainEqual({ file: "out-link.js", reason: expect.stringMatching(/outside the project/) });
  });
});

describe("headers set where a host or framework sets them", () => {
  it("reads vercel.json, so a Next.js app that sets its headers there gets no missing-header finding", () => {
    const vercel = { headers: [{ source: "/(.*)", headers: ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security", "Referrer-Policy"].map((key) => ({ key, value: key === "Strict-Transport-Security" ? "max-age=63072000" : "x" })) }] };
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
      // The secret is built at run time, so Penthera's own self-scan does not report this file.
      "app/api/login/route.ts": `const sessionSecret = "${["q7Vt2Lm9", "Xp4Rk8Wz"].join("")}";\nexport async function POST(request: Request) {\n  const store = await cookies();\n  store.set("session", "x");\n  return Response.json({ ok: true });\n}\n`,
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

describe("review re-check fixes (9 Nov)", () => {
  it("vercel.json counts headers set for every route only; a single route, a comment key or HSTS max-age=0 do not", () => {
    const vercel = {
      comment: { key: "X-Content-Type-Options" },
      headers: [
        { source: "/never-used", headers: ["Content-Security-Policy", "X-Frame-Options"].map((key) => ({ key, value: "x" })) },
        { source: "/(.*)", headers: [{ key: "Strict-Transport-Security", value: "max-age=0" }, { key: "Referrer-Policy", value: "no-referrer" }] },
      ],
    };
    const root = repo({ ...NEXT, "vercel.json": JSON.stringify(vercel), "next.config.mjs": "export default {};\n" });
    const titles = probeRepoDetailed(root).findings.filter((f) => f.category === "headers").map((f) => f.title).join("\n");
    for (const h of ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"]) expect(titles).toContain(h);
    expect(titles).not.toContain("Referrer-Policy");
  });

  it("a cookie call written over several lines (Prettier) is reported, and the fix leaves it alone", async () => {
    const src = 'res.cookie("session", token, {\n  maxAge: 1000,\n});\n';
    expect(probeCookies("app.js", src)).toEqual([expect.objectContaining({ title: 'Cookie "session" missing HttpOnly, missing Secure, missing SameSite', line: 1 })]);
    const root = repo({ ...EXPRESS, "app.js": src });
    const { plans } = await planFixes(root, probeRepoDetailed(root).findings.filter((f) => f.category === "cookie"));
    expect(plans).toEqual([]);
  });

  it("multi-line reading stays bounded: unclosed calls over many lines end in the read budget, not hours", () => {
    const t = Date.now();
    const found = probeCookies("a.js", 'res.cookie("s", v,\n'.repeat(200_000));
    expect(Date.now() - t).toBeLessThan(15_000);
    expect(found.at(-1)).toMatchObject({ title: "Cookie calls not all checked: a.js", incomplete: { file: "a.js" } });
  }, 60_000);

  it("the scan does not plan fixes: 4 files of 3.9 MB of cookies stay fast", () => {
    const files = { ...EXPRESS };
    for (let i = 0; i < 4; i++) files[`s${i}.js`] = 'res.cookie("session","b");\n'.repeat(Math.floor(3.9e6 / 27));
    const root = repo(files);
    const t = Date.now();
    const out = spawnSync(process.execPath, [resolve("bin/penthera.js"), "--repo", root], { encoding: "utf-8", env: { ...process.env, HOME: root, NO_COLOR: "1", CI: "1" }, timeout: 120_000 });
    expect(Date.now() - t).toBeLessThan(30_000);
    expect(out.stdout).toMatch(/A fix recipe matches \d+ of the \d+ problems?: penthera fix --plan --repo/);
  }, 120_000);

  it("many small files each just under their read budget stay fast (re-check 2, 9 Nov)", () => {
    const files = { ...NEXT };
    const body = `const s = cookies();\n${'s.set("a",\n'.repeat(400)}`;
    for (let i = 0; i < 1350; i++) files[`app/f${i}.ts`] = body;
    const root = repo(files);
    const t = Date.now();
    const out = spawnSync(process.execPath, [resolve("bin/penthera.js"), "--repo", root], { encoding: "utf-8", env: { ...process.env, HOME: root, NO_COLOR: "1", CI: "1" }, timeout: 120_000 });
    expect(Date.now() - t).toBeLessThan(30_000);
    expect(out.status).toBe(2); // the calls do not close: not all read, so the run is incomplete
  }, 120_000);

  it("a src/out folder is source and is read; out/ next to package.json is output", () => {
    const root = repo({ ...EXPRESS, "src/out/a.js": 'res.cookie("session", v);\n', "out/b.js": 'res.cookie("token", v);\n' });
    expect(probeRepoDetailed(root).findings.filter((f) => f.category === "cookie").map((f) => f.file)).toEqual(["src/out/a.js"]);
  });

  it("a comment inside a multi-line options object neither drops the finding nor counts as a flag", () => {
    const found = probeCookies("a.js", 'res.cookie("session", t, {\n  // don\'t (set by the proxy\n  maxAge: 1, /* httpOnly: true */\n});\n');
    expect(found.map((f) => f.title)).toEqual(['Cookie "session" missing HttpOnly, missing Secure, missing SameSite']);
  });

  it("a multi-line call the fix does not edit is not counted as covered by another file's edit", async () => {
    const root = repo({ ...EXPRESS, "a.js": 'res.cookie("session", t);\n', "b.js": 'res.cookie("session", t, {\n  maxAge: 1,\n});\n' });
    const findings = probeRepoDetailed(root).findings.filter((f) => f.category === "cookie");
    const { plans, unmatched } = await planFixes(root, findings);
    expect(plans.flatMap((p) => p.findings.map((f) => f.file))).toEqual(["a.js"]);
    expect(unmatched.map((f) => f.file)).toEqual(["b.js"]);
  });

  it("a regex with // inside a one-line cookie call is code, not a comment (re-check 3)", async () => {
    const src = 'res.cookie("session", p.replace(/\\/\\//g, "/"));\nres.cookie("sid", /^https?:\\/\\//.test(u) ? a : b);\n';
    expect(probeCookies("app.js", src).map((f) => f.title)).toEqual([
      'Cookie "session" missing HttpOnly, missing Secure, missing SameSite',
      'Cookie "sid" missing HttpOnly, missing Secure, missing SameSite',
    ]);
    const root = repo({ ...EXPRESS, "app.js": src });
    const { plans } = await planFixes(root, probeRepoDetailed(root).findings.filter((f) => f.category === "cookie"));
    expect(plans.map((p) => p.recipe)).toEqual(["cookie-flags", "cookie-flags"]);
  });

  it("unclosed mentions in comments do not mark a normal file as not fully checked (re-check 3)", async () => {
    // Nine unclosed mentions at the top of a 13 KB file: read over many lines,
    // each would run to the end of the file and use up the read budget.
    const lines = Array.from({ length: 9 }, (_, i) => `// call res.cookie( with an empty value ${i}`);
    for (let k = 0; k < 280; k++) lines.push(`const v${k} = compute(${k}, "some text here");`);
    lines.push('res.cookie("session", t);');
    const root = repo({ ...EXPRESS, "app.js": `${lines.join("\n")}\n` });
    const r = await scanRepo(root);
    expect(r.incomplete ?? []).toEqual([]);
    expect(r.findings.filter((f) => f.category === "cookie").map((f) => f.title)).toEqual(['Cookie "session" missing HttpOnly, missing Secure, missing SameSite']);
  });

  it("the scan's count leaves out a multi-line cookie call no recipe changes (re-check 3)", async () => {
    const { fixSummary } = await import("../lib/fix/index.js");
    const root = repo({ ...EXPRESS, "a.js": 'res.cookie("session", t);\n', "b.js": 'res.cookie("token", t, {\n  maxAge: 1,\n});\n' });
    const cookies = probeRepoDetailed(root).findings.filter((f) => f.category === "cookie");
    expect(cookies.map((f) => [f.file, Boolean(f.multiline)])).toEqual([["a.js", false], ["b.js", true]]);
    expect(fixSummary(cookies)).toBe(1);
    expect(cookies[1].description).toMatch(/add the flags by hand/);
  });

  // Vercel Security Review on PR 314: the entry-file anchors ran with the m flag over the
  // whole file, so `^(\s*)` rescanned every blank-line run (quadratic).
  for (const fw of ["express", "hono"]) {
    it(`${fw}: a server.js of blank lines with no app declaration is read in linear time (doubling check)`, () => {
      const time = (n) => {
        const root = repo({ "package.json": JSON.stringify({ dependencies: { [fw]: "4.0.0" } }), "server.js": `${"\n".repeat(n)}x` });
        const t = process.hrtime.bigint();
        probeRepoDetailed(root);
        return Number(process.hrtime.bigint() - t) / 1e6;
      };
      time(1000); // warm up
      const small = time(1024 * 1024);
      const big = time(4 * 1024 * 1024);
      expect(big).toBeLessThan(2_000);
      // Four times the input: linear is about 4x, quadratic 16x. Allow noise.
      expect(big).toBeLessThan(Math.max(10 * small, 400));
    }, 60_000);
  }

  it("the entry anchors still find the app line, with blank lines around it", async () => {
    const { findEntryFile, lineAnchor } = await import("../lib/fix/util.js");
    const root = repo({ ...EXPRESS, "server.js": `${"\n".repeat(5000)}  const app = express();\r\n${"\n".repeat(5000)}app.listen(3000);\n` });
    expect(findEntryFile(root, lineAnchor(/^(\s*)(?:const|let|var)\s+(\w+)\s*=\s*express\(\s*\)(?:\s*;)?\s*$/))?.file).toBe("server.js");
  });
});
