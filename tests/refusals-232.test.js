/**
 * Vercel Security Review (6 Nov, after the 2.3.2 merge) and the 2.3.2 sweep:
 * a file Penthera refuses to read never becomes a pass. What was read stays,
 * the refused input is named, and the run is incomplete: exit 2.
 *
 * Oversized files are sparse (truncateSync), so no test writes real data
 * past a cap.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, truncateSync, symlinkSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanDeps } from "../lib/deps/index.js";
import { scanRepo } from "../src/scan-repo.js";
import { scanAgents } from "../lib/agents/index.js";
import { execFileSync } from "node:child_process";
import { exitCodeOf } from "../src/report/exit.js";
import { mergeResults } from "../src/cli/merge-results.js";

const tmp = (p = "penthera-refusals-") => mkdtempSync(join(tmpdir(), p));
const sparse = (path, bytes) => { writeFileSync(path, ""); truncateSync(path, bytes); };

/** A .venv with one site-packages and the given dist-info folders. */
function venv(root, dists) {
  const site = join(root, ".venv", "lib", "python3.12", "site-packages");
  mkdirSync(site, { recursive: true });
  for (const [name, version, files = {}] of dists) {
    const info = join(site, `${name}-${version}.dist-info`);
    mkdirSync(info);
    const mod = join(site, name);
    mkdirSync(mod);
    writeFileSync(join(mod, "__init__.py"), "x = 1\n");
    writeFileSync(join(info, "METADATA"), `Metadata-Version: 2.1\nName: ${name}\nVersion: ${version}\n`);
    writeFileSync(join(info, "RECORD"), `${name}/__init__.py,,\n${name}-${version}.dist-info/METADATA,,\n`);
    for (const [f, bytes] of Object.entries(files)) sparse(join(info, f), bytes);
  }
  return site;
}

const py = (d) => scanDeps(d, { ecosystem: "python", pipCacheDir: tmp(), uvCacheDir: tmp() });
const OVER_META = 16 * 1024 * 1024 + 1;

describe("1: an oversized METADATA or RECORD keeps the package, unscanned, and the run exits 2", () => {
  it("METADATA over the cap: the package is still in the tree, unscanned, named and incomplete", async () => {
    const d = tmp();
    venv(d, [["goodpkg", "1.0.0"], ["evilpkg", "6.6.6", { METADATA: OVER_META }]]);
    const r = await py(d);
    const evil = r.deps.unscanned.find((u) => u.package === "evilpkg@6.6.6");
    expect(evil?.reason).toMatch(/METADATA was not read/);
    expect(r.deps.total).toBe(2);
    expect(r.findings.some((f) => f.title.startsWith("File not read:") && /evilpkg-6\.6\.6\.dist-info\/METADATA/.test(f.title))).toBe(true);
    expect(r.incomplete.map((x) => x.file)).toEqual([expect.stringMatching(/evilpkg-6\.6\.6\.dist-info\/METADATA$/)]);
    expect(exitCodeOf(mergeResults([r]))).toBe(2);
  });

  it("RECORD over the cap: the package is unscanned, not read from a guessed folder, and the run exits 2", async () => {
    const d = tmp();
    venv(d, [["evilpkg", "6.6.6", { RECORD: OVER_META }]]);
    const r = await py(d);
    expect(r.deps.unscanned.find((u) => u.package === "evilpkg@6.6.6")?.reason).toMatch(/RECORD was not read/);
    expect(r.incomplete.map((x) => x.file)).toEqual([expect.stringMatching(/RECORD$/)]);
    expect(exitCodeOf(r)).toBe(2);
  });

  it("a venv with nothing refused is complete", async () => {
    const d = tmp();
    venv(d, [["goodpkg", "1.0.0"]]);
    const r = await py(d);
    expect(r.incomplete).toBeUndefined();
    expect(r.deps.total).toBe(1);
  });
});

describe("2: a route file over the size cap makes --repo incomplete", () => {
  const OVER_SOURCE = 5 * 1024 * 1024 + 1;
  const route = "export async function GET(req) { return Response.json({ ok: true }); }\n";

  it("a Next.js route.ts over 5 MiB next to a normal one: named, incomplete, exit 2", async () => {
    const d = tmp();
    for (const r of ["ok", "big"]) mkdirSync(join(d, "app", "api", r), { recursive: true });
    writeFileSync(join(d, "app", "api", "ok", "route.ts"), route);
    sparse(join(d, "app", "api", "big", "route.ts"), OVER_SOURCE);
    const r = await scanRepo(d, { offline: true });
    expect(r.findings.some((f) => f.title === "File not read: app/api/big/route.ts")).toBe(true);
    expect(r.incomplete).toEqual([expect.objectContaining({ file: "app/api/big/route.ts" })]);
    expect(exitCodeOf(mergeResults([r]))).toBe(2);
  });

  it("an Express server file over 5 MiB: incomplete, and it survives a merge with another target", async () => {
    const d = tmp();
    writeFileSync(join(d, "package.json"), JSON.stringify({ name: "x", dependencies: { express: "4.0.0" } }));
    writeFileSync(join(d, "app.js"), "const app = require('express')();\napp.get('/ok', (req, res) => res.send('ok'));\n");
    sparse(join(d, "server.js"), OVER_SOURCE);
    const r = await scanRepo(d, { offline: true });
    expect(r.incomplete?.map((x) => x.file)).toContain("server.js");
    const merged = mergeResults([r, { target: "other", mode: "url", findings: [] }]);
    expect(exitCodeOf(merged)).toBe(2);
  });

  it("a repo with nothing refused is complete", async () => {
    const d = tmp();
    mkdirSync(join(d, "app", "api", "ok"), { recursive: true });
    writeFileSync(join(d, "app", "api", "ok", "route.ts"), route);
    const r = await scanRepo(d, { offline: true });
    expect(r.incomplete).toBeUndefined();
    expect(exitCodeOf(r)).toBe(0);
  });
});

const posix = process.platform !== "win32";
const put = (root, rel, text) => { mkdirSync(join(root, rel, ".."), { recursive: true }); writeFileSync(join(root, rel), text); };

describe("3: penthera agents: agent config that is there but not read makes the run incomplete", () => {
  const OVER_AGENT = 5 * 1024 * 1024 + 1;

  it("an .mcp.json over 5 MiB: incomplete, exit 2", async () => {
    const d = tmp();
    sparse(join(d, ".mcp.json"), OVER_AGENT);
    const r = await scanAgents(d);
    expect(r.incomplete).toEqual([expect.objectContaining({ file: ".mcp.json" })]);
    expect(exitCodeOf(mergeResults([r]))).toBe(2);
  });

  it.skipIf(!posix)("a FIFO plugin .npmrc and a FIFO skill .npmrc: both named, incomplete, exit 2", async () => {
    const d = tmp();
    put(d, "plugins/p/skills/x/SKILL.md", "---\nname: x\n---\nok\n");
    execFileSync("mkfifo", [join(d, "plugins/p/.npmrc")]);
    put(d, "skills/py/SKILL.md", "---\nname: py\n---\nInstall the helper.\n");
    execFileSync("mkfifo", [join(d, "skills/py/.npmrc")]);
    const r = await scanAgents(d);
    expect(r.incomplete.map((x) => x.file).sort()).toEqual(["plugins/p/.npmrc", "skills/py/.npmrc"]);
    expect(exitCodeOf(r)).toBe(2);
  });

  it("a skill file over 5 MiB that you did not name: incomplete, exit 2", async () => {
    const d = tmp();
    put(d, "skills/py/SKILL.md", "---\nname: py\n---\nok\n");
    sparse(join(d, "skills/py/notes.md"), OVER_AGENT);
    const r = await scanAgents(d);
    expect(r.incomplete?.map((x) => x.file)).toContain("skills/py/notes.md");
    expect(exitCodeOf(r)).toBe(2);
  });

  it("agent config that is all read is complete", async () => {
    const d = tmp();
    put(d, ".mcp.json", JSON.stringify({ mcpServers: {} }));
    put(d, "skills/py/SKILL.md", "---\nname: py\n---\nok\n");
    const r = await scanAgents(d);
    expect(r.incomplete).toBeUndefined();
  });
});

describe("Fact-checker recheck: every agent config that is there but not read, and an unread .pth", () => {
  const MCP = ".mcp.json";
  // Every way a config can be there and not read. Each must make the run incomplete.
  const kinds = {
    fifo: (p) => execFileSync("mkfifo", [p]),
    folder: (p) => mkdirSync(p),
    "broken link": (p) => symlinkSync(join(tmpdir(), "penthera-no-such-target"), p),
    "link out": (p) => { const out = join(tmp(), "outside.json"); writeFileSync(out, "{}"); symlinkSync(out, p); },
    oversized: (p) => sparse(p, 5 * 1024 * 1024 + 1),
    ...(process.getuid?.() === 0 ? {} : { "no permission": (p) => { writeFileSync(p, "{}"); chmodSync(p, 0o000); } }),
  };

  for (const [kind, make] of Object.entries(kinds)) {
    it.skipIf(!posix)(`${kind}: .mcp.json, .claude/settings.json, CLAUDE.md and a SKILL.md each exit 2`, async () => {
      for (const rel of [MCP, ".claude/settings.json", "CLAUDE.md", "skills/x/SKILL.md"]) {
        const d = tmp();
        mkdirSync(join(d, rel, ".."), { recursive: true });
        make(join(d, rel));
        const r = await scanAgents(d);
        expect(r.incomplete?.map((x) => x.file), `${kind} ${rel}`).toContain(rel);
        expect(exitCodeOf(r), `${kind} ${rel}`).toBe(2);
      }
    });
  }

  it.skipIf(!posix)("a named skill whose SKILL.md is a FIFO exits 2", async () => {
    const d = tmp();
    execFileSync("mkfifo", [join(d, "SKILL.md")]);
    writeFileSync(join(d, "run.sh"), "echo hi\n");
    const r = await scanAgents(d, { skillTarget: true });
    expect(r.incomplete?.map((x) => x.file)).toContain("SKILL.md");
    expect(exitCodeOf(r)).toBe(2);
  });

  it("an unowned .pth over 16 MiB in site-packages: named, incomplete, exit 2", async () => {
    const d = tmp();
    const site = venv(d, [["goodpkg", "1.0.0"]]);
    sparse(join(site, "zz-startup.pth"), OVER_META);
    const r = await py(d);
    expect(r.incomplete?.map((x) => x.file)).toEqual([expect.stringMatching(/zz-startup\.pth$/)]);
    expect(exitCodeOf(mergeResults([r]))).toBe(2);
  });

  it.skipIf(!posix)("an unowned .pth that is a FIFO: incomplete, exit 2; a small one is read as before", async () => {
    const d = tmp();
    const site = venv(d, [["goodpkg", "1.0.0"]]);
    execFileSync("mkfifo", [join(site, "zz-startup.pth")]);
    expect(exitCodeOf(await py(d))).toBe(2);
    const ok = tmp();
    const site2 = venv(ok, [["goodpkg", "1.0.0"]]);
    writeFileSync(join(site2, "paths.pth"), "/opt/lib\n");
    const r = await py(ok);
    expect(r.incomplete).toBeUndefined();
  });
});

describe.skipIf(!posix)("final sweep: a package file that can't be read leaves the package unscanned", () => {
  it("Python: a .py in RECORD that is a FIFO makes the package unscanned, never clean", async () => {
    const d = tmp();
    const site = venv(d, [["goodpkg", "1.0.0"]]);
    writeFileSync(join(site, "goodpkg-1.0.0.dist-info", "RECORD"), "goodpkg/__init__.py,,\ngoodpkg/evil.py,,\n");
    execFileSync("mkfifo", [join(site, "goodpkg", "evil.py")]);
    const r = await py(d);
    expect(r.deps.unscanned.find((u) => u.package === "goodpkg@1.0.0")?.reason).toMatch(/could not be read.*evil\.py/);
  });

  it("Python: an egg whose installed-files.txt is a FIFO: unscanned and incomplete", async () => {
    const d = tmp();
    const site = venv(d, []);
    const egg = join(site, "eggpkg-2.0.egg-info");
    mkdirSync(egg);
    writeFileSync(join(egg, "PKG-INFO"), "Metadata-Version: 1.1\nName: eggpkg\nVersion: 2.0\n");
    execFileSync("mkfifo", [join(egg, "installed-files.txt")]);
    const r = await py(d);
    expect(r.deps.unscanned.find((u) => u.package === "eggpkg@2.0")?.reason).toMatch(/installed-files\.txt was not read/);
    expect(exitCodeOf(r)).toBe(2);
  });

  it("npm: an installed .js that is a FIFO makes the package unscanned", async () => {
    const d = tmp();
    writeFileSync(join(d, "package-lock.json"), JSON.stringify({ name: "app", lockfileVersion: 3, packages: { "": { name: "app", dependencies: { dep: "1.0.0" } }, "node_modules/dep": { version: "1.0.0" } } }));
    mkdirSync(join(d, "node_modules", "dep"), { recursive: true });
    writeFileSync(join(d, "node_modules", "dep", "package.json"), JSON.stringify({ name: "dep", version: "1.0.0", main: "index.js" }));
    writeFileSync(join(d, "node_modules", "dep", "index.js"), "module.exports = 1;\n");
    execFileSync("mkfifo", [join(d, "node_modules", "dep", "evil.js")]);
    const r = await scanDeps(d, { ecosystem: "npm", cacheDir: tmp() });
    expect(r.deps.unscanned.find((u) => u.package === "dep@1.0.0")?.reason ?? "").toMatch(/could not be read.*evil\.js|evil\.js/);
  });
});
