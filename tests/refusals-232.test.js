/**
 * Vercel Security Review (6 Nov, after the 2.3.2 merge) and the 2.3.2 sweep:
 * a file Penthera refuses to read never becomes a pass. What was read stays,
 * the refused input is named, and the run is incomplete: exit 2.
 *
 * Oversized files are sparse (truncateSync), so no test writes real data
 * past a cap.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, truncateSync } from "node:fs";
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
