/**
 * Vercel Security Review A and C (2.3.2): a dependency input Penthera refuses to
 * read must never become an empty tree that passes CI. The pins already read
 * stay, the other inputs are still scanned, and the run is incomplete: exit 2.
 *
 * The lockfile cap is lowered through a mock of fs-safe, so no test writes a
 * real 64 MiB file.
 */
import { describe, it, expect, vi } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CAP = 4096;
vi.mock(import("../lib/fs-safe.js"), async (importOriginal) => {
  const orig = await importOriginal();
  return {
    ...orig,
    // Only the lockfile cap (64 MiB) is lowered; smaller caps stay as they are.
    readRepoFile: (p, o = {}) => orig.readRepoFile(p, o.maxBytes === 64 * 1024 * 1024 ? { ...o, maxBytes: CAP } : o),
  };
});

const { scanDeps } = await import("../lib/deps/index.js");
const { exitCodeOf, exitReason } = await import("../src/report/exit.js");
const { mergeResults } = await import("../src/cli/merge-results.js");

const posix = process.platform !== "win32";
const tmp = (p = "penthera-gate-") => mkdtempSync(join(tmpdir(), p));
const py = (d) => scanDeps(d, { ecosystem: "python", pipCacheDir: tmp(), uvCacheDir: tmp() });

describe.skipIf(!posix)("A: a refused -r include keeps the file's other pins", () => {
  it("an empty -r /dev/null next to a known-bad pin still finds the pin and exits 2", async () => {
    const d = tmp();
    writeFileSync(join(d, "requirements.txt"), "-r /dev/null\nlitellm==1.107.0\n");
    const r = await py(d);
    expect(r.deps.total).toBe(1);
    expect(r.findings.some((f) => /litellm/.test(f.title) && (f.severity === "critical" || f.severity === "high"))).toBe(true);
    const info = r.findings.find((f) => f.title.startsWith("File not read: -r /dev/null"));
    expect(info).toMatchObject({ severity: "info", file: "requirements.txt" });
    expect(r.incomplete).toEqual([expect.objectContaining({ file: "requirements.txt" })]);
    expect(exitCodeOf(mergeResults([r]))).toBe(2);
  });

  it("a refused include with only safe pins is still not a pass", async () => {
    const d = tmp();
    writeFileSync(join(d, "requirements.txt"), "requests==2.31.0\n-r /dev/null\n");
    const r = await py(d);
    expect(r.deps.total).toBe(1);
    expect(r.findings.some((f) => f.severity === "critical" || f.severity === "high")).toBe(false);
    expect(exitCodeOf(r)).toBe(2);
    expect(exitReason(r)).toMatch(/exits 2.*not read: requirements\.txt/);
  });

  it("a nested include that is refused is said once, by the file that has it", async () => {
    const d = tmp();
    writeFileSync(join(d, "requirements.txt"), "-r base.txt\n");
    writeFileSync(join(d, "base.txt"), "litellm==1.107.0\n-r /dev/null\n");
    const r = await py(d);
    expect(r.deps.total).toBe(1);
    expect(r.incomplete.map((x) => x.file)).toEqual(["base.txt"]);
    expect(exitCodeOf(r)).toBe(2);
  });

  it("a clean scan with nothing refused still exits 0", async () => {
    const d = tmp();
    writeFileSync(join(d, "requirements.txt"), "requests==2.31.0\n");
    const r = await py(d);
    expect(r.incomplete).toBeUndefined();
    expect(exitCodeOf(r)).toBe(0);
  });
});

describe("C: a lockfile over the size cap is an incomplete scan", () => {
  const lock = (pad) => JSON.stringify({
    name: "app", lockfileVersion: 3,
    packages: { "": { name: "app", dependencies: { "@nx/devkit": "20.9.0" } }, "node_modules/@nx/devkit": { version: "20.9.0" } },
    pad,
  });

  it("a padded but valid package-lock.json over the cap exits 2, not 0", async () => {
    const d = tmp();
    writeFileSync(join(d, "package-lock.json"), lock("x".repeat(CAP)));
    const r = await scanDeps(d, { ecosystem: "npm", cacheDir: tmp() });
    expect(r.findings.map((f) => f.title)).toContain("File not read: package-lock.json");
    expect(r.incomplete).toEqual([expect.objectContaining({ file: "package-lock.json" })]);
    expect(exitCodeOf(mergeResults([r]))).toBe(2);
    // The PR comment the Action posts says so too.
    const { formatPrComment } = await import("../lib/deps/report.js");
    expect(formatPrComment(r)).toMatch(/\*\*Incomplete:\*\* Penthera could not read `package-lock.json`.*exit 2/);
  });

  it("the same lockfile under the cap is read, and the known-bad pin fails it", async () => {
    const d = tmp();
    writeFileSync(join(d, "package-lock.json"), lock(""));
    const r = await scanDeps(d, { ecosystem: "npm", cacheDir: tmp() });
    expect(r.incomplete).toBeUndefined();
    expect(exitCodeOf(r)).toBe(1);
  });

  it("an oversized npm lockfile next to Python inputs: Python is still scanned, the run is incomplete", async () => {
    const d = tmp();
    writeFileSync(join(d, "package-lock.json"), lock("x".repeat(CAP)));
    writeFileSync(join(d, "requirements.txt"), "litellm==1.107.0\n");
    const r = await scanDeps(d, { cacheDir: tmp(), pipCacheDir: tmp(), uvCacheDir: tmp() });
    expect(r.findings.some((f) => /litellm/.test(f.title))).toBe(true);
    expect(r.incomplete.map((x) => x.file)).toEqual(["package-lock.json"]);
    expect(exitCodeOf(r)).toBe(2);
  });
});

describe.skipIf(!posix)("C, penthera install: a refused proposed lockfile stops the install", () => {
  it("throws before the policy can pass an empty tree, and leaves the project alone", async () => {
    const { planInstall } = await import("../lib/install/index.js");
    const d = tmp("penthera-gate-install-");
    writeFileSync(join(d, "package.json"), '{"name":"x","version":"1.0.0"}');
    // A stand-in npm: `install --package-lock-only` writes a valid lockfile over the lowered cap.
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: { "": { name: "x", version: "1.0.0", dependencies: { dep: "1.0.0" } }, "node_modules/dep": { version: "1.0.0", resolved: "https://registry.npmjs.org/dep/-/dep-1.0.0.tgz", integrity: "sha512-AAAA" } },
      pad: "x".repeat(CAP),
    });
    const bin = join(d, "bin");
    mkdirSync(bin);
    const script = join(d, "fake-npm.mjs");
    writeFileSync(script, `
import { writeFileSync } from "node:fs";
const args = process.argv.slice(2);
if (args[0] === "--version") console.log("10.9.0");
else if (args[0] === "config") console.log(JSON.stringify({ registry: "https://registry.npmjs.org/" }));
else if (args[0] === "install" && args.includes("--package-lock-only")) writeFileSync("package-lock.json", ${JSON.stringify(lock)});
`);
    writeFileSync(join(bin, "npm"), `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(script)} "$@"\n`);
    chmodSync(join(bin, "npm"), 0o755);
    const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, npm_config_cache: join(d, "cache") };
    await expect(planInstall(d, ["dep@1.0.0"], { env })).rejects.toThrow(/proposed lockfile was not read.*Nothing was installed/);
    expect(existsSync(join(d, "package-lock.json"))).toBe(false);
  });
});
