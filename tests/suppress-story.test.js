import { describe, it, expect, afterAll } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";

const dirs = [];
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
const temp = () => { const d = mkdtempSync(join(tmpdir(), "penthera-supp-")); dirs.push(d); return d; };

function cli(args, env) {
  try {
    return { status: 0, out: execFileSync(process.execPath, [resolve("bin/penthera.js"), ...args], { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, NO_COLOR: "1", ...env } }) };
  } catch (e) { return { status: e.status, out: e.stdout, err: e.stderr }; }
}

describe("suppressions and a plain scan", () => {
  const key = `sk_${"live"}_51NfakefakefakefakefakefakeABCD`;
  const setup = () => {
    const dir = temp();
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "a", version: "1.0.0" }));
    writeFileSync(join(dir, "a.js"), `module.exports = "${key}";\n`);
    return { dir, env: { PENTHERA_HOME: temp() } };
  };
  const fid = (r) => JSON.parse(r.out).findings.find((f) => f.severity === "critical").fid;

  it("prints a finding's id without --memory", () => {
    const { dir, env } = setup();
    expect(fid(cli(["--repo", dir, "--offline", "--json"], env))).toMatch(/^[0-9a-f]{16}$/);
  });

  it("counts it, says so, and names --memory", () => {
    const { dir, env } = setup();
    const id = fid(cli(["--repo", dir, "--offline", "--json"], env));
    writeFileSync(join(dir, "penthera.suppress.json"), JSON.stringify({ version: 1, suppress: [{ id, reason: "a test fixture" }] }));
    const r = cli(["--repo", dir, "--offline", "--brief"], env);
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/1 finding here is suppressed.*--memory/);
  });

  it("says where a local suppression applies", () => {
    const { dir, env } = setup();
    const id = fid(cli(["--repo", dir, "--offline", "--json"], env));
    const r = cli(["memory", "suppress", id, "--reason", "a test fixture", "--repo", dir], env);
    expect(r.out).toMatch(/--memory scans and the fix loop on this machine/);
    expect(r.out).toMatch(/penthera\.suppress\.json/);
    const scan = cli(["--repo", dir, "--offline", "--brief"], env);
    expect(scan.out).toMatch(/1 finding here is suppressed/);
  });
});
