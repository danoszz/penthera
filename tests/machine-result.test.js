/**
 * `--machine` runs through two paths, the CLI and shared executeScan. They share the result
 * object and keep their own handling around it. The audit is replaced, so no test reads this machine.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { machineScanResult } from "../src/cli/machine-result.js";
import { executeScan } from "../src/cli/run-scan.js";

const audit = vi.hoisted(() => vi.fn());
vi.mock("../lib/machine.js", () => ({ auditMachine: audit }));

const BIN = fileURLToPath(new URL("../bin/penthera.js", import.meta.url));
const FINDING = { severity: "high", title: "Fixed", description: "d", category: "persistence", source: "machine-audit" };
const dirs = [];
const temp = () => { const d = mkdtempSync(join(tmpdir(), "penthera-machine-")); dirs.push(d); return d; };
afterEach(() => { audit.mockReset(); for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

/** The real CLI with lib/machine.js swapped out before it loads. */
function cli(body, args) {
  const dir = temp();
  const hook = join(dir, "hook.mjs");
  writeFileSync(hook, `import { registerHooks } from "node:module";\nregisterHooks({ load(url, c, next) { return url.endsWith("/lib/machine.js") ? { format: "module", shortCircuit: true, source: ${JSON.stringify(`export async function auditMachine() { ${body} }`)} } : next(url, c); } });\n`);
  return spawnSync(process.execPath, ["--import", hook, BIN, "--machine", ...args], { cwd: dir, env: { ...process.env, HOME: dir, NO_COLOR: "1" }, encoding: "utf8" });
}

describe("the --machine result", () => {
  it("holds the audit under its fixed target and mode, and passes onPhase on", async () => {
    const machine = { findings: [FINDING] }, onPhase = () => {};
    audit.mockResolvedValue(machine);
    const r = await machineScanResult({ onPhase });
    expect(Object.keys(r)).toEqual(["target", "mode", "timestamp", "duration", "machine", "findings"]);
    expect(r).toMatchObject({ target: "this machine", mode: "machine", duration: 0, machine, findings: [FINDING] });
    expect(audit).toHaveBeenCalledWith({ onPhase });
  });

  it("executeScan keeps its profile and action plan on the merged result", async () => {
    audit.mockResolvedValue({ findings: [FINDING] });
    const { merged } = await executeScan({ machine: true, json: true, quiet: true, onPhase: () => {} });
    expect(merged.profile).toBe("standard");
    expect(merged.actionPlan).toBeDefined();
    expect(merged.findings.map((f) => f.title)).toEqual(["Fixed"]);
  });

  it("executeScan passes an audit failure to its caller", async () => {
    audit.mockRejectedValue(new Error("no audit"));
    await expect(executeScan({ machine: true, json: true, quiet: true, onPhase: () => {} })).rejects.toThrow("no audit");
  });

  it("the CLI prints the machine result as JSON", () => {
    const r = cli(`return { findings: ${JSON.stringify([FINDING])} };`, ["--json"]);
    expect(r.status).toBe(1);
    expect(JSON.parse(r.stdout).findings.map((f) => f.title)).toEqual(["Fixed"]);
  });

  it("the CLI reports an audit failure and exits 2", () => {
    const r = cli(`throw new Error("no audit");`, ["--json"]);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("Scan failed: no audit");
  });
});
