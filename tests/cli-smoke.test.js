/**
 * CLI smoke tests: spawn the real binary and check the new offline commands wire
 * up and write their outputs. Network-free (no live target).
 */
import { describe, it, expect, afterAll } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, existsSync, readFileSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";

const BIN = resolve("bin/penthera.js");
const REPO = resolve(".");
const dir = mkdtempSync(join(tmpdir(), "penthera-cli-"));

function run(args) {
  try {
    execFileSync(process.execPath, [BIN, ...args], {
      cwd: dir,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, NO_COLOR: "1", PENTHERA_NO_ONBOARDING: "1" },
    });
    return 0;
  } catch (e) {
    return e.status ?? 1;
  }
}

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("CLI smoke (offline commands)", () => {
  it("lists every subcommand in the top-level --help, penthera hook included (360 review)", () => {
    const help = execFileSync(process.execPath, [BIN, "--help"], { encoding: "utf-8", env: { ...process.env, NO_COLOR: "1" } });
    for (const cmd of ["agents", "deps", "install", "hook", "memory", "fix", "evidence", "agent"]) {
      expect(help, cmd).toMatch(new RegExp(`\\$ penthera ${cmd}\\b`));
    }
  });

  it("no arguments without a terminal: a short list of commands, not the whole help, exit 2 (B3)", () => {
    const env = { ...process.env, NO_COLOR: "1", HOME: dir, PENTHERA_HOME: join(dir, ".penthera") };
    delete env.npm_command;
    for (const [args, first] of [[[], /setup wizard needs a terminal/], [["--offline"], /Give a URL, --repo <path>, or a command/]]) {
      let err;
      try {
        execFileSync(process.execPath, [BIN, ...args], { cwd: dir, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"], env });
      } catch (e) {
        err = e;
      }
      expect(err?.status).toBe(2);
      const text = err.stderr + err.stdout;
      expect(text).toMatch(first);
      expect(text).toContain("penthera init --yes --dry-run");
      expect(text).toContain("penthera --repo .");
      expect(text).not.toContain("Exit codes");
      expect(text.split("\n").length).toBeLessThan(15);
    }
  });

  it("a repo scan piped to another program prints the agent brief; PENTHERA_BRIEF=0 or CI keeps the terminal report", () => {
    const repo = resolve("tests/fixtures/repo-scan/express-routes");
    const scan = (extra) => {
      const env = { ...process.env, NO_COLOR: "1", PENTHERA_NO_ONBOARDING: "1", ...extra };
      delete env.PENTHERA_BRIEF;
      delete env.CI;
      Object.assign(env, extra);
      try {
        return execFileSync(process.execPath, [BIN, "--repo", repo], { cwd: dir, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"], env });
      } catch (e) {
        return e.stdout; // exit 1: the fixture has a critical finding
      }
    };
    const piped = scan({});
    expect(piped).toMatch(/^\*\*Penthera: Fix now\.\*\*/);
    expect(piped).toMatch(/### Act on[\s\S]*### Not checked/);
    expect(scan({ PENTHERA_BRIEF: "0" })).toMatch(/penthera\s+security scanner/);
    expect(scan({ CI: "true" })).toMatch(/penthera\s+security scanner/);
  });

  it("the terminal report has no color codes in a pipe; FORCE_COLOR=1 brings them back, NO_COLOR still wins (#231)", () => {
    const repo = resolve("tests/fixtures/repo-scan/express-routes");
    const report = (extra) => {
      const env = { ...process.env, PENTHERA_NO_ONBOARDING: "1", PENTHERA_BRIEF: "0" };
      for (const k of ["NO_COLOR", "FORCE_COLOR", "CI"]) delete env[k];
      Object.assign(env, extra);
      try {
        return execFileSync(process.execPath, [BIN, "--repo", repo], { cwd: dir, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"], env });
      } catch (e) {
        return e.stdout; // exit 1: the fixture has a critical finding
      }
    };
    const plain = report({});
    expect(plain).toMatch(/penthera\s+security scanner/);
    expect(plain).not.toContain("\x1b[");
    expect(report({ FORCE_COLOR: "1" })).toContain("\x1b[");
    expect(report({ FORCE_COLOR: "1", NO_COLOR: "1" })).not.toContain("\x1b[");
  });

  it("FORCE_COLOR=0 or false turns colors off in a terminal too", () => {
    const colorOffOnTty = (extra) => {
      const env = { ...process.env };
      for (const k of ["NO_COLOR", "FORCE_COLOR"]) delete env[k];
      Object.assign(env, extra);
      const code = 'Object.defineProperty(process.stdout, "isTTY", { value: true });'
        + "const { colorOff } = await import(process.argv[1]);"
        + "process.stdout.write(String(colorOff));";
      const ansiUrl = new URL("../src/cli/ansi.js", import.meta.url).href;
      return execFileSync(process.execPath, ["--input-type=module", "-e", code, ansiUrl], { encoding: "utf-8", env });
    };
    expect(colorOffOnTty({})).toBe("false");
    expect(colorOffOnTty({ FORCE_COLOR: "1" })).toBe("false");
    expect(colorOffOnTty({ FORCE_COLOR: "0" })).toBe("true");
    expect(colorOffOnTty({ FORCE_COLOR: "false" })).toBe("true");
    expect(colorOffOnTty({ NO_COLOR: "1" })).toBe("true");
  });

  it("an unknown word is a usage error, not a TypeError stack trace (e2e 2026-10-22)", () => {
    let err;
    try {
      execFileSync(process.execPath, [BIN, "notacommand"], { cwd: dir, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, NO_COLOR: "1", PENTHERA_NO_ONBOARDING: "1" } });
    } catch (e) {
      err = e;
    }
    expect(err?.status).toBe(2);
    expect(err.stderr + err.stdout).toMatch(/not a penthera command or a URL/);
    expect(err.stderr + err.stdout).not.toMatch(/TypeError|node:internal/);
  });

  it("ROADMAP.md claims for 1.5.0 only what 1.5.0 shipped (360 review)", () => {
    const row = readFileSync(join(REPO, "ROADMAP.md"), "utf-8").split("\n").find((l) => l.startsWith("| 1.5.0 |"));
    expect(row).toMatch(/hook.*license policy.*CRA.*AI-BOM/);
    expect(row).not.toMatch(/rule pack|dashboard|Python|internal audit/i);
  });

  it("--assessment-init writes a valid self-assessment template", () => {
    run(["--assessment-init", "a.json"]);
    const a = JSON.parse(readFileSync(join(dir, "a.json"), "utf-8"));
    expect(a.answers).toBeDefined();
    expect(Object.keys(a.answers).length).toBeGreaterThan(10);
  });

  it("--incident-init writes an incident template with aware_at", () => {
    run(["--incident-init", "i.json"]);
    expect(JSON.parse(readFileSync(join(dir, "i.json"), "utf-8"))).toHaveProperty("aware_at");
  });

  it("--incident drafts reports with the deadline timeline", () => {
    writeFileSync(join(dir, "inc.json"), JSON.stringify({ aware_at: "2026-08-15T09:00:00Z", title: "test" }));
    run(["--incident", "inc.json"]);
    expect(readFileSync(join(dir, "incident-reports.md"), "utf-8")).toMatch(/Reporting timeline/);
  });

  it("--sbom generates a CycloneDX bill of materials from a repo", () => {
    run(["--repo", REPO, "--sbom", "sbom.json"]);
    const s = JSON.parse(readFileSync(join(dir, "sbom.json"), "utf-8"));
    expect(s.bomFormat).toBe("CycloneDX");
    expect(s.components.length).toBeGreaterThan(0);
  });

  it("--readiness (attestation-only, no scan) writes a readiness report", () => {
    run(["--assessment-init", "a2.json"]);
    run(["--readiness", "--assessment", "a2.json"]);
    expect(existsSync(join(dir, "nis2-readiness.md"))).toBe(true);
    expect(readFileSync(join(dir, "nis2-readiness.md"), "utf-8")).toMatch(/NIS2 readiness report/);
  });

  it("--policy-pack writes the core policy templates", () => {
    run(["--policy-pack", "policies", "--org", "Test BV"]);
    expect(existsSync(join(dir, "policies", "incident-response-plan.md"))).toBe(true);
    expect(existsSync(join(dir, "policies", "README.md"))).toBe(true);
  });

  it("--questionnaire drafts a response from a self-assessment", () => {
    writeFileSync(join(dir, "q.txt"), "Do you use TLS?\nDo you enforce MFA?\nWhat is your retention period?\n");
    run(["--questionnaire", "q.txt", "--assessment", "a2.json"]);
    const md = readFileSync(join(dir, "questionnaire-response.md"), "utf-8");
    expect(md).toMatch(/Draft answer/);
    expect(md).toMatch(/NEEDS HUMAN INPUT/);
  });
});
