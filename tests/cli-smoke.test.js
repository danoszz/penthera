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
