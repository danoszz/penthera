import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { startMockServer } from "./fixtures/mock-server.js";
import { executeScan, writeScanReports } from "../src/cli/run-scan.js";

describe("validate-report.mjs", () => {
  it("rejects invalid JSON", () => {
    const dir = mkdtempSync(join(tmpdir(), "penthera-val-"));
    const bad = join(dir, "bad.json");
    writeFileSync(bad, "{not json");
    const result = spawnSync(process.execPath, [
      resolve("skills/penthera/scripts/validate-report.mjs"),
      bad,
    ]);
    expect(result.status).toBe(1);
    rmSync(dir, { recursive: true, force: true });
  });

  it("accepts a real scan report", async () => {
    const mock = await startMockServer(0);
    const dir = mkdtempSync(join(tmpdir(), "penthera-val-"));
    const jsonPath = join(dir, "scan.json");

    try {
      const result = await executeScan({
        url: mock.url,
        profile: "quick",
        output: jsonPath,
        quiet: true,
      });
      writeScanReports(
        { merged: result.merged },
        { json: jsonPath, markdown: null, sarif: null },
        result.mdOpts,
        { quiet: true, writeSarif: false },
      );

      const validation = spawnSync(process.execPath, [
        resolve("skills/penthera/scripts/validate-report.mjs"),
        jsonPath,
      ]);
      expect(validation.status).toBe(0);
      expect(validation.stdout.toString()).toContain("findings");
    } finally {
      await mock.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
