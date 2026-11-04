/**
 * docs/commands/scan.md says how many requests `--profile quick` sends to the
 * mock server (#235): people pick a profile partly by how much traffic it
 * makes, and a CDN firewall can start challenging a scanner that sends too
 * many. This runs the real CLI and fails if the count grows past that number,
 * so a new probe in quick has to update the docs too.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { startMockServer } from "./fixtures/mock-server.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function documentedCount() {
  const doc = readFileSync(join(root, "docs", "commands", "scan.md"), "utf-8");
  const m = doc.match(/How many requests `quick` sends: (\d+) against the test server/);
  if (!m) throw new Error("docs/commands/scan.md no longer states the quick request count");
  return Number(m[1]);
}

let mock;
beforeAll(async () => { mock = await startMockServer(0); });
afterAll(() => mock.close());

describe("quick profile request count", () => {
  it("sends no more requests to the mock server than docs/commands/scan.md states", async () => {
    // Async spawn, not spawnSync: the mock server runs in this process and has to answer.
    const code = await new Promise((resolve, reject) => {
      const p = spawn(process.execPath, [join(root, "bin", "penthera.js"), mock.url, "--profile", "quick"], {
        cwd: root,
        stdio: "ignore",
        env: { ...process.env, CI: "1", NO_COLOR: "1" },
      });
      p.on("error", reject);
      p.on("exit", resolve);
    });
    // 1 = critical or high findings: the mock server is vulnerable on purpose.
    expect([0, 1]).toContain(code);
    expect(mock.requests.length).toBeGreaterThan(0);
    expect(mock.requests.length).toBeLessThanOrEqual(documentedCount());
  }, 60_000);
});
