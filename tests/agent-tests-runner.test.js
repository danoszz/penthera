import { describe, it, expect, afterAll } from "vitest";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runProjectTests } from "../src/agent/tests.js";

const dirs = [];
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

function project(script) {
  const dir = mkdtempSync(join(tmpdir(), "penthera-tests-"));
  dirs.push(dir);
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "x", scripts: { test: "node t.js" } }));
  writeFileSync(join(dir, "t.js"), script);
  return dir;
}

const SERVER = 'require("node:child_process").spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], { stdio: "inherit" }).unref();';

describe("project tests under --run-tests", () => {
  it("returns a passing result when a left-over server holds the output open", async () => {
    const r = await runProjectTests(project(`${SERVER}\nconsole.log("ok");`), { timeout: 20_000, exitGrace: 300 });
    expect(r.ok).toBe(true);
    expect(r.durationMs).toBeLessThan(8_000);
  }, 15_000);

  it("stops the tests when the run is interrupted", async () => {
    const dir = project(`const fs = require("node:fs"); fs.writeFileSync("started", ""); setTimeout(() => fs.writeFileSync("survived", ""), 1500);`);
    const runner = join(dir, "run.mjs");
    writeFileSync(runner, `import { runProjectTests } from ${JSON.stringify(new URL("../src/agent/tests.js", import.meta.url).href)};\nawait runProjectTests(${JSON.stringify(dir)}, {});\n`);
    const child = spawn(process.execPath, [runner], { stdio: "ignore" });
    for (let i = 0; i < 100 && !existsSync(join(dir, "started")); i++) await new Promise((r) => setTimeout(r, 50));
    child.kill("SIGINT");
    await new Promise((r) => child.on("close", r));
    await new Promise((r) => setTimeout(r, 2_000));
    expect(existsSync(join(dir, "started"))).toBe(true);
    expect(existsSync(join(dir, "survived"))).toBe(false);
  }, 15_000);

  it("reports progress while tests run", async () => {
    const seen = [];
    const r = await runProjectTests(project("setTimeout(() => {}, 700);"), { progressEvery: 200, onProgress: (ms) => seen.push(ms) });
    expect(r.ok).toBe(true);
    expect(seen.length).toBeGreaterThan(0);
  }, 10_000);

  it("gives up at the timeout, even on a process that ignores SIGTERM", async () => {
    const r = await runProjectTests(project('process.on("SIGTERM",()=>{});setInterval(()=>{},1000);'), { timeout: 500, killGrace: 300 });
    expect(r.ok).toBe(false);
    expect(r.output).toMatch(/timed out/);
    expect(r.durationMs).toBeLessThan(6_000);
  }, 10_000);
});
