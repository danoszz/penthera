import { describe, it, expect, afterAll } from "vitest";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";

const dirs = [];
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

function repo() {
  const dir = mkdtempSync(join(tmpdir(), "penthera-unread-"));
  dirs.push(dir);
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
  writeFileSync(join(dir, "index.js"), "module.exports = 1;\n");
  return dir;
}

const cli = (url, dir) => new Promise((done) => {
  execFile(process.execPath, [resolve("bin/penthera.js"), url, "--repo", dir, "--offline", "--brief"], { env: { ...process.env, NO_COLOR: "1", PENTHERA_BRIEF: "1" } }, (err, stdout) => done(stdout));
});

const listen = (handler) => new Promise((done) => {
  const server = createServer(handler).listen(0, "127.0.0.1", () => done(server));
});

describe("a site that was not read, through the real CLI", () => {
  it("says so when the URL answers 503", async () => {
    const server = await listen((req, res) => { res.statusCode = 503; res.end("down"); });
    const out = await cli(`http://127.0.0.1:${server.address().port}`, repo());
    server.close();
    expect(out).toContain("**Penthera: Site not read.**");
    expect(out).toContain("Target answered HTTP 503");
  }, 30_000);

  it("says so when nothing answers", async () => {
    const server = await listen(() => {});
    const { port } = server.address();
    await new Promise((r) => server.close(r));
    const out = await cli(`http://127.0.0.1:${port}`, repo());
    expect(out).toContain("**Penthera: Site not read.**");
    expect(out).toContain("Target unreachable");
  }, 30_000);
});
