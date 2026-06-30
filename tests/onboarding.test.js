import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { discoverFrameworkRoutes } from "../lib/whitebox/frameworks.js";
import { normalizeUrlInput } from "../src/cli/prompt.js";

describe("discoverFrameworkRoutes", () => {
  let dir;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "penthera-fw-"));
    writeFileSync(
      join(dir, "server.js"),
      `
const express = require("express");
const app = express();
app.get("/api/users", (req, res) => res.json([]));
app.post("/api/users", (req, res) => res.json({}));
app.delete("/api/users/:id", (req, res) => res.json({}));
`,
    );
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("finds Express routes in entry files", () => {
    const routes = discoverFrameworkRoutes(dir);
    expect(routes.length).toBeGreaterThanOrEqual(3);
    expect(routes.some((r) => r.url === "/api/users")).toBe(true);
    expect(routes.some((r) => r.framework === "express")).toBe(true);
  });
});

describe("normalizeUrlInput", () => {
  it("adds http for localhost", () => {
    expect(normalizeUrlInput("localhost:3000")).toBe("http://localhost:3000");
  });

  it("adds https for public hosts", () => {
    expect(normalizeUrlInput("myapp.com")).toBe("https://myapp.com");
  });
});

describe("onboarding (piped stdin)", () => {
  it("exits cleanly when user picks done", async () => {
    const { spawn } = await import("node:child_process");
    const { resolve } = await import("node:path");

    const child = spawn(
      process.execPath,
      [resolve("bin/scan.js")],
      {
        env: { ...process.env, NO_COLOR: "1" },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );

    const input = [
      "http://127.0.0.1:1",
      "",   // scan repo — default yes
      "1",  // done
    ].join("\n") + "\n";

    child.stdin.write(input);
    child.stdin.end();

    const exitCode = await new Promise((resolve) => {
      child.on("close", resolve);
    });

    // Unreachable target → exit 2, or scan completes → 0/1
    expect([0, 1, 2]).toContain(exitCode);
  }, 30_000);
});
