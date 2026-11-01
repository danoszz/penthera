/**
 * End to end: spawn `penthera mcp` the way a client does (stdio, no shell),
 * call every tool on fixtures, and check stdout carries only protocol
 * messages. Also holds Penthera's own MCP client configs to Penthera's rules.
 */
import { createServer } from "node:http";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, cpSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startMockServer } from "./fixtures/mock-server.js";
import { buildFixtures } from "./fixtures/deps/build.js";
import { scanAgents } from "../lib/agents/index.js";
import { checkMcpServer } from "../lib/agents/rules.js";

const ROOT = join(import.meta.dirname, "..");
const BIN = join(ROOT, "bin", "penthera.js");
const EXAMPLES = join(ROOT, "docs", "mcp-clients");

/** A client over a child process's stdio. */
function spawnServer(args, cwd) {
  const child = spawn(process.execPath, [BIN, "mcp", ...args], { cwd, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, NO_COLOR: "1" } });
  const lines = [];
  const waiters = new Map();
  let buf = "";
  let stderr = "";
  child.stderr.on("data", (d) => { stderr += d; });
  child.stdout.on("data", (d) => {
    buf += d;
    let nl;
    while ((nl = buf.indexOf("\n")) !== -1) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      lines.push(line);
      const msg = JSON.parse(line); // throws, failing the test, if anything but JSON reaches stdout
      waiters.get(msg.id)?.(msg);
    }
  });
  let n = 0;
  const request = (method, params) => new Promise((resolve) => {
    const id = ++n;
    waiters.set(id, resolve);
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
  const exited = new Promise((resolve) => child.on("close", (code) => resolve(code)));
  return { child, lines, request, exited, stderr: () => stderr, close: () => { child.stdin.end(); return exited; } };
}

let ws, mock, server;

beforeAll(async () => {
  ws = realpathSync(mkdtempSync(join(tmpdir(), "penthera-mcp-e2e-")));
  mkdirSync(join(ws, "src"));
  writeFileSync(join(ws, "src", "app.js"), "const x = 1;\n");
  writeFileSync(join(ws, "Dockerfile"), "FROM nginx:1.18.0\n");
  writeFileSync(join(ws, ".mcp.json"), readFileSync(join(EXAMPLES, "claude-code.mcp.json")));
  const deps = buildFixtures(join(ws, "deps-fixture"));
  cpSync(deps.benign, join(ws, "deps"), { recursive: true });
  mock = await startMockServer(0);
  server = spawnServer(["--offline"], ws);
  const init = await server.request("initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "e2e", version: "1" } });
  expect(init.result.serverInfo.name).toBe("penthera");
  server.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
}, 60_000);

afterAll(async () => {
  if (server) await server.close();
  await mock?.close();
  rmSync(ws, { recursive: true, force: true });
});

const call = async (name, args) => (await server.request("tools/call", { name, arguments: args })).result;

describe("penthera mcp over stdio", () => {
  it("lists six read-only tools", async () => {
    const res = await server.request("tools/list", {});
    expect(res.result.tools.map((t) => t.name)).toHaveLength(6);
    expect(res.result.tools.every((t) => t.annotations.readOnlyHint)).toBe(true);
  });

  it.each([
    ["scan_repo", {}],
    ["check_dependencies", { path: "deps" }],
    ["audit_ai_tooling", {}],
    ["explain_finding", { id: "agents/mcp-exec" }],
    ["runtime_advisories", { path: "." }],
    ["runtime_advisories", { headers: { server: "Apache/2.4.49" } }],
  ])("%s answers with structured content and a summary", async (name, args) => {
    const r = await call(name, args);
    expect(r.isError, r.content?.[0]?.text).toBeUndefined();
    expect(r.structuredContent.tool).toBe(name);
    expect(r.content[0].type).toBe("text");
  }, 60_000);

  it("scan_url says a firewall answered, never that there is nothing to fix", async () => {
    const wall = createServer((req, res) => { res.writeHead(503, { "cf-mitigated": "challenge" }); res.end("just a moment"); });
    await new Promise((r) => wall.listen(0, "127.0.0.1", r));
    const r = await call("scan_url", { url: `http://127.0.0.1:${wall.address().port}`, profile: "quick" });
    wall.close();
    const text = JSON.stringify(r);
    expect(text).toContain("Site not read");
    expect(text).not.toContain("Nothing to fix");
  });

  it("scan_url scans the loopback app", async () => {
    const r = await call("scan_url", { url: mock.url, profile: "quick" });
    expect(r.isError, r.content?.[0]?.text).toBeUndefined();
    expect(r.structuredContent.offline).toBe(true);
  }, 60_000);

  it("the dogfood config penthera itself recommends grades clean on its MCP rules", async () => {
    const r = await call("audit_ai_tooling", {});
    expect(r.structuredContent.findings.filter((f) => /^agents\/mcp-/.test(f.rule))).toEqual([]);
  });

  it("logs to stderr only, and exits 0 when stdin closes", async () => {
    const s = spawnServer([], ws);
    const code = await s.close();
    expect(code).toBe(0);
    expect(s.lines).toEqual([]);
    expect(s.stderr()).toMatch(/penthera mcp .*stdio/);
  });
});

describe("penthera mcp command line", () => {
  const run = (...args) => spawnSync(process.execPath, [BIN, "mcp", ...args], { encoding: "utf8", input: "" });

  it("prints help with the flags", () => {
    const r = run("--help");
    expect(r.status).toBe(0);
    for (const f of ["--root", "--allow-host", "--offline"]) expect(r.stdout).toContain(f);
  });

  it("refuses bad arguments with exit 2", () => {
    expect(run("--nope").status).toBe(2);
    expect(run("extra").status).toBe(2);
    expect(run("--root", "/does/not/exist").status).toBe(2);
    expect(run("--allow-host", "*.example.com").status).toBe(2);
  });

  it("is listed in the main help", () => {
    expect(spawnSync(process.execPath, [BIN, "--help"], { encoding: "utf8" }).stdout).toMatch(/penthera mcp/);
  });
});

describe("the client configs Penthera recommends pass Penthera's MCP rules", () => {
  const MCP_RULES = /^mcp-/;

  it("Claude Code, Cursor and VS Code configs, through penthera agents", async () => {
    const dir = mkdtempSync(join(tmpdir(), "penthera-mcp-configs-"));
    try {
      mkdirSync(join(dir, ".cursor"));
      mkdirSync(join(dir, ".vscode"));
      cpSync(join(EXAMPLES, "claude-code.mcp.json"), join(dir, ".mcp.json"));
      cpSync(join(EXAMPLES, "cursor.mcp.json"), join(dir, ".cursor", "mcp.json"));
      cpSync(join(EXAMPLES, "vscode.mcp.json"), join(dir, ".vscode", "mcp.json"));
      const r = await scanAgents(dir, {});
      expect(r.agents.inventory.mcpServers).toBe(3);
      expect(r.findings.filter((f) => /^agents\/mcp-/.test(f.templateId))).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("Windsurf and Codex configs, through the same rule functions", () => {
    const windsurf = JSON.parse(readFileSync(join(EXAMPLES, "windsurf.mcp_config.json"), "utf8")).mcpServers.penthera;
    const toml = readFileSync(join(EXAMPLES, "codex.config.toml"), "utf8");
    const codex = { command: /command = "([^"]+)"/.exec(toml)[1], args: JSON.parse(/args = (\[.*\])/.exec(toml)[1]) };
    for (const [name, def] of [["windsurf", windsurf], ["codex", codex]]) {
      expect(checkMcpServer({ name, def, file: name }).filter((h) => MCP_RULES.test(h.rule)), name).toEqual([]);
    }
    // And the rule does fire on the unpinned form, so the check above means something.
    expect(checkMcpServer({ name: "x", def: { command: "npx", args: ["-y", "penthera", "mcp"] }, file: "x" }).map((h) => h.rule)).toContain("mcp-unpinned");
  });

  it("every example pins the same exact version", () => {
    const versions = new Set();
    for (const f of ["claude-code.mcp.json", "cursor.mcp.json", "vscode.mcp.json", "windsurf.mcp_config.json", "codex.config.toml"]) {
      for (const m of readFileSync(join(EXAMPLES, f), "utf8").matchAll(/penthera@([^"\s]+)/g)) versions.add(m[1]);
    }
    expect([...versions]).toHaveLength(1);
    expect([...versions][0]).toMatch(/^\d+\.\d+\.\d+(-[\w.]+)?$/);
  });
});

describe("server.json for the MCP Registry", () => {
  const read = (p) => JSON.parse(readFileSync(join(ROOT, p), "utf8"));

  it("conforms to the registry's server.json schema", async () => {
    const { default: Ajv } = await import("ajv");
    const ajv = new Ajv({ strict: false, validateFormats: false, allErrors: true });
    const validate = ajv.compile(read("tests/fixtures/mcp-spec/server.schema-2025-12-11.json"));
    const ok = validate(read("server.json"));
    expect(ok, JSON.stringify(validate.errors)).toBe(true);
  });

  it("matches package.json's mcpName and the version the docs pin, and starts `penthera mcp`", () => {
    const server = read("server.json");
    expect(server.name).toBe(read("package.json").mcpName);
    expect(server.packages[0].identifier).toBe(read("package.json").name);
    expect(server.packages[0].version).toBe(server.version);
    const pinned = /penthera@([^"\s]+)/.exec(readFileSync(join(EXAMPLES, "claude-code.mcp.json"), "utf8"))[1];
    expect(server.version).toBe(pinned);
    expect(server.packages[0].packageArguments).toEqual([{ type: "positional", value: "mcp" }]);
    expect(server.packages[0].transport).toEqual({ type: "stdio" });
  });
});
