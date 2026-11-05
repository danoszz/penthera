// The rule gate (roadmap 110). Every rule Penthera runs is read from the code
// (scripts/rule-inventory.mjs), then the real engines run over the fixtures and
// the corpus (tests/corpus/). The gate fails when:
//   - a rule no fixture fires is not on the allowlist (a new rule needs a fixture),
//   - an allowlisted rule now fires (take it off: the count only goes down),
//   - a high or critical rule a corpus case fires doesn't reach the CLI's exit code,
//   - a reader skips input past a cap with no coverage note or finding nearby (R2).
// Offline: temp dirs and the loopback mock server only.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { ruleInventory } from "../scripts/rule-inventory.mjs";
import { scanAgents } from "../lib/agents/index.js";
import { findSecretsInText, isSecretScanTarget } from "../lib/whitebox/secrets.js";
import { scanPackage } from "../lib/deps/capabilities.js";
import { MapSource } from "../lib/deps/source.js";
import { packageFiles } from "./fixtures/deps/build.js";
import { BUILT_IN_TEMPLATES, executeTemplate } from "../lib/templates.js";
import { startMockServer } from "./fixtures/mock-server.js";
import { evidenceFromRepo, evidenceFromResponse } from "../lib/advisories/evidence.js";
import { matchRuntimeAdvisories } from "../lib/advisories/index.js";
import { AGENT_CASES, SECRET_CASES } from "./corpus/cases.js";
import ALLOW from "./rule-gate.allow.json" with { type: "json" };

const ROOT = join(import.meta.dirname, "..");
const BIN = join(ROOT, "bin", "penthera.js");
const DEPS_PACKAGES = ["tiny-format@1.0.0", "net-helper@1.0.0", "net-helper@1.1.0", "native-thing@2.0.0", "fast-fmt@0.0.1", "expresss@1.0.0", "setup-hooks@1.0.0", "uses-env@1.0.0", "dev-only@1.0.0"];

const temps = [];
const temp = () => { const d = mkdtempSync(join(tmpdir(), "penthera-rule-gate-")); temps.push(d); return d; };
afterAll(() => temps.forEach((d) => rmSync(d, { recursive: true, force: true })));

/** Write a case's files into a fresh folder. */
function materialize(files) {
  const dir = temp();
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
}

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

const fired = new Set();
let inventory = [];

beforeAll(async () => {
  inventory = await ruleInventory();

  // Agent config: the fixture folders and the corpus cases.
  const agentDirs = readdirSync(join(ROOT, "tests/fixtures/agents")).map((d) => join(ROOT, "tests/fixtures/agents", d));
  for (const c of AGENT_CASES) agentDirs.push(materialize(c.files));
  for (const dir of agentDirs) {
    for (const f of (await scanAgents(dir, { home: false })).findings) fired.add(f.templateId);
  }

  // Secrets: every text fixture the secret scan would read, and the corpus.
  for (const file of walk(join(ROOT, "tests/fixtures"))) {
    const rel = relative(ROOT, file);
    if (!isSecretScanTarget(rel)) continue;
    for (const h of findSecretsInText(readFileSync(file, "utf-8"), { path: rel })) fired.add(`secret:${h.name}`);
  }
  for (const c of SECRET_CASES) for (const h of findSecretsInText(c.text, { path: c.path })) fired.add(`secret:${h.name}`);

  // Dependency capabilities: the deps fixture packages.
  for (const key of DEPS_PACKAGES) {
    const { files } = packageFiles(key);
    const pkg = scanPackage(new MapSource(new Map(Object.entries(files).map(([k, v]) => [k, Buffer.from(v)]))));
    for (const id of Object.keys(pkg.capabilities || {})) fired.add(`deps:${id}`);
  }

  // Live-check templates, against the loopback mock server.
  const mock = await startMockServer(0);
  try {
    for (const t of BUILT_IN_TEMPLATES) if ((await executeTemplate(mock.url, t))?.length) fired.add(`template:${t.id}`);
  } finally {
    await mock.close();
  }

  // Runtime advisories: the labelled runtime-strings set.
  const set = JSON.parse(readFileSync(join(ROOT, "bench/runtime-strings/strings.json"), "utf-8"));
  for (const e of set.entries) {
    let ev;
    if (e.input.headers) ev = evidenceFromResponse({ headers: e.input.headers, cookieNames: e.input.cookies || [] });
    else {
      const dir = temp();
      if (e.input.image) writeFileSync(join(dir, "Dockerfile"), `FROM ${e.input.image}\n`);
      else writeFileSync(join(dir, e.input.file), e.input.content);
      ev = evidenceFromRepo(dir);
    }
    for (const f of matchRuntimeAdvisories(ev)) for (const id of [f.rule, ...(f.advisories || [])]) if (id) for (const r of String(id).split(",")) fired.add(`runtime:${r}`);
  }
}, 120_000);

describe("the rule gate", () => {
  it("every allowlist entry says why", () => {
    for (const [id, why] of [...Object.entries(ALLOW.unfired), ...Object.entries(ALLOW.silentSkips)]) expect(String(why).length, id).toBeGreaterThan(10);
  });

  it("reads a rule inventory from the code", () => {
    expect(inventory.length).toBeGreaterThan(100);
    for (const f of ["agents", "secrets", "deps", "templates", "runtime"]) expect(inventory.some((r) => r.family === f), f).toBe(true);
  });

  it("every rule is fired by a fixture, or is on the allowlist of today's gaps", () => {
    const unfired = inventory.filter((r) => !fired.has(r.id)).map((r) => r.id).sort();
    const allowed = new Set(Object.keys(ALLOW.unfired));
    const missing = unfired.filter((id) => !allowed.has(id));
    const stale = Object.keys(ALLOW.unfired).filter((id) => fired.has(id) || !inventory.some((r) => r.id === id));
    console.log(`rule gate: ${inventory.length} rules, ${inventory.length - unfired.length} fired by a fixture, ${unfired.length} not (allowlisted: ${allowed.size})`);
    expect(missing, "a rule no fixture fires: add a case to tests/corpus/cases.js").toEqual([]);
    expect(stale, "these fire now, or are gone: take them off tests/rule-gate.allow.json").toEqual([]);
  });

  // The severity the engine gives the finding in this case, not the rule's worst: one rule
  // can be high in one place and info in another (an unreadable skill vs a broken config).
  const SEVERE = new Set(["critical", "high"]);
  it("every high or critical finding a corpus case fires reaches the CLI's report and exit code", async () => {
    for (const c of AGENT_CASES) {
      const dir = materialize(c.files);
      const want = (await scanAgents(dir, { home: false })).findings.filter((f) => c.fires.includes(f.templateId) && SEVERE.has(f.severity)).map((f) => f.templateId);
      const r = spawnSync(process.execPath, [BIN, "agents", dir, "--json"], { encoding: "utf-8", env: { ...process.env, NO_COLOR: "1" } });
      const ids = new Set(JSON.parse(r.stdout).findings.map((f) => f.templateId));
      for (const id of want) expect(ids.has(id), `${c.name}: ${id} reaches the report`).toBe(true);
      if (want.length) expect(r.status, `${c.name}: exit code`).toBe(1);
    }
    for (const c of SECRET_CASES) {
      const dir = materialize({ [c.path]: c.text });
      const want = findSecretsInText(c.text, { path: c.path }).filter((h) => c.fires.includes(`secret:${h.name}`) && SEVERE.has(h.severity)).map((h) => `secret:${h.name}`);
      const r = spawnSync(process.execPath, [BIN, "--repo", dir, "--json", "--offline"], { encoding: "utf-8", env: { ...process.env, NO_COLOR: "1" } });
      const out = JSON.parse(r.stdout);
      for (const id of want) expect(out.findings.some((f) => `secret:${f.title.replace(/ in source$/, "")}` === id), `${c.name}: ${id} reaches the report`).toBe(true);
      if (want.length) expect(r.status, `${c.name}: exit code`).toBe(1);
    }
  }, 120_000);

  it("each corpus case fires the rules it names", async () => {
    for (const c of AGENT_CASES) {
      const ids = new Set((await scanAgents(materialize(c.files), { home: false })).findings.map((f) => f.templateId));
      for (const id of c.fires) expect(ids.has(id), `${c.name}: ${id}`).toBe(true);
    }
    for (const c of SECRET_CASES) {
      const ids = new Set(findSecretsInText(c.text, { path: c.path }).map((h) => `secret:${h.name}`));
      for (const id of c.fires) expect(ids.has(id), `${c.name}: ${id}`).toBe(true);
    }
  });
});

// ── R2: no silent skip ──────────────────────────────────────────────────────

const READERS = [
  "lib/whitebox/secrets.js", "lib/whitebox/code-sinks.js", "lib/agents/discover.js", "lib/agents/index.js", "lib/agents/lock.js",
  "lib/agents/hidden-content.js", "lib/agents/rules.js", "lib/deps/index.js", "lib/deps/source.js", "lib/deps/capabilities.js",
  "lib/hook/index.js", "lib/install/index.js",
];
const CAP = /\b((?:MAX|MIN)_[A-Z0-9_]+|[A-Z0-9_]+_(?:LIMIT|CAP|BUDGET|BYTES))\b/;
const SKIP = /\b(continue|break)\b|return (?:null|\[\]|undefined|;|false)/;
const TRACE = /skipp|notRead|not_read|unread|oversiz|tooLarge|too-large|too large|coverage|blindSpot|truncat|unchecked|warning|warn\(|notChecked|unreadable|findings?\.push|hits\.push|over the|limit/i;

/** Places where a reader compares against a cap and then skips, with no trace within five lines. */
function silentSkips(file, text) {
  const lines = text.split("\n");
  const out = [];
  lines.forEach((line, i) => {
    const cap = CAP.exec(line);
    if (!cap || !/[<>]=?|\.length|size/.test(line) || /^\s*(?:\/\/|\*|const|export|let)\b/.test(line)) return;
    const after = lines.slice(i, i + 4).join("\n");
    if (!SKIP.test(after)) return;
    const near = lines.slice(Math.max(0, i - 5), i + 6).join("\n");
    if (!TRACE.test(near)) out.push(`${file}:${cap[1]}`);
  });
  return [...new Set(out)];
}

describe("R2: no reader skips input silently", () => {
  const found = READERS.flatMap((f) => silentSkips(f, readFileSync(join(ROOT, f), "utf-8")));
  it("every cap that skips input leaves a coverage note or a finding nearby, or is a known gap", () => {
    const allowed = new Set(Object.keys(ALLOW.silentSkips));
    console.log(`rule gate: ${found.length} skip site(s) with no trace near them (allowlisted: ${allowed.size})`);
    expect(found.filter((s) => !allowed.has(s)), "a new silent skip: record it in coverage or a finding").toEqual([]);
    expect([...allowed].filter((s) => !found.includes(s)), "fixed or gone: take it off tests/rule-gate.allow.json").toEqual([]);
  });

  it("the detector itself sees a silent skip and passes a traced one", () => {
    expect(silentSkips("x.js", "for (const f of files) {\n  if (f.size > MAX_FILE_BYTES) continue;\n}")).toEqual(["x.js:MAX_FILE_BYTES"]);
    expect(silentSkips("x.js", "if (f.size > MAX_FILE_BYTES) {\n  skipped.push(f);\n  continue;\n}")).toEqual([]);
  });
});
