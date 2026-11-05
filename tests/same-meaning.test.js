// Same-meaning tests (roadmap 108, metamorphic testing). A bad file written another way
// that means the same, such as CRLF, a BOM, other key order, \u escapes, comments or a long
// line, must give the same findings. fast-check picks the rewrites and shrinks a failure to
// the smallest set that changes the result. Cases: tests/corpus/cases.js.
// Offline: temp folders only.
import { describe, it, expect, afterAll } from "vitest";
import fc from "fast-check";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, extname, join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { scanAgents } from "../lib/agents/index.js";
import { findSecretsInText } from "../lib/whitebox/secrets.js";
import { scanPackage } from "../lib/deps/capabilities.js";
import { MapSource } from "../lib/deps/source.js";
import { runHook } from "../lib/hook/index.js";
import { packageFiles } from "./fixtures/deps/build.js";
import { AGENT_CASES, SECRET_CASES } from "./corpus/cases.js";
import { apply, JSON_FORMS, MARKDOWN, TEXT } from "./corpus/transforms.js";

const temps = [];
const temp = () => { const d = mkdtempSync(join(tmpdir(), "penthera-same-")); temps.push(d); return d; };
afterAll(() => temps.forEach((d) => rmSync(d, { recursive: true, force: true })));

const ext = (p) => extname(p).slice(1).toLowerCase();
const tableFor = (p) => (ext(p) === "json" ? JSON_FORMS : ext(p) === "md" ? MARKDOWN : ["pyc", "pem"].includes(ext(p)) ? null : TEXT);
/** fast-check: a subset of a table's transforms, in a fixed order, and a seed. */
const rewrite = (table) => fc.record({ names: fc.subarray(Object.keys(table), { minLength: 1 }), seed: fc.integer({ min: 1, max: 2 ** 31 - 1 }) });
const RUNS = { numRuns: 25 };

function writeAll(files) {
  const dir = temp();
  for (const [p, t] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, p)), { recursive: true });
    writeFileSync(join(dir, p), t);
  }
  return dir;
}

describe("secrets: the same key, written another way", () => {
  for (const c of SECRET_CASES) {
    const table = ext(c.path) === "json" ? { ...TEXT, ...JSON_FORMS } : ext(c.path) === "pem" ? { crlf: TEXT.crlf, bom: TEXT.bom, trailingSpace: TEXT.trailingSpace } : TEXT;
    const base = new Set(findSecretsInText(c.text, { path: c.path }).map((h) => h.name));
    it(c.name, () => {
      fc.assert(fc.property(rewrite(table), ({ names, seed }) => {
        const text = apply(c.text, names, table, seed, ext(c.path));
        const got = new Set(findSecretsInText(text, { path: c.path }).map((h) => h.name));
        expect([...got].sort(), names.join("+")).toEqual([...base].sort());
      }), RUNS);
    });
  }
});

describe("agent config: the same config, written another way", () => {
  const ids = async (files) => new Set((await scanAgents(writeAll(files), { home: false })).findings.map((f) => f.templateId));
  for (const c of AGENT_CASES) {
    it(c.name, async () => {
      const base = await ids(c.files);
      await fc.assert(fc.asyncProperty(fc.record({ names: fc.subarray(["crlf", "bom", "trailingSpace", "blankLines", "keyOrder", "compact", "tabs", "escapes"], { minLength: 1 }), seed: fc.integer({ min: 1, max: 2 ** 31 - 1 }) }), async ({ names, seed }) => {
        const files = {};
        for (const [p, t] of Object.entries(c.files)) {
          const table = tableFor(p);
          const mine = table ? names.filter((n) => n in table) : [];
          files[p] = mine.length ? apply(t, mine, table, seed, ext(p)) : t;
        }
        expect([...(await ids(files))].sort(), names.join("+")).toEqual([...base].sort());
      }), { numRuns: 15 });
    });
  }
});

describe("dependencies: the same package, written another way", () => {
  const PACKAGES = ["net-helper@1.1.0", "native-thing@2.0.0", "setup-hooks@1.0.0", "uses-env@1.0.0", "fast-fmt@0.0.1"];
  const caps = (files) => Object.keys(scanPackage(new MapSource(new Map(Object.entries(files).map(([k, v]) => [k, Buffer.from(v)])))).capabilities || {}).sort();
  for (const key of PACKAGES) {
    const { files } = packageFiles(key);
    it(key, () => {
      const base = caps(files);
      fc.assert(fc.property(rewrite({ ...TEXT, ...JSON_FORMS }), ({ names, seed }) => {
        const out = {};
        for (const [p, t] of Object.entries(files)) {
          const table = ext(p) === "json" ? JSON_FORMS : TEXT;
          const mine = names.filter((n) => n in table);
          out[p] = mine.length ? apply(t, mine, table, seed, ext(p)) : t;
        }
        expect(caps(out), names.join("+")).toEqual(base);
      }), RUNS);
    });
  }
});

describe("the lock file: the same pins, written another way", () => {
  it("a changed config is still reported after the lock is rewritten", async () => {
    const dir = writeAll({ ".mcp.json": JSON.stringify({ mcpServers: { notes: { command: "npx", args: ["-y", "notes-mcp@1.0.0"] } } }, null, 2) });
    await scanAgents(dir, { home: false, pin: true });
    writeFileSync(join(dir, ".mcp.json"), JSON.stringify({ mcpServers: { notes: { command: "npx", args: ["-y", "notes-mcp@6.6.6"] } } }, null, 2));
    const lock = readFileSync(join(dir, "penthera.lock"), "utf-8");
    const ids = async () => new Set((await scanAgents(dir, { home: false })).findings.map((f) => f.templateId));
    const base = await ids();
    expect(base.has("agents/lock-changed")).toBe(true);
    await fc.assert(fc.asyncProperty(rewrite(JSON_FORMS), async ({ names, seed }) => {
      writeFileSync(join(dir, "penthera.lock"), apply(lock, names, JSON_FORMS, seed));
      expect([...(await ids())].sort(), names.join("+")).toEqual([...base].sort());
    }), { numRuns: 20 });
  });
});

describe("the pre-commit hook: the same staged file, written another way", () => {
  it("blocks a staged key whatever the file's line endings, BOM or padding", async () => {
    const repo = temp();
    const git = (...a) => execFileSync("git", a, { cwd: repo, stdio: ["ignore", "pipe", "pipe"] });
    git("init", "-q", "-b", "main");
    const c = SECRET_CASES.find((x) => x.name === "Anthropic API key");
    await fc.assert(fc.asyncProperty(rewrite(TEXT), async ({ names, seed }) => {
      writeFileSync(join(repo, "ai.js"), apply(c.text, names, TEXT, seed, "js"));
      git("add", "ai.js");
      const r = await runHook(repo);
      expect(r.blocking.map((f) => f.title), names.join("+")).toContain("Anthropic API key in source");
    }), { numRuns: 12 });
  });
});
