/**
 * Vercel Security Review on PR 281, the four findings that hid real findings:
 * 2. a ternary read as a typed arrow took over the arrow's parameters
 * 3. a conditional return type ended the type early and dropped the function
 * 8. a pipe inside "$(...)" or a backtick in double quotes was not a boundary
 * 9. whitespace around require(...) and its "." hid a request-fed exec
 * Each case is found on main or should be; none may be lost again.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { scanRepo } from "../src/scan-repo.js";
import { firstShellPipe } from "../lib/agents/hidden-content.js";

const repo = (files) => {
  const d = mkdtempSync(join(tmpdir(), "penthera-281-"));
  for (const [f, text] of Object.entries(files)) {
    mkdirSync(dirname(join(d, f)), { recursive: true });
    writeFileSync(join(d, f), text);
  }
  return d;
};
const injection = async (files) => (await scanRepo(repo(files))).findings.filter((f) => /command-injection/.test(f.title) && f.severity !== "info");
const lib = (code, file = "index.ts") => ({ "package.json": JSON.stringify({ name: "mylib", version: "1.0.0", main: file }), [file]: code });
const route = (body) => ({ "package.json": '{"name":"app","private":true}', "routes/run.js": `const express = require("express");\nconst router = express.Router();\n${body}\nmodule.exports = router;\n` });

describe("2: a ternary is not a typed arrow", () => {
  it("the arrow in `c ? (a) : (cmd) => exec(cmd)` keeps its own parameters", async () => {
    expect(await injection(lib(`const { exec } = require("child_process");\nmodule.exports = { run: flag ? (fallback) : (cmd) => exec("git " + cmd) };\n`, "index.js"))).not.toEqual([]);
  });
  it("a real typed arrow is still read", async () => {
    expect(await injection(lib(`import { exec } from "child_process";\nexport const run = (cmd: string): void => { exec(cmd); };\n`))).not.toEqual([]);
  });
});

describe("3: a conditional return type is part of the type", () => {
  for (const [name, code] of Object.entries({
    method: `export class R { run<T>(cmd: T): T extends string ? void : never { exec(cmd as any); return undefined as any; } }`,
    function: `export function run(cmd: string): string extends string ? void : never { exec(cmd); }`,
    nested: `export function run<T>(cmd: T): T extends string ? (T extends "" ? null : void) : never { exec(cmd as any); return undefined as any; }`,
    arrow: `export const run = (cmd: string): string extends string ? void : never => { exec(cmd); };`,
    generic: `export function run<T>(cmd: string): void { exec(cmd); }`,
  })) {
    it(name, async () => {
      expect(await injection(lib(`import { exec } from "child_process";\n${code}\n`))).not.toEqual([]);
    });
  }
});

describe("8: command substitution inside double quotes is code", () => {
  it("finds a pipe into a shell inside \"$(...)\" and \"`...`\"", () => {
    for (const t of [
      'echo "$(cat x | /usr/bin/env bash)"',
      'echo "$(cat x | sudo -u root bash)"',
      'echo "`cat x | sudo -u root bash`"',
      'echo "ok $(a "$(cat x | /usr/bin/env bash)") "',
      'echo "$( (cat x) | /usr/bin/env bash)"',
    ]) expect(firstShellPipe(t), t).not.toBe(-1);
  });
  it("a pipe in plain quoted text is still inert", () => {
    for (const t of ['echo "a | grep b"', 'echo "x $(echo y) | /usr/bin/env bash"']) expect(firstShellPipe(t), t).toBe(-1);
  });
  it("stays linear on nested substitutions", () => {
    const t = Date.now();
    firstShellPipe(`echo "${"$(".repeat(300_000)}| x`);
    firstShellPipe('"$(a|b)" '.repeat(200_000));
    firstShellPipe('"`'.repeat(300_000) + "|sh");
    expect(Date.now() - t).toBeLessThan(5000);
  });
});

describe("9: whitespace around require(...) and its dot", () => {
  for (const [name, body] of Object.entries({
    "space before the dot": `router.post("/run", (req, res) => { require("child_process") .exec(req.body.cmd); });`,
    "newline before the dot": `router.post("/run", (req, res) => { require("child_process")\n  .exec(req.body.cmd); });`,
    "space after require": `router.post("/run", (req, res) => { require ("child_process").exec(req.body.cmd); });`,
    "space after the dot": `router.post("/run", (req, res) => { require("child_process"). exec(req.body.cmd); });`,
  })) {
    it(name, async () => {
      const [f] = await injection(route(body));
      expect(f?.severity).toBe("critical");
    });
  }
});

// The blind review of ee65d4b and 6361a49 (9 Nov 2026): the same class, open on main too.
describe("generics, typed ternary branches and require member forms", () => {
  const ts = (code) => lib(`import { exec } from "child_process";\n${code}\n`);
  const js = (code) => lib(`const { exec } = require("child_process");\n${code}\n`, "index.js");
  for (const [name, files] of Object.entries({
    "a generic arrow": ts(`export const run = <T>(cmd: string) => { exec(cmd); };`),
    "a generic arrow with a comma": ts(`export const run = <T,>(cmd: string) => { exec(cmd); };`),
    "a nested generic": ts(`export function run<T extends Array<string>>(cmd: string) { exec(cmd); }`),
    "a nested generic on a method": ts(`export class R { run<T extends Record<string, number>>(cmd: string) { exec(cmd); } }`),
    "a generic with parentheses": ts(`export function run<T extends (x: string) => void>(cmd: string) { exec(cmd); }`),
    "a generic over 200 characters": ts(`export function run<T extends ${Array.from({ length: 40 }, (_, i) => `"v${i}"`).join(" | ")}>(cmd: string) { exec(cmd); }`),
    "a typed second branch": ts(`export const run = flag ? (a: any) : (cmd: string): void => { exec(cmd); };`),
    "two typed branches": ts(`export const run = flag ? (a: number) : (cmd: string) => { exec(cmd); };`),
    "an arrow in both branches": js(`exports.run = flag ? (a) => 1 : (cmd) => exec(cmd);`),
    "a comparison in the condition": js(`exports.run = x === 1 ? noop : (cmd) => exec(cmd);`),
    "a nested ternary": js(`exports.run = a ? b : c >= 2 ? d : (cmd) => exec(cmd);`),
  })) {
    it(name, async () => { expect(await injection(files)).not.toEqual([]); });
  }
  for (const [name, body] of Object.entries({
    "require(…)?.exec": `router.post("/run", (req, res) => { require("child_process")?.exec(req.body.cmd); });`,
    'require(…)["exec"]': `router.post("/run", (req, res) => { require("child_process")["exec"](req.body.cmd); });`,
    "an alias from require(…)?.[\"execSync\"]": `const run = require("child_process")?.["execSync"];\nrouter.post("/run", (req, res) => { run(req.body.cmd); });`,
  })) {
    it(name, async () => { expect((await injection(route(body)))[0]?.severity).toBe("critical"); });
  }
  it("a generic too long to skip after `function name` makes the file incomplete", async () => {
    const r = await scanRepo(repo(ts(`export function run<T extends ${"A | ".repeat(2000)}B>(cmd: string) { exec(cmd); }`)));
    expect(r.incomplete?.length).toBeGreaterThan(0);
  });
});
