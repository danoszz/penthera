/**
 * Mythos deep assessment for 2.5 (12 Nov 2026), batch 4: shared source and sink
 * tables (A4, A6), and the sink scan on route files. Every snippet is inert text.
 */
import { describe, it, expect } from "vitest";
import { findSinks } from "../lib/whitebox/code-sinks.js";
import { RISK_RE } from "../lib/whitebox/frameworks.js";

const CP = 'import { exec, execSync } from "child_process";\n';
const tainted = (src) => findSinks(src).some((h) => h.tainted);
const ms = (fn) => { const t = performance.now(); fn(); return performance.now() - t; };

describe("A4: the Web Request API and Server Action arguments are request data", () => {
  const cases = {
    "await request.json()": CP + "export async function POST(request) { const { cmd } = await request.json(); exec(cmd); }",
    "formData.get in a Server Action": '"use server";\n' + CP + 'export async function clone(formData) { exec(`git clone ${formData.get("url")}`); }',
    "searchParams.get": CP + 'export async function GET(request) { execSync("ping " + new URL(request.url).searchParams.get("host")); }',
    "a Server Action's parameter": '"use server";\n' + CP + "export async function run(cmd) { exec(cmd); }",
    "a destructured Server Action parameter": '"use server";\n' + CP + "export const run = async ({ cmd }) => { exec(cmd); };",
  };
  for (const [name, src] of Object.entries(cases)) it(name, () => expect(tainted(src)).toBe(true));
  it("a non-action export's parameter is not request data", () => {
    expect(tainted(CP + "export async function run(cmd) { exec(cmd); }")).toBe(false);
  });
});

describe("A6: eval and vm by every name", () => {
  const cases = {
    "Function(x)()": "const y = req.body.y; Function(y)();",
    "eval?.(x)": "const y = req.body.y; eval?.(y);",
    "eval.call(null, x)": "const y = req.body.y; eval.call(null, y);",
    "vm by named import": 'import { runInNewContext } from "node:vm";\nconst y = req.body.y; runInNewContext(y, {});',
    "vm by an aliased named import": 'import { runInThisContext as r } from "vm";\nconst y = req.body.y; r(y);',
    "vm under another name": 'const vm2 = require("vm");\nconst y = req.body.y; vm2.runInThisContext(y);',
    "const e = eval": "const e = eval; const y = req.body.y; e(y);",
  };
  for (const [name, src] of Object.entries(cases)) it(name, () => expect(tainted(src)).toBe(true));
  it("new Function is not counted twice as Function", () => {
    expect(findSinks("const y = req.body.y; new Function(y);").filter((h) => h.tainted)).toHaveLength(1);
  });
  it("the route records share the list: Function( and vm count, retrieval( does not", () => {
    const has = (s) => new RegExp(RISK_RE.eval.source).test(s);
    expect(has("Function(x)()")).toBe(true);
    expect(has("vm.runInNewContext(x)")).toBe(true);
    expect(has("await retrieval(q)")).toBe(false);
  });
});

describe("blind review: no silent caps, every Server Action form", () => {
  const cases = {
    "a parameter list over 2,000 characters": '"use server";\n' + CP + `export async function run(cmd: string, o: {a:"${"x".repeat(2100)}"}) { exec(cmd) }`,
    "after a decoy with 257 parameters": '"use server";\n' + CP + `export async function d(${Array.from({ length: 257 }, (_, i) => "p" + i).join(",")}) {}\nexport async function run(cmd) { exec(cmd) }`,
    "the 33rd eval alias": Array.from({ length: 32 }, (_, i) => `const e${i} = eval;`).join("\n") + "\nconst z = eval; z(req.body.y);",
    "the 33rd vm binding": Array.from({ length: 32 }, (_, i) => `const v${i} = require("vm");`).join("\n") + '\nconst z = require("vm"); z.runInThisContext(req.body.y);',
    "a destructured default": '"use server";\n' + CP + "export async function run({ cmd = 'ls' }) { exec(cmd) }",
    "a nested pattern": '"use server";\n' + CP + "export async function run({ a: { cmd } }) { exec(cmd) }",
    "an array pattern": '"use server";\n' + CP + "export async function run([cmd]) { exec(cmd) }",
    "an async function expression": '"use server";\n' + CP + "export const run = async function (cmd) { exec(cmd) }",
    "a single-parameter arrow": '"use server";\n' + CP + "export const run = async cmd => { exec(cmd) }",
    "a generic arrow": '"use server";\n' + CP + "export const run = async <T,>(cmd: T) => { exec(cmd as any) }",
    "an export list": '"use server";\n' + CP + "async function run(cmd){ exec(cmd) }\nexport { run }",
    "an inline 'use server'": CP + "export default function Page() { async function act(cmd) { 'use server'; exec(cmd) } return null }",
    "(0, eval) as an alias": "const e = (0, eval); e(req.body.y);",
    "destructured from a vm binding": 'import vm from "vm";\nconst { runInNewContext } = vm;\nrunInNewContext(req.body.y);',
    'require("vm").runInNewContext': 'require("vm").runInNewContext(req.body.y);',
  };
  for (const [name, src] of Object.entries(cases)) it(name, () => expect(tainted(src)).toBe(true));
});

describe("only real Server Actions: helpers, stray directives and strings are not (blind review)", () => {
  it("a helper called with a constant is not request data", () => expect(tainted('"use server";\n' + CP + 'async function git(args){ exec("git "+args) }\nexport async function status(){ await git("status") }')).toBe(false));
  it("an inline directive marks only its own function", () => expect(tainted(CP + 'export default function P() { async function act(){ "use server" } }\nasync function build(dir){ exec("npm run build " + dir) }')).toBe(false));
  it("the words in a string are no directive", () => expect(tainted('"use client";\n' + CP + 'const D = ["use client","use server"];\nexport async function run(cmd){ exec(cmd) }')).toBe(false));
});

describe("Vercel review of PR 338", () => {
  it("01M81EXARANE7RZ654FWBJK5AY: any JavaScript whitespace before the directive", () => {
    for (const ws of ["\v", "\f", "\u00a0", "\u2028", "\ufeff", "\u3000"]) {
      expect(tainted(ws + '"use server";\n' + CP + "export async function run(cmd) { exec(cmd) }"), JSON.stringify(ws)).toBe(true);
    }
  });
  it("01M81ESZCYAEMCJSCSNMECYFWW: actions nested in parameter defaults stay linear and mark the file incomplete", () => {
    let s = "x";
    for (let i = 0; i < 4000; i++) s = `async (a${i} = ${s}) => { 'use server' }`;
    const incomplete = [];
    expect(ms(() => findSinks('"use server";\n' + CP + "export const f = " + s + ";", { onIncomplete: (m) => incomplete.push(m) }))).toBeLessThan(1500);
    expect(incomplete.join(" ")).toMatch(/Server Action parameters/);
  });
});

describe("Vercel 01M81PPS3Q3GW2HR57T14PPTQT: action names are read without backtracking", () => {
  it("a long $-separated name with blanks before the ( stays linear, in both forms, and is still an action", () => {
    for (const n of [20000, 320000]) {
      const name = "a$function$".repeat(n / 11);
      expect(ms(() => findSinks('"use server";\n' + CP + `export async function ${name}   (cmd) { exec(cmd) }`))).toBeLessThan(1500);
      expect(tainted('"use server";\n' + CP + `export const ${"a$b$".repeat(n / 4)}  =  async (cmd) => { exec(cmd) }`)).toBe(true);
    }
  });
});

describe("Vercel: action names with function in a parameter, and CRLF", () => {
  const cases = {
    "01M81RZZQFCM68A8X7NV94YPG9: an arrow parameter named functionInput": '"use server";\n' + CP + "const run = async functionInput => { exec(functionInput) };\nexport { run };",
    "a type parameter named functionT": '"use server";\n' + CP + "const run = async <functionT,>(cmd: functionT) => { exec(cmd as any) };\nexport { run };",
    "01M81RZQ16Z9XGZVZ2PQESBMAJ: CRLF after function": '"use server";\r\n' + CP + "async function\r\nrun(cmd) { exec(cmd) }\r\nexport { run };",
    "CRLF in a const assignment": '"use server";\r\n' + CP + "export const run =\r\n  async (cmd) => { exec(cmd) };",
    "a no-break space after function": '"use server";\n' + CP + "async function\u00a0run(cmd) { exec(cmd) }\nexport { run };",
  };
  for (const [name, src] of Object.entries(cases)) it(name, () => expect(tainted(src)).toBe(true));
});

describe("crafted input stays linear", () => {
  it("a file of `/*` and many `*//*` before the directive (CodeQL on PR 338)", () => {
    const src = "/*" + "*//*".repeat(1000) + '\n"use server";\n' + CP + "export async function run(cmd) { exec(cmd) }";
    expect(ms(() => findSinks(src))).toBeLessThan(1000);
    expect(tainted('/* header */\n// note\n"use server";\n' + CP + "export async function run(cmd) { exec(cmd) }")).toBe(true);
  });
  it("many bindings, aliases and action heads", () => {
    for (const filler of ['import { runInNewContext as r } from "vm";\n', "const e = eval;\n", '"use server";\nexport async function a(x, { y }, ...z) {}\n', "Function(".repeat(1) + "x);\n"]) {
      const src = filler.repeat(Math.ceil(2e6 / filler.length));
      expect(ms(() => findSinks(src)), filler).toBeLessThan(6000);
    }
  });
});
