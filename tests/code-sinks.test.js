/**
 * Code-execution sinks in server code (E10 pilot misses `cmdi-ping` on DVNA
 * and `b2b-eval`, `profile-eval` on Juice Shop). The repo scan never read
 * those files: DVNA's sink sits in a helper module, and both apps have an
 * Express `routes/` folder that the scanner took for a Next.js API root with
 * no route files, so it stopped before the risky-pattern check. The fixture
 * repo is written to a temp dir at runtime; nothing in it is executed.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { scanCodeSinks, findSinks, taintedNames, stripComments, maskStrings } from "../lib/whitebox/code-sinks.js";
import { scanRepo } from "../src/scan-repo.js";

// Split so Penthera's own scans do not read the fixtures as real sinks.
const EVAL = ["ev", "al"].join("");
const EXEC = ["ex", "ec"].join("");
const CP = ["child", "_process"].join("");

const FILES = {
  // DVNA shape: request body concatenated into a shell command in a helper.
  "core/handler.js": `const ${EXEC} = require('${CP}').${EXEC};\nmodule.exports.ping = function (req, res) {\n  ${EXEC}('ping -c 2 ' + req.body.address, function (err, out) { res.send(out) });\n};\n`,
  // Juice Shop B2B shape: destructured request body into a vm context.
  "routes/b2b.ts": `import vm from 'vm'\nexport function order () {\n  return ({ body }: Request, res: Response) => {\n    const lines = body.orderLines || ''\n    const sandbox = { safeEval, lines }\n    vm.createContext(sandbox)\n    vm.runInContext('safeEval(lines)', sandbox, { timeout: 2000 })\n  }\n}\n`,
  // Juice Shop profile shape: a value of unknown origin into eval.
  "lib/render.js": `export function render (template) {\n  const code = template.slice(2, -1)\n  return ${EVAL}(code)\n}\n`,
  // Not sinks, or not reachable server code:
  "lib/safe.js": [
    `const { ${EXEC}Sync } = require('${CP}')`,
    `const v = ${EXEC}Sync(\`git rev-parse \${ref}\`)`, // untainted shell command: tooling
    `const n = ${EVAL}('1 + 1')`, // literal
    `const m = /a(b)/.${EXEC}(input)`, // RegExp.prototype.exec
    `const doc = "call ${EVAL}(req.body.x) to break things"`, // inside a string
    `// ${EVAL}(req.body.x) in a comment`,
    `vm.runInContext('render()', { render })`, // fixed script, untainted context
  ].join("\n") + "\n",
  "test/handler.test.js": `${EVAL}(req.body.x)\n`,
  "public/app.js": `${EVAL}(location.hash)\n`,
  "lib/bundle.js": `var a=1;${"x".repeat(6000)};${EVAL}(req.query.q)\n`,
  "app/api/run/route.ts": `export async function POST (request) { return ${EVAL}((await request.json()).x) }\n`,
};

let repo;
beforeAll(() => {
  repo = mkdtempSync(join(tmpdir(), "penthera-sinks-"));
  for (const [path, body] of Object.entries(FILES)) {
    mkdirSync(join(repo, dirname(path)), { recursive: true });
    writeFileSync(join(repo, path), body);
  }
});
afterAll(() => rmSync(repo, { recursive: true, force: true }));

describe("code-sink scan", () => {
  it("reports each sink file once, with the confidence its evidence supports", () => {
    const byFile = Object.fromEntries(scanCodeSinks(repo).map((f) => [f.file, f]));
    // lib/bundle.js is minified and still scanned (Red Team E23): its request-fed eval is found.
    expect(Object.keys(byFile).sort()).toEqual(["core/handler.js", "lib/bundle.js", "lib/render.js", "routes/b2b.ts"]);
    expect(byFile["lib/bundle.js"]).toMatchObject({ title: "eval in lib/bundle.js", confidence: "likely" });
    expect(byFile["core/handler.js"]).toMatchObject({
      title: "command-injection in core/handler.js", severity: "critical", confidence: "likely",
      line: 3, category: "code-pattern", source: "static-analysis", pattern: "command-injection",
    });
    expect(byFile["routes/b2b.ts"]).toMatchObject({ title: "eval in routes/b2b.ts", severity: "high", confidence: "likely", line: 7 });
    expect(byFile["lib/render.js"]).toMatchObject({ title: "eval in lib/render.js", confidence: "potential", line: 3 });
    expect(byFile["core/handler.js"].description).toMatch(/derived from the request/);
  });

  it("follows request data through destructuring and assignments", () => {
    const names = taintedNames("({ body }: Request) => {\n const a = body.x\n const b = { a }\n let c = other\n}");
    expect([...names].sort()).toEqual(["a", "b", "body"]);
    expect([...taintedNames("const { query, user } = req;\n")]).toEqual(["query"]);
  });

  it("ignores comments and strings when looking for calls", () => {
    const src = `// ${EVAL}(x)\nconst s = "${EVAL}(y)"\n/* ${EVAL}(z) */`;
    expect(findSinks(src)).toEqual([]);
    expect(stripComments(src)).toHaveLength(src.length);
    expect(maskStrings(src)).toHaveLength(src.length);
  });

  it("needs child_process before calling exec(...) a shell", () => {
    expect(findSinks(`${EXEC}('ls ' + req.query.dir)`)).toEqual([]);
  });
});

describe("repo scan runs the code-sink pass", () => {
  it("even when routes/ holds no Next.js route files", async () => {
    // Before, finding routes/ as an API root with no route.js files made the
    // scan return before any code-pattern check.
    const result = await scanRepo(repo);
    expect(result.executedProbes).toContain("code-sinks");
    const titles = result.findings.map((f) => f.title);
    expect(titles).toContain("command-injection in core/handler.js");
    expect(titles).toContain("eval in routes/b2b.ts");
  });
});
