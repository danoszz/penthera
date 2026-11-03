import { describe, it, expect, afterAll } from "vitest";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseClaims, checkClaims, readRepo } from "../scripts/claim-map.mjs";
import { totalRules } from "../scripts/docs-numbers.mjs";
import { activePacks } from "../lib/rules/index.js";
import { fuzzField } from "../lib/fuzzer.js";
import { probeMethodConfusion } from "../lib/adaptive-probes.js";
import { SecurityKnowledgeGraph } from "../lib/knowledge-graph.js";
import { RUNS } from "../bench/known-vuln/apps.mjs";

const ROOT = join(import.meta.dirname, "..");

describe("the claim map", () => {
  it("every claim is in its file and held by a test", () => {
    const rows = parseClaims(readRepo("docs/claims.md"));
    expect(rows.length).toBeGreaterThanOrEqual(15);
    expect(checkClaims(rows, readRepo)).toEqual([]);
  });

  const row = { claim: "no telemetry", where: "`README.md`", heldBy: "`tests/a.test.js`: `holds it`" };
  const files = { "README.md": "MIT,\n  no <b>telemetry</b>", "tests/a.test.js": 'it("holds it", () => {});' };
  const read = (f) => files[f] ?? null;

  it("passes a good row, across line breaks and HTML tags", () => {
    expect(checkClaims([row], read)).toEqual([]);
  });

  it("fails when the claim left the file", () => {
    expect(checkClaims([{ ...row, claim: "no tracking" }], read)).toEqual(["no tracking: not in README.md"]);
  });

  it("fails when a named file is gone", () => {
    expect(checkClaims([{ ...row, where: "`GONE.md`" }], read)).toEqual(["no telemetry: GONE.md doesn't exist"]);
  });

  it("fails when the test file is gone", () => {
    expect(checkClaims([{ ...row, heldBy: "`tests/b.test.js`: `holds it`" }], read))
      .toEqual(["no telemetry: tests/b.test.js doesn't exist"]);
  });

  it("fails when the test was renamed", () => {
    expect(checkClaims([{ ...row, heldBy: "`tests/a.test.js`: `held it`" }], read))
      .toEqual(['no telemetry: no test "held it" in tests/a.test.js']);
  });

  it("fails when the test is skipped", () => {
    const skipped = (f) => (f === "tests/a.test.js" ? 'it.skip("holds it", () => {});' : read(f));
    expect(checkClaims([row], skipped)).toEqual(['no telemetry: no test "holds it" in tests/a.test.js']);
  });

  // Each of these leaves the title in the file while the test never runs.
  it.each([
    ["it.skip", 'it.skip("holds it", () => {});'],
    ["it.todo", 'it.todo("holds it");'],
    ["it.fails", 'it.fails("holds it", () => {});'],
    ["it.skipIf", 'it.skipIf(true)("holds it", () => {});'],
    ["it.runIf", 'it.runIf(false)("holds it", () => {});'],
    ["xit", 'xit("holds it", () => {});'],
    ["test.skip", 'test.skip("holds it", () => {});'],
    ["xtest", 'xtest("holds it", () => {});'],
    ["describe.skip", 'describe.skip("group", () => { it("holds it", () => {}); });'],
    ["xdescribe", 'xdescribe("group", () => { it("holds it", () => {}); });'],
    ["nested describe.skip", 'describe.skip("a", () => { describe("b", () => { it("holds it", () => {}); }); });'],
    ["a line comment", '// it("holds it", () => {});'],
    ["a block comment", '/*\n  it("holds it", () => {});\n*/'],
    ["a string", 'const s = \'it("holds it", () => {});\';'],
    ["only elsewhere in the file", 'it.only("other", () => {});\nit("holds it", () => {});'],
  ])("fails when the test can't run: %s", (_, source) => {
    const test = (f) => (f === "tests/a.test.js" ? source : read(f));
    expect(checkClaims([row], test)).toEqual(['no telemetry: no test "holds it" in tests/a.test.js']);
  });

  it.each([
    ["it", 'it("holds it", () => {});'],
    ["test", 'test("holds it", () => {});'],
    ["a template title", "it(`holds it`, () => {});"],
    ["inside describe", 'describe("group", () => { it("holds it", () => {}); });'],
    ["it.concurrent", 'it.concurrent("holds it", () => {});'],
    ["it.each", 'it.each([1])("holds it", () => {});'],
    ["it.only", 'it.only("holds it", () => {});'],
    ["beside a skipped group", 'describe.skip("a", () => { it("x", () => {}); });\nit("holds it", () => {});'],
  ])("passes a test that runs: %s", (_, source) => {
    const test = (f) => (f === "tests/a.test.js" ? source : read(f));
    expect(checkClaims([row], test)).toEqual([]);
  });

  it("names a test file it can't parse", () => {
    const test = (f) => (f === "tests/a.test.js" ? "it(" : read(f));
    expect(checkClaims([row], test)[0]).toMatch(/no telemetry: can't parse tests\/a\.test\.js/);
  });

  it("fails on an empty map and on a malformed row", () => {
    expect(checkClaims([], read)).toEqual(["docs/claims.md: no claims found"]);
    expect(checkClaims([{ ...row, heldBy: "tests/a.test.js" }], read)[0]).toMatch(/"Held by" should be/);
  });
});

// Claims with no test of their own until the map asked for one.
describe("claims the map holds itself", () => {
  it("README and site quote the same rule total", () => {
    const total = totalRules(activePacks());
    expect(readRepo("README.md")).toContain(`**${total}** readable rules`);
    expect(readRepo("README.md")).toContain(`| ${total} in this release:`);
  });

  it("no E10 run logs in", () => {
    expect(Object.keys(RUNS).length).toBeGreaterThan(0);
    for (const [name, run] of Object.entries(RUNS)) expect(run.auth, name).toBe(false);
  });

  it("package.json has no runtime dependencies", () => {
    const { dependencies, optionalDependencies, peerDependencies } = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
    expect({ ...dependencies, ...optionalDependencies, ...peerDependencies }).toEqual({});
  });

  it("--fuzz sends the DROP TABLE string the docs name", () => {
    expect(fuzzField("name")).toContain("'; DROP TABLE users; --");
  });

  describe("adaptive probes", () => {
    const seen = [];
    const server = createServer((req, res) => { seen.push(req.method); res.statusCode = 404; res.end(); });
    afterAll(() => server.close());

    it("--adaptive sends DELETE to a route that does not declare it", async () => {
      await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
      const base = `http://127.0.0.1:${server.address().port}`;
      const route = { url: "/api/items", methods: ["GET"], auth: [] };
      await probeMethodConfusion(base, route, new SecurityKnowledgeGraph());
      expect(seen).toEqual(expect.arrayContaining(["DELETE", "PUT", "PATCH", "POST"]));
      expect(seen).not.toContain("GET");
    });
  });
});
