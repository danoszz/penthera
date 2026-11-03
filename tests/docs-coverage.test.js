import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { docFiles, helpModel, PLANNING_DOCS } from "../scripts/docs-commands.mjs";
import { TOOLS } from "../src/mcp/tools.js";

const ROOT = join(import.meta.dirname, "..");
const read = (f) => readFileSync(join(ROOT, f), "utf-8");
const help = (argv) => {
  const r = spawnSync(process.execPath, [join(ROOT, "bin", "penthera.js"), ...argv], { encoding: "utf-8" });
  return r.stdout + r.stderr;
};

// The other way round from tests/docs-commands.test.js: that one checks every
// documented command exists, this one that everything shipped is documented.
describe("everything shipped is documented", () => {
  const userDocs = docFiles(ROOT)
    .filter((f) => !PLANNING_DOCS.some((p) => f.startsWith(p)))
    .map(read).join("\n");

  it("every --help flag appears in the user docs", () => {
    const model = helpModel(help);
    const flags = new Set([model.main.flags, ...[...model.subs.values()].map((s) => s.flags)].flatMap((f) => [...f]));
    const longFlags = [...flags].filter((f) => f.startsWith("--"));
    expect(longFlags.length).toBeGreaterThan(50);
    expect(longFlags.filter((f) => !new RegExp(`${f}(?![\\w-])`).test(userDocs))).toEqual([]);
  }, 60_000);

  it("every subcommand has a row in docs/commands/README.md", () => {
    const index = read("docs/commands/README.md");
    const subs = [...helpModel(help).subs.keys()].filter((s) => !["http", "https"].includes(s));
    expect(subs.length).toBeGreaterThan(10);
    expect(subs.filter((s) => !index.includes(`penthera ${s}`))).toEqual([]);
  }, 60_000);

  it("the MCP listing calls Penthera a security scanner, not an agent", () => {
    const listing = read("docs/mcp-listing.md");
    expect(listing).toContain("Penthera is a free, open-source security scanner that runs on your own machine.");
    expect(listing).not.toMatch(/security agent/i);
  });

  it("every MCP tool is on the MCP page and the listing", () => {
    expect(TOOLS.length).toBeGreaterThan(0);
    for (const doc of ["docs/commands/mcp.md", "docs/mcp-listing.md"]) {
      expect(TOOLS.map((t) => t.name).filter((n) => !read(doc).includes(n))).toEqual([]);
    }
  });
});
