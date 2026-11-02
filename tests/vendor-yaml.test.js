// The vendored yaml parser is upstream's code, byte for byte. A silent edit to it
// would change what Penthera reads in a skill, so any change fails here first.
import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "../lib/vendor/yaml/index.js";

const DIR = fileURLToPath(new URL("../lib/vendor/yaml/", import.meta.url));
// yaml 2.9.1: browser/dist, browser/index.js and LICENSE from the npm tarball.
// Recompute with the steps in lib/vendor/yaml/README.md, never by hand.
const TREE_SHA256 = "5355a67c2bfeab64d845afd1a0671ef90b2ba2d978faa3c1492df41e9fab888b";
const FILES = 75;

/** sha256 over each upstream file's path and its own sha256, in path order. */
function treeHash(dir) {
  const files = [];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name !== "README.md") files.push(relative(dir, p).split(sep).join("/"));
    }
  };
  walk(dir);
  files.sort();
  const h = createHash("sha256");
  for (const f of files) h.update(`${f}\0${createHash("sha256").update(readFileSync(join(dir, f))).digest("hex")}\n`);
  return { hash: h.digest("hex"), count: files.length };
}

describe("the vendored yaml parser", () => {
  it("is the reviewed upstream copy, unchanged", () => {
    expect(treeHash(DIR)).toEqual({ hash: TREE_SHA256, count: FILES });
  });
  it("names its version and source hash", () => {
    const readme = readFileSync(join(DIR, "README.md"), "utf8");
    expect(readme).toContain("2.9.1");
    expect(readme).toContain("sha512-3NxN8+78OdzbT7C/WjGsyfPAtJaN3FNDsWxv7Y7mcDsT/oOmgW8BpyQQFFBnvZE3j9Y2Sdz1ULFLezL7Eb2yFw==");
    expect(readme).toContain(TREE_SHA256);
  });
  it("parses skill frontmatter", () => {
    expect(YAML.parse("name: x\ndescription: |\n  two\n  lines\n")).toEqual({ name: "x", description: "two\nlines\n" });
  });
});
