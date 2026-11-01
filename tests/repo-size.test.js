import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, lstatSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dirname, "..");
const LIMIT = 256 * 1024;

// Datasets and other large files stay out of the repo. A file on this list needs
// a reason. Remove its row when the file goes or shrinks: the test asks for that.
const ALLOWED = {
  "site/media/film.mp4": "the homepage film",
  "site/media/social/reel.mp4": "the social reel",
  "assets/demo.gif": "the README demo",
  "assets/walkthrough.mp4": "the README walkthrough",
  "bench/front-door/psl/public_suffix_list.dat": "pinned input of the registered E20 study",
  "tests/fixtures/giants/semgrep/1.180.0/output.txt": "recorded tool output for the adapter test",
  "tests/fixtures/cyclonedx/bom-1.6.schema.json": "the SBOM schema tests validate against, read offline",
};

/** Paths over the limit that aren't allowed, and allowed paths no longer over it. */
function checkSizes(files, allowed, limit = LIMIT) {
  const big = files.filter((f) => f.size > limit).map((f) => f.path);
  return {
    tooBig: big.filter((p) => !(p in allowed)),
    stale: Object.keys(allowed).filter((p) => !big.includes(p)),
  };
}

describe("repo size", () => {
  it("no tracked file is over 256 KB without a reason", () => {
    const paths = execFileSync("git", ["ls-files", "-z"], { cwd: ROOT, encoding: "utf8", maxBuffer: 1e7 }).split("\0").filter(Boolean);
    expect(paths.length).toBeGreaterThan(100);
    // A file deleted but not yet staged is still listed.
    const files = paths.filter((path) => existsSync(join(ROOT, path))).map((path) => ({ path, size: lstatSync(join(ROOT, path)).size }));
    expect(checkSizes(files, ALLOWED)).toEqual({ tooBig: [], stale: [] });
  });

  it("fails a new large file, and passes one at the limit", () => {
    const files = [{ path: "data/new.csv", size: 257 * 1024 }, { path: "edge.json", size: LIMIT }];
    expect(checkSizes(files, {})).toEqual({ tooBig: ["data/new.csv"], stale: [] });
  });

  it("passes an allowed file, and fails a row whose file left or shrank", () => {
    const big = { path: "a.mp4", size: 2 * LIMIT };
    expect(checkSizes([big], { "a.mp4": "why" })).toEqual({ tooBig: [], stale: [] });
    expect(checkSizes([{ path: "a.mp4", size: 1 }], { "a.mp4": "why" }).stale).toEqual(["a.mp4"]);
    expect(checkSizes([], { "gone.mp4": "why" }).stale).toEqual(["gone.mp4"]);
  });
});
