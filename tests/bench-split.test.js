import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseHashes, verifyManifest, readManifest, fetchSplit, makeSplit, SPLIT_DIR, SPLIT_URL } from "../bench/public/split.mjs";

const HASH_FILE = join(import.meta.dirname, "..", "bench", "public", "split.sha256");
const sha = (s) => createHash("sha256").update(s).digest("hex");
const GOOD = Buffer.from('{"ids":{"dev":["a"],"test":["b"]}}');
const hashes = { demo: sha(GOOD) };

function withDirs(run) {
  const root = mkdtempSync(join(tmpdir(), "penthera-split-"));
  const dirs = [join(root, "repo"), join(root, "cache")];
  mkdirSync(dirs[0]);
  return Promise.resolve(run(dirs)).finally(() => rmSync(root, { recursive: true, force: true }));
}

describe("the E11b split manifests", () => {
  it("pins all four benchmarks, and matches any manifest still in the repo", () => {
    const pinned = parseHashes(readFileSync(HASH_FILE, "utf-8"));
    expect(Object.keys(pinned).sort()).toEqual(["benign", "creddata", "malware", "secbench"]);
    for (const bench of Object.keys(pinned)) {
      const file = join(SPLIT_DIR, `${bench}.json`);
      if (existsSync(file)) expect(() => verifyManifest(bench, readFileSync(file), pinned)).not.toThrow();
    }
  });

  it("refuses a manifest whose hash doesn't match", () => {
    expect(() => verifyManifest("demo", Buffer.from("{}"), hashes)).toThrow(/Refusing this manifest/);
    expect(() => verifyManifest("other", GOOD, hashes)).toThrow(/not in bench\/public\/split\.sha256/);
  });

  it("reads and verifies from the first folder that has it", () => withDirs(([repo, cache]) => {
    mkdirSync(cache);
    writeFileSync(join(cache, "demo.json"), GOOD);
    expect(readManifest("demo", { dirs: [repo, cache], hashes }).ids.dev).toEqual(["a"]);
    writeFileSync(join(repo, "demo.json"), "{}");
    expect(() => readManifest("demo", { dirs: [repo, cache], hashes })).toThrow(/Refusing/);
  }));

  it("says how to get a manifest that isn't here", () => withDirs((dirs) => {
    expect(() => readManifest("demo", { dirs, hashes })).toThrow("npm run bench:public -- --fetch-split");
  }));

  it("downloads a missing manifest from the release and keeps it", () => withDirs(async (dirs) => {
    const asked = [];
    const fetcher = async (url) => { asked.push(url); return GOOD; };
    expect(await fetchSplit({ fetcher, dirs, hashes })).toEqual({ demo: "fetched" });
    expect(asked).toEqual([`${SPLIT_URL}/demo.json`]);
    expect(readFileSync(join(dirs[1], "demo.json"))).toEqual(GOOD);
  }));

  it("makes no request for a manifest already here", () => withDirs(async ([repo, cache]) => {
    writeFileSync(join(repo, "demo.json"), GOOD);
    const fetcher = async () => { throw new Error("must not fetch"); };
    expect(await fetchSplit({ fetcher, dirs: [repo, cache], hashes })).toEqual({ demo: "here" });
  }));

  it("writes nothing when the download is tampered with or missing", () => withDirs(async (dirs) => {
    await expect(fetchSplit({ fetcher: async () => Buffer.from("{}"), dirs, hashes })).rejects.toThrow(/Refusing/);
    await expect(fetchSplit({ fetcher: async () => null, dirs, hashes })).rejects.toThrow(/not on the v/);
    expect(existsSync(join(dirs[1], "demo.json"))).toBe(false);
  }));

  it("won't redraw the sealed split, even with the manifests gone", async () => {
    await expect(makeSplit()).rejects.toThrow(/sealed/);
  });
});
