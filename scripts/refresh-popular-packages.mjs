#!/usr/bin/env node
/**
 * Refresh lib/deps/popular-packages.json.gz, the vendored list of popular npm
 * package names that `penthera deps` checks for typosquats.
 *
 * Run at release time only. This is the one place the typosquat list touches
 * the network; the scanner itself never fetches it.
 *
 * Source: npm-high-impact (MIT, https://github.com/wooorm/npm-high-impact),
 * the npm packages with the most downloads or dependents. We keep every name
 * from its most-dependents list and the top --count from its most-downloaded
 * list, interleaved so rank stays meaningful. The tarball is
 * fetched from the npm registry, checked against its published integrity, and
 * its name list is read as text (it is never executed).
 *
 *   node scripts/refresh-popular-packages.mjs [--count 5000]
 */
import { writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { gunzipSync } from "node:zlib";
import { untar, verifyIntegrity } from "../lib/deps/source.js";

const SOURCE = "npm-high-impact";
const countArg = process.argv.indexOf("--count");
const COUNT = countArg > -1 ? parseInt(process.argv[countArg + 1], 10) : 5000;
const OUT = new URL("../lib/deps/popular-packages.json.gz", import.meta.url);

const meta = await (await fetch(`https://registry.npmjs.org/${SOURCE}/latest`)).json();
const tgz = Buffer.from(await (await fetch(meta.dist.tarball)).arrayBuffer());
if (!verifyIntegrity(tgz, meta.dist.integrity)) {
  console.error(`Integrity mismatch for ${SOURCE}@${meta.version}, refusing to update.`);
  process.exit(1);
}
const files = untar(gunzipSync(tgz));
const list = (file) => {
  const text = files.get(file)?.toString("utf-8");
  if (!text) {
    console.error(`${SOURCE}@${meta.version} has no ${file}; the package layout changed.`);
    process.exit(1);
  }
  return [...text.matchAll(/^\s*'((?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+)',?\s*$/gm)].map((m) => m[1]);
};
const downloads = list("lib/top-download.js").slice(0, COUNT);
const dependents = list("lib/top-dependent.js");
const merged = [];
for (let i = 0; i < Math.max(downloads.length, dependents.length); i++) {
  if (i < downloads.length) merged.push(downloads[i]);
  if (i < dependents.length) merged.push(dependents[i]);
}
const unique = [...new Set(merged)];
if (unique.length < 1000) {
  console.error(`Only parsed ${unique.length} names from ${SOURCE}@${meta.version}; refusing to update.`);
  process.exit(1);
}

writeFileSync(OUT, gzipSync(JSON.stringify({
  source: `${SOURCE}@${meta.version}`,
  license: meta.license,
  description: `Top ${COUNT} most-downloaded plus all most-depended-on npm package names, interleaved by rank. Refreshed at release time by scripts/refresh-popular-packages.mjs.`,
  count: unique.length,
  names: unique,
}, null, 0) + "\n", { level: 9 }));
console.log(`Wrote ${unique.length} names from ${SOURCE}@${meta.version} to lib/deps/popular-packages.json.gz`);
