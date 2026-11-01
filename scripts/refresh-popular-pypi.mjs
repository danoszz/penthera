#!/usr/bin/env node
/**
 * Refresh lib/deps/popular-pypi.json.gz, the vendored list of popular PyPI
 * project names that `penthera deps` checks Python dependencies against for
 * typosquats.
 *
 * Run at release time only. This is the one place the PyPI typosquat list
 * touches the network; the scanner itself never fetches it.
 *
 * Source: top-pypi-packages by Hugo van Kemenade
 * (https://github.com/hugovk/top-pypi-packages), the most-downloaded PyPI
 * projects over the last 30 days, from the public PyPI BigQuery dataset. The
 * JSON is read as data; only project names (no other content) are kept, PEP
 * 503 normalised and in rank order.
 *
 *   node scripts/refresh-popular-pypi.mjs [--count 8000]
 */
import { writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";

const URL_ = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json";
const countArg = process.argv.indexOf("--count");
const COUNT = countArg > -1 ? parseInt(process.argv[countArg + 1], 10) : 8000;
const OUT = new URL("../lib/deps/popular-pypi.json.gz", import.meta.url);

const res = await fetch(URL_);
if (!res.ok) {
  console.error(`Fetching ${URL_} failed: HTTP ${res.status}`);
  process.exit(1);
}
const data = await res.json();
const rows = Array.isArray(data.rows) ? data.rows : [];
const normalize = (n) => String(n).replace(/[-_.]+/g, "-").toLowerCase();
const names = [...new Set(rows.map((r) => r.project).filter((n) => typeof n === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(n)).map(normalize))].slice(0, COUNT);
if (names.length < 1000) {
  console.error(`Only parsed ${names.length} names from ${URL_}; refusing to update.`);
  process.exit(1);
}
const updated = String(data.last_update || "").slice(0, 10) || "unknown";

writeFileSync(OUT, gzipSync(JSON.stringify({
  source: `top-pypi-packages@${updated}`,
  license: "Project names only (factual data) from the public PyPI downloads dataset, ranked by top-pypi-packages",
  description: `Top ${names.length} most-downloaded PyPI projects (30 days), PEP 503 normalised, in rank order. Refreshed at release time by scripts/refresh-popular-pypi.mjs.`,
  count: names.length,
  names,
}, null, 0) + "\n", { level: 9 }));
console.log(`Wrote ${names.length} names (data from ${updated}) to lib/deps/popular-pypi.json.gz`);
