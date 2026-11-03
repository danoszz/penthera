#!/usr/bin/env node
/**
 * The release the install matrix upgrades from: the newest stable release of the
 * previous minor, as CHANGELOG.md lists them. For 2.2.x that is 2.1.2, so the job
 * tests a real upgrade, never a reinstall of the candidate.
 *
 *   node scripts/ci/upgrade-from.mjs   prints it, e.g. 2.1.2
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const parts = (v) => v.split(".").map(Number);

/** @param {string} version  the candidate  @param {string} changelog  CHANGELOG.md's text */
export function upgradeFrom(version, changelog) {
  const [major, minor] = parts(version);
  const released = [...changelog.matchAll(/^## \[(\d+\.\d+\.\d+)\]/gm)].map((m) => m[1]);
  const from = released.find((v) => { const [a, b] = parts(v); return a < major || (a === major && b < minor); });
  if (!from) throw new Error(`no release before ${major}.${minor} in CHANGELOG.md`);
  return from;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = new URL("../../", import.meta.url);
  const { version } = JSON.parse(readFileSync(new URL("package.json", root), "utf8"));
  process.stdout.write(`${upgradeFrom(version, readFileSync(new URL("CHANGELOG.md", root), "utf8"))}\n`);
}
