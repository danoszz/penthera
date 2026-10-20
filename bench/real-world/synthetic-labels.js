#!/usr/bin/env node
/**
 * Penthera Bench v1: synthetic labels for a pipeline check ONLY.
 *
 *   node bench/real-world/synthetic-labels.js --corpus bench/real-world/pilot/corpus.json
 *
 * Writes labels-A.jsonl and labels-B.jsonl into <study>/synthetic/, generated
 * from a seed: "A" says yes to flagged units with probability 0.8 and to
 * unflagged units with probability 0.05, "B" copies A 90% of the time. They
 * exist so fetch → scan → units → κ → score can be tested end to end before
 * people label anything. They are not labels and never feed a real result:
 * score.js must be run with --synthetic and --labels-dir pointing here, and
 * the report then says so at the top.
 */
import { join, resolve } from "node:path";
import { mulberry32 } from "../prng.js";
import { cacheDir, isMain, parseArgs, readJsonl, readManifest, studyDir, writeJsonl } from "./lib.js";

export function syntheticLabels(units, seed = 1) {
  const rnd = mulberry32(seed);
  const pick = () => (rnd() < 0.9 ? "yes" : "no");
  const A = [];
  const B = [];
  for (const u of units) {
    const a = rnd() < (u.flagged ? 0.8 : 0.05) ? "yes" : "no";
    const aAct = a === "yes" ? pick() : null;
    const b = rnd() < 0.9 ? a : a === "yes" ? "no" : "yes";
    const bAct = b === "yes" ? (b === a ? aAct : pick()) : null;
    const at = "1970-01-01T00:00:00.000Z";
    A.push({ id: u.id, labeller: "synthetic-A", set: u.set, correct: a, actionable: aAct, note: null, codebook: "synthetic", at });
    B.push({ id: u.id, labeller: "synthetic-B", set: u.set, correct: b, actionable: bAct, note: null, codebook: "synthetic", at });
  }
  return { A, B };
}

async function main() {
  const args = parseArgs(process.argv.slice(2), ["allow-file"]);
  if (!args.corpus) {
    console.error("usage: node bench/real-world/synthetic-labels.js --corpus <manifest.json> [--cache <dir>]");
    process.exit(2);
  }
  const cache = cacheDir(args.cache);
  const manifest = readManifest(resolve(args.corpus), { allowFile: !!args["allow-file"] });
  const out = studyDir(cache, manifest.set);
  const { A, B } = syntheticLabels(readJsonl(join(out, "units-key.jsonl")), Number(args.seed || 1));
  writeJsonl(join(out, "synthetic", "labels-A.jsonl"), A);
  writeJsonl(join(out, "synthetic", "labels-B.jsonl"), B);
  console.log(`Synthetic labels for ${A.length} units in ${join(out, "synthetic")} (pipeline check only).`);
}

if (isMain(import.meta.url)) main().catch((e) => { console.error(e.message); process.exit(1); });
