#!/usr/bin/env node
/**
 * Penthera Bench v1: the blind labelling tool (E1 § 6.2).
 *
 *   node bench/real-world/label.js --corpus bench/real-world/pilot/corpus.json --labeller A --set calibration
 *
 * Shows one unit at a time from the labeller's own queue: the category
 * question and the code. It never shows Penthera's verdict, severity,
 * confidence, or the other labeller's answer, and never reads units-key.jsonl.
 * Answers are appended to labels-<labeller>.jsonl in the study folder (outside
 * the repository); quitting and restarting resumes where you stopped.
 *
 * The analysis set opens only after the calibration gate has passed
 * (kappa.js --set calibration), as the pre-registration requires.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { spawnSync } from "node:child_process";
import { appendJsonl, cacheDir, isMain, parseArgs, readJson, readJsonl, readManifest, studyDir } from "./lib.js";

export const ANSWERS = { y: "yes", n: "no", c: "cannot" };
export const CODEBOOK_VERSION = "1";

/** Lines of a file with numbers, trimmed to `max` lines, marking lines that contain `mark`. */
export function excerpt(text, { max = 200, mark = null } = {}) {
  const lines = String(text).split("\n");
  const width = String(Math.min(lines.length, max)).length;
  const shown = lines.slice(0, max).map((l, i) => `${mark && l.includes(mark) ? ">" : " "}${String(i + 1).padStart(width)}  ${l.length > 220 ? l.slice(0, 220) + " …" : l}`);
  if (lines.length > max) shown.push(`   … ${lines.length - max} more lines (press o to open the whole file)`);
  return shown.join("\n");
}

/** Where a unit's content lives on disk, and the text to show. */
export function render(item, { cache, out }) {
  const s = item.show;
  if (s.kind === "package") {
    const dir = join(out, "packages", readdirSafe(join(out, "packages")).find((d) => d.endsWith(`${s.package.replace(/[/@]/g, "_")}@${s.version}`)) || "missing");
    if (!existsSync(dir)) return { path: null, text: "(package source not available)" };
    const files = listFiles(dir).filter((f) => f !== ".bench.json");
    const manifest = files.find((f) => /(^|\/)package\.json$/.test(f)) || files.find((f) => /METADATA$/.test(f));
    const body = manifest ? `\n--- ${manifest} ---\n${excerpt(readFileSync(join(dir, manifest), "utf8"), { max: 60 })}` : "";
    return { path: dir, text: `Package folder: ${dir}\n${files.length} files:\n${files.slice(0, 80).map((f) => `  ${f}  (${statSync(join(dir, f)).size} B)`).join("\n")}${files.length > 80 ? "\n  …" : ""}${body}` };
  }
  const path = join(cache, "repos", item.project, s.path);
  if (!existsSync(path)) return { path: null, text: `(file ${s.path} is not present in the project)` };
  const mark = s.kind === "route" ? s.route.replace(/\[[^\]]+\]|:[^/]+/g, "").split("/").filter(Boolean).pop() || null : null;
  return { path, text: excerpt(readFileSync(path, "utf8"), { mark }) };
}

function readdirSafe(d) { try { return readdirSync(d); } catch { return []; } }

function listFiles(dir, base = dir, out = []) {
  for (const e of readdirSafe(dir)) {
    const p = join(dir, e);
    const st = statSync(p);
    if (st.isDirectory()) listFiles(p, base, out);
    else out.push(p.slice(base.length + 1));
  }
  return out;
}

/** Units still to label for a labeller and set, in queue order. */
export function pending(queue, labels, set) {
  const done = new Set(labels.map((l) => l.id));
  return queue.filter((q) => (set ? q.set === set : true) && !done.has(q.id));
}

async function main() {
  const args = parseArgs(process.argv.slice(2), ["allow-file", "force"]);
  const L = args.labeller;
  if (!args.corpus || !["A", "B"].includes(L)) {
    console.error("usage: node bench/real-world/label.js --corpus <manifest.json> --labeller A|B [--set calibration|analysis] [--cache <dir>]");
    process.exit(2);
  }
  const cache = cacheDir(args.cache);
  const manifest = readManifest(resolve(args.corpus), { allowFile: !!args["allow-file"] });
  const out = studyDir(cache, manifest.set);
  const set = args.set || "calibration";
  if (set === "analysis" && !args.force) {
    const gate = readJson(join(out, "calibration-gate.json"), null);
    if (!gate?.passed) {
      console.error("The calibration gate has not passed yet (kappa.js --set calibration). Analysis labelling starts only after it does.");
      process.exit(1);
    }
  }
  const queue = readJsonl(join(out, `queue-${L}.jsonl`));
  const labelsPath = join(out, `labels-${L}.jsonl`);
  const todo = pending(queue, readJsonl(labelsPath), set);
  const total = queue.filter((q) => q.set === set).length;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const ask = async (q, allowed) => {
    for (;;) {
      const a = (await rl.question(q)).trim().toLowerCase();
      if (allowed.includes(a)) return a;
    }
  };
  try {
    for (const [i, item] of todo.entries()) {
      const { path, text } = render(item, { cache, out });
      process.stdout.write("\x1b[2J\x1b[H");
      console.log(`[${total - todo.length + i + 1}/${total}] ${set} · ${item.category} · ${item.project}`);
      const loc = item.show.kind === "route" ? `${(item.show.methods || []).join(",")} ${item.show.route}  (${item.show.path})` : item.show.kind === "package" ? `${item.show.package}@${item.show.version}` : item.show.path;
      console.log(`Location: ${loc}\n`);
      console.log(text);
      console.log(`\nQuestion: ${item.question}`);
      let a;
      for (;;) {
        a = await ask("Correct? [y]es [n]o [c]annot tell, [o]pen, [s]kip, [q]uit: ", ["y", "n", "c", "o", "s", "q"]);
        if (a === "o" && path) spawnSync(process.env.PAGER || "less", [path], { stdio: "inherit" });
        else if (a !== "o") break;
      }
      if (a === "q") break;
      if (a === "s") continue;
      let actionable = null;
      if (a === "y") actionable = ANSWERS[await ask("Should the owner change something because of it? [y]es [n]o [c]annot tell: ", ["y", "n", "c"])];
      const note = (await rl.question("Note (optional, Enter to skip): ")).trim();
      appendJsonl(labelsPath, { id: item.id, labeller: L, set, correct: ANSWERS[a], actionable, note: note || null, codebook: CODEBOOK_VERSION, at: new Date().toISOString() });
    }
  } finally {
    rl.close();
  }
  const left = pending(queue, readJsonl(labelsPath), set).length;
  console.log(left ? `${left} ${set} units left. Run again to continue.` : `All ${set} units labelled.`);
}

if (isMain(import.meta.url)) main().catch((e) => { console.error(e.message); process.exit(1); });
