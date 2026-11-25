/**
 * The timing check: does a scanner's work grow in line with its input?
 *
 * Almost every slowdown the Vercel Security Review found in Penthera (20 of
 * the 38 findings logged by 22 Nov 2026) had one shape: a keyword the rule
 * looks for, repeated with some glue, and no match at the end. Each repeat
 * made the rule read the rest of the file again. A regex linter does not see
 * this, because each single attempt is cheap; only the total is quadratic.
 *
 * So this builds that input for every rule from the rule's own words. It reads
 * the words out of the regex literals in the rule's source file, glues them
 * into fillers (`w . w . w`, `w(w(w(`, `"w "w "w`, `w://?w://?` …), and times
 * the scanner at one size and at four times that size. Linear work grows about
 * 4x, quadratic about 16x.
 */
import { readFileSync } from "node:fs";
import { cpuMs } from "../fixtures/cpu-time.js";

/** Words in the regex literals and quoted alternations of a source file, most rule keywords among them. */
export function ruleWords(file, { max = 2000 } = {}) {
  const src = readFileSync(file, "utf-8");
  const words = new Set();
  const add = (body) => { for (const w of body.match(/[A-Za-z_$][\w$-]{1,23}/g) || []) words.add(w); };
  // regex literals: /…/flags, after a token that cannot end an expression
  for (const m of src.matchAll(/(?<=[=(,:;!&|?{}[\n]\s*)\/(?![*/])((?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n])+)\/[dgimsuy]*/g)) add(m[1].replace(/\\[a-zA-Z]/g, " "));
  // word lists in strings: "a|b|c".split("|") and String.raw alternations
  for (const m of src.matchAll(/["'`]((?:[\w$.-]+\|){2,}[\w$.-]+)["'`]/g)) add(m[1].replace(/\|/g, " "));
  return [...words].sort().slice(0, max);
}

/** Glue shapes. Each takes the next word and returns one unit of filler. */
export const SHAPES = {
  "w ": (w) => `${w} `,
  "w . ": (w) => `${w} . `,
  "w.": (w) => `${w}.`,
  "w(": (w) => `${w}(`,
  "w -a ": (w) => `${w} -a `,
  "w -a b ": (w) => `${w} -a b `,
  "w a=b ": (w) => `${w} a=b `,
  "| w -a ": (w) => `| ${w} -a `,
  "w(a) . ": (w) => `${w}(a) . `,
  "| w ": (w) => `| ${w} `,
  '"w ': (w) => `"${w} `,
  "'w": (w) => `'${w}`,
  "w://?": (w) => `${w}://?`,
  "w:////": (w) => `${w}:////`,
  "/w": (w) => `/${w}`,
  "w: false, ": (w) => `${w}: false, `,
  "w, one per line": (w) => `${w}\n`,
  "w = ": (w) => `${w} = `,
  "{ w: ": (w) => `{ ${w}: `,
  "[w, ": (w) => `[${w}, `,
  "w<": (w) => `${w}<`,
  "/* w ": (w) => `/* ${w} `,
  "${w": (w) => "${" + w,
  "`w ": (w) => "`" + w + " ",
  "w && ": (w) => `${w} && `,
  "; w ": (w) => `; ${w} `,
  "w, line continued": (w) => `${w} \\\n`,
  "<w ": (w) => `<${w} `,
  "w=w&": (w) => `${w}=${w}&`,
  "- w: ": (w) => `- ${w}: `,
  "w: block scalar": (w) => `${w}: |\n  `,
};

/** Text of about `size` characters: `shape` applied to `words` in turn. */
export function filler(shape, words, size) {
  const unit = [];
  let len = 0;
  for (let i = 0; len < size; i++) { const u = shape(words[i % words.length]); unit.push(u); len += u.length; }
  return unit.join("");
}

/**
 * Text of about `size` characters in `words.length` blocks: each block is one
 * word repeated with the glue. A trigger usually needs the same word again and
 * again (`http://?http://?…`), and a mix of words dilutes it; a block per word
 * keeps it, and lets one measurement test many words at once. With k words a
 * quadratic path still costs n²/k, so keep k small (16 by default).
 */
export function blocks(shape, words, size) {
  const each = Math.ceil(size / words.length);
  return words.map((w) => filler(shape, [w], each)).join("\n");
}

/** `list` in groups of `k`. */
export const groups = (list, k) => Array.from({ length: Math.ceil(list.length / k) }, (_, i) => list.slice(i * k, i * k + k));

/** A long quoted key, then the filler inside its object: the shape of the session-cookie finding. */
export const PREFIXES = {
  "": (size) => "",
  '"kkk…": { ': (size) => `"${"k".repeat(size)}": { `,
  "((((": (size) => "(".repeat(Math.min(size, 2000)),
  '; "': () => '; "',
  "&& '": () => "&& '",
};
/** Which shapes also run behind which prefixes. */
export const PREFIXED = {
  "w: false, ": ['"kkk…": { ', "(((("],
  "w ": ['"kkk…": { ', "(((("],
  "w = ": ["(((("],
  "/w": ['; "', "&& '"],
  "w.": ['; "'],
};

// CPU time, not wall-clock: a busy machine deschedules the worker, and that is not the scanner's work.
const once = (run, text) => cpuMs(() => run(text));
const best = (run, text, tries) => cpuMs(() => run(text), { runs: tries });

/**
 * Time `run(make(size))` at n and 4n. Returns null when the growth is linear,
 * or { n, a, b, ratio, why } when it is not. A first reading over the limit is
 * taken again three times, and confirmed at 16n, so one slow moment on a busy
 * machine does not fail the check.
 */
export function superlinear(run, make, { n = 32 * 1024, limit = 9, floor = 3, tooSlow = 1500 } = {}) {
  // Exponential work shows on a few hundred characters, and would never finish at n:
  // read a small ladder first and stop at the first step that is far too slow.
  // Small steps: exponential work multiplies per repeat, and a scan cannot be stopped once it starts.
  for (let tiny = 48; tiny <= 640; tiny += 16) {
    const t = once(run, make(tiny));
    if (t > 250) return { n: tiny, a: t, b: NaN, ratio: NaN, why: `${Math.round(t)} ms for ${tiny} characters (exponential?)` };
  }
  // Screen at 4n first: fast there means linear enough, and most inputs stop here.
  const quick = once(run, make(4 * n));
  if (quick < limit * floor) return null;
  const tn = make(n);
  let a = once(run, tn);
  if (a > tooSlow) { a = best(run, tn, 2); if (a > tooSlow) return { n, a, b: NaN, ratio: NaN, why: `${Math.round(a)} ms for ${n} characters` }; }
  const t4 = make(4 * n);
  let b = once(run, t4);
  if (b / Math.max(a, floor) < limit) return null;
  // A second at 4n and well over the limit is not noise: report it without measuring again.
  if (b > 1000 && b / Math.max(a, floor) > 1.3 * limit) return { n, a, b, ratio: b / Math.max(a, floor), why: `${a.toFixed(1)} ms at n, ${b.toFixed(1)} ms at 4n` };
  a = best(run, tn, 3);
  b = best(run, t4, 3);
  const ratio = b / Math.max(a, floor);
  if (ratio < limit) return null;
  if (b > 250) return { n, a, b, ratio, why: `${a.toFixed(1)} ms at n, ${b.toFixed(1)} ms at 4n` };
  // Confirm at 16n: quadratic keeps climbing, a cache or JIT step does not.
  const c = best(run, make(16 * n), 2);
  if (c / Math.max(b, floor) < limit * 0.75) return null;
  return { n, a, b, ratio, why: `${a.toFixed(1)} ms at n, ${b.toFixed(1)} ms at 4n, ${c.toFixed(1)} ms at 16n` };
}

/**
 * The words in `group` that make `run` superlinear, as [{ word, why }].
 *
 * One measurement first, with every word in its own block: if it costs about
 * what a neutral word costs (`baseline` ms at 4n), no word here is slow enough
 * to matter and the group passes. If it costs more, each word is measured
 * alone at full size, where a quadratic path cannot hide behind the others.
 */
export function slowWords(run, make, group, baseline, opts = {}) {
  const n = opts.n ?? 32 * 1024;
  if (group.length > 1) {
    const t = once(run, make(group, 4 * n));
    if (t < Math.max(2 * baseline, baseline + 4)) return [];
  }
  const out = [];
  for (const word of group) {
    const r = superlinear(run, (size) => make([word], size), opts);
    if (r) out.push({ word, why: r.why });
  }
  return out;
}

/** The time of `run` on neutral input at 4n: the best of two, in ms. */
export function baselineOf(run, make, opts = {}) {
  return best(run, make(["zq"], 4 * (opts.n ?? 32 * 1024)), 2);
}
