/**
 * Minimal unified-diff support for fix recipes: create a patch from two
 * versions of a file, parse one back, and apply its hunks to text.
 *
 * Recipes compute the new file content in memory and turn it into a diff here;
 * nothing in this module touches the filesystem.
 */
import { cutAtFirst } from "../linear-text.js";

const CONTEXT = 3;
// Marks a final line that has no trailing newline, so "x" and "x\n" compare as
// different lines (as they do in git).
const NOEOL = "\u0000";

function toLines(text) {
  if (!text) return [];
  const lines = text.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  else lines[lines.length - 1] += NOEOL;
  return lines;
}

function fromLines(lines) {
  return lines.map((l, i) => (l.endsWith(NOEOL) && i === lines.length - 1 ? l.slice(0, -1) : l.replace(NOEOL, "") + "\n")).join("");
}

/** Line diff as a list of ops ({ t: " " | "-" | "+", line }). */
function diffLines(a, b) {
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length;
  let endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) { endA--; endB--; }

  const midA = a.slice(start, endA);
  const midB = b.slice(start, endB);
  const n = midA.length;
  const m = midB.length;
  const ends = [...a.slice(0, start).map((line) => ({ t: " ", line }))];
  const tail = a.slice(endA).map((line) => ({ t: " ", line }));
  // The LCS table is n x m: a recipe that edits 80,000 lines asked for 6.4
  // billion cells (Vercel Security Review, 2.3.2). Past LCS_MAX_CELLS the
  // middle is diffed in one pass instead: still a correct patch, maybe longer.
  if (n * m > LCS_MAX_CELLS) return [...ends, ...greedyDiff(midA, midB), ...tail];
  // LCS table over the changed middle only; recipe edits are small and local.
  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = midA[i] === midB[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const mid = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (midA[i] === midB[j]) { mid.push({ t: " ", line: midA[i] }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) mid.push({ t: "-", line: midA[i++] });
    else mid.push({ t: "+", line: midB[j++] });
  }
  while (i < n) mid.push({ t: "-", line: midA[i++] });
  while (j < m) mid.push({ t: "+", line: midB[j++] });

  return [...ends, ...mid, ...tail];
}

const LCS_MAX_CELLS = 4_000_000;
const LOOKAHEAD = 64;

/**
 * A line diff in one pass: equal lines are kept; at a difference, a line seen
 * again within LOOKAHEAD lines on the other side marks lines added or removed,
 * otherwise the line is replaced. O((n + m) x LOOKAHEAD).
 */
function greedyDiff(midA, midB) {
  const out = [];
  let i = 0;
  let j = 0;
  while (i < midA.length && j < midB.length) {
    if (midA[i] === midB[j]) { out.push({ t: " ", line: midA[i] }); i++; j++; continue; }
    let added = -1;
    for (let k = 1; k <= LOOKAHEAD && j + k < midB.length; k++) if (midB[j + k] === midA[i]) { added = k; break; }
    let removed = -1;
    for (let k = 1; k <= LOOKAHEAD && i + k < midA.length; k++) if (midA[i + k] === midB[j]) { removed = k; break; }
    if (added !== -1 && (removed === -1 || added <= removed)) { for (let k = 0; k < added; k++) out.push({ t: "+", line: midB[j++] }); }
    else if (removed !== -1) { for (let k = 0; k < removed; k++) out.push({ t: "-", line: midA[i++] }); }
    else { out.push({ t: "-", line: midA[i++] }); out.push({ t: "+", line: midB[j++] }); }
  }
  while (i < midA.length) out.push({ t: "-", line: midA[i++] });
  while (j < midB.length) out.push({ t: "+", line: midB[j++] });
  return out;
}

function renderLine(op) {
  const noeol = op.line.endsWith(NOEOL);
  const text = `${op.t}${noeol ? op.line.slice(0, -1) : op.line}`;
  return noeol ? `${text}\n\\ No newline at end of file` : text;
}

/**
 * Unified diff for one file. `before` is null for a new file. Returns "" when
 * nothing changed.
 */
export function createPatch(file, before, after) {
  const a = toLines(before);
  const b = toLines(after);
  const ops = diffLines(a, b);
  if (!ops.some((o) => o.t !== " ")) return "";

  // Group changes into hunks with CONTEXT lines around each.
  const hunks = [];
  let current = null;
  ops.forEach((op, idx) => {
    if (op.t === " ") return;
    const lo = Math.max(0, idx - CONTEXT);
    const hi = Math.min(ops.length - 1, idx + CONTEXT);
    if (current && lo <= current.hi + 1) current.hi = Math.max(current.hi, hi);
    else hunks.push((current = { lo, hi }));
  });

  const out = [`--- ${before == null ? "/dev/null" : `a/${file}`}`, `+++ b/${file}`];
  let oldNo = 1;
  let newNo = 1;
  let cursor = 0;
  for (const h of hunks) {
    for (; cursor < h.lo; cursor++) {
      if (ops[cursor].t !== "+") oldNo++;
      if (ops[cursor].t !== "-") newNo++;
    }
    const slice = ops.slice(h.lo, h.hi + 1);
    const oldCount = slice.filter((o) => o.t !== "+").length;
    const newCount = slice.filter((o) => o.t !== "-").length;
    out.push(`@@ -${oldCount ? oldNo : oldNo - 1},${oldCount} +${newCount ? newNo : newNo - 1},${newCount} @@`);
    for (const op of slice) out.push(renderLine(op));
    for (; cursor <= h.hi; cursor++) {
      if (ops[cursor].t !== "+") oldNo++;
      if (ops[cursor].t !== "-") newNo++;
    }
  }
  return out.join("\n") + "\n";
}

function stripPrefix(p) {
  if (p === "/dev/null") return null;
  return cutAtFirst(p.replace(/^[ab]\//, ""), "\t\n");
}

/** Parse a (multi-file) unified diff into [{ oldPath, newPath, hunks }]. */
export function parsePatch(text) {
  const files = [];
  const lines = String(text || "").split("\n");
  let file = null;
  let hunk = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith("--- ") && lines[i + 1]?.startsWith("+++ ")) {
      file = { oldPath: stripPrefix(line.slice(4).trim()), newPath: stripPrefix(lines[i + 1].slice(4).trim()), hunks: [] };
      files.push(file);
      hunk = null;
      i++;
      continue;
    }
    const header = line.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
    if (header) {
      if (!file) throw new Error("Malformed diff: hunk before file header");
      hunk = {
        oldStart: Number(header[1]),
        oldLines: header[2] == null ? 1 : Number(header[2]),
        newStart: Number(header[3]),
        newLines: header[4] == null ? 1 : Number(header[4]),
        ops: [],
      };
      file.hunks.push(hunk);
      continue;
    }
    if (!hunk) continue;
    if (line.startsWith("\\")) {
      const last = hunk.ops[hunk.ops.length - 1];
      if (last) last.line += NOEOL;
      continue;
    }
    const oldSeen = hunk.ops.filter((o) => o.t !== "+").length;
    const newSeen = hunk.ops.filter((o) => o.t !== "-").length;
    if (oldSeen >= hunk.oldLines && newSeen >= hunk.newLines) continue; // past the hunk
    const t = line[0];
    if (t === " " || t === "-" || t === "+") hunk.ops.push({ t, line: line.slice(1) });
    // Some editors strip the single space of an empty context line.
    else if (line === "") hunk.ops.push({ t: " ", line: "" });
  }
  for (const f of files) {
    for (const h of f.hunks) {
      const oldCount = h.ops.filter((o) => o.t !== "+").length;
      const newCount = h.ops.filter((o) => o.t !== "-").length;
      if (oldCount !== h.oldLines || newCount !== h.newLines) {
        throw new Error(`Malformed diff: hunk line counts do not match its header in ${f.newPath || f.oldPath}`);
      }
    }
  }
  return files;
}

function matchesAt(lines, expected, pos) {
  if (pos < 0 || pos + expected.length > lines.length) return false;
  for (let k = 0; k < expected.length; k++) if (lines[pos + k] !== expected[k]) return false;
  return true;
}

/**
 * Apply one parsed file's hunks to `text` (null for a new file). Context must
 * match exactly; a hunk may move by a few lines but is never fuzzed. Throws if
 * any hunk does not apply.
 */
export function applyHunks(text, hunks) {
  const lines = toLines(text);
  let offset = 0;
  for (const h of hunks) {
    const expected = h.ops.filter((o) => o.t !== "+").map((o) => o.line);
    const replacement = h.ops.filter((o) => o.t !== "-").map((o) => o.line);
    const want = (expected.length ? h.oldStart - 1 : h.oldStart) + offset;
    let pos = -1;
    for (let d = 0; d <= 50 && pos < 0; d++) {
      if (matchesAt(lines, expected, want - d)) pos = want - d;
      else if (matchesAt(lines, expected, want + d)) pos = want + d;
    }
    if (pos < 0) throw new Error(`Hunk @@ -${h.oldStart},${h.oldLines} @@ does not apply: the file changed since the plan was made`);
    lines.splice(pos, expected.length, ...replacement);
    offset += replacement.length - expected.length;
  }
  return fromLines(lines);
}
