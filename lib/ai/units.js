/**
 * Code units for the AI hunt: the parts of a repository a model reads, one at
 * a time, in a fixed order.
 *
 * A unit is a whole source file, or for a long file a run of top-level
 * declarations up to MAX_UNIT_LINES. Its id (`path:start-end`) is stable for
 * the same file, so the report can say what the model read and what it did
 * not. Order: files no code analysis read first (the coverage ledger's blind
 * spots), then files that look like entry points, then by path. Tests,
 * minified files and anything over the size cap are left out. Secrets the
 * secret scan recognises are masked before a unit leaves this module.
 */
import { closeSync, constants, fstatSync, openSync, readSync, realpathSync } from "node:fs";
import { isAbsolute, join, relative, sep } from "node:path";
import { fileCoverage } from "../coverage.js";
import { findSecretsInText } from "../whitebox/secrets.js";
import { trimEndChars } from "../linear-text.js";

export const MAX_UNIT_LINES = 200;
const MAX_FILE_BYTES = 256 * 1024;
export const SECRET_MASK = "[secret masked by Penthera]";

const TEST_FILE = /(^|\/)(tests?|__tests__|spec|fixtures?)\//i;
const TEST_NAME = /\.(test|spec)\.[^.]+$|(^|\/)test_[^/]*\.py$|_test\.(py|go)$|(^|\/)conftest\.py$/i;
const MINIFIED = /\.min\.(js|mjs|cjs)$|\.bundle\.js$/i;
// A line that starts a top-level declaration in the languages we split.
const TOP_LEVEL = /^(?:export\s+|module\.exports|exports\.|(?:async\s+)?function\b|class\b|const\b|let\b|var\b|def\b|async\s+def\b|@|func\b|type\b|interface\b|public\b|private\b|protected\b|static\b|(?:app|router|server)\.)/;
// Signs that a file handles outside input.
const ENTRY_HINT = /\breq\.(?:body|query|params|headers)|\brequest\.(?:json|form|args|body|query|params)|\bctx\.(?:req|request|params|query)|@app\.(?:route|get|post|put|delete)|@router\.|\b(?:app|router|server|fastify)\.(?:get|post|put|patch|delete|use|route)\s*\(|export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b|process\.argv|exports\.handler|addEventListener\(\s*['"]message/;

function readInside(root, rel) {
  let fd;
  try {
    const real = realpathSync(join(root, rel));
    const r = relative(root, real);
    if (!r || r === ".." || r.startsWith(`..${sep}`) || isAbsolute(r)) return null;
    fd = openSync(real, constants.O_RDONLY | (constants.O_NONBLOCK || 0) | (constants.O_NOFOLLOW || 0));
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > MAX_FILE_BYTES) return null;
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < st.size) {
      const n = readSync(fd, buf, off, st.size - off, off);
      if (n === 0) break;
      off += n;
    }
    const text = buf.subarray(0, off).toString("utf-8");
    return text.includes("\u0000") ? null : text;
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * Replace every span the secret scan recognises, keeping lines where they are.
 * The finder stops at 50 hits per rule, so this repeats until nothing is
 * found; text that still has hits after that is refused (null), never sent.
 */
export function maskSecrets(text) {
  let out = text;
  let masked = 0;
  for (let round = 0; round < 50; round++) {
    const hits = findSecretsInText(out);
    if (!hits.length) return { text: out, masked };
    out = maskSpans(out, hits.map((h) => hitSpan(out, h)));
    masked += hits.length;
  }
  return findSecretsInText(out).length ? null : { text: out, masked };
}

/**
 * The span of `text` a hit covers, in the coordinates of `text` itself. A hit
 * found in the raw text is its match. A hit found in the decoded copy
 * (`sk_live_…`) carries the decoded match and the start of its line: the
 * decoded length says nothing about the raw text, so the whole raw line (and
 * as many more as the match spans) is masked instead (R14).
 */
function hitSpan(text, h) {
  const end = h.index + h.match.length;
  if (text.slice(h.index, end) === h.match) return [h.index, end];
  let lineEnd = h.index;
  for (let n = (h.match.match(/\n/g) || []).length; n >= 0; n--) {
    const nl = text.indexOf("\n", lineEnd);
    if (nl === -1) return [h.index, text.length];
    lineEnd = n ? nl + 1 : nl;
  }
  return [h.index, lineEnd];
}

/** Replace spans (merged where they overlap) with the mask, one per line, so lines stay where they are. */
function maskSpans(text, spans) {
  const merged = [];
  for (const [a, b] of spans.sort((x, y) => x[0] - y[0])) {
    const last = merged[merged.length - 1];
    if (last && a <= last[1]) last[1] = Math.max(last[1], b);
    else merged.push([a, b]);
  }
  let out = "";
  let at = 0;
  for (const [a, b] of merged) {
    out += text.slice(at, a) + text.slice(a, b).split("\n").map(() => SECRET_MASK).join("\n");
    at = b;
  }
  return out + text.slice(at);
}

/** Split a file's lines into [start, end] ranges (1-based, inclusive) of at most MAX_UNIT_LINES. */
export function splitLines(lines) {
  if (lines.length <= MAX_UNIT_LINES) return [[1, Math.max(1, lines.length)]];
  const ranges = [];
  let start = 1;
  let lastBoundary = null;
  for (let i = 2; i <= lines.length; i++) {
    if (TOP_LEVEL.test(lines[i - 1])) lastBoundary = i;
    if (i - start + 1 > MAX_UNIT_LINES) {
      const cut = lastBoundary && lastBoundary > start ? lastBoundary : i;
      ranges.push([start, cut - 1]);
      start = cut;
      lastBoundary = null;
    }
  }
  ranges.push([start, lines.length]);
  return ranges;
}

/**
 * @param {string} repoPath
 * @param {object} scanResult - the repo scan result (for the coverage ledger)
 * @param {{ scope?: string|null }} [opts] - scope: only files under this repo-relative folder
 * @returns {{ units: object[], skipped: Record<string, number> }}
 */
export function buildUnits(repoPath, scanResult, { scope = null } = {}) {
  const root = realpathSync(repoPath);
  const prefix = scope ? trimEndChars(scope.replace(/\\/g, "/").replace(/^\.\//, ""), "/") + "/" : null;
  const { files } = fileCoverage(root, scanResult || {});
  const units = [];
  const skipped = {};
  const skip = (why) => { skipped[why] = (skipped[why] || 0) + 1; };
  for (const [rel, entry] of files) {
    if (!entry.language) continue;
    if (prefix && !rel.startsWith(prefix)) { skip("outside --ai-scope"); continue; }
    if (TEST_FILE.test(rel) || TEST_NAME.test(rel)) { skip("test file"); continue; }
    if (MINIFIED.test(rel)) { skip("minified"); continue; }
    if (entry.size > MAX_FILE_BYTES) { skip("over 256 KB"); continue; }
    const raw = readInside(root, rel);
    if (raw === null) { skip("not readable"); continue; }
    const m = maskSecrets(raw);
    if (!m) { skip("secrets could not all be masked"); continue; }
    const { text, masked } = m;
    const lines = text.split("\n");
    if (lines.length && lines[lines.length - 1] === "") lines.pop();
    if (!lines.length) continue;
    const blind = entry.routes !== "examined";
    const entryPoint = ENTRY_HINT.test(raw);
    for (const [start, end] of splitLines(lines)) {
      units.push({
        id: `${rel}:${start}-${end}`,
        file: rel,
        start,
        end,
        language: entry.language,
        blind,
        entryPoint,
        secretsMasked: masked,
        text: lines.slice(start - 1, end).join("\n"),
      });
    }
  }
  const score = (u) => (u.blind ? 2 : 0) + (u.entryPoint ? 1 : 0);
  units.sort((a, b) => score(b) - score(a) || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.start - b.start);
  return { units, skipped };
}
