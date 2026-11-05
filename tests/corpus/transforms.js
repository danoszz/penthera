// Rewrites that keep a file's meaning, for the same-meaning tests (roadmap 108). Each takes
// the text and a seeded random function and returns text the reader must judge the same.
// A transform only applies to formats where it doesn't change the meaning.

const lines = (t) => t.split("\n");

/** A seeded random number in [0, 1). */
export function rng(seed) {
  let x = seed >>> 0 || 1;
  return () => {
    x ^= x << 13; x >>>= 0; x ^= x >> 17; x ^= x << 5; x >>>= 0;
    return x / 4294967296;
  };
}

const COMMENT = { js: "// ", ts: "// ", py: "# ", sh: "# ", yml: "# ", yaml: "# ", toml: "# " };

export const TEXT = {
  crlf: (t) => t.replace(/\r?\n/g, "\r\n"),
  bom: (t) => `﻿${t}`,
  // Before a line's ending, as an editor leaves them: "abc  \r\n", never "abc\r  \n".
  trailingSpace: (t) => lines(t).map((l) => (l ? l.replace(/(\r?)$/, "  $1") : l)).join("\n"),
  blankLines: (t) => `\n\n${t.replace(/\n/g, "\n\n")}`,
  longLineBefore: (t, _r, ext) => (COMMENT[ext] ? `${COMMENT[ext]}${"x".repeat(5000)}\n${t}` : t),
  commentBefore: (t, _r, ext) => (COMMENT[ext] ? `${COMMENT[ext]}build helper, see README\n${t}` : t),
  indent: (t, _r, ext) => (["js", "ts", "json"].includes(ext) ? lines(t).map((l) => (l ? `    ${l}` : l)).join("\n") : t),
  // JS: double quotes as single quotes, when no quote of the other kind is inside.
  singleQuotes: (t, _r, ext) => (["js", "ts"].includes(ext) && !t.includes("'") ? t.replace(/"/g, "'") : t),
};

/** JSON: the same value, written another way. */
function reorder(v, r) {
  if (Array.isArray(v)) return v.map((x) => reorder(x, r));
  if (v && typeof v === "object") {
    const keys = Object.keys(v);
    for (let i = keys.length - 1; i > 0; i--) {
      const j = Math.floor(r() * (i + 1));
      [keys[i], keys[j]] = [keys[j], keys[i]];
    }
    return Object.fromEntries(keys.map((k) => [k, reorder(v[k], r)]));
  }
  return v;
}
/** Every ASCII letter in strings as a \uXXXX escape, roughly one in three. */
function escapeStrings(json, r) {
  return json.replace(/"((?:[^"\\]|\\.)*)"/g, (m, body) => `"${body.replace(/(?<!\\)[a-z]/gi, (c) => (r() < 0.34 ? `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}` : c))}"`);
}

export const JSON_FORMS = {
  keyOrder: (t, r) => JSON.stringify(reorder(JSON.parse(t), r), null, 2),
  compact: (t) => JSON.stringify(JSON.parse(t)),
  tabs: (t) => JSON.stringify(JSON.parse(t), null, "\t"),
  escapes: (t, r) => escapeStrings(t, r),
  crlf: TEXT.crlf,
  bom: TEXT.bom,
};

export const MARKDOWN = {
  crlf: TEXT.crlf,
  bom: TEXT.bom,
  trailingSpace: TEXT.trailingSpace,
  blankLines: (t) => t.replace(/\n\n/g, "\n\n\n"),
};

const PARSES = ["keyOrder", "compact", "tabs", "escapes"];
const isJson = (t) => { try { JSON.parse(t); return true; } catch { return false; } };

/**
 * Apply the named transforms. Those that rewrite JSON run first, on the plain text, and only
 * when it parses: a file that was never valid JSON gets the text rewrites only.
 */
export function apply(text, names, table, seed, ext = "") {
  const r = rng(seed);
  const json = isJson(text);
  // A BOM is only a BOM at the very start, so it goes on last.
  const rank = (n) => (PARSES.includes(n) ? 0 : n === "bom" ? 2 : 1);
  const order = [...names].filter((n) => json || !PARSES.includes(n)).sort((a, b) => rank(a) - rank(b));
  return order.reduce((t, n) => table[n](t, r, ext), text);
}
