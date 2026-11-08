/**
 * Shared parts for card layouts: the wordmark, the mosaic number, text
 * wrapping and the dither field. All of it reduces to draw.js operations.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CELL, GLYPHS } from "./font.js";
import { textWidth } from "./draw.js";

export const C = {
  blue: "#0000ed",
  blueDeep: "#0000b8",
  blueSoft: "#7a7aff",
  bluePale: "#c9c9ff",
  white: "#ffffff",
  paper: "#fdfdfa",
  ink: "#0a0a0a",
  black: "#000000",
  steel100: "#e4e8ed",
  steel300: "#b9c0ca",
  steel400: "#9aa3b0",
  gun400: "#5d6572",
  gun700: "#2b2f36",
  gun900: "#15171b",
  plateDark: "#1c1e23",
  slabLight: "#e6e6e1",
};

const LOGO_FILE = join(dirname(fileURLToPath(import.meta.url)), "..", "ui", "static", "logo.svg");
let logo = null;
/** The wordmark's paths and size, read from the shipped logo (never set in a font). */
export function wordmark() {
  if (!logo) {
    const svg = readFileSync(LOGO_FILE, "utf8");
    logo = {
      w: Number(/viewBox="0 0 ([\d.]+) /.exec(svg)[1]),
      h: Number(/viewBox="0 0 [\d.]+ ([\d.]+)"/.exec(svg)[1]),
      paths: [...svg.matchAll(/<path[^>]* d="([^"]+)"/g)].map((m) => m[1]),
    };
  }
  return logo;
}

export const logoOp = (x, y, width, fill) => {
  const L = wordmark();
  return { op: "path", paths: L.paths, x, y, s: width / L.w, fill };
};

// Rows 3..10 of a glyph hold capitals and digits (the cap height is 8 pixels).
const CAP_TOP = 3, CAP_ROWS = 8;

/**
 * A string as mosaic rows: each glyph's pixels become blocks. Columns that are
 * empty in every glyph's outer edge are trimmed once at the ends.
 */
export function mosaicRows(s) {
  const chars = [...String(s)];
  const rows = Array.from({ length: CAP_ROWS }, () => "");
  for (const ch of chars) {
    const hexs = GLYPHS[ch.codePointAt(0)] || GLYPHS[63];
    for (let r = 0; r < CAP_ROWS; r++) {
      const v = parseInt(hexs.slice((CAP_TOP + r) * 2, (CAP_TOP + r) * 2 + 2), 16);
      rows[r] += v.toString(2).padStart(CELL.w, "0");
    }
  }
  // Trim the empty columns on both ends so the block sits on the margin.
  let left = 0, right = rows[0].length;
  while (left < right && rows.every((r) => r[left] === "0")) left++;
  while (right > left && rows.every((r) => r[right - 1] === "0")) right--;
  return rows.map((r) => r.slice(left, right));
}

/** Width and height in pixels of a mosaic at block size k and gap g. */
export const mosaicSize = (rows, k, g) => ({ w: rows[0].length * (k + g) - g, h: rows.length * (k + g) - g });

/** Cut a line back to its last whole word (no regex: lines can be long). */
export function dropLastWord(s) {
  const t = String(s).trimEnd();
  const i = t.lastIndexOf(" ");
  return i > 0 ? t.slice(0, i).trimEnd() : t;
}

/** Wrap text to lines of at most n characters, breaking at spaces. */
export function wrap(s, n, maxLines = 3) {
  const words = String(s).split(/\s+/).filter(Boolean);
  const lines = [];
  let cur = "";
  for (const w of words) {
    if (!cur) cur = w;
    else if ((cur + " " + w).length <= n) cur += " " + w;
    else { lines.push(cur); cur = w; }
  }
  if (cur) lines.push(cur);
  if (lines.length > maxLines) {
    const kept = lines.slice(0, maxLines);
    kept[maxLines - 1] = `${dropLastWord(kept[maxLines - 1].slice(0, n - 1))}…`;
    return kept;
  }
  return lines.map((l) => (l.length > n ? `${l.slice(0, n - 1)}…` : l));
}

/** Right-aligned text op. */
export const textRight = (s, right, y, k, fill, alpha) => ({ op: "text", s, x: right - textWidth(s, k), y, k, fill, alpha });
export const textCenter = (s, cx, y, k, fill, alpha) => ({ op: "text", s, x: Math.round(cx - textWidth(s, k) / 2), y, k, fill, alpha });

const BAYER = [
  [0, 32, 8, 40, 2, 34, 10, 42], [48, 16, 56, 24, 50, 18, 58, 26],
  [12, 44, 4, 36, 14, 46, 6, 38], [60, 28, 52, 20, 62, 30, 54, 22],
  [3, 35, 11, 43, 1, 33, 9, 41], [51, 19, 59, 27, 49, 17, 57, 25],
  [15, 47, 7, 39, 13, 45, 5, 37], [63, 31, 55, 23, 61, 29, 53, 21],
];

/**
 * A 1-bit field: ordered dither of a density function over a grid. The same
 * size gives the same field, so cards stay reproducible.
 * @param {(u: number, v: number) => number} density  0..1 over the unit square
 */
export function ditherRows(cols, rows, density) {
  const out = [];
  for (let y = 0; y < rows; y++) {
    let line = "";
    for (let x = 0; x < cols; x++) {
      const d = density(cols > 1 ? x / (cols - 1) : 0, rows > 1 ? y / (rows - 1) : 0);
      line += d * 64 > BAYER[y % 8][x % 8] + 0.5 ? "1" : "0";
    }
    out.push(line);
  }
  return out;
}

/** A soft cloud: a few fixed blobs, no randomness. */
export function cloud(blobs) {
  return (u, v) => {
    let d = 0;
    for (const [bu, bv, r, a] of blobs) {
      const du = (u - bu) / r, dv = (v - bv) / r;
      d += a * Math.exp(-(du * du + dv * dv));
    }
    return Math.max(0, Math.min(1, d));
  };
}
