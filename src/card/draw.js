/**
 * The share card's drawing layer. A card is a list of plain drawing operations,
 * and two backends turn the same list into an SVG string or PNG bytes. Nearly
 * everything is an axis-aligned rectangle (pixel type, mosaic blocks, dither),
 * so the PNG needs no font engine or image library; the logo is the one curve,
 * filled by a small scanline rasteriser. Same input, same bytes.
 *
 * Operations (all coordinates in card pixels):
 *   { op: "rect",   x, y, w, h, fill, alpha? }
 *   { op: "grad",   x, y, w, h, from, to }          vertical gradient
 *   { op: "text",   s, x, y, k, fill, alpha? }      Departure Mono, y is the cell top, k the pixel size
 *   { op: "cells",  x, y, k, rows: ["0110", ...], fill, gap? }   a block of k-sized squares
 *   { op: "path",   paths: [d], x, y, s, fill }     an SVG path, scaled by s
 */
import { CELL, GLYPHS } from "./font.js";
import { encodePng } from "./png.js";

// ── shared helpers ──────────────────────────────────────────────────────────

const FALLBACK = 63; // "?"

/** The pixel rows of one glyph as bit masks. */
function glyphRows(cp) {
  const hex = GLYPHS[cp] ?? GLYPHS[FALLBACK];
  const rows = [];
  for (let r = 0; r < CELL.h; r++) rows.push(parseInt(hex.slice(r * 2, r * 2 + 2), 16));
  return rows;
}

/** Horizontal runs of lit pixels in a glyph: [col, row, length]. */
function glyphRuns(cp) {
  const out = [];
  glyphRows(cp).forEach((bits, row) => {
    let col = 0;
    while (col < CELL.w) {
      if (bits & (1 << (CELL.w - 1 - col))) {
        let n = 1;
        while (col + n < CELL.w && bits & (1 << (CELL.w - 1 - col - n))) n++;
        out.push([col, row, n]);
        col += n;
      } else col++;
    }
  });
  return out;
}

/** Width of a string in pixels at pixel size k. */
export const textWidth = (s, k) => [...String(s)].length * CELL.w * k;

/** Runs of "1" in a cells row: [start, length]. */
function cellRuns(row) {
  const out = [];
  for (let i = 0; i < row.length; i++) {
    if (row[i] !== "1") continue;
    let n = 1;
    while (row[i + n] === "1") n++;
    out.push([i, n]);
    i += n - 1;
  }
  return out;
}

function hex(c) {
  const m = /^#([0-9a-f]{6})$/i.exec(c);
  if (!m) throw new Error(`card: colour ${c} is not #rrggbb`);
  const v = parseInt(m[1], 16);
  return [(v >> 16) & 255, (v >> 8) & 255, v & 255];
}

// Two decimals at most, without trailing zeros ("1.5", not "1.50").
const num = (n) => (Number.isInteger(n) ? String(n) : String(Math.round(n * 100) / 100));

function escXml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" })[c]);
}

// ── SVG ─────────────────────────────────────────────────────────────────────

/**
 * @param {{ w: number, h: number, ops: object[], title?: string, desc?: string }} card
 * @returns {string}
 */
export function toSvg({ w, h, ops, title = "", desc = "" }) {
  const used = new Set();
  const grads = [];
  const body = [];
  for (const o of ops) {
    const a = o.alpha != null && o.alpha < 1 ? ` fill-opacity="${num(o.alpha)}"` : "";
    if (o.op === "rect") body.push(`<rect x="${num(o.x)}" y="${num(o.y)}" width="${num(o.w)}" height="${num(o.h)}" fill="${o.fill}"${a}/>`);
    else if (o.op === "grad") {
      const id = `g${grads.length}`;
      grads.push(`<linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${o.from}"/><stop offset="1" stop-color="${o.to}"/></linearGradient>`);
      body.push(`<rect x="${num(o.x)}" y="${num(o.y)}" width="${num(o.w)}" height="${num(o.h)}" fill="url(#${id})"/>`);
    } else if (o.op === "text") {
      const uses = [];
      [...String(o.s)].forEach((ch, i) => {
        const cp = ch.codePointAt(0);
        if (cp === 32) return;
        const id = GLYPHS[cp] ? cp : FALLBACK;
        used.add(id);
        uses.push(`<use href="#c${id}" x="${i * CELL.w}"/>`);
      });
      if (uses.length) body.push(`<g fill="${o.fill}"${a} transform="translate(${num(o.x)} ${num(o.y)}) scale(${num(o.k)})">${uses.join("")}</g>`);
    } else if (o.op === "cells") {
      const step = o.k + (o.gap || 0);
      const d = [];
      o.rows.forEach((row, r) => {
        for (const [c, n] of cellRuns(row)) {
          // With a gap every block is its own square; without, a run is one bar.
          if (o.gap) for (let i = 0; i < n; i++) d.push(`M${num(o.x + (c + i) * step)} ${num(o.y + r * step)}h${num(o.k)}v${num(o.k)}h-${num(o.k)}z`);
          else d.push(`M${num(o.x + c * step)} ${num(o.y + r * step)}h${num(n * step)}v${num(o.k)}h-${num(n * step)}z`);
        }
      });
      if (d.length) body.push(`<path fill="${o.fill}"${a} d="${d.join("")}"/>`);
    } else if (o.op === "path") {
      body.push(`<g fill="${o.fill}" shape-rendering="geometricPrecision" transform="translate(${num(o.x)} ${num(o.y)}) scale(${num(o.s)})">${o.paths.map((d) => `<path d="${d}"/>`).join("")}</g>`);
    } else throw new Error(`card: unknown op ${o.op}`);
  }
  const defs = [...used].sort((x, y) => x - y).map((cp) => {
    const d = glyphRuns(cp).map(([c, r, n]) => `M${c} ${r}h${n}v1h-${n}z`).join("");
    return `<path id="c${cp}" d="${d}"/>`;
  });
  return [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" shape-rendering="crispEdges" role="img">`,
    title ? `<title>${escXml(title)}</title>` : "",
    desc ? `<desc>${escXml(desc)}</desc>` : "",
    `<defs>${defs.join("")}${grads.join("")}</defs>`,
    ...body,
    "</svg>",
    "",
  ].filter((l) => l !== "").join("\n") + "\n";
}

// ── PNG ─────────────────────────────────────────────────────────────────────

class Raster {
  constructor(w, h) {
    this.w = w;
    this.h = h;
    this.px = new Uint8Array(w * h * 3);
  }

  /** Blend colour c over pixel (x, y) with coverage a (0..1). */
  blend(x, y, c, a) {
    if (x < 0 || y < 0 || x >= this.w || y >= this.h || a <= 0) return;
    const i = (y * this.w + x) * 3;
    if (a >= 1) {
      this.px[i] = c[0]; this.px[i + 1] = c[1]; this.px[i + 2] = c[2];
      return;
    }
    for (let k = 0; k < 3; k++) this.px[i + k] = Math.round(this.px[i + k] * (1 - a) + c[k] * a);
  }

  /** A rectangle with fractional edges, anti-aliased by area. */
  rect(x, y, w, h, c, alpha = 1) {
    const x0 = Math.max(0, Math.floor(x)), x1 = Math.min(this.w, Math.ceil(x + w));
    const y0 = Math.max(0, Math.floor(y)), y1 = Math.min(this.h, Math.ceil(y + h));
    for (let py = y0; py < y1; py++) {
      const cy = Math.min(py + 1, y + h) - Math.max(py, y);
      for (let px = x0; px < x1; px++) {
        const cx = Math.min(px + 1, x + w) - Math.max(px, x);
        this.blend(px, py, c, cx * cy * alpha);
      }
    }
  }

  /** Fill polygons (nonzero winding) with 4 x 4 supersampling. */
  fill(polys, c) {
    const SS = 4;
    let minY = Infinity, maxY = -Infinity, minX = Infinity, maxX = -Infinity;
    const edges = [];
    for (const p of polys) {
      for (let i = 0; i < p.length; i++) {
        const [x1, y1] = p[i], [x2, y2] = p[(i + 1) % p.length];
        if (y1 === y2) continue;
        edges.push(y1 < y2 ? [x1, y1, x2, y2, 1] : [x2, y2, x1, y1, -1]);
        minY = Math.min(minY, y1, y2); maxY = Math.max(maxY, y1, y2);
        minX = Math.min(minX, x1, x2); maxX = Math.max(maxX, x1, x2);
      }
    }
    if (!edges.length) return;
    const ox = Math.max(0, Math.floor(minX)), wx = Math.min(this.w, Math.ceil(maxX) + 1) - ox;
    for (let py = Math.max(0, Math.floor(minY)); py < Math.min(this.h, Math.ceil(maxY)); py++) {
      const cov = new Float32Array(wx);
      for (let sy = 0; sy < SS; sy++) {
        const y = py + (sy + 0.5) / SS;
        const xs = [];
        for (const [x1, y1, x2, y2, dir] of edges) {
          if (y < y1 || y >= y2) continue;
          xs.push([x1 + ((y - y1) * (x2 - x1)) / (y2 - y1), dir]);
        }
        xs.sort((a, b) => a[0] - b[0]);
        let wind = 0;
        for (let i = 0; i < xs.length - 1; i++) {
          wind += xs[i][1];
          if (!wind) continue;
          // Span [a, b): add the horizontal coverage of each pixel it touches.
          const a = xs[i][0] - ox, b = xs[i + 1][0] - ox;
          for (let px = Math.max(0, Math.floor(a)); px < Math.min(wx, Math.ceil(b)); px++) {
            cov[px] += (Math.min(px + 1, b) - Math.max(px, a)) / SS;
          }
        }
      }
      for (let px = 0; px < wx; px++) if (cov[px] > 0) this.blend(ox + px, py, c, Math.min(1, cov[px]));
    }
  }
}

/** Parse an SVG path into polygons (absolute and relative M L H V C S Q T Z). */
export function pathPolygons(d, tx = 0, ty = 0, s = 1) {
  const toks = String(d).match(/[a-zA-Z]|-?(?:\d+\.?\d*|\.\d+)(?:e[-+]?\d+)?/g) || [];
  const polys = [];
  let poly = null, i = 0, cmd = "", x = 0, y = 0, sx = 0, sy = 0, cx = 0, cy = 0, prev = "";
  const n = () => Number(toks[i++]);
  const pt = (px, py) => poly.push([tx + px * s, ty + py * s]);
  const bez = (pts) => {
    const STEPS = 12;
    for (let k = 1; k <= STEPS; k++) {
      const t = k / STEPS, u = 1 - t;
      let px, py;
      if (pts.length === 4) {
        px = u * u * u * pts[0][0] + 3 * u * u * t * pts[1][0] + 3 * u * t * t * pts[2][0] + t * t * t * pts[3][0];
        py = u * u * u * pts[0][1] + 3 * u * u * t * pts[1][1] + 3 * u * t * t * pts[2][1] + t * t * t * pts[3][1];
      } else {
        px = u * u * pts[0][0] + 2 * u * t * pts[1][0] + t * t * pts[2][0];
        py = u * u * pts[0][1] + 2 * u * t * pts[1][1] + t * t * pts[2][1];
      }
      pt(px, py);
    }
  };
  while (i < toks.length) {
    if (/[a-zA-Z]/.test(toks[i])) cmd = toks[i++];
    const rel = cmd === cmd.toLowerCase();
    const C = cmd.toUpperCase();
    const bx = rel ? x : 0, by = rel ? y : 0;
    if (C === "M") {
      x = bx + n(); y = by + n();
      poly = []; polys.push(poly); pt(x, y); sx = x; sy = y;
      cmd = rel ? "l" : "L";
    } else if (C === "L") { x = bx + n(); y = by + n(); pt(x, y); }
    else if (C === "H") { x = bx + n(); pt(x, y); }
    else if (C === "V") { y = by + n(); pt(x, y); }
    else if (C === "C" || C === "S") {
      let x1, y1;
      if (C === "C") { x1 = bx + n(); y1 = by + n(); }
      else { x1 = /[CS]/i.test(prev) ? 2 * x - cx : x; y1 = /[CS]/i.test(prev) ? 2 * y - cy : y; }
      const x2 = bx + n(), y2 = by + n(), ex = bx + n(), ey = by + n();
      bez([[x, y], [x1, y1], [x2, y2], [ex, ey]]);
      cx = x2; cy = y2; x = ex; y = ey;
    } else if (C === "Q" || C === "T") {
      let x1, y1;
      if (C === "Q") { x1 = bx + n(); y1 = by + n(); }
      else { x1 = /[QT]/i.test(prev) ? 2 * x - cx : x; y1 = /[QT]/i.test(prev) ? 2 * y - cy : y; }
      const ex = bx + n(), ey = by + n();
      bez([[x, y], [x1, y1], [ex, ey]]);
      cx = x1; cy = y1; x = ex; y = ey;
    } else if (C === "Z") { x = sx; y = sy; }
    else throw new Error(`card: path command ${cmd} is not supported`);
    prev = C;
  }
  return polys.filter((p) => p.length > 2);
}

/**
 * Draw a card into an RGB pixel buffer.
 * @param {{ w: number, h: number, ops: object[] }} card
 * @returns {{ w: number, h: number, px: Uint8Array }}
 */
export function rasterize({ w, h, ops }) {
  const r = new Raster(w, h);
  for (const o of ops) {
    const alpha = o.alpha ?? 1;
    if (o.op === "rect") r.rect(o.x, o.y, o.w, o.h, hex(o.fill), alpha);
    else if (o.op === "grad") {
      const a = hex(o.from), b = hex(o.to);
      for (let row = 0; row < o.h; row++) {
        const t = o.h > 1 ? (row + 0.5) / o.h : 0;
        r.rect(o.x, o.y + row, o.w, 1, a.map((v, k) => Math.round(v + (b[k] - v) * t)));
      }
    } else if (o.op === "text") {
      const c = hex(o.fill);
      [...String(o.s)].forEach((ch, i) => {
        for (const [col, row, len] of glyphRuns(ch.codePointAt(0))) {
          r.rect(o.x + (i * CELL.w + col) * o.k, o.y + row * o.k, len * o.k, o.k, c, alpha);
        }
      });
    } else if (o.op === "cells") {
      const c = hex(o.fill), step = o.k + (o.gap || 0);
      o.rows.forEach((row, ri) => {
        for (const [ci, len] of cellRuns(row)) {
          if (o.gap) for (let j = 0; j < len; j++) r.rect(o.x + (ci + j) * step, o.y + ri * step, o.k, o.k, c, alpha);
          else r.rect(o.x + ci * step, o.y + ri * step, len * step, o.k, c, alpha);
        }
      });
    } else if (o.op === "path") {
      r.fill(o.paths.flatMap((d) => pathPolygons(d, o.x, o.y, o.s)), hex(o.fill));
    } else throw new Error(`card: unknown op ${o.op}`);
  }
  return { w, h, px: r.px };
}

/** A card as PNG bytes. */
export function toPng(card) {
  const { w, h, px } = rasterize(card);
  return encodePng(w, h, px);
}
