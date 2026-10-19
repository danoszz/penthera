// Hand-rolled 1-bit charts: shade characters (█ ▓ ▒ ░) for bars, small SVGs
// for lines and columns, filled with patterns instead of colours. Every chart
// carries its numbers as text, so no pattern or colour is the only channel.
import { h, s } from "./dom.js";
import { SEVERITIES, stamp } from "./format.js";

/** The shade each severity is drawn with: solid, dense, half, sparse, dotted. */
export const SHADE = { critical: "█", high: "▓", medium: "▒", low: "░", info: "·" };

/** One hidden <svg> holding the fill patterns the charts reference by id. */
export function patternDefs() {
  const hatch = s("pattern", { id: "pt-hatch", width: 6, height: 6, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" },
    s("line", { class: "hatch-line", x1: 0, y1: 0, x2: 0, y2: 6 }));
  const dither = s("pattern", { id: "pt-dither", width: 2, height: 2, patternUnits: "userSpaceOnUse" },
    s("rect", { class: "dither-dot", x: 0, y: 0, width: 1, height: 1 }));
  const hatchInk = s("pattern", { id: "pt-hatch-ink", width: 4, height: 4, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" },
    s("line", { class: "hatch-ink", x1: 0, y1: 0, x2: 0, y2: 4 }));
  return s("svg", { width: 0, height: 0, "aria-hidden": "true", focusable: "false", class: "sr" }, s("defs", {}, hatch, dither, hatchInk));
}

/** A bar of `width` characters filled to value/max with `ch`, the rest dotted. */
export function textBar(value, max, width = 24, ch = "█") {
  const n = value > 0 && max > 0 ? Math.max(1, Math.round(Math.min(1, value / max) * width)) : 0;
  return { filled: ch.repeat(n), rest: "·".repeat(Math.max(0, width - n)) };
}

/** Rows of label / bar / count. */
export function bars(rows, { width = 24 } = {}) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  const el = h("div", { class: "bars", role: "list" });
  for (const r of rows) {
    const { filled, rest } = textBar(r.value, max, width, r.ch || "█");
    el.append(
      h("span", { class: r.cls || "t1", role: "listitem", "aria-label": `${r.label}: ${r.value}` }, r.label),
      h("span", { class: "bar", "aria-hidden": "true" }, h("span", { class: "shade" }, filled), h("span", { class: "shade track" }, rest)),
      h("span", { class: "num t1", "aria-hidden": "true" }, String(r.value)),
    );
  }
  return el;
}

export function severityBars(counts, opts = {}) {
  return bars(SEVERITIES.map((sev) => ({ label: sev, value: counts?.[sev] || 0, cls: `sev sev-${sev}`, ch: SHADE[sev] })), opts);
}

/** One stacked bar across all severities, as shade characters. */
export function stackedBar(counts, { width = 40 } = {}) {
  const total = SEVERITIES.reduce((n, k) => n + (counts?.[k] || 0), 0);
  let out = "";
  if (total) {
    for (const k of SEVERITIES) {
      const c = counts?.[k] || 0;
      if (c) out += SHADE[k].repeat(Math.max(1, Math.round((c / total) * width)));
    }
  }
  out = out.slice(0, width).padEnd(width, " ");
  return h("div", { class: "stackbar", role: "img", "aria-label": SEVERITIES.map((k) => `${counts?.[k] || 0} ${k}`).join(", ") }, out);
}

/** Tiny line, last point marked. */
export function sparkline(values, { width = 140, height = 24, label = "trend", zero = true } = {}) {
  const vs = values.filter((v) => Number.isFinite(v));
  const svg = s("svg", { class: "spark", viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": vs.length ? `${label}: ${vs.join(", ")}` : `${label}: no data` });
  if (vs.length < 2) {
    svg.append(s("line", { class: "grid-line", x1: 0, y1: height / 2, x2: width, y2: height / 2 }));
    return svg;
  }
  const max = Math.max(...vs, 1);
  const min = zero ? Math.min(...vs, 0) : Math.min(...vs) - 2;
  const pad = 3;
  const pts = vs.map((v, i) => [pad + (i * (width - pad * 2)) / (vs.length - 1), height - pad - ((v - min) / (max - min || 1)) * (height - pad * 2)]);
  svg.append(s("polyline", { class: "s-line", points: pts.map((p) => p.map((n) => n.toFixed(1)).join(",")).join(" ") }));
  const last = pts[pts.length - 1];
  svg.append(s("rect", { class: "s-dot", x: last[0] - 2, y: last[1] - 2, width: 4, height: 4 }));
  return svg;
}

/**
 * Findings over time: open (blue line over a hatched area) and critical+high
 * (dashed ink).
 * @param {{ ts: string, total: number, severe: number }[]} points
 */
export function trendChart(points, { width = 640, height = 180 } = {}) {
  const m = { l: 30, r: 10, t: 10, b: 22 };
  const iw = width - m.l - m.r;
  const ih = height - m.t - m.b;
  const max = Math.max(1, ...points.map((p) => p.total));
  const nice = Math.ceil(max / 5) * 5 || 5;
  const x = (i) => m.l + (points.length < 2 ? iw / 2 : (i * iw) / (points.length - 1));
  const y = (v) => m.t + ih - (v / nice) * ih;
  const svg = s("svg", {
    class: "chart", viewBox: `0 0 ${width} ${height}`, role: "img",
    "aria-label": points.length
      ? `Open findings over ${points.length} scans: from ${points[0].total} to ${points[points.length - 1].total}; critical and high from ${points[0].severe} to ${points[points.length - 1].severe}`
      : "No scans yet",
  });
  for (let i = 0; i <= 5; i++) {
    const v = (nice / 5) * i;
    svg.append(s("line", { class: i ? "grid-line" : "axis", x1: m.l, x2: width - m.r, y1: y(v), y2: y(v) }));
    svg.append(s("text", { class: "tick", x: m.l - 6, y: y(v) + 3, "text-anchor": "end" }, String(Math.round(v))));
  }
  if (!points.length) return svg;
  const line = (key) => points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`).join("");
  svg.append(s("path", { class: "area-total", d: `${line("total")}L${x(points.length - 1).toFixed(1)},${y(0)}L${x(0).toFixed(1)},${y(0)}Z` }));
  svg.append(s("path", { class: "line-total", d: line("total") }));
  svg.append(s("path", { class: "line-severe", d: line("severe") }));
  points.forEach((p, i) => {
    svg.append(s("rect", { class: "dot", x: x(i) - 3, y: y(p.total) - 3, width: 6, height: 6 }, s("title", {}, `${stamp(p.ts)}: ${p.total} open, ${p.severe} critical/high`)));
  });
  const ticks = points.length <= 6 ? points.map((_, i) => i) : [0, Math.floor((points.length - 1) / 2), points.length - 1];
  for (const i of ticks) {
    svg.append(s("text", { class: "tick", x: x(i), y: height - 6, "text-anchor": i === 0 ? "start" : i === points.length - 1 ? "end" : "middle" }, stamp(points[i].ts).slice(5, 10)));
  }
  return svg;
}

/** Vertical columns, dither-filled, with value labels. */
export function columns(items, { width = 320, height = 130, label = "distribution" } = {}) {
  const m = { t: 16, b: 20 };
  const max = Math.max(1, ...items.map((i) => i.n));
  const bw = width / items.length;
  const svg = s("svg", { class: "chart", viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": `${label}: ${items.map((i) => `${i.label} ${i.n}`).join(", ")}` });
  svg.append(s("line", { class: "axis", x1: 0, x2: width, y1: height - m.b, y2: height - m.b }));
  items.forEach((it, i) => {
    const hgt = ((height - m.t - m.b) * it.n) / max;
    const x0 = i * bw + bw * 0.22;
    if (it.n) svg.append(s("rect", { class: "col", x: x0, y: height - m.b - hgt, width: bw * 0.56, height: hgt }));
    svg.append(s("text", { class: "col-value", x: i * bw + bw / 2, y: height - m.b - hgt - 4, "text-anchor": "middle" }, String(it.n)));
    svg.append(s("text", { class: "col-label", x: i * bw + bw / 2, y: height - 5, "text-anchor": "middle" }, it.label));
  });
  return svg;
}

const BIG = {
  A: [" ▄▀▀▄ ", "█▄▄▄█", "█   █"],
  B: ["█▀▀▄", "█▀▀▄", "█▄▄▀"],
  C: ["▄▀▀▀", "█   ", "▀▄▄▄"],
  D: ["█▀▀▄", "█  █", "█▄▄▀"],
  F: ["█▀▀▀", "█▀▀ ", "█   "],
};

export function bigGrade(letter) {
  const rows = BIG[letter] || ["", letter || "?", ""];
  return h("pre", { class: `grade-big grade-${letter}`, "aria-hidden": "true" }, rows.join("\n"));
}

// The CLI's wordmark (src/cli/ansi.js LOGO_BIG), ANSI Shadow block letters.
const LOGO = [
  "██████╗ ███████╗███╗   ██╗████████╗██╗  ██╗███████╗██████╗  █████╗ ",
  "██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██║  ██║██╔════╝██╔══██╗██╔══██╗",
  "██████╔╝█████╗  ██╔██╗ ██║   ██║   ███████║█████╗  ██████╔╝███████║",
  "██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══██║██╔══╝  ██╔══██╗██╔══██║",
  "██║     ███████╗██║ ╚████║   ██║   ██║  ██║███████╗██║  ██║██║  ██║",
  "╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝",
];

/** The wordmark: solid blocks in #0000ed, the box-drawing shadow in a second tone. */
export function wordmark() {
  const pre = h("pre", { class: "wordmark", "aria-hidden": "true" });
  for (const row of LOGO) {
    for (const run of row.match(/█+|[^█]+/g)) pre.append(h("span", { class: run[0] === "█" ? "fill" : "edge" }, run));
    pre.append("\n");
  }
  return pre;
}

/**
 * Finding lifetimes as a Gantt chart: one lane per finding, a bar from the
 * scan it first appeared in to the last one it was seen in. Open findings are
 * hatched up to "now", critical ones solid, fixed ones an empty outline.
 * Every scan is a dashed line with a black chip (S1, S2, ...) on top.
 * @param {{ title: string, severity: string, from: number, to: number, open: boolean }[]} rows
 * @param {{ ts: string }[]} scans
 */
export function ganttChart(rows, scans, { width = 1100 } = {}) {
  const lane = 24;
  const m = { l: 290, r: 16, t: 46, b: 10 };
  const height = m.t + rows.length * lane + m.b;
  const n = Math.max(1, scans.length - 1);
  const iw = width - m.l - m.r;
  const x = (i) => m.l + (i / n) * iw * 0.94;
  const nowX = m.l + iw;
  const svg = s("svg", { class: "chart gantt", viewBox: `0 0 ${width} ${height}`, role: "img",
    "aria-label": `${rows.length} findings across ${scans.length} scans: ${rows.filter((r) => r.open).length} still open, ${rows.filter((r) => !r.open).length} fixed` });
  // Axis: scan chips and dashed lines.
  svg.append(s("line", { class: "axis", x1: m.l, x2: width - m.r, y1: m.t - 6, y2: m.t - 6 }));
  scans.forEach((sc, i) => {
    const cx = x(i);
    svg.append(s("line", { class: "scan-line", x1: cx, x2: cx, y1: m.t - 6, y2: height - m.b }));
    svg.append(s("rect", { class: "chip", x: cx - 13, y: 2, width: 26, height: 15 }));
    svg.append(s("text", { class: "chip-t", x: cx, y: 13, "text-anchor": "middle" }, `S${i + 1}`));
    svg.append(s("text", { class: "axis-t", x: cx, y: m.t - 12, "text-anchor": "middle" }, stamp(sc.ts).slice(5, 10)));
  });
  svg.append(s("line", { class: "now-line", x1: nowX, x2: nowX, y1: m.t - 14, y2: height - m.b }));
  svg.append(s("path", { class: "chip", d: `M${nowX - 5},${m.t - 20}h10l-5,7z` }));
  svg.append(s("text", { class: "axis-t", x: nowX - 8, y: m.t - 24, "text-anchor": "end" }, "now"));
  rows.forEach((r, i) => {
    const y = m.t + i * lane;
    const label = r.title.length > 34 ? `${r.title.slice(0, 33)}…` : r.title;
    svg.append(s("text", { class: "lane-code", x: 0, y: y + 15 }, ({ critical: "C+", high: "H+", medium: "M+", low: "L+" })[r.severity] || "I+"));
    svg.append(s("text", { class: ["lane-label", r.open ? "b" : null].filter(Boolean).join(" "), x: 28, y: y + 15 }, s("title", {}, r.title), label));
    const x0 = x(r.from);
    const x1 = r.open ? nowX : Math.max(x(r.to) + 10, x0 + 10);
    svg.append(s("rect", { class: `bar${r.open ? " open" : ""}${r.open && r.severity === "critical" ? " crit" : ""}`, x: x0, y: y + 5, width: x1 - x0, height: 13 }));
  });
  return svg;
}
