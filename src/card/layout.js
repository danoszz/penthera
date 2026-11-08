/**
 * The receipt layout: a paper slip on blue, torn at the bottom, in two sizes.
 *
 *   post  1080 × 1350 (4:5, for X and other feeds)
 *   og    1200 × 630  (link previews; the logo at the top, X's bottom-left corner kept clear)
 *
 * Layouts take the card model (src/card/model.js) and return draw.js
 * operations. They never drop the not-checked lines: when space runs out the
 * fix text shortens first.
 */
import { textWidth } from "./draw.js";
import { C, logoOp, mosaicRows, mosaicSize, wrap, textRight, textCenter } from "./kit.js";

/**
 * The verdict line: "VERDICT: NOTHING TO FIX NOW". On a check-only card the
 * number to check is the big block beside it, so the line keeps the verdict
 * itself. It sits beside the number when it fits there on one line (without
 * the prefix if need be), or null: then it goes on its own line under the
 * number, never cut and never over the label.
 */
function verdictBeside(m, cols) {
  const v = upper(String(m.verdict).split(" · ")[0]);
  const full = `VERDICT: ${v}`;
  if (wrap(full, cols, 1)[0] === full) return full;
  return wrap(v, cols, 1)[0] === v ? v : null;
}
const verdictText = (m) => `VERDICT: ${upper(String(m.verdict).split(" · ")[0])}`;
const firstLabel = (m) => (m.tone === "check" ? "CHECK FIRST" : "FIX FIRST");

export const SIZES = { post: { w: 1080, h: 1350 }, og: { w: 1200, h: 630 } };

const MARK = { read: "■", partly: "▪", nothing: "□", "not-run": "□", unread: "□" };
const upper = (s) => String(s).toUpperCase();
const isRead = (it) => it.state === "read" || it.state === "partly";
const MADE = "Made offline. Nothing left this machine.";

/** Item value on the slip: the detail when read, a short state when not. */
function itemValue(it) {
  if (isRead(it)) return it.detail;
  if (it.state === "unread") return "NOT READ";
  if (it.state === "nothing") return upper(it.detail);
  return "NOT RUN";
}

// Lines that must stay on a card however short it gets.
const MUST_KEEP = [/not proven/i, /MCP tool descriptions/i, /couldn't see your site/i, /read nothing/i, /suppressed/i];

/** At most n lines, the ones that must stay first (so they get the room), then the rest. */
function keepNotChecked(lines, n) {
  const must = lines.filter((l) => MUST_KEEP.some((re) => re.test(l)));
  const rest = lines.filter((l) => !must.includes(l));
  return [...must, ...rest].slice(0, Math.max(n, must.length));
}

/** Torn edge: a row of pixel teeth under the slip. */
function teeth(x, y, w, fill) {
  const tooth = 12;
  const rows = [];
  for (let r = 0; r < 3; r++) {
    let row = "";
    for (let c = 0; c < Math.floor(w / tooth); c++) {
      const p = c % 6;
      row += (r === 0 ? p !== 5 : r === 1 ? p > 0 && p < 4 : p === 2) ? "1" : "0";
    }
    rows.push(row);
  }
  return { op: "cells", x, y, k: tooth, rows, fill };
}

/** The slip's contents from y down, with a given budget for the fix text. */
function slipBody(m, { L, R, CX, y }, budget) {
  const ops = [];
  ops.push(logoOp(CX - 120, y, 240, C.ink));
  y += 80;
  ops.push(textCenter("SECURITY RECEIPT", CX, y, 3, C.ink)); y += 48;
  ops.push(textCenter(`${m.target} · ${m.date}`, CX, y, 2, C.ink, 0.6)); y += 52;
  for (const it of m.checked) {
    ops.push({ op: "text", s: `${MARK[it.state] || "□"} ${it.name}`, x: L, y, k: 3, fill: C.ink, alpha: isRead(it) ? 1 : 0.6 });
    ops.push(textRight(itemValue(it), R, y, 3, C.ink, isRead(it) ? 1 : 0.6));
    y += 48;
  }
  y += 28;
  // The total. With a grade: the letter in blue blocks, the score beside it, and what to fix
  // as a line item. Without: what to do on the left, the number in blue blocks on the right.
  const graded = !!m.grade;
  const rows = mosaicRows(graded ? m.grade.letter : m.hero.value);
  const k = graded ? 27 : 17, g = 4;
  const sz = mosaicSize(rows, k, g);
  const leftCols = (px) => Math.floor((R - L - sz.w - 32) / px);
  ops.push({ op: "rect", x: L, y, w: R - L, h: 8, fill: C.ink });
  y += 36;
  if (graded) {
    ops.push({ op: "text", s: "GRADE", x: L, y, k: 2, fill: C.ink, alpha: 0.6 });
    ops.push({ op: "text", s: `${m.grade.score}/100`, x: L, y: y + 40, k: 5, fill: C.ink });
  } else {
    wrap(upper(m.hero.label), leftCols(21), 2).forEach((l, i) => ops.push({ op: "text", s: l, x: L, y: y + i * 46, k: 3, fill: C.ink }));
  }
  const beside = verdictBeside(m, leftCols(14));
  if (beside) ops.push({ op: "text", s: beside, x: L, y: y + sz.h - 28, k: 2, fill: C.blue });
  ops.push({ op: "cells", x: R - sz.w, y, k, gap: g, rows, fill: C.blue });
  y += sz.h + 36;
  if (!beside) {
    for (const l of wrap(verdictText(m), Math.floor((R - L) / 14), 2)) { ops.push({ op: "text", s: l, x: L, y: y - 8, k: 2, fill: C.blue }); y += 30; }
    y += 6;
  }
  ops.push({ op: "rect", x: L, y, w: R - L, h: 8, fill: C.ink });
  y += 44;
  if (graded) {
    ops.push({ op: "text", s: m.toFix.label, x: L, y, k: 3, fill: C.ink });
    ops.push(textRight(String(m.toFix.value), R, y, 3, C.ink));
    y += 50;
  }
  const cols2 = Math.floor((R - L) / 14), cols3 = Math.floor((R - L) / 21);
  if (m.top && budget.title > 0) {
    // A graded card names the fix right under its "to fix first" line.
    if (!graded) { ops.push({ op: "text", s: firstLabel(m), x: L, y, k: 2, fill: C.ink, alpha: 0.6 }); y += 34; }
    if (graded) for (const l of wrap(`→ ${m.top.title}`, cols2, budget.title)) { ops.push({ op: "text", s: l, x: L, y, k: 2, fill: C.ink }); y += 32; }
    else for (const l of wrap(m.top.title, cols3, budget.title)) { ops.push({ op: "text", s: l, x: L, y, k: 3, fill: C.ink }); y += 44; }
    if (m.top.fix && budget.fix > 0) for (const l of wrap(m.top.fix, cols2, budget.fix)) { ops.push({ op: "text", s: l, x: L, y, k: 2, fill: C.ink, alpha: 0.72 }); y += 30; }
    y += 26;
  }
  ops.push({ op: "text", s: "NOT CHECKED", x: L, y, k: 2, fill: C.ink, alpha: 0.6 }); y += 34;
  for (const l of keepNotChecked(m.notChecked, budget.notChecked)) {
    for (const w of wrap(l, cols2, 3)) { ops.push({ op: "text", s: w, x: L, y, k: 2, fill: C.ink }); y += 30; }
  }
  y += 22;
  ops.push(textCenter(MADE, CX, y, 2, C.ink, 0.6)); y += 44;
  return { ops, end: y };
}

// Budgets from roomy to tight; the first that fits wins.
const BUDGETS = [
  { title: 2, fix: 3, notChecked: 4 },
  { title: 2, fix: 2, notChecked: 3 },
  { title: 1, fix: 2, notChecked: 3 },
  { title: 1, fix: 1, notChecked: 2 },
  { title: 1, fix: 0, notChecked: 2 },
  { title: 0, fix: 0, notChecked: 2 },
];

/** 1080 × 1350. */
export function postLayout(m) {
  const { w: W, h: H } = SIZES.post;
  const SX = 156, SW = W - 2 * SX, SY = 44, P = 52;
  const frame = { L: SX + P, R: SX + SW - P, CX: W / 2, y: SY + 48 };
  const FOOT = 140; // the blue band under the slip, for the command
  let body;
  for (const b of BUDGETS) {
    body = slipBody(m, frame, b);
    if (body.end + 36 <= H - FOOT) break;
  }
  // A short receipt sits in the middle of the space above the footer.
  const free = H - FOOT - (body.end + 36);
  const dy = free > 0 ? Math.floor(free / 8) * 4 : 0;
  for (const o of body.ops) o.y += dy;
  const top = SY + dy, end = body.end + dy;
  return {
    w: W,
    h: H,
    ops: [
      { op: "rect", x: 0, y: 0, w: W, h: H, fill: C.blue },
      { op: "rect", x: SX, y: top, w: SW, h: end - top, fill: C.paper },
      teeth(SX, end, SW, C.paper),
      ...body.ops,
      textCenter(`$ ${m.command}`, W / 2, H - 96, 3, C.white),
      textCenter("rules decide, not AI · penthera.org", W / 2, H - 50, 2, C.white, 0.72),
    ],
  };
}

/** 1200 × 630: the slip runs off the bottom edge, like paper still feeding out. */
export function ogLayout(m) {
  const { w: W, h: H } = SIZES.og;
  const M = 56;
  const ops = [{ op: "rect", x: 0, y: 0, w: W, h: H, fill: C.blue }];
  ops.push(logoOp(M, M, 250, C.white));
  ops.push({ op: "text", s: "SECURITY RECEIPT", x: M, y: M + 104, k: 4, fill: C.white });
  const meta = `${m.target} · ${m.date}`;
  ops.push({ op: "text", s: textWidth(meta, 2) > 600 - 2 * M ? m.target : meta, x: M, y: M + 172, k: 2, fill: C.white, alpha: 0.72 });
  ops.push({ op: "text", s: `$ ${m.command}`, x: M, y: M + 230, k: 2, fill: C.white });
  const SX = 600, SW = W - SX - M, SY = 40, P = 40, L = SX + P, R = SX + SW - P;
  const cols2 = Math.floor((R - L) / 14);
  ops.push({ op: "rect", x: SX, y: SY, w: SW, h: H - SY, fill: C.paper });
  let y = SY + 36;
  for (const it of m.checked) {
    ops.push({ op: "text", s: `${MARK[it.state] || "□"} ${it.name}`, x: L, y, k: 2, fill: C.ink, alpha: isRead(it) ? 1 : 0.6 });
    ops.push(textRight(itemValue(it), R, y, 2, C.ink, isRead(it) ? 1 : 0.6));
    y += 30;
  }
  y += 14;
  ops.push({ op: "rect", x: L, y, w: R - L, h: 6, fill: C.ink });
  y += 26;
  const graded = !!m.grade;
  const rows = mosaicRows(graded ? m.grade.letter : m.hero.value);
  const k = graded ? 16 : 13, g = 3;
  const sz = mosaicSize(rows, k, g);
  const leftCols = (px) => Math.floor((R - L - sz.w - 24) / px);
  if (graded) {
    ops.push({ op: "text", s: "GRADE", x: L, y, k: 2, fill: C.ink, alpha: 0.6 });
    ops.push({ op: "text", s: `${m.grade.score}/100`, x: L, y: y + 28, k: 4, fill: C.ink });
    ops.push({ op: "text", s: `${m.toFix.label}: ${m.toFix.value}`, x: L, y: y + 88, k: 2, fill: C.ink });
  } else {
    wrap(upper(m.hero.label), leftCols(21), 2).forEach((l, i) => ops.push({ op: "text", s: l, x: L, y: y + i * 42, k: 3, fill: C.ink }));
  }
  const beside = verdictBeside(m, leftCols(14));
  if (beside) ops.push({ op: "text", s: beside, x: L, y: y + sz.h - 28, k: 2, fill: C.blue });
  ops.push({ op: "cells", x: R - sz.w, y, k, gap: g, rows, fill: C.blue });
  y += sz.h + 20;
  if (!beside) {
    for (const l of wrap(verdictText(m), cols2, 2)) { ops.push({ op: "text", s: l, x: L, y, k: 2, fill: C.blue }); y += 30; }
    y += 4;
  }
  ops.push({ op: "rect", x: L, y, w: R - L, h: 6, fill: C.ink });
  y += 24;
  // Not checked comes before the fix here: on a short card it is the line that must stay.
  ops.push({ op: "text", s: "NOT CHECKED", x: L, y, k: 2, fill: C.ink, alpha: 0.6 }); y += 32;
  // As many lines as fit; the engines' own not-read lines come first and are never cut mid-way.
  const room = Math.floor((H - 12 - y) / 30);
  const lines = [];
  for (const l of keepNotChecked(m.notChecked, 3)) {
    const w = wrap(l, cols2, 4);
    if (lines.length + w.length > room) continue;
    lines.push(...w);
  }
  for (const l of lines) { ops.push({ op: "text", s: l, x: L, y, k: 2, fill: C.ink }); y += 30; }
  if (m.top && y + 76 <= H - 16) {
    y += 14;
    ops.push({ op: "text", s: firstLabel(m), x: L, y, k: 2, fill: C.ink, alpha: 0.6 }); y += 32;
    ops.push({ op: "text", s: wrap(m.top.title, cols2, 1)[0], x: L, y, k: 2, fill: C.ink });
  }
  return { w: W, h: H, ops };
}
