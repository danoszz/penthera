/**
 * `--card`: the security receipt, one shareable image of a scan.
 *
 * Built offline from the brief (the same deterministic verdict, no model),
 * drawn by our own renderer (src/card/draw.js), written next to you as SVG
 * and PNG. Nothing is uploaded and nothing is fetched.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { buildCardModel } from "./model.js";
import { postLayout, ogLayout } from "./layout.js";
import { toSvg, toPng } from "./draw.js";

export { buildCardModel } from "./model.js";

export const DEFAULT_CARD_OUT = "penthera-card";

function describe(m) {
  const title = `Penthera security receipt for ${m.target}`;
  const read = m.checked.filter((c) => c.state === "read" || c.state === "partly").map((c) => c.name.toLowerCase());
  const desc = [
    m.grade ? `Grade ${m.grade.letter}, ${m.grade.score} out of 100. Verdict: ${m.verdict}. ${m.toFix.label}: ${m.toFix.value}.` : `Verdict: ${m.verdict}. ${m.hero.value} ${m.hero.label}.`,
    read.length ? `Checked: ${read.join(", ")}.` : "Nothing was read.",
    `Not checked: ${m.notChecked.join("; ")}.`,
    m.top ? `Fix first: ${m.top.title}.` : "",
  ].filter(Boolean).join(" ");
  return { title, desc };
}

/** The two cards as SVG strings and PNG buffers. */
export function renderCards(model) {
  const meta = describe(model);
  const out = {};
  for (const [name, layout] of [["post", postLayout], ["og", ogLayout]]) {
    const card = { ...layout(model), ...meta };
    out[name] = { svg: toSvg(card), png: toPng(card), w: card.w, h: card.h };
  }
  return out;
}

/**
 * Build and write the cards: <out>.svg, <out>.png (1080 × 1350) and
 * <out>-og.svg, <out>-og.png (1200 × 630). Returns the paths written.
 */
export function writeCards(brief, results, { version, out = DEFAULT_CARD_OUT, date } = {}) {
  const base = resolve(String(out).replace(/\.(?:png|svg)$/i, ""));
  mkdirSync(dirname(base), { recursive: true });
  const model = buildCardModel(brief, results, { version, date });
  const cards = renderCards(model);
  const paths = [];
  for (const [name, c] of Object.entries(cards)) {
    const stem = name === "post" ? base : `${base}-og`;
    writeFileSync(`${stem}.png`, c.png);
    writeFileSync(`${stem}.svg`, c.svg);
    paths.push(`${stem}.png`, `${stem}.svg`);
  }
  return { model, paths };
}
