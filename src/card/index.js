/**
 * `--card`: the security receipt, one shareable image of a scan.
 *
 * Built offline from the brief (the same deterministic verdict, no model),
 * drawn by our own renderer (src/card/draw.js), written next to you as SVG
 * and PNG. Nothing is uploaded and nothing is fetched.
 */
import { closeSync, constants as FS, lstatSync, mkdirSync, openSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";
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

/** The card was not written, and why. The message names the path, never any content. */
export class CardWriteError extends Error {
  constructor(path, reason) {
    super(`The share card was not written: ${path} ${reason}.`);
    this.name = "CardWriteError";
    this.code = "ECARDREFUSED";
    this.path = path;
  }
}

/**
 * Make sure `dir` is a real folder reached without symbolic links a checkout
 * could have planted (`reports -> /etc`), creating missing parts one level at
 * a time. Below the working directory every part is checked. For a folder
 * outside it, every part from the filesystem root is checked, and only links
 * owned by root (the system's own, like /tmp and /var on macOS) are allowed:
 * a scanned repo cannot create one of those.
 */
function safeDir(dir, cwd) {
  const rel = relative(cwd, dir);
  const insideCwd = rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
  const base = insideCwd ? cwd : parse(dir).root;
  const parts = (insideCwd ? rel : relative(base, dir)).split(sep).filter(Boolean);
  let cur = base;
  for (const part of parts) {
    cur = join(cur, part);
    let st;
    try { st = lstatSync(cur); } catch (e) {
      if (e.code !== "ENOENT") throw e;
      mkdirSync(cur); // one level, never through a link
      st = lstatSync(cur);
    }
    if (st.isSymbolicLink()) {
      if (!insideCwd && st.uid === 0) continue;
      throw new CardWriteError(cur, "is a symbolic link; pick a real folder with --card-out");
    }
    if (!st.isDirectory()) throw new CardWriteError(cur, "is not a folder");
  }
}

/**
 * Write `buf` to `file` without ever opening what is already there: a new
 * temp file is created exclusively (O_EXCL, O_NOFOLLOW) next to it and renamed
 * over the name. A rename replaces a planted link itself, never its target.
 */
function replaceFile(file, buf) {
  const tmp = join(dirname(file), `.${basename(file)}.${randomBytes(6).toString("hex")}.tmp`);
  const fd = openSync(tmp, FS.O_WRONLY | FS.O_CREAT | FS.O_EXCL | (FS.O_NOFOLLOW || 0), 0o644);
  try {
    let off = 0;
    while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
  } catch (e) {
    closeSync(fd);
    try { unlinkSync(tmp); } catch { /* already gone */ }
    throw e;
  }
  closeSync(fd);
  try {
    const st = (() => { try { return lstatSync(file); } catch { return null; } })();
    if (st && st.isDirectory()) throw new CardWriteError(file, "is a folder");
    renameSync(tmp, file);
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* already gone */ }
    throw e;
  }
}

/**
 * Build and write the cards: <out>.svg, <out>.png (1080 × 1350) and
 * <out>-og.svg, <out>-og.png (1200 × 630). Returns the paths written. Throws a
 * CardWriteError when the place to write it goes through a symbolic link.
 */
export function writeCards(brief, results, { version, out = DEFAULT_CARD_OUT, date, cwd = resolve(".") } = {}) {
  const base = resolve(cwd, String(out).replace(/\.(?:png|svg)$/i, ""));
  safeDir(dirname(base), cwd);
  const model = buildCardModel(brief, results, { version, date });
  const cards = renderCards(model);
  const paths = [];
  for (const [name, c] of Object.entries(cards)) {
    const stem = name === "post" ? base : `${base}-og`;
    replaceFile(`${stem}.png`, c.png);
    replaceFile(`${stem}.svg`, Buffer.from(c.svg, "utf8"));
    paths.push(`${stem}.png`, `${stem}.svg`);
  }
  return { model, paths };
}
