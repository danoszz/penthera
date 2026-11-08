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
    m.top ? `${m.tone === "check" ? "Check first" : "Fix first"}: ${m.top.title}.` : "",
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
      // A root-owned link is the system's own only when we are not root: run as root
      // (a container), every link a checkout makes is root's. Windows has no getuid.
      const uid = typeof process.getuid === "function" ? process.getuid() : 0;
      if (!insideCwd && uid !== 0 && st.uid === 0) continue;
      throw new CardWriteError(cur, "is a symbolic link; pick a real folder with --card-out");
    }
    if (!st.isDirectory()) throw new CardWriteError(cur, "is not a folder");
  }
}

/**
 * Write all files without ever opening what is already there. Every
 * destination is checked first, then each file goes to a new temp file
 * created exclusively (O_EXCL, O_NOFOLLOW) next to it, and only when all are
 * written are they renamed over their names. A rename replaces a planted link
 * itself, never its target, and a failure leaves no half-written set.
 */
function replaceFiles(files) {
  for (const { file } of files) {
    const st = (() => { try { return lstatSync(file); } catch { return null; } })();
    if (st && st.isDirectory()) throw new CardWriteError(file, "is a folder");
  }
  const temps = [];
  try {
    for (const { file, buf } of files) {
      const tmp = join(dirname(file), `.${basename(file)}.${randomBytes(6).toString("hex")}.tmp`);
      const fd = openSync(tmp, FS.O_WRONLY | FS.O_CREAT | FS.O_EXCL | (FS.O_NOFOLLOW || 0), 0o644);
      temps.push(tmp);
      try {
        let off = 0;
        while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
      } finally {
        closeSync(fd);
      }
    }
    files.forEach(({ file }, i) => { renameSync(temps[i], file); temps[i] = null; });
  } finally {
    for (const t of temps) if (t) { try { unlinkSync(t); } catch { /* already gone */ } }
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
  const files = Object.entries(cards).flatMap(([name, c]) => {
    const stem = name === "post" ? base : `${base}-og`;
    return [{ file: `${stem}.png`, buf: c.png }, { file: `${stem}.svg`, buf: Buffer.from(c.svg, "utf8") }];
  });
  replaceFiles(files);
  return { model, paths: files.map((f) => f.file) };
}
