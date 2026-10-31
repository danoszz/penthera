#!/usr/bin/env node
/**
 * Render the site's social images with a local headless Chrome:
 *
 *   og.png       1200 × 630   the share card (Open Graph, X, LinkedIn, Facebook)
 *   og-plain.png 1200 × 630   the plain card for research pages
 *   square.png   1080 × 1080  Instagram and other square feeds
 *   story.png    1080 × 1920  TikTok, Reels and Stories (9:16)
 *
 *   CHROME=/path/to/chrome node site/tools/social.mjs
 *
 * Built from the site's own pieces: the dithered field (media/field.png), the
 * logotype, Departure Mono and the approved one-liner. Outputs go to
 * site/media/social/ and are committed; the build only copies them.
 * site/tools/reel.mjs imports `page` and `shoot` for the link-preview reel's
 * end card.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const SITE = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ROOT = resolve(SITE, "..");
const OUT = join(SITE, "media", "social");
const CHROME = process.env.CHROME || {
  darwin: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  linux: "google-chrome",
  win32: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
}[process.platform];

const logo = readFileSync(join(ROOT, "src", "ui", "static", "logo.svg"), "utf8")
  .replace(/<svg /, '<svg class="logo" ')
  .replace(/fill="currentColor"/g, 'fill="#ffffff"');
const field = `data:image/png;base64,${readFileSync(join(SITE, "media", "field.png")).toString("base64")}`;
const font = pathToFileURL(join(ROOT, "src", "ui", "static", "fonts", "DepartureMono-Regular.woff2")).href;
// The approved title, without the "Penthera:" the logotype already says. A
// non-breaking hyphen keeps "open-source" on one line.
export const LINE = "Your open\u2011source cyber security agent";
const CHIPS = '<span class="cmd">$ npx penthera</span><span class="pill">Open source</span><span class="pill">MIT</span><span class="pill">Offline</span>';

/**
 * One page per image. Two groups with a fixed rhythm between them: the
 * logotype, then the message (title, subline, chips). `split` pins the
 * logotype to the top and the message to the bottom, with the field owning
 * the right side; `stack` sets both below the field with fixed gaps.
 * `l.chips` replaces the row of chips under the title.
 */
export const page = (w, h, l) => `<!doctype html><html><head><meta charset="utf-8"><style>
@font-face { font-family: "Departure Mono"; src: url("${font}") format("woff2"); }
* { box-sizing: border-box; margin: 0; }
html, body { width: ${w}px; height: ${h}px; background: #000; color: #fff; overflow: hidden; }
body { position: relative; font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased; }
.field { position: absolute; ${l.field}; object-fit: cover; object-position: 50% 0; image-rendering: pixelated; -webkit-mask-image: ${l.mask}; }
.wrap { position: absolute; inset: 0; padding: ${l.pad}px ${l.pad}px ${l.padBottom}px; display: flex; flex-direction: column; justify-content: ${l.mode === "split" ? "space-between" : "flex-end"}; }
.logo { display: block; flex: none; width: ${l.logoW}px; height: auto; margin-bottom: ${l.mode === "split" ? 0 : l.logoGap}px; }
.msg { max-width: ${l.msgW}px; }
h1 { font-weight: 500; font-size: ${l.h1}px; line-height: 0.98; letter-spacing: -0.04em; max-width: ${l.measure}; text-wrap: balance; }
.row { display: flex; flex-wrap: wrap; align-items: center; gap: ${l.chipGap}px; margin-top: ${l.rowGap}px; font-family: "Departure Mono", monospace; font-size: ${l.mono}px; letter-spacing: 0.02em; }
.cmd { padding: ${l.chipPad}; background: #0000ed; border: 1px solid #0000ed; }
.pill { padding: ${l.chipPad}; border: 1px solid #fff; background: #000; }
/* "Free", above the title: the chips' own size and padding, inverted so it
 * reads as a label rather than one more chip in the row. */
.chip.free { display: inline-block; margin-bottom: ${l.freeGap}px; padding: ${l.chipPad}; font-family: "Departure Mono", monospace; font-size: ${l.mono}px; letter-spacing: 0.02em; line-height: normal; color: #000; background: #fff; border: 1px solid #fff; }
</style></head><body>
<img class="field" src="${field}" alt="">
<div class="wrap">
  ${logo}
  <div class="msg">
    <span class="chip free">Free</span>
    <h1>${LINE}</h1>
    <div class="row">${l.chips ?? CHIPS}</div>
  </div>
</div>
</body></html>`;

export const SHOTS = [
  // 1200 × 630: 64 px margins and a deeper bottom one; the logotype top-left,
  // the title and chips bottom-left, the field owning the right.
  { file: "og.png", w: 1200, h: 630, layout: {
    mode: "split", pad: 64, padBottom: 104, msgW: 700,
    field: "top: 0; right: 0; width: 56%; height: 100%", mask: "linear-gradient(to right, transparent, #000 40%)",
    logoW: 220, logoGap: 0, h1: 66, measure: "700px", freeGap: 24,
    rowGap: 36, chipGap: 14, chipPad: "10px 16px", mono: 19,
  } },
  // 1080 × 1080: the field across the top, the logotype, title and chips below
  // it with the same rhythm.
  { file: "square.png", w: 1080, h: 1080, layout: {
    mode: "stack", pad: 80, padBottom: 120, msgW: 900,
    field: "top: 0; left: 0; width: 100%; height: 36%", mask: "linear-gradient(#000 25%, transparent)",
    logoW: 300, logoGap: 56, h1: 92, measure: "900px", freeGap: 32,
    rowGap: 52, chipGap: 16, chipPad: "12px 20px", mono: 24,
  } },
];

/**
 * The share card since the glass hero (2026-10-30): the first screen of the
 * site. The field is check/field.js itself, running in the page, under a solid
 * header with a hard edge; the question and a real report float in one panel of
 * heavy glass, and the scan button is the one blue action. The report is
 * penthera.org's own: 95/100, its one gap (SPF and DMARC) listed honestly.
 * `l.split` puts the plate beside the message (og), otherwise below it.
 */
const meter = (score, px, gap) => `<div class="meter" style="grid-template-columns: repeat(10, ${px}px); gap: ${gap}px">${
  Array.from({ length: 100 }, (_, i) => `<i class="${i < score ? "on" : ""}" style="width:${px}px;height:${px}px"></i>`).join("")}</div>`;

const fieldSrc = readFileSync(join(SITE, "check", "field.js"), "utf8");

export const scanCard = (w, h, l) => `<!doctype html><html style="--ink-rgb: 255, 255, 255; --accent-ink: #7a7aff"><head><meta charset="utf-8"><style>
@font-face { font-family: "Departure Mono"; src: url("${font}") format("woff2"); }
* { box-sizing: border-box; margin: 0; }
html, body { width: ${w}px; height: ${h}px; background: #000; color: #fff; overflow: hidden; }
body { position: relative; font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased; }
.mono { font-family: "Departure Mono", monospace; letter-spacing: 0.02em; }
.hero { position: absolute; inset: 0; }
.field { position: absolute; inset: 0; width: 100%; height: 100%; image-rendering: pixelated; }
.hero.live img.field { visibility: hidden; }
.head { position: absolute; inset: 0 0 auto; height: ${l.head}px; padding: 0 ${l.pad}px ${l.headPad}px; display: flex; align-items: flex-end; justify-content: space-between; background: #000; }
.logo { display: block; width: ${l.logoW}px; height: auto; }
.url { font-size: ${l.small}px; color: rgba(255,255,255,0.72); }
.panel {
  position: absolute; top: ${l.head + l.gap}px; right: ${l.gap}px; bottom: ${l.bottom}px; left: ${l.gap}px;
  padding: ${l.panelPad}px; display: grid; gap: ${l.colGap}px; align-items: center;
  ${l.split ? `grid-template-columns: minmax(0, 1fr) ${l.plateW}px;` : "align-content: center;"}
  background: rgba(0,0,0,0.58); -webkit-backdrop-filter: blur(40px) saturate(1.5); backdrop-filter: blur(40px) saturate(1.5);
  border: 1px solid rgba(255,255,255,0.24); box-shadow: inset 0 1px 0 rgba(255,255,255,0.2);
}
h1 { font-weight: 500; font-size: ${l.h1}px; line-height: 0.98; letter-spacing: -0.04em; text-wrap: balance; }
.sub { margin-top: ${l.h1 * 0.28}px; font-size: ${l.sub}px; font-weight: 500; letter-spacing: -0.01em; line-height: 1.3; }
.scan { display: grid; grid-template-columns: 1fr auto; margin-top: ${l.scanGap}px; }
.scan .in { height: ${l.scanH}px; display: flex; align-items: center; padding: 0 ${l.scanH * 0.3}px; font-size: ${l.mono}px; color: rgba(255,255,255,0.6); background: #000; border: 1px solid #fff; border-right: 0; }
.scan .go { height: ${l.scanH}px; display: flex; align-items: center; padding: 0 ${l.scanH * 0.5}px; font-size: ${l.mono}px; color: #fff; background: linear-gradient(180deg, #4a4aff, #0000ed 58%, #0000b8); box-shadow: inset 0 1px 0 rgba(255,255,255,0.45); }
.note { margin-top: ${l.noteGap}px; font-size: ${l.small}px; color: rgba(255,255,255,0.72); }
.plate { position: relative; padding: ${l.platePad}px; border: 1px solid rgba(255,255,255,0.24);
  background: radial-gradient(${l.plateW * 1.1}px circle at 50% -40%, rgba(255,255,255,0.16), transparent 70%), linear-gradient(180deg, rgba(255,255,255,0.08), transparent 48%, rgba(0,0,0,0.45)), #16171a;
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.3), inset 0 -1px 0 rgba(0,0,0,0.6); }
.plate::before { content: ""; position: absolute; inset: 0; background: repeating-linear-gradient(180deg, rgba(255,255,255,0.035) 0 1px, transparent 1px 3px); pointer-events: none; }
.host { font-size: ${l.small}px; color: rgba(255,255,255,0.6); }
.verdict { margin-top: 6px; font-size: ${l.verdict}px; font-weight: 500; letter-spacing: -0.03em; }
.score { display: flex; align-items: center; gap: ${l.platePad * 0.7}px; margin-top: ${l.platePad * 0.6}px; }
.meter { display: grid; }
.meter i { display: block; background: rgba(255,255,255,0.14); }
.meter i.on { background: #fff; }
.n { font-size: ${l.score}px; line-height: 0.85; letter-spacing: -0.05em; font-weight: 500; }
.n span { font-family: "Departure Mono", monospace; font-size: ${l.small}px; letter-spacing: 0; color: rgba(255,255,255,0.6); margin-left: 6px; }
.rows { display: grid; gap: 4px; margin-top: ${l.platePad * 0.7}px; }
.rows div { display: flex; align-items: center; gap: 12px; padding: ${l.rowPad}px; background: rgba(255,255,255,0.05); font-size: ${l.rowFont}px; }
.rows .m { flex: none; width: ${l.markW}px; text-align: center; padding: 1px 0; font-size: ${l.small * 0.85}px; color: #fff; border: 1px solid rgba(255,255,255,0.5); }
.rows .bad .m { background: #fff; color: #000; border-color: #fff; }
</style></head><body>
<div class="hero"><img class="field" src="${field}" alt=""></div>
<div class="head">${logo}<span class="url mono">penthera.org</span></div>
<div class="panel">
  <div>
    <h1>Is your site/app safe?</h1>
    <p class="sub">Find out in seconds. Then fix it with your coding agent.</p>
    <div class="scan mono"><div class="in">your-site.com</div><div class="go">Check</div></div>
    <p class="note mono">Passive · nothing stored · your own site only</p>
  </div>
  <div class="plate">
    <p class="host mono">penthera.org</p>
    <p class="verdict">Solid basics</p>
    <div class="score">${meter(95, l.cell, 2)}<p class="n">95<span>/100</span></p></div>
    <div class="rows">
      <div><span class="m mono">OK</span>HTTPS, TLS 1.3, HSTS</div>
      <div><span class="m mono">OK</span>7 of 7 browser protections</div>
      <div class="bad"><span class="m mono">FIX</span>No SPF or DMARC record</div>
    </div>
  </div>
</div>
<script type="module">${fieldSrc}
liveField(document.querySelector(".field"));</script>
</body></html>`;

/**
 * The link card: two chat bubbles on blue, over the dithered field. X lays its
 * title bar over the bottom left, across the card at phone size, so the bottom
 * 160 px stay clear and the logo sits at the top. No score: a number here could
 * read as a claim about a real site.
 */
export const bubbleCard = () => `<!doctype html><meta charset="utf-8"><style>*{box-sizing:border-box;margin:0}html,body{width:1200px;height:630px;overflow:hidden;font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}body{position:relative;color:#fff}
.lg{position:absolute;right:56px;top:62px;width:200px}.lg svg{display:block;width:100%;height:auto}
.b{position:absolute;padding:.22em .44em .3em;font-weight:500;letter-spacing:-.035em;line-height:1.04}
.q{left:56px;top:48px;font-size:70px;border-radius:.36em .36em .36em 0}
.a{right:56px;top:204px;font-size:88px;max-width:930px;border-radius:.36em .36em 0 .36em}
.bg{position:absolute;inset:0}
</style><style>body{background:#0000ed}.f{position:absolute;left:0;right:0;top:0;bottom:0;background:url(${field}) center/1500px auto;filter:blur(1px);opacity:.55;mix-blend-mode:screen}.q{background:rgba(0,0,160,.55);border:1px solid rgba(255,255,255,.5);backdrop-filter:blur(18px)}.a{background:rgba(255,255,255,.92);color:#0000ed;backdrop-filter:blur(18px)}</style><div class="f"></div><div class="b q">yo is my app secure?</div><div class="b a">check it before<br>they wreck it</div><span class="lg">${logo}</span>`;

/** The plain card for research pages: no joke beside results. */
export const plainCard = () => `<!doctype html><meta charset="utf-8"><style>*{box-sizing:border-box;margin:0}html,body{width:1200px;height:630px;overflow:hidden;font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased;background:#000;color:#fff}
.strip{position:absolute;left:0;right:0;bottom:0;height:150px;background:url(${field}) left top/1100px auto repeat-x}
h1{position:absolute;left:64px;top:132px;font-size:124px;font-weight:500;letter-spacing:-.035em;line-height:1.02;max-width:1080px}
.lg{position:absolute;left:64px;top:48px;width:230px}.lg svg{display:block;width:100%;height:auto}</style>
<div class="strip"></div><h1>Measured in public</h1><span class="lg">${logo}</span>`;

/** The cards the site ships: og.png for link previews, square.png for square feeds, story.png for 9:16. */
export const CARDS = [
  { file: "og.png", w: 1200, h: 630, layout: {
    split: true, pad: 28, head: 76, headPad: 18, gap: 28, bottom: 28, panelPad: 32, plateW: 400, colGap: 36,
    logoW: 168, h1: 62, sub: 20, scanGap: 28, scanH: 60, mono: 20, noteGap: 14, small: 15,
    platePad: 24, verdict: 30, score: 68, cell: 8, rowPad: 8, rowFont: 16, markW: 42,
  } },
  { file: "square.png", w: 1080, h: 1080, layout: {
    split: false, pad: 32, head: 96, headPad: 22, gap: 32, bottom: 64, panelPad: 36, plateW: 900, colGap: 26,
    logoW: 208, h1: 84, sub: 26, scanGap: 24, scanH: 68, mono: 23, noteGap: 12, small: 19,
    platePad: 24, verdict: 32, score: 72, cell: 7, rowPad: 8, rowFont: 20, markW: 48,
  } },
  // 1080 × 1920, 9:16 for TikTok, Reels and Stories. The top 220 px and bottom
  // 360 px stay clear of the apps' own buttons and captions.
  { file: "story.png", w: 1080, h: 1920, layout: {
    split: false, pad: 40, head: 240, headPad: 36, gap: 40, bottom: 380, panelPad: 52, plateW: 900, colGap: 44,
    logoW: 240, h1: 124, sub: 34, scanGap: 36, scanH: 88, mono: 28, noteGap: 18, small: 23,
    platePad: 34, verdict: 44, score: 104, cell: 11, rowPad: 12, rowFont: 26, markW: 60,
  } },
];

/**
 * Screenshot one page with headless Chrome.
 * @param {string} html the page
 * @param {string} file the PNG to write
 * @param {{ transparent?: boolean }} opts transparent: keep the page's
 *   background see-through (for overlays)
 */
export function shoot(html, w, h, file, { transparent = false } = {}) {
  const tmp = mkdtempSync(join(tmpdir(), "penthera-social-"));
  try {
    const src = join(tmp, "page.html");
    writeFileSync(src, html);
    const t0 = Date.now();
    // Headless Chrome writes the screenshot and then sometimes lingers: a
    // timeout is fine as long as a fresh image is on disk.
    try {
      execFileSync(CHROME, [
        "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
        `--user-data-dir=${join(tmp, "profile")}`, "--allow-file-access-from-files",
        ...(transparent ? ["--default-background-color=00000000"] : []),
        `--window-size=${w},${h}`, `--screenshot=${file}`, "--virtual-time-budget=2000",
        pathToFileURL(src).href,
      ], { stdio: "ignore", timeout: 90_000, killSignal: "SIGKILL" });
    } catch (e) {
      if (!existsSync(file) || statSync(file).mtimeMs < t0) throw e;
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  mkdirSync(OUT, { recursive: true });
  shoot(plainCard(), 1200, 630, join(OUT, "og-plain.png"));
  for (const s of CARDS) {
    shoot(s.file === "og.png" ? bubbleCard() : scanCard(s.w, s.h, s.layout), s.w, s.h, join(OUT, s.file));
    console.log(`site/media/social/${s.file} ${s.w}×${s.h}`);
  }
}
