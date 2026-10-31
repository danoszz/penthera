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
// The approved tagline.
export const LINE = "Make your app more secure for free";
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

/**
 * The same bubbles for feeds. One field, drawn once and faded at the edges, so
 * no seam shows on a tall card. `l.top` sets the group below the apps' own
 * buttons.
 */
export const bubbleFeed = (w, h, l) => `<!doctype html><meta charset="utf-8"><style>*{box-sizing:border-box;margin:0}html,body{width:${w}px;height:${h}px;overflow:hidden;font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}body{position:relative;color:#fff;background:#0000ed}
.f{position:absolute;inset:0;background:url(${field}) center/${l.field}px auto no-repeat;image-rendering:pixelated;filter:blur(1px);opacity:.55;mix-blend-mode:screen;-webkit-mask-image:linear-gradient(transparent ${l.fade[0]}%,#000 ${l.fade[1]}%,#000 ${l.fade[2]}%,transparent ${l.fade[3]}%)}
.lg{position:absolute;left:64px;top:${l.logoTop}px;width:${l.logoW}px}.lg svg{display:block;width:100%;height:auto}
.b{position:absolute;padding:.22em .44em .3em;font-weight:500;letter-spacing:-.035em;line-height:1.04;backdrop-filter:blur(18px)}
.q{left:64px;top:${l.top}px;font-size:${l.q}px;border-radius:.36em .36em .36em 0;background:rgba(0,0,160,.55);border:1px solid rgba(255,255,255,.5)}
.a{right:64px;top:${l.top + l.gap}px;font-size:${l.a}px;border-radius:.36em .36em 0 .36em;background:rgba(255,255,255,.92);color:#0000ed}
</style><div class="f"></div><div class="b q">yo is my app secure?</div><div class="b a">check it before<br>they wreck it</div><span class="lg">${logo}</span>`;

/** The plain card for research pages: no joke beside results. */
export const plainCard = () => `<!doctype html><meta charset="utf-8"><style>*{box-sizing:border-box;margin:0}html,body{width:1200px;height:630px;overflow:hidden;font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased;background:#000;color:#fff}
.strip{position:absolute;left:0;right:0;bottom:0;height:150px;background:url(${field}) left top/1100px auto repeat-x}
h1{position:absolute;left:64px;top:132px;font-size:124px;font-weight:500;letter-spacing:-.035em;line-height:1.02;max-width:1080px}
.lg{position:absolute;left:64px;top:48px;width:230px}.lg svg{display:block;width:100%;height:auto}</style>
<div class="strip"></div><h1>Measured in public</h1><span class="lg">${logo}</span>`;

/** The feed cards. story.png keeps the top 220 px and bottom 360 px clear of the apps' own buttons and captions. */
export const FEEDS = [
  { file: "square.png", w: 1080, h: 1080, layout: { field: 1728, fade: [0, 12, 88, 100], logoTop: 64, logoW: 240, top: 340, gap: 186, q: 76, a: 110 } },
  { file: "story.png", w: 1080, h: 1920, layout: { field: 3000, fade: [8, 20, 84, 96], logoTop: 240, logoW: 280, top: 640, gap: 220, q: 84, a: 124 } },
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
  shoot(bubbleCard(), 1200, 630, join(OUT, "og.png"));
  for (const s of FEEDS) {
    shoot(bubbleFeed(s.w, s.h, s.layout), s.w, s.h, join(OUT, s.file));
    console.log(`site/media/social/${s.file} ${s.w}×${s.h}`);
  }
}
