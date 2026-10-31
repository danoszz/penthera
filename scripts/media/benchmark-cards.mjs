#!/usr/bin/env node
/**
 * Share images of the public-benchmark ranking, in the site's own style: the
 * same cards (site/public-bench.mjs) and site/dist/styles.css, rendered by
 * headless Chrome. Run `node site/build.mjs` first.
 *
 *   node scripts/media/benchmark-cards.mjs --published bench/public/published.json --out <dir>
 *
 * Writes linkedin.png (1200x627), x.png (1600x900) and one x-<benchmark>.png
 * per card (1600x900) for a thread. A sample file gets a SAMPLE stamp.
 *
 *   node scripts/media/benchmark-cards.mjs --site
 *
 * writes the share cards of /benchmarks and its pages instead (1200x630, into
 * site/media/social/bench/), with the hash of the published.json they show:
 * the site build uses a card only while that file is unchanged.
 */
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync, cpSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { parseArgs } from "node:util";
import { publicBenchHtml } from "../../site/public-bench.mjs";
import { benchmarkViews, fieldTools, n2, ord, pubHash, tiedPhrase } from "../../site/benchmarks.mjs";
import { mosaic } from "../../site/news.mjs";

const { values: args } = parseArgs({ options: { published: { type: "string" }, out: { type: "string" }, chrome: { type: "string" }, site: { type: "boolean" } } });
const ROOT = resolve(import.meta.dirname, "..", "..");
const DIST = join(ROOT, "site", "dist");
const CHROME = args.chrome || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const pubFile = args.site ? join(ROOT, "bench", "public", "published.json") : resolve(args.published);
const pubText = readFileSync(pubFile, "utf-8");
const pub = JSON.parse(pubText);
const out = args.site ? join(ROOT, "site", "media", "social", "bench") : resolve(args.out);
mkdirSync(out, { recursive: true });

// One page per image: the site's stylesheet and fonts, the trust band's
// colours, and the cards without the lede, links or "How it is scored".
const tmp = mkdtempSync(join(tmpdir(), "penthera-cards-"));
cpSync(join(DIST, "styles.css"), join(tmp, "styles.css"));
cpSync(join(DIST, "fonts"), join(tmp, "fonts"), { recursive: true });
cpSync(join(DIST, "logo.svg"), join(tmp, "logo.svg"));
cpSync(join(ROOT, "site", "media", "field.png"), join(tmp, "field.png"));
const css = readFileSync(join(tmp, "styles.css"), "utf-8").replaceAll('url("/fonts/', 'url("fonts/');
writeFileSync(join(tmp, "styles.css"), css);

function page(w, h, cardsHtml, cols, forceCompact = false, url = "penthera.org/#public-benchmarks") {
  // Compact type for the short formats: LinkedIn and X, and the Instagram square.
  const compact = forceCompact || h < 700 || (w <= 1100 && h <= 1100);
  return `<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><link rel="stylesheet" href="styles.css"><style>
  html, body { margin: 0; width: ${w}px; height: ${h}px; overflow: hidden; color: var(--text-1); }
  html { background: var(--ground); }
  body { position: relative; z-index: 0; background: transparent; }
  .pb > h3, .pb .bench-lede, .pb .links { display: none; }
  .pb-card { padding: ${compact ? 16 : 22}px; gap: ${compact ? 6 : 10}px; }
  .pb-place { font-size: ${compact ? 48 : 72}px; }
  .pb-row { font-size: ${compact ? 10 : 13}px; } .pb-chart { gap: ${compact ? 2 : 5}px; }
  .pb-track { height: ${compact ? 7 : 10}px; }
  /* Retro: the site's 1-bit dither field tiled faintly, scanlines, one blue glow. */
  body::before { content: ""; position: fixed; inset: 0; z-index: -2; background: url("field.png") 0 0 / 180px auto repeat; opacity: 0.16; image-rendering: pixelated; }
  body::after { content: ""; position: fixed; inset: 0; z-index: -1; background:
    repeating-linear-gradient(180deg, rgba(255,255,255,0.035) 0 1px, transparent 1px 3px),
    radial-gradient(70% 60% at 85% 0%, rgba(0,0,237,0.35), transparent 70%),
    radial-gradient(90% 80% at 0% 100%, rgba(0,0,0,0.85), transparent 70%); }
  .shot-head { display: grid; justify-items: start; gap: ${compact ? 10 : 18}px; }
  .shot-logo { display: block; flex: none; height: ${compact ? 36 : 46}px; width: auto; filter: invert(1); } /* logo.svg is black ink */
  .shot-right { text-align: left; }
  .shot-t { max-width: none; white-space: nowrap; }
  .shot-right .shot-k { margin: 0; }
  body { display: grid; grid-template-rows: auto 1fr auto; gap: ${compact ? 18 : 28}px; padding: ${compact ? "36px 48px" : "56px 64px"}; box-sizing: border-box; }
  .shot-k { font-family: var(--px); font-size: 18px; color: var(--text-2); }
  .shot-t { margin: 10px 0 0; font-family: var(--display); font-size: ${compact ? 40 : 64}px; line-height: 1; letter-spacing: -0.035em; font-weight: 500; color: var(--text-1); }
  .pb { margin: 0; } .pb-cards { margin: 0; grid-template-columns: repeat(${cols}, 1fr) !important; }
  .pb-more, .pb-sample, .pb-link { display: none; }
  .shot-f { display: flex; flex-direction: ${w < 1200 ? "column" : "row"}; gap: 6px; justify-content: space-between; font-family: var(--px); font-size: 16px; color: var(--text-2); }
  .stamp { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%); padding: 6px 10px; font-family: var(--px); font-size: 16px; background: var(--accent-ink); color: #fff; }
  </style></head><body>
  <div class="shot-head"><img class="shot-logo" src="logo.svg" alt="Penthera"><div class="shot-right"><p class="shot-k">Public benchmarks · sealed test half</p><h1 class="shot-t">Ranked against the free tools</h1></div></div>
  ${cardsHtml}
  <p class="shot-f"><span>Sealed half of each dataset, scored once. Same scoring for every tool.</span><span>${url}</span></p>
  ${pub.sample ? '<p class="stamp">SAMPLE · practice data, not a result</p>' : ""}
  </body></html>`;
}

function shot(name, html, w, h, scale = 2) {
  const file = join(tmp, `${name}.html`);
  writeFileSync(file, html);
  const png = join(out, `${name}.png`);
  rmSync(png, { force: true });
  const r = spawnSync(CHROME, ["--headless=new", "--disable-gpu", "--hide-scrollbars", `--force-device-scale-factor=${scale}`, `--window-size=${w},${h}`, `--screenshot=${png}`, `file://${file}`], { encoding: "utf-8", timeout: 60_000 });
  // Headless Chrome can exit non-zero on teardown after writing the file.
  if (!existsSync(png)) throw new Error(`chrome: ${r.stderr.slice(-300)}`);
  console.log(png);
}

const all = publicBenchHtml(pub);
const single = (key) => publicBenchHtml({ ...pub, benchmarks: { [key]: pub.benchmarks[key] } });
// The site's cards, on the hub's paper: the RANK block title, then the place.
function paper(url, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><style>
  @font-face { font-family: "Departure Mono"; src: url("fonts/DepartureMono-Regular.woff2") format("woff2"); }
  * { box-sizing: border-box; margin: 0; }
  html, body { width: 1200px; height: 630px; overflow: hidden; background: #e6e6e1; color: #12151a; font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased; }
  .bar { display: flex; justify-content: space-between; padding: 12px 40px; font: 18px "Departure Mono", monospace; color: #fff; background: #0000ed; }
  .top { display: grid; grid-template-columns: 392px 1fr; gap: 36px; align-items: end; padding: 32px 40px 0; }
  .ttx-title { display: block; width: 392px; height: 118px; } rect { fill: transparent; } rect.on { fill: #ff7a00; }
  h1 { font-size: 46px; font-weight: 500; line-height: 1.02; letter-spacing: -.035em; }
  .main { position: absolute; left: 40px; right: 40px; top: 228px; bottom: 74px; }
  .foot { position: absolute; left: 40px; right: 40px; bottom: 26px; display: flex; justify-content: space-between; font: 18px "Departure Mono", monospace; color: #3a404b; }
  .cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; height: 100%; }
  .card { display: flex; flex-direction: column; padding: 22px 20px; background: #fff; }
  .card h2 { font-size: 24px; font-weight: 500; line-height: 1.1; letter-spacing: -.02em; }
  .place { margin-top: auto; font-size: 92px; font-weight: 500; line-height: 1; letter-spacing: -.04em; }
  .of, .tied { font: 20px "Departure Mono", monospace; letter-spacing: 0; }
  .tied { min-height: 26px; margin-top: 10px; }
  .one { display: grid; grid-template-columns: 290px 1fr; gap: 36px; align-items: center; height: 100%; padding: 22px 26px; background: #fff; }
  .one .place { margin: 0; font-size: 110px; }
  .bars { display: grid; align-content: center; gap: 6px; font: 18px "Departure Mono", monospace; }
  .bars p { display: grid; grid-template-columns: 170px 1fr 56px; gap: 12px; align-items: center; }
  .bars i { display: block; height: 12px; background: #4a4f58; } .bars .us { font-weight: 700; } .bars .us i { background: #0000ed; }
  .bars span { overflow: hidden; white-space: nowrap; text-overflow: ellipsis; } .bars b { font-weight: 400; text-align: right; }
  </style></head><body><p class="bar"><span>Penthera benchmarks</span><span>${url}</span></p>${body}
  <p class="foot"><span>Penthera ${pub.benchmarks[Object.keys(pub.benchmarks)[0]].rows.find((r) => r.kind === "penthera").version} against free tools, on the sealed half</span><span>Every score and loss on the page</span></p></body></html>`;
}
const range = (v) => (tiedPhrase(v.iv) || (v.close ? ", within the margin of error" : "")).replace(/^, /, "");
if (args.site) {
  if (pub.sample) throw new Error("refusing to render site cards from a sample file");
  const views = benchmarkViews(pub);
  shot("hub", paper("penthera.org/benchmarks", `<div class="top">${mosaic("RANK")}<h1>Penthera and ${fieldTools(pub)} free security tools</h1></div>
  <div class="main"><div class="cards">${views.map((v) => `<div class="card"><h2>${v.c.label}</h2><p class="place">${ord(v.us.rank)}<span class="of"> of ${v.b.of}</span></p><p class="tied">${range(v)}</p></div>`).join("")}</div></div>`), 1200, 630, 1);
  for (const v of views) {
    const max = Math.max(...v.ranked.map((r) => r.score), 0.01), top = v.ranked.slice(0, 6);
    if (!top.includes(v.us)) top[5] = v.us;
    shot(v.c.slug, paper(`penthera.org/benchmarks/${v.c.slug}`, `<div class="top">${mosaic("RANK")}<h1>${v.c.label}</h1></div>
    <div class="main"><div class="one"><div><p class="place">${ord(v.us.rank)}<span class="of"> of ${v.b.of}</span></p><p class="tied">${range(v)}</p></div>
    <div class="bars">${top.map((r) => `<p class="${r.kind === "penthera" ? "us" : ""}"><span>${r.tool}</span><i style="width:${Math.max(1, Math.round((Math.max(0, r.score) / max) * 100))}%"></i><b>${n2(r.score)}</b></p>`).join("")}</div></div></div>`), 1200, 630, 1);
  }
  writeFileSync(join(out, "source.json"), JSON.stringify({ published: pubHash(pubText) }, null, 2) + "\n");
  rmSync(tmp, { recursive: true, force: true });
  process.exit(0);
}
shot("linkedin", page(1200, 627, all, 4), 1200, 627);
shot("x", page(1600, 900, all, 4), 1600, 900);
// Instagram: a square post (2 x 2 cards) and a story (cards stacked).
shot("instagram-square", page(1080, 1080, all, 2), 1080, 1080);
shot("instagram-story", page(1080, 1920, all, 1, true), 1080, 1920);
for (const key of Object.keys(pub.benchmarks)) {
  const one = single(key);
  shot(`x-${key}`, page(1600, 900, one, 1).replace(".pb-cards { margin: 0;", ".pb-cards { margin: 0 auto; max-width: 560px;"), 1600, 900);
}
rmSync(tmp, { recursive: true, force: true });
