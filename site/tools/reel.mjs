#!/usr/bin/env node
/**
 * Render the link-preview reel, site/media/social/reel.mp4: the muted loop
 * that iMessage, Slack and other apps play for a shared penthera.org link
 * (og:video), with og.png as its poster and fallback.
 *
 *   node site/tools/reel.mjs
 *   CHROME=/path/to/chrome node site/tools/reel.mjs
 *
 * Five beats, 1200 × 630 like the share card so the preview keeps its shape:
 *
 *   1. `npx penthera`: setup        ┐ cut from assets/walkthrough.mp4,
 *   2. an offline scan's findings    │ captions cropped off; cut points
 *   3. the Simple-mode verdict       ┘ follow assets/walkthrough.vtt
 *   4. the PHP advisory of 21 Oct 2026, caught in a pinned Dockerfile
 *      (scripts/media/tapes/advisory.tape, recorded with vhs)
 *   5. the share card itself, og.png (site/tools/social.mjs bubbleCard)
 *
 * Each beat crossfades into the next, and the card crossfades back into the
 * first beat, so the loop has no seam. A one-line label in the card's mono
 * type names each beat. Re-run after scripts/media/walkthrough.mjs re-renders
 * the walkthrough or the card changes.
 *
 * Needs Node 22+, a local Chrome or Chromium, vhs (with ttyd) and ffmpeg with
 * libx264. Demo data only: the walkthrough uses the mock server and
 * `penthera ui --demo`, and the advisory beat scans a throwaway folder.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { bubbleCard, shoot } from "./social.mjs";

const SITE = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ROOT = resolve(SITE, "..");
const OUT = join(SITE, "media", "social", "reel.mp4");
const W = 1200;
const H = 630;
const FPS = 30;
const FADE = 0.4;
// Link previews fetch the whole file; Apple caps the image and video of one
// preview at 10 MB together. Stay well under.
const MAX_BYTES = 3 * 1024 * 1024;

/**
 * The beats. `crop` is a W:H window of the 1280 × 800 walkthrough frame
 * (x, y, width), above the caption band, scaled up to fill the reel.
 * `at` puts the label in the top or bottom right corner, wherever the
 * beat's own text leaves room.
 */
const BEATS = [
  { label: "$ npx penthera", at: "top", from: "walkthrough", ss: 2.6, t: 2.6, crop: [0, 16, 1040] },
  { label: "Scans offline. Real findings.", at: "bottom", from: "walkthrough", ss: 22.5, t: 2.8, crop: [0, 0, 900] },
  { label: "One sentence: can you ship?", at: "top", from: "walkthrough", ss: 36.05, t: 2.6, crop: [250, 70, 740] },
  { label: "21 Oct 2026: PHP's critical flaws, caught the day they shipped", at: "bottom", from: "advisory", ss: 2.4, t: 3.6 },
  { label: null, from: "card", t: 3.6 },
];

const font = pathToFileURL(join(ROOT, "src", "ui", "static", "fonts", "DepartureMono-Regular.woff2")).href;

/**
 * The labels, in the card's chip style, as one transparent page: a W × H
 * slot per beat, stacked, so one Chrome run renders them all.
 */
const labelsPage = (beats) => `<!doctype html><html><head><meta charset="utf-8"><style>
@font-face { font-family: "Departure Mono"; src: url("${font}") format("woff2"); }
* { margin: 0; }
html, body { width: ${W}px; height: ${H * beats.length}px; background: transparent; overflow: hidden; }
div { position: relative; width: ${W}px; height: ${H}px; }
span { position: absolute; right: 40px; padding: 10px 16px; font: 19px/1.2 "Departure Mono", monospace; letter-spacing: 0.02em; color: #fff; background: #0000ed; border: 1px solid #0000ed; }
.top { top: 36px; } .bottom { bottom: 36px; }
</style></head><body>${beats.map((b) => `<div>${b.label ? `<span class="${b.at}">${b.label.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</span>` : ""}</div>`).join("")}</body></html>`;

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { cwd: ROOT, stdio: ["ignore", "inherit", "inherit"], ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.slice(0, 3).join(" ")}... failed (${r.status ?? r.signal})`);
}

const tmp = mkdtempSync(join(tmpdir(), "penthera-reel-"));
const scratch = [tmp];
try {
  // The end card: the share card itself (og.png), so the loop ends on the
  // poster that link previews show before it plays.
  const card = join(tmp, "card.png");
  shoot(bubbleCard(), W, H, card);
  console.log("end card: the og.png share card");

  const labels = join(tmp, "labels.png");
  shoot(labelsPage(BEATS), W, H * BEATS.length, labels, { transparent: true });

  // The advisory beat: a folder whose Dockerfile pins a PHP the advisory
  // covers. Under /tmp where there is one, so the scan's Target line is short.
  const media = mkdtempSync(join(process.platform === "win32" ? tmpdir() : "/tmp", "penthera-"));
  scratch.push(media);
  mkdirSync(join(media, "shop"));
  writeFileSync(join(media, "shop", "Dockerfile"), "FROM php:8.3.12-apache\nCOPY . /var/www/html\n");
  const advisory = join(tmp, "advisory.mp4");
  run("vhs", ["scripts/media/tapes/advisory.tape", "-o", advisory], {
    env: { ...process.env, PENTHERA_ROOT: ROOT, PENTHERA_MEDIA: media },
    stdio: ["ignore", "ignore", "inherit"],
  });

  // One input per beat, plus the first beat again for the crossfade that closes the loop.
  const walkthrough = join(ROOT, "assets", "walkthrough.mp4");
  const inputs = [];
  const graph = [];
  const source = (b) => {
    if (b.from === "card") inputs.push("-loop", "1", "-framerate", String(FPS), "-t", String(b.t), "-i", card);
    else inputs.push("-ss", String(b.ss), "-t", String(b.t), "-i", b.from === "walkthrough" ? walkthrough : advisory);
  };
  const fit = (b) => {
    // TV range throughout: the card's PNG would otherwise make the output
    // full-range (yuvj420p), which some players show washed out.
    const scale = `scale=${W}:${H}:flags=lanczos:out_range=tv`;
    if (!b.crop) return scale;
    const [x, y, w] = b.crop;
    return `crop=${w}:${Math.round((w * H) / W)}:${x}:${y},${scale}`;
  };
  [...BEATS, { ...BEATS[0], t: 1, closing: true }].forEach((b, i) => {
    source(b);
    graph.push(`[${i}:v]${fit(b)},fps=${FPS},setsar=1,format=yuv420p,setpts=PTS-STARTPTS[c${i}]`);
  });
  // The labels go in last: one input, a slot cut out per beat.
  const all = [...BEATS, BEATS[0]];
  const n = inputs.filter((a) => a === "-i").length;
  inputs.push("-i", labels);
  graph.push(`[${n}:v]split=${all.length}${all.map((_, i) => `[l${i}]`).join("")}`);
  all.forEach((b, i) => {
    if (!b.label) {
      graph.push(`[l${i}]nullsink;[c${i}]null[v${i}]`);
      return;
    }
    graph.push(`[l${i}]crop=${W}:${H}:0:${(i % BEATS.length) * H}[s${i}];[c${i}][s${i}]overlay=0:0:format=auto,format=yuv420p[v${i}]`);
  });
  let prev = "v0";
  let offset = 0;
  for (let i = 1; i < all.length; i++) {
    offset += BEATS[i - 1].t - FADE;
    graph.push(`[${prev}][v${i}]xfade=transition=fade:duration=${FADE}:offset=${offset.toFixed(3)}[x${i}]`);
    prev = `x${i}`;
  }
  // End exactly where the closing crossfade lands on the first beat's first frame.
  const total = offset + FADE;
  graph.push(`[${prev}]trim=0:${total.toFixed(3)},setpts=PTS-STARTPTS[out]`);

  mkdirSync(dirname(OUT), { recursive: true });
  run("ffmpeg", [
    "-v", "error", "-y", ...inputs, "-filter_complex", graph.join(";"), "-map", "[out]",
    // H.264 Main, yuv420p, no audio track: plays muted everywhere a preview
    // plays video. faststart puts the index first so playback starts early.
    "-c:v", "libx264", "-profile:v", "main", "-level", "4.0", "-pix_fmt", "yuv420p",
    "-preset", "slow", "-crf", "24", "-tune", "animation", "-g", String(FPS * 2),
    "-color_range", "tv", "-an", "-movflags", "+faststart", OUT,
  ]);
  const bytes = statSync(OUT).size;
  console.log(`site/media/social/reel.mp4 ${W}×${H}, ${total.toFixed(1)} s, ${Math.round(bytes / 1024)} KB`);
  if (bytes > MAX_BYTES) throw new Error(`reel.mp4 is ${Math.round(bytes / 1024)} KB, over ${MAX_BYTES / 1024} KB; raise -crf or shorten the beats`);
} finally {
  for (const d of scratch) rmSync(d, { recursive: true, force: true });
}
