#!/usr/bin/env node
/**
 * Render the link-preview reel, site/media/social/reel.mp4: the muted loop
 * that iMessage, Slack and other apps play for a shared penthera.org link
 * (og:video), with og.png as its poster and fallback.
 *
 *   node site/tools/reel.mjs
 *   CHROME=/path/to/chrome node site/tools/reel.mjs
 *
 * Five beats, 1200 × 630 like the share card so the preview keeps its shape.
 * The first four are cut from the homepage film, site/media/film.mp4; their
 * cut points follow its scenes:
 *
 *   1. the opening line
 *   2. the dashboard's verdict
 *   3. a fix applied and checked
 *   4. the rules deciding
 *   5. the share card itself, og.png (site/tools/social.mjs bubbleCard)
 *
 * Each beat crossfades into the next, and the card crossfades back into the
 * first beat, so the loop has no seam. Re-run after the film or the card
 * changes.
 *
 * Needs Node 22+, a local Chrome or Chromium and ffmpeg with libx264.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
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

/** The beats: where each one starts in the film and how long it lasts, in seconds. */
const BEATS = [
  { ss: 0.5, t: 2.3 },
  { ss: 17, t: 2.2 },
  { ss: 29.8, t: 2.4 },
  { ss: 42.4, t: 3.2 },
  { card: true, t: 3.4 },
];

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { cwd: ROOT, stdio: ["ignore", "inherit", "inherit"], ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.slice(0, 3).join(" ")}... failed (${r.status ?? r.signal})`);
}

const tmp = mkdtempSync(join(tmpdir(), "penthera-reel-"));
try {
  // The end card: the share card itself (og.png), so the loop ends on the
  // poster that link previews show before it plays.
  const card = join(tmp, "card.png");
  shoot(bubbleCard(), W, H, card);
  console.log("end card: the og.png share card");

  // One input per beat, plus the first beat again for the crossfade that closes the loop.
  const film = join(SITE, "media", "film.mp4");
  const all = [...BEATS, { ...BEATS[0], t: 1 }];
  const inputs = [];
  const graph = [];
  all.forEach((b, i) => {
    if (b.card) inputs.push("-loop", "1", "-framerate", String(FPS), "-t", String(b.t), "-i", card);
    else inputs.push("-ss", String(b.ss), "-t", String(b.t), "-i", film);
    // The film is 16:9: a centred strip of it fills the card's shape. TV range
    // throughout: the card's PNG would otherwise make the output full-range
    // (yuvj420p), which some players show washed out.
    const fit = b.card ? "" : `crop=iw:iw*${H}/${W}:0:(ih-oh)/2,`;
    graph.push(`[${i}:v]${fit}scale=${W}:${H}:flags=lanczos:out_range=tv,fps=${FPS},setsar=1,format=yuv420p,setpts=PTS-STARTPTS[v${i}]`);
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
  rmSync(tmp, { recursive: true, force: true });
}
