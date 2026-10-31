#!/usr/bin/env node
/**
 * Render the homepage film, site/media/film.mp4, from scripts/media/film/film.html.
 *
 *   FILM_DIR=<folder> node scripts/media/film/render.mjs
 *
 * film.html is a timeline: window.render(t) draws any moment, so a frame never
 * depends on the one before it. FILM_DIR holds what the film shows: s3-verdict.png
 * and s4-first.png (real dashboard shots), rects.json, lines.json (real terminal
 * output), logo.svg and the font. Real output on a demo app, on the released
 * version; illustration scenes carry no numbers. Motion values and their sources
 * are in private/brand/motion.md.
 *
 * Needs Chrome, ffmpeg and playwright-core (PLAYWRIGHT_ROOT: a folder that has it).
 */
/* global document, window */
import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const { chromium } = createRequire(`${process.env.PLAYWRIGHT_ROOT || process.cwd()}/`)("playwright-core");
const DIR = process.env.FILM_DIR, HERE = import.meta.dirname, DUR = 30, FPS = 30;
const CHROME = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

const b = await chromium.launch({ executablePath: CHROME, headless: true, args: ["--headless=new"] });
const p = await b.newPage({ viewport: { width: 1600, height: 900 } });
const html = readFileSync(join(HERE, "film.html"), "utf8").replace('JSON.parse(document.currentScript.dataset.r || "{}")', readFileSync(join(DIR, "rects.json"), "utf8"));
writeFileSync(join(DIR, "_film.html"), html);
await p.goto(`file://${join(DIR, "_film.html")}`, { waitUntil: "load" });
await p.evaluate(() => document.fonts.ready);
await p.evaluate((l) => window.setup(l), JSON.parse(readFileSync(join(DIR, "lines.json"), "utf8")));
const out = spawn("ffmpeg", ["-y", "-f", "image2pipe", "-framerate", String(FPS), "-i", "-", "-c:v", "libx264", "-preset", "slow", "-crf", "16", "-pix_fmt", "yuv420p", "-movflags", "+faststart", "-an", join(DIR, "film.mp4")], { stdio: ["pipe", "ignore", "ignore"] });
for (let i = 0; i < DUR * FPS; i++) {
  await p.evaluate((t) => window.render(t), i / FPS);
  if (!out.stdin.write(await p.screenshot({ type: "jpeg", quality: 95 }))) await new Promise((r) => out.stdin.once("drain", r));
}
out.stdin.end();
await new Promise((r) => out.on("close", r));
await b.close();
