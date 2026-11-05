#!/usr/bin/env node
/**
 * Figures for the two benchmark posts in blog/, drawn from data in the repo:
 *
 *   secrets-precision-recall.svg  every tool on the CredData test half, precision
 *                                 against recall with 95% Wilson intervals
 *                                 (bench/public/published.json)
 *   dev-to-test.svg               Penthera's score per benchmark on the dev half
 *                                 after tuning, and on the sealed test half in both
 *                                 final runs (bench/public/RESULTS.md, "Dev to test"
 *                                 and "Both test runs")
 *
 *   node blog/figures/make.mjs           write both SVGs
 *   node blog/figures/make.mjs --check   exit 1 if either is stale
 *
 * No number is typed in here: each comes from those two files, and the script
 * fails if the text it reads is not there.
 *
 * Figure style (the /benchmarks scoreboard's, on the paper pages):
 * - A paper plate (an explicit rect, also in dark mode) with a 1 px ink frame,
 *   ink text, Helvetica Neue with a tight, medium title. No shadows or gradients.
 * - Thin plot frame at 25% ink, very light grid, ticks at round values, axis
 *   titles in plain words with units.
 * - Direct labels next to the marks instead of a legend where possible.
 * - Uncertainty as thin 95% whiskers wherever the data has an interval.
 * - Reference lines dashed, thin, labelled at the edge in grey.
 * - Two hues only, as on the scoreboard: Penthera in #0000ED, #7A7AFF for a
 *   secondary Penthera series, the rest in ink and greys. Colour is never the
 *   only cue: hollow marks and squares carry it too.
 * - 640 wide, type sized to stay readable at 358 px on a phone; caption and alt
 *   text in the page.
 */
import { readFileSync, writeFileSync } from "node:fs";

const ROOT = new URL("../../", import.meta.url);
const read = (p) => readFileSync(new URL(p, ROOT), "utf8");
const pub = JSON.parse(read("bench/public/published.json"));
const results = read("bench/public/RESULTS.md");

const C = { blue: "#0000ED", light: "#7A7AFF", tool: "#3a3d42", mid: "#8c8c8c", pale: "#bfbfbf", ink: "#12151a", ink2: "#3a3d42", edge: "#6b6e73", ref: "#b3b3b3", frame: "#bfbfbf", grid: "#ebebe6", bg: "#fdfdfa" };
const FONT = `font-family="'Helvetica Neue', Helvetica, Arial, sans-serif"`;
const TITLE = `font-size="21" font-weight="500" letter-spacing="-0.4"`;
const plate = (W, H) => `<rect x="0.5" y="0.5" width="${W - 1}" height="${H - 1}" fill="${C.bg}" stroke="${C.ink}"/>`;
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;");
const f2 = (v) => v.toFixed(2);

// ── Figure 1: precision against recall on CredData ──────────────────────────

function precisionRecall() {
  const b = pub.benchmarks.secrets;
  const rows = b.rows.filter((r) => r.p != null && r.r != null && r.precisionCI && r.recallCI);
  const W = 640, H = 590, L = 66, R = 18, T = 50, B = 84;
  const pw = W - L - R, ph = H - T - B;
  const X = (r) => L + r * pw;
  const Y = (p) => T + (1 - p) * ph;
  const name = (r) => (r.kind === "penthera" ? `Penthera ${r.version}` : r.kind === "penthera-before" ? `Penthera ${r.version}, before` : r.tool);
  const out = [];
  out.push(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-labelledby="t d" ${FONT}>`);
  out.push(`<title id="t">Secret scanners on the CredData test half: precision against recall</title>`);
  out.push(`<desc id="d">Scatter of ${rows.length} results on ${b.n.toLocaleString("en-US")} labelled secrets, recall on the x axis and precision on the y axis, each with 95% Wilson intervals. ${rows.map((r) => `${name(r)}: precision ${f2(r.p)}, recall ${f2(r.r)}${r.rank ? `, rank ${r.rank}` : ", not ranked"}`).join("; ")}. Dashed curves mark equal F1.</desc>`);
  out.push(plate(W, H));
  out.push(`<text x="16" y="32" ${TITLE} fill="${C.ink}">Secret scanners on the sealed CredData test half</text>`);
  for (let t = 0; t <= 10; t += 2) {
    const v = t / 10;
    out.push(`<line x1="${X(v)}" y1="${T}" x2="${X(v)}" y2="${T + ph}" stroke="${C.grid}"/><text x="${X(v)}" y="${T + ph + 18}" font-size="15" fill="${C.ink2}" text-anchor="middle">${v.toFixed(1)}</text>`);
    out.push(`<line x1="${L}" y1="${Y(v)}" x2="${L + pw}" y2="${Y(v)}" stroke="${C.grid}"/><text x="${L - 8}" y="${Y(v) + 4.5}" font-size="15" fill="${C.ink2}" text-anchor="end">${v.toFixed(1)}</text>`);
  }
  out.push(`<rect x="${L}" y="${T}" width="${pw}" height="${ph}" fill="none" stroke="${C.frame}"/>`);
  out.push(`<text x="${L + pw / 2}" y="${H - 32}" font-size="16" fill="${C.ink2}" text-anchor="middle">Recall (share of the ${b.n.toLocaleString("en-US")} labelled secrets reported)</text>`);
  out.push(`<text transform="translate(22 ${T + ph / 2}) rotate(-90)" font-size="16" fill="${C.ink2}" text-anchor="middle">Precision (share of reports that were real)</text>`);
  // F1 reference curves: p = f r / (2 r - f), for r > f / 2
  for (const f of [0.2, 0.4, 0.6, 0.8]) {
    const pts = [];
    for (let r = f / 2 + 0.004; r <= 1.0001; r += 0.004) {
      const p = (f * r) / (2 * r - f);
      if (p <= 1) pts.push(`${X(r).toFixed(1)},${Y(p).toFixed(1)}`);
    }
    out.push(`<polyline points="${pts.join(" ")}" fill="none" stroke="${C.ref}" stroke-width="0.8" stroke-dasharray="3 3"/>`);
    out.push(`<text x="${X(1) - 3}" y="${Y(f / (2 - f)) - 7}" font-size="13.5" fill="${C.edge}" text-anchor="end">F1 = ${f.toFixed(1)}</text>`);
  }
  // Label offsets keep names off each other and off the whiskers.
  const offset = { deepsecrets: [8, -8, "start"], noseyparker: [-8, 17, "end"], gitleaks: [-8, -8, "end"], kingfisher: [8, -7, "start"], ripsecrets: [8, 16, "start"], secretlint: [-8, -8, "end"], "detect-secrets": [8, 16, "start"], whispers: [8, -8, "start"], trufflehog: [8, 16, "start"], credsweeper: [-8, 17, "end"] };
  const order = [...rows].sort((a, z) => (a.kind === "penthera") - (z.kind === "penthera"));
  for (const r of order) {
    const col = r.kind === "penthera" ? C.blue : r.kind === "penthera-before" ? C.ink : r.rank != null ? C.tool : C.mid;
    const hollow = r.rank == null;
    const [rx0, rx1] = r.recallCI, [py0, py1] = r.precisionCI;
    out.push(`<g><title>${esc(name(r))}: precision ${f2(r.p)} (${f2(py0)} to ${f2(py1)}), recall ${f2(r.r)} (${f2(rx0)} to ${f2(rx1)}), F1 ${f2(r.f1)}${r.rank ? `, rank ${r.rank}` : ", not ranked"}</title>`);
    out.push(`<line x1="${X(rx0).toFixed(1)}" y1="${Y(r.p).toFixed(1)}" x2="${X(rx1).toFixed(1)}" y2="${Y(r.p).toFixed(1)}" stroke="${col}" stroke-width="1"/>`);
    out.push(`<line x1="${X(r.r).toFixed(1)}" y1="${Y(py0).toFixed(1)}" x2="${X(r.r).toFixed(1)}" y2="${Y(py1).toFixed(1)}" stroke="${col}" stroke-width="1"/>`);
    const cx = X(r.r).toFixed(1), cy = Y(r.p).toFixed(1);
    out.push(r.kind === "penthera" || r.kind === "penthera-before"
      ? `<rect x="${(X(r.r) - 5.5).toFixed(1)}" y="${(Y(r.p) - 5.5).toFixed(1)}" width="11" height="11" fill="${hollow ? C.bg : col}" stroke="${col}" stroke-width="1.5"/></g>`
      : `<circle cx="${cx}" cy="${cy}" r="5" fill="${hollow ? C.bg : col}" stroke="${col}" stroke-width="1.5"/></g>`);
    const [dx, dy, anchor] = r.kind === "penthera" ? [-17, 5, "end"] : r.kind === "penthera-before" ? [9, -9, "start"] : offset[r.tool] || [8, -8, "start"];
    const label = r.rank == null ? (r.kind === "penthera-before" ? name(r) : `${name(r)}, not ranked`) : `${name(r)} (${r.rank})`;
    const ink = r.kind === "penthera" ? C.blue : C.ink2;
    out.push(`<text x="${(X(r.r) + dx).toFixed(1)}" y="${(Y(r.p) + dy).toFixed(1)}" font-size="15" fill="${ink}" text-anchor="${anchor}"${r.kind === "penthera" ? ' font-weight="bold"' : ""}>${esc(label)}</text>`);
  }
  out.push(`<text x="16" y="${H - 12}" font-size="13.5" fill="${C.edge}">n = ${b.n.toLocaleString("en-US")} secrets, test half, ${esc(pub.date)}. (k): rank by F1. Data: bench/public/published.json</text>`);
  out.push(`</svg>`);
  return `${out.join("\n")}\n`;
}

// ── Figure 2: dev half against the sealed test half ─────────────────────────

function devToTest() {
  const line = results.replace(/\s+/g, " ").match(/\*\*Dev to test:\*\* (secrets F1 .+? to \d\.\d\d)\. The test numbers/);
  if (!line) throw new Error('bench/public/RESULTS.md has no "Dev to test:" line');
  const dev = Object.fromEntries([...line[1].matchAll(/(secrets F1|SecBench\.js|npm|PyPI) (\d\.\d\d) to (\d\.\d\d)/g)].map((m) => [m[1], { dev: +m[2], test: +m[3] }]));
  const table = {};
  for (const [label, key] of [["Secrets F1", "secrets F1"], ["npm, caught minus false alarms", "npm"], ["PyPI, caught minus false alarms", "PyPI"], ["SecBench.js, found", "SecBench.js"]]) {
    const m = results.match(new RegExp(`\\| ${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} \\| (\\d\\.\\d\\d) \\| (\\d\\.\\d\\d) \\|`));
    if (!m) throw new Error(`bench/public/RESULTS.md "Both test runs" has no row "${label}"`);
    table[key] = { r1: +m[1], r2: +m[2] };
  }
  const items = [
    ["secrets F1", "Secrets, F1"],
    ["SecBench.js", "JS injection, share found"],
    ["npm", "npm malware, Youden's J"],
    ["PyPI", "PyPI malware, Youden's J"],
  ].map(([k, label]) => {
    if (!dev[k]) throw new Error(`"Dev to test" has no ${k}`);
    if (dev[k].test !== table[k].r2) throw new Error(`${k}: "Dev to test" says ${dev[k].test}, the test-run table ${table[k].r2}`);
    return { label, ...dev[k], ...table[k] };
  });
  const W = 640, L = 222, R = 24, T = 92, rowH = 64, H = T + items.length * rowH + 80;
  const lo = 0.5, hi = 1.0;
  const X = (v) => L + ((v - lo) / (hi - lo)) * (W - L - R);
  const yEnd = T + items.length * rowH - 22;
  const out = [];
  out.push(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-labelledby="t d" ${FONT}>`);
  out.push(`<title id="t">Penthera's score on the tuned dev half and the sealed test half</title>`);
  out.push(`<desc id="d">For four benchmarks, Penthera's score on the dev half after tuning, and on the sealed test half in final run 1 and final run 2. ${items.map((i) => `${i.label}: dev ${f2(i.dev)}, test run 1 ${f2(i.r1)}, test run 2 ${f2(i.r2)}`).join("; ")}. Every test score is below its dev score.</desc>`);
  out.push(plate(W, H));
  out.push(`<text x="12" y="32" ${TITLE} fill="${C.ink}">Penthera on the half it was tuned on, and on the sealed half</text>`);
  for (let k = 0; k <= 5; k++) {
    const v = lo + k * 0.1;
    out.push(`<line x1="${X(v)}" y1="${T - 26}" x2="${X(v)}" y2="${yEnd}" stroke="${C.grid}"/><text x="${X(v)}" y="${yEnd + 17}" font-size="15" fill="${C.ink2}" text-anchor="middle">${v.toFixed(1)}</text>`);
  }
  out.push(`<rect x="${L}" y="${T - 26}" width="${W - L - R}" height="${yEnd - T + 26}" fill="none" stroke="${C.frame}"/>`);
  out.push(`<text x="${L + (W - L - R) / 2}" y="${yEnd + 34}" font-size="16" fill="${C.ink2}" text-anchor="middle">Score, 0 to 1 (axis starts at 0.5)</text>`);
  items.forEach((i, n) => {
    const y = T + n * rowH;
    out.push(`<text x="16" y="${y + 5}" font-size="16" fill="${C.ink}">${esc(i.label)}</text>`);
    out.push(`<line x1="${X(i.r2)}" y1="${y}" x2="${X(i.dev)}" y2="${y}" stroke="${C.pale}" stroke-width="1"/>`);
    out.push(`<g><title>${esc(i.label)}: dev ${f2(i.dev)}, test run 1 ${f2(i.r1)}, test run 2 ${f2(i.r2)}</title>${mark(X(i.dev), y, "dev")}${mark(X(i.r1), y, "r1")}${mark(X(i.r2), y, "r2")}</g>`);
    const same = i.r1 === i.r2;
    // Direct labels: test values left of the marks, dev values right, run 1 above.
    // The first row (and the first row where run 1 differs) also names the mark.
    const firstSplit = items.findIndex((j) => j.r1 !== j.r2) === n;
    const tag = (x, t, dx, dy, col, anchor) => `<text x="${(x + dx).toFixed(1)}" y="${y + dy}" font-size="15" fill="${col}" text-anchor="${anchor}">${t}</text>`;
    out.push(tag(X(i.r2), f2(i.r2), 0, 22, C.blue, "middle"));
    if (n === 0) out.push(tag(X(Math.min(i.r1, i.r2)), same ? "test, runs 1 and 2" : "test, run 2", -10, 4, C.blue, "end"));
    if (!same) out.push(tag(X(i.r1), `${firstSplit ? "run 1: " : ""}${f2(i.r1)}`, 0, -11, C.ink2, "middle"));
    out.push(tag(X(i.dev), `${f2(i.dev)}${n === 0 ? " dev" : ""}`, 10, 4, C.ink2, "start"));
  });
  out.push(`<text x="16" y="${H - 30}" font-size="13.5" fill="${C.edge}">Square: dev half, tuned. Dot: test, run 2. Ring: test, run 1.</text>`);
  out.push(`<text x="16" y="${H - 12}" font-size="13.5" fill="${C.edge}">Data: bench/public/RESULTS.md, ${esc(pub.date)}</text>`);
  out.push(`</svg>`);
  return `${out.join("\n")}\n`;
}

function mark(x, y, k) {
  if (k === "dev") return `<rect x="${(x - 4.5).toFixed(1)}" y="${y - 4.5}" width="9" height="9" fill="${C.light}"/>`;
  if (k === "r1") return `<circle cx="${x.toFixed(1)}" cy="${y}" r="6.5" fill="none" stroke="${C.mid}" stroke-width="1.5"/>`;
  return `<circle cx="${x.toFixed(1)}" cy="${y}" r="4" fill="${C.blue}"/>`;
}

// ── Figures 3 to 5: A Practical Guide to Security for 2027 ──────────────────
// No data here: the text follows docs/security-guide-2027.md, step by step.

const MONO = `font-family="ui-monospace, 'SF Mono', Menlo, monospace"`;
const svgOpen = (W, H, title, desc) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-labelledby="t d" ${FONT}>\n<title id="t">${esc(title)}</title>\n<desc id="d">${esc(desc)}</desc>\n${plate(W, H)}`;
const tagBox = (x, y, t, fill, ink) => `<rect x="${x}" y="${y}" width="${t.length * 8 + 14}" height="20" fill="${fill}"/><text x="${x + 7}" y="${y + 14.5}" font-size="13" ${MONO} fill="${ink}">${esc(t)}</text>`;

function attackMap() {
  const cells = [
    [0, 0, "Step 1", "Public domains", ["previews and staging too"]],
    [1, 0, "Step 2", "Keys in git", ["committed and pushed"]],
    [2, 0, "Step 3", "Agent config", ["skills, MCP servers,", "extensions"]],
    [0, 1, "Step 8", "Long-lived keys", ["keys that never expire"]],
    [2, 1, "Steps 4 and 5", "New packages", ["what an agent installs"]],
    [0, 2, "Step 9", "Accounts, laptops", ["logins, sessions, devices"]],
    [2, 2, "Steps 6 and 7", "CI and workflows", ["what runs on every push"]],
  ];
  const W = 640, L = 16, T = 56, gap = 8, cw = (W - 2 * L - 2 * gap) / 3, ch = 104, H = T + 3 * ch + 2 * gap + 40;
  const out = [svgOpen(W, H, "Where attacks come in for a small team", `Your team of 2 to 10 people in the middle, with the seven ways in around it and the guide step for each: ${cells.map((c) => `${c[3]} (${c[2]})`).join(", ")}.`)];
  out.push(`<text x="${L}" y="34" ${TITLE} fill="${C.ink}">Where attacks come in for a small team</text>`);
  for (const [cx, cy, tag, title, sub] of cells) {
    const x = L + cx * (cw + gap), y = T + cy * (ch + gap);
    out.push(`<rect x="${x}" y="${y}" width="${cw}" height="${ch}" fill="none" stroke="${C.frame}"/>`);
    out.push(tagBox(x + 12, y + 12, tag, C.grid, C.ink2));
    out.push(`<text x="${x + 12}" y="${y + 56}" font-size="17" font-weight="500" fill="${C.ink}">${esc(title)}</text>`);
    sub.forEach((s, i) => out.push(`<text x="${x + 12}" y="${y + 78 + i * 17}" font-size="14" fill="${C.edge}">${esc(s)}</text>`));
  }
  const x = L + cw + gap, y = T + ch + gap;
  out.push(`<rect x="${x}" y="${y}" width="${cw}" height="${ch}" fill="${C.blue}"/>`);
  out.push(`<text x="${x + 12}" y="${y + 40}" font-size="21" font-weight="500" letter-spacing="-0.4" fill="#fff">Your team</text>`);
  ["2 to 10 people, building", "with coding agents"].forEach((s, i) => out.push(`<text x="${x + 12}" y="${y + 66 + i * 18}" font-size="14.5" fill="#fff">${s}</text>`));
  out.push(`<text x="${L}" y="${H - 14}" font-size="13.5" fill="${C.edge}">Each box names the step in the guide that covers it.</text>`);
  out.push(`</svg>`);
  return `${out.join("\n")}\n`;
}

const STEPS = ["Know what you expose", "Keep secrets out of git", "Audit what your agents load", "Look before you install", "Know what your packages can do", "Put the checks in CI", "Harden your workflows", "Retire long-lived keys", "Lock down accounts and devices", "Log it and plan the bad day"];
const nn = (i) => String(i + 1).padStart(2, "0");

function weekVs30() {
  const W = 640, L = 16, T = 56, gap = 8, cw = (W - 2 * L - gap) / 2, rowH = 40, H = T + 48 + 5 * rowH + 44;
  const out = [svgOpen(W, H, "This week and the next 30 days", `The ten steps in two columns. This week: ${STEPS.slice(0, 5).join(", ")}. The next 30 days: ${STEPS.slice(5).join(", ")}.`)];
  out.push(`<text x="${L}" y="34" ${TITLE} fill="${C.ink}">This week, and the next 30 days</text>`);
  [["This week", 0, C.blue, "#fff"], ["Next 30 days", 5, C.grid, C.ink2]].forEach(([label, from, fill, ink], col) => {
    const x = L + col * (cw + gap);
    out.push(`<rect x="${x}" y="${T}" width="${cw}" height="${48 + 5 * rowH + 8}" fill="none" stroke="${col ? C.frame : C.blue}"/>`);
    out.push(tagBox(x + 12, T + 14, label, fill, ink));
    STEPS.slice(from, from + 5).forEach((s, i) => {
      const y = T + 48 + i * rowH + 24;
      out.push(`<text x="${x + 12}" y="${y}" font-size="14" ${MONO} fill="${col ? C.edge : C.blue}">${nn(from + i)}</text><text x="${x + 44}" y="${y}" font-size="16" fill="${C.ink}">${esc(s)}</text>`);
    });
  });
  out.push(`<text x="${L}" y="${H - 14}" font-size="13.5" fill="${C.edge}">Five steps for this week, five for the month after.</text>`);
  out.push(`</svg>`);
  return `${out.join("\n")}\n`;
}

function commands() {
  const rows = [
    ["<url> · MCP scan_url", "Doesn't log in"],
    ["hook install · --repo .", "Your repo, not your laptop"],
    ["agents · agents --pin", "No editor extensions yet"],
    ["install <pkg>", "No release-age check"],
    ["deps", "No CVE lookup"],
    ["init · the GitHub Action", "No lockfile-install check yet"],
    ["--repo . (workflows)", "Not reusable workflows in other files"],
    [null, ["Finds hardcoded keys", "Can't rotate them"]],
    [null, ["Not Penthera", "Identity provider, MDM, EDR"]],
    [null, ["Not Penthera", "Your platform's logs"]],
  ];
  const W = 640, L = 16, T = 74, rowH = 48, H = T + rowH * rows.length + 40;
  const out = [svgOpen(W, H, "Which command covers which step, and where Penthera stops", `For each of the ten steps, the Penthera command if there is one, and its limit. ${rows.map((r, i) => `${nn(i)} ${STEPS[i]}: ${r[0] ? `${r[0]}; ` : ""}${[].concat(r[1]).join("; ")}`).join(". ")}.`)];
  out.push(`<text x="${L}" y="34" ${TITLE} fill="${C.ink}">Which command covers which step, and where it stops</text>`);
  out.push(`<text x="${L}" y="58" font-size="13.5" ${MONO} fill="${C.edge}">Each command runs as npx penthera@2.3.1 …</text>`);
  rows.forEach(([cmd, limit], i) => {
    const y = T + i * rowH;
    if (i % 2 === 0) out.push(`<rect x="${L}" y="${y}" width="${W - 2 * L}" height="${rowH}" fill="${C.grid}" opacity="0.6"/>`);
    out.push(`<text x="${L + 10}" y="${y + 29}" font-size="14" ${MONO} fill="${C.edge}">${nn(i)}</text>`);
    out.push(`<text x="${L + 44}" y="${y + 29}" font-size="16" fill="${cmd || i < 8 ? C.ink : C.edge}">${esc(STEPS[i])}</text>`);
    if (cmd) {
      out.push(`<text x="${L + 324}" y="${y + 20}" font-size="13.5" ${MONO} fill="${C.blue}">${esc(cmd)}</text>`);
      out.push(`<text x="${L + 324}" y="${y + 38}" font-size="13.5" fill="${C.edge}">${esc(limit)}</text>`);
    } else {
      const [a, b] = limit;
      out.push(`<text x="${L + 324}" y="${y + 20}" font-size="13.5" fill="${C.ink2}">${esc(a)}</text>`);
      out.push(`<text x="${L + 324}" y="${y + 38}" font-size="13.5" fill="${C.edge}">${esc(b)}</text>`);
    }
  });
  out.push(`<text x="${L}" y="${H - 14}" font-size="13.5" fill="${C.edge}">Blue: the command. Grey: where it stops.</text>`);
  out.push(`</svg>`);
  return `${out.join("\n")}\n`;
}

const figures = {
  "blog/figures/secrets-precision-recall.svg": precisionRecall(),
  "blog/figures/dev-to-test.svg": devToTest(),
  "blog/figures/guide-2027-attack-map.svg": attackMap(),
  "blog/figures/guide-2027-week-vs-30.svg": weekVs30(),
  "blog/figures/guide-2027-commands.svg": commands(),
};
let stale = false;
for (const [path, svg] of Object.entries(figures)) {
  const url = new URL(path, ROOT);
  if (process.argv.includes("--check")) {
    let now = "";
    try { now = readFileSync(url, "utf8"); } catch {}
    if (now !== svg) { console.error(`${path} is stale: run node blog/figures/make.mjs`); stale = true; }
  } else {
    writeFileSync(url, svg);
    console.log(`wrote ${path}`);
  }
}
if (stale) process.exit(1);
