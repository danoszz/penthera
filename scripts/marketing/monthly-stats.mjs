#!/usr/bin/env node
/**
 * Monthly stats issue: "Penthera this month: <Month YYYY>".
 *
 *   node scripts/marketing/monthly-stats.mjs --repo owner/name [--month 2026-09] [--dry-run]
 *
 * Public endpoints only, read without cookies or tracking: npm downloads
 * (api.npmjs.org), stars, forks and merged PRs (GitHub API), skills.sh
 * installs and dependent repositories (their public pages, parsed strictly; a
 * number that does not parse is left out, never guessed). Month-over-month
 * deltas come from the hidden JSON in the previous stats issue, so there is no
 * state file. Fetchers are injected for tests (tests/marketing.test.js).
 */
import { spawnSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";

export const LABEL = "monthly-stats";
export const DATA_MARKER = "penthera-stats";
export const PACKAGE = "penthera";
export const SKILL_PATH = "danoszz/penthera/penthera";
const REPO_URL = "https://github.com/danoszz/penthera";

/** "2026-09" → { start: "2026-09-01", end: "2026-09-30", label: "September 2026" }. */
export function monthRange(month) {
  const m = /^(\d{4})-(\d{2})$/.exec(month);
  if (!m) throw new Error(`--month must look like 2026-09, got "${month}"`);
  const y = Number(m[1]), mo = Number(m[2]);
  const last = new Date(Date.UTC(y, mo, 0)).getUTCDate();
  const label = new Date(Date.UTC(y, mo - 1, 1)).toLocaleString("en-US", { month: "long", year: "numeric", timeZone: "UTC" });
  return { start: `${month}-01`, end: `${month}-${String(last).padStart(2, "0")}`, label };
}

/** The month before `now`, as "YYYY-MM" (UTC). */
export function previousMonth(now = new Date()) {
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
  return d.toISOString().slice(0, 7);
}

/** skills.sh skill page → install count, or null when the markup is not what we expect. */
export function parseSkillsInstalls(html) {
  const hits = [...String(html).matchAll(/<span>Installs<\/span><\/div>\s*<div[^>]*>\s*([\d,]+)\s*<\/div>/g)].map((m) => m[1]);
  if (hits.length === 0 || new Set(hits).size !== 1) return null;
  const n = Number(hits[0].replace(/,/g, ""));
  return Number.isSafeInteger(n) ? n : null;
}

/** GitHub network/dependents page → repository count, or null. */
export function parseDependents(html) {
  const m = String(html).replace(/\s+/g, " ").match(/<\/svg> ([\d,]+) Repositor(?:y|ies) <\/a>/);
  if (!m) return null;
  const n = Number(m[1].replace(/,/g, ""));
  return Number.isSafeInteger(n) ? n : null;
}

/** The JSON stats embedded in a previous issue body, or null. */
export function parsePrevious(body) {
  const m = String(body || "").match(new RegExp(`<!-- ${DATA_MARKER} (\\{.*?\\}) -->`));
  if (!m) return null;
  try { return JSON.parse(m[1]); } catch { return null; }
}

async function attempt(fn) {
  try {
    const v = await fn();
    return Number.isFinite(v) ? v : null;
  } catch {
    return null;
  }
}

/**
 * @param {{ month: string, repo: string, fetchJson(url): Promise<any>, fetchText(url): Promise<string>, gh(args: string[]): any }} io
 */
export async function collectStats({ month, repo, fetchJson, fetchText, gh }) {
  const { start, end } = monthRange(month);
  let repoInfo = null;
  try { repoInfo = gh(["api", `repos/${repo}`]); } catch { /* left as n/a */ }
  return {
    month,
    npmDownloads: await attempt(async () => (await fetchJson(`https://api.npmjs.org/downloads/point/${start}:${end}/${PACKAGE}`)).downloads),
    stars: repoInfo?.stargazers_count ?? null,
    forks: repoInfo?.forks_count ?? null,
    skillsInstalls: await attempt(async () => parseSkillsInstalls(await fetchText(`https://skills.sh/${SKILL_PATH}`))),
    dependents: await attempt(async () => parseDependents(await fetchText(`https://github.com/${repo}/network/dependents`))),
    prsMerged: await attempt(async () => gh(["api", "-X", "GET", "search/issues", "-f", `q=repo:${repo} is:pr is:merged merged:${start}..${end}`]).total_count),
  };
}

const ROWS = [
  ["npmDownloads", "npm downloads (month)"],
  ["stars", "GitHub stars"],
  ["forks", "Forks"],
  ["skillsInstalls", "skills.sh installs"],
  ["dependents", "Dependent repositories"],
  ["prsMerged", "PRs merged (month)"],
];

const fmt = (n) => (n == null ? "n/a" : n.toLocaleString("en-US"));
function delta(cur, prev) {
  if (cur == null || prev == null) return "–";
  const d = cur - prev;
  return d === 0 ? "±0" : `${d > 0 ? "+" : ""}${d.toLocaleString("en-US")}`;
}

export function draftPost(stats, prev) {
  const { label } = monthRange(stats.month);
  const bits = [];
  if (stats.npmDownloads != null) bits.push(`${fmt(stats.npmDownloads)} npm downloads`);
  if (stats.stars != null) bits.push(`${fmt(stats.stars)} stars${prev?.stars != null && stats.stars > prev.stars ? ` (+${fmt(stats.stars - prev.stars)})` : ""}`);
  if (stats.skillsInstalls != null) bits.push(`${fmt(stats.skillsInstalls)} skill installs`);
  if (stats.prsMerged) bits.push(`${fmt(stats.prsMerged)} PRs merged`);
  return [
    `Penthera in ${label}: ${bits.length ? bits.join(", ") : "another month of work"}.`,
    "",
    "What shipped: <one line per highlight from the CHANGELOG>",
    "",
    "Open-source security for the apps and AI systems you ship. Offline, no telemetry, MIT.",
    REPO_URL,
  ].join("\n");
}

export function formatIssue(stats, prev) {
  const { label } = monthRange(stats.month);
  const L = [
    `Public numbers for ${label}${prev ? `, compared with ${monthRange(prev.month).label}` : ""}.`,
    "",
    "| Metric | This month | Change |",
    "|--------|-----------:|-------:|",
    ...ROWS.map(([k, name]) => `| ${name} | ${fmt(stats[k])} | ${delta(stats[k], prev?.[k])} |`),
    "",
    "n/a means the source was unreachable or its page changed; the number is left out rather than guessed.",
    "",
    "### Draft post",
    "",
    "```text",
    draftPost(stats, prev),
    "```",
    "",
    "- [ ] Fill in what shipped, post it, close this issue",
    "",
    `<!-- ${DATA_MARKER} ${JSON.stringify(stats)} -->`,
  ];
  return { title: `Penthera this month: ${label}`, body: L.join("\n") };
}

/** Previous stats issue (most recent with the marker, for another month). */
export function findPrevious(issues, month) {
  return [...(issues || [])]
    .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))
    .map((i) => parsePrevious(i.body))
    .find((p) => p && p.month && p.month < month) || null;
}

export async function runMonthly({ repo, month, dryRun = false, fetchJson, fetchText, gh, log = console.log }) {
  const stats = await collectStats({ month, repo, fetchJson, fetchText, gh });
  const issues = gh(["api", `repos/${repo}/issues?labels=${LABEL}&state=all&per_page=24`]) || [];
  const prev = findPrevious(issues, month);
  const issue = formatIssue(stats, prev);
  if (issues.some((i) => i.title === issue.title)) {
    log(`"${issue.title}" already exists; nothing to do.`);
    return { issue, created: false };
  }
  if (dryRun) {
    log(`--- would open: ${issue.title}\n${issue.body}`);
    return { issue, created: false };
  }
  gh(["api", `repos/${repo}/issues`, "-X", "POST", "--input", "-"], { input: JSON.stringify({ ...issue, labels: [LABEL] }) });
  log(`Opened "${issue.title}".`);
  return { issue, created: true };
}

const UA = { "user-agent": "penthera-monthly-stats (+https://github.com/danoszz/penthera)" };
export const defaultFetchJson = async (url) => {
  const r = await fetch(url, { headers: UA, signal: AbortSignal.timeout(15_000) });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.json();
};
export const defaultFetchText = async (url) => {
  const r = await fetch(url, { headers: UA, signal: AbortSignal.timeout(15_000) });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.text();
};
export function ghCli({ run = spawnSync } = {}) {
  return (args, { input } = {}) => {
    const r = run("gh", args, { encoding: "utf-8", input });
    if (r.error) throw r.error;
    if (r.status !== 0) throw new Error(`gh ${args.slice(0, 3).join(" ")} failed: ${(r.stderr || "").trim()}`);
    return r.stdout.trim() ? JSON.parse(r.stdout) : null;
  };
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const { values } = parseArgs({
    options: {
      repo: { type: "string", default: process.env.GITHUB_REPOSITORY },
      month: { type: "string" },
      "dry-run": { type: "boolean", default: false },
    },
  });
  if (!values.repo) {
    console.error("Usage: monthly-stats.mjs --repo owner/name [--month YYYY-MM] [--dry-run]");
    process.exit(2);
  }
  const lines = [];
  const log = (s) => { console.log(s); lines.push(s); };
  try {
    await runMonthly({
      repo: values.repo, month: values.month || previousMonth(), dryRun: values["dry-run"],
      fetchJson: defaultFetchJson, fetchText: defaultFetchText, gh: ghCli(), log,
    });
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `## Monthly stats\n\n${lines.join("\n")}\n`);
}
