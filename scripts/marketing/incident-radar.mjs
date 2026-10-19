#!/usr/bin/env node
/**
 * Incident radar: turn new malware advisories from the public GitHub Advisory
 * Database into issues a person can act on (add IOCs, verify detection, post).
 *
 *   node scripts/marketing/incident-radar.mjs --repo owner/name [--since-hours 48] [--cap 5] [--mode notable|all] [--dry-run]
 *
 * State lives in the issues themselves: an advisory counts as seen when its
 * GHSA id appears in an `incident-radar` issue or in a radar comment updated
 * inside the look-back window. No state file, no branch, no extra token.
 *
 * mode "notable" (default) opens one issue per advisory that hits a popular
 * npm package (lib/deps/popular-packages.json) and rolls every other new
 * advisory into one standing batch issue as a comment. mode "all" opens one
 * issue per advisory. Either way at most `cap` issues per run.
 *
 * `gh` is injected so tests run without GitHub (tests/marketing.test.js).
 */
import { readFileSync, existsSync, appendFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";

export const LABEL = "incident-radar";
export const BATCH_TITLE = "Incident radar: other new malware advisories";
export const BATCH_MARKER = "<!-- incident-radar:batch -->";
export const ECOSYSTEMS = ["npm", "pip"];
const GHSA = /GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/gi;
const ECOSYSTEM_LABEL = { npm: "npm", pip: "PyPI" };

/** GHSA ids mentioned anywhere in the given texts, upper-cased. */
export function seenIds(texts) {
  const ids = new Set();
  for (const t of texts) for (const m of String(t || "").matchAll(GHSA)) ids.add(m[0].toUpperCase());
  return ids;
}

export function packagesOf(adv) {
  return (adv.vulnerabilities || []).map((v) => ({
    ecosystem: v.package?.ecosystem || "unknown",
    name: v.package?.name || "unknown",
    range: v.vulnerable_version_range || "unknown",
  }));
}

const uniqueNames = (pkgs) => [...new Set(pkgs.map((p) => p.name))];

export function isNotable(adv, popular) {
  return packagesOf(adv).some((p) => p.ecosystem === "npm" && popular.has(p.name));
}

/** Split new advisories into individual issues (at most `cap`) and the batch. */
export function plan(advisories, { seen, popular = new Set(), cap = 5, mode = "notable" }) {
  const unique = new Map();
  for (const a of advisories) {
    const id = String(a.ghsa_id || "").toUpperCase();
    if (id && !seen.has(id) && !a.withdrawn_at && !unique.has(id)) unique.set(id, a);
  }
  const fresh = [...unique.values()].sort((a, b) =>
    Number(isNotable(b, popular)) - Number(isNotable(a, popular)) || String(b.published_at).localeCompare(String(a.published_at)));
  const eligible = mode === "all" ? fresh : fresh.filter((a) => isNotable(a, popular));
  const individual = eligible.slice(0, cap);
  const picked = new Set(individual);
  return { individual, batch: fresh.filter((a) => !picked.has(a)) };
}

const tick = (s) => `\`${String(s).replace(/`/g, "'")}\``;
const cell = (s) => String(s).replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\n/g, " ");

export function issueTitle(adv) {
  const pkgs = packagesOf(adv);
  const all = uniqueNames(pkgs);
  const names = all.slice(0, 3).join(", ") + (all.length > 3 ? ", …" : "");
  const eco = [...new Set(pkgs.map((p) => ECOSYSTEM_LABEL[p.ecosystem] || p.ecosystem))].join("/");
  return `Incident radar: malware in ${names} (${eco}) · ${adv.ghsa_id}`;
}

/** Ready-to-paste "check if you're affected" post. */
export function draftPost(adv) {
  const pkgs = packagesOf(adv);
  const eco = ECOSYSTEM_LABEL[pkgs[0]?.ecosystem] || pkgs[0]?.ecosystem || "a registry";
  const names = uniqueNames(pkgs).join(", ");
  return [
    `Malicious code was published to ${eco} as ${names} (${adv.ghsa_id}). If it was installed, treat that machine as compromised and rotate its secrets.`,
    "",
    "Check if you're affected with one command, offline, no account:",
    "",
    "npx penthera deps .",
    "",
    adv.html_url,
  ].join("\n");
}

export function issueBody(adv, { rulesDir = false, notable = false } = {}) {
  const pkgs = packagesOf(adv);
  const L = [
    `**Advisory:** ${adv.html_url}`,
    `**Published:** ${adv.published_at || "unknown"} · **Severity:** ${adv.severity || "unknown"}${notable ? " · **Popular package**" : ""}`,
    "",
    `> ${cell(adv.summary || "")}`,
    "",
    "| Ecosystem | Package | Affected versions |",
    "|-----------|---------|-------------------|",
    ...pkgs.map((p) => `| ${cell(ECOSYSTEM_LABEL[p.ecosystem] || p.ecosystem)} | ${tick(p.name)} | ${tick(p.range)} |`),
    "",
    "### Checklist",
    "",
    rulesDir
      ? `- [ ] Add the IOCs (package names, versions, domains, hashes) to a rule pack in \`lib/rules/\``
      : "- [ ] Add the IOCs (package names, versions, domains, hashes) to the deps rules (no `lib/rules/` yet)",
    `- [ ] Verify \`penthera deps\` flags it: a fixture lockfile with ${uniqueNames(pkgs).map(tick).join(", ")} at an affected version`,
    "- [ ] Post the draft below (only after the box above is ticked), then close this issue",
    "",
    "### Draft post",
    "",
    "```text",
    draftPost(adv),
    "```",
    "",
    `<sub>Opened by .github/workflows/incident-radar.yml from the public GitHub Advisory Database. Nothing was posted anywhere.</sub>`,
  ];
  return L.join("\n");
}

export function batchComment(advs, { date }) {
  const L = [
    BATCH_MARKER,
    `### ${advs.length} new malware ${advs.length === 1 ? "advisory" : "advisories"} · ${date}`,
    "",
    "| Advisory | Ecosystem | Packages | Versions |",
    "|----------|-----------|----------|----------|",
  ];
  for (const a of advs) {
    const pkgs = packagesOf(a);
    L.push(`| [${a.ghsa_id}](${a.html_url}) | ${cell([...new Set(pkgs.map((p) => ECOSYSTEM_LABEL[p.ecosystem] || p.ecosystem))].join(", "))} | ${uniqueNames(pkgs).map(tick).join(", ")} | ${pkgs.map((p) => tick(p.range)).join(", ")} |`);
  }
  L.push("", "Most of these are typosquats nobody installs. If one turns out to matter, open an issue from it with the radar checklist.");
  return L.join("\n");
}

/** Default `gh` runner: `gh api ...` with JSON output, or null on 404-style failures for lookups. */
export function ghCli({ run = spawnSync } = {}) {
  return (args, { input } = {}) => {
    const r = run("gh", args, { encoding: "utf-8", input, maxBuffer: 64 * 1024 * 1024 });
    if (r.error) throw r.error;
    if (r.status !== 0) throw new Error(`gh ${args.slice(0, 3).join(" ")} failed: ${(r.stderr || "").trim()}`);
    const out = (r.stdout || "").trim();
    if (!out) return null;
    // --paginate prints one JSON array per page; join them.
    return JSON.parse(out.startsWith("[") ? `[${out.replace(/\]\s*\[/g, "],[")}]` : out);
  };
}

const flat = (x) => (Array.isArray(x) && x.every(Array.isArray) ? x.flat() : x ?? []);

export async function runRadar({ gh, repo, now = new Date(), sinceHours = 48, cap = 5, mode = "notable", dryRun = false, popular = new Set(), rulesDir = false, log = console.log }) {
  const since = new Date(now.getTime() - sinceHours * 3600_000).toISOString();
  const day = since.slice(0, 10);
  const advisories = [];
  for (const eco of ECOSYSTEMS) {
    advisories.push(...flat(gh(["api", "--paginate", `/advisories?type=malware&ecosystem=${eco}&published=>=${day}&per_page=100`])));
  }
  const recent = advisories.filter((a) => !a.published_at || a.published_at >= since);

  const issues = flat(gh(["api", "--paginate", `repos/${repo}/issues?labels=${LABEL}&state=all&since=${since}&per_page=100`]));
  const comments = flat(gh(["api", "--paginate", `repos/${repo}/issues/comments?since=${since}&per_page=100`]))
    .filter((c) => String(c.body || "").includes(BATCH_MARKER));
  const seen = seenIds([...issues.flatMap((i) => [i.title, i.body]), ...comments.map((c) => c.body)]);

  const { individual, batch } = plan(recent, { seen, popular, cap, mode });
  log(`${recent.length} advisories in the window, ${seen.size} already tracked, ${individual.length} new issues, ${batch.length} for the batch.`);

  const out = { individual: [], batch: null };
  for (const a of individual) {
    const title = issueTitle(a);
    const body = issueBody(a, { rulesDir, notable: isNotable(a, popular) });
    out.individual.push({ title, body });
    if (dryRun) { log(`\n--- would open: ${title}\n${body}`); continue; }
    gh(["api", `repos/${repo}/issues`, "-X", "POST", "--input", "-"], { input: JSON.stringify({ title, body, labels: [LABEL] }) });
  }
  if (batch.length) {
    const body = batchComment(batch, { date: now.toISOString().slice(0, 10) });
    out.batch = body;
    if (dryRun) log(`\n--- would add to "${BATCH_TITLE}":\n${body}`);
    else {
      const open = flat(gh(["api", `repos/${repo}/issues?labels=${LABEL}&state=open&per_page=100`]))
        .find((i) => i.title === BATCH_TITLE && !i.pull_request);
      const number = open?.number ?? gh(["api", `repos/${repo}/issues`, "-X", "POST", "--input", "-"], {
        input: JSON.stringify({ title: BATCH_TITLE, labels: [LABEL], body: "New malware advisories that did not get their own issue. One comment per run. Close it whenever; the next run opens a new one." }),
      }).number;
      gh(["api", `repos/${repo}/issues/${number}/comments`, "-X", "POST", "--input", "-"], { input: JSON.stringify({ body }) });
    }
  }
  return out;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const { values } = parseArgs({
    options: {
      repo: { type: "string", default: process.env.GITHUB_REPOSITORY },
      "since-hours": { type: "string", default: "48" },
      cap: { type: "string", default: "5" },
      mode: { type: "string", default: "notable" },
      "dry-run": { type: "boolean", default: false },
    },
  });
  if (!values.repo || !["notable", "all"].includes(values.mode)) {
    console.error("Usage: incident-radar.mjs --repo owner/name [--since-hours 48] [--cap 5] [--mode notable|all] [--dry-run]");
    process.exit(2);
  }
  const popularFile = new URL("../../lib/deps/popular-packages.json", import.meta.url);
  const popular = new Set(existsSync(popularFile) ? JSON.parse(readFileSync(popularFile, "utf-8")).names : []);
  const lines = [];
  const log = (s) => { console.log(s); lines.push(s); };
  try {
    await runRadar({
      gh: ghCli(), repo: values.repo, sinceHours: Number(values["since-hours"]), cap: Number(values.cap),
      mode: values.mode, dryRun: values["dry-run"], popular, rulesDir: existsSync(new URL("../../lib/rules/", import.meta.url)), log,
    });
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `## Incident radar\n\n\`\`\`text\n${lines.join("\n").replace(/```/g, "'''")}\n\`\`\`\n`);
}
