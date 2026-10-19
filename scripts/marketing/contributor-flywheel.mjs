#!/usr/bin/env node
/**
 * Contributor flywheel: when fewer than 3 issues labelled "good first issue"
 * are open, open (or update) one reminder issue that lists the
 * `TODO(good-first-issue)` markers in the code as candidates.
 *
 *   node scripts/marketing/contributor-flywheel.mjs --repo owner/name [--min 3] [--dry-run]
 *
 * Run by .github/workflows/contributor-flywheel.yml when an issue closes. To
 * add a candidate, write `TODO(good-first-issue): <what to do>` in a comment
 * next to the code it is about.
 */
import { spawnSync } from "node:child_process";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";

export const GFI_LABEL = "good first issue";
export const LABEL = "contributor-flywheel";
export const TITLE = "Maintainer: turn a few TODOs into good first issues";
export const MARKER = "<!-- penthera-flywheel -->";
const TAG = "TODO(good-first-issue)";

/** Parse `git grep -n` output into { file, line, text }. */
export function parseMarkers(grepOutput) {
  const out = [];
  for (const row of String(grepOutput).split("\n")) {
    const m = row.match(/^(.+?):(\d+):(.*)$/);
    if (!m || !m[3].includes(TAG)) continue;
    const text = m[3].slice(m[3].indexOf(TAG) + TAG.length).replace(/^[:\s-]+/, "").replace(/\s*\*\/\s*$/, "").replace(/[<>]/g, "").trim();
    out.push({ file: m[1], line: Number(m[2]), text });
  }
  return out;
}

export function findMarkers({ run = spawnSync, cwd = process.cwd() } = {}) {
  const r = run("git", ["grep", "-n", "-I", "--fixed-strings", TAG, "--", ".", ":!tests/fixtures", ":!*.md", ":!scripts/marketing/contributor-flywheel.mjs"], { cwd, encoding: "utf-8" });
  if (r.status > 1 || r.error) throw new Error(`git grep failed: ${r.stderr || r.error}`);
  return parseMarkers(r.stdout || "");
}

export function reminderBody(markers, { open, min, repo, ref = "main" }) {
  const L = [
    MARKER,
    `Only ${open} open ${open === 1 ? "issue is" : "issues are"} labelled \`${GFI_LABEL}\` (target: ${min}). New contributors pick from that list, so keep it stocked.`,
    "",
  ];
  if (markers.length) {
    L.push("Candidates from `TODO(good-first-issue)` markers in the code:", "");
    for (const m of markers) L.push(`- [ ] [\`${m.file}:${m.line}\`](https://github.com/${repo}/blob/${ref}/${m.file}#L${m.line}): ${m.text.replace(/[\r\n]/g, " ")}`);
    L.push("", `Open an issue for one or two (label \`${GFI_LABEL}\`, say which file and how to test), then close this reminder.`);
  } else {
    L.push(`No \`TODO(good-first-issue)\` markers left in the code. Add a few next to small, well-scoped changes, or label an existing issue \`${GFI_LABEL}\`.`);
  }
  L.push("", "<sub>Updated by .github/workflows/contributor-flywheel.yml when an issue closes.</sub>");
  return L.join("\n");
}

export function runFlywheel({ gh, repo, min = 3, markers, dryRun = false, log = console.log }) {
  const open = (gh(["api", `repos/${repo}/issues?labels=${encodeURIComponent(GFI_LABEL)}&state=open&per_page=100`]) || [])
    .filter((i) => !i.pull_request).length;
  if (open >= min) {
    log(`${open} open good first issues (>= ${min}); nothing to do.`);
    return { action: "none", open };
  }
  const body = reminderBody(markers, { open, min, repo });
  const existing = (gh(["api", `repos/${repo}/issues?labels=${LABEL}&state=open&per_page=100`]) || [])
    .find((i) => String(i.body || "").includes(MARKER));
  const action = existing ? (existing.body === body ? "unchanged" : "updated") : "created";
  if (dryRun) {
    log(`--- would be ${action}: ${TITLE}\n${body}`);
    return { action, open, body };
  }
  if (action === "created") gh(["api", `repos/${repo}/issues`, "-X", "POST", "--input", "-"], { input: JSON.stringify({ title: TITLE, body, labels: [LABEL] }) });
  if (action === "updated") gh(["api", `repos/${repo}/issues/${existing.number}`, "-X", "PATCH", "--input", "-"], { input: JSON.stringify({ body }) });
  log(`Reminder ${action} (${open} open good first issues, ${markers.length} candidates).`);
  return { action, open, body };
}

function ghCli({ run = spawnSync } = {}) {
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
      min: { type: "string", default: "3" },
      "dry-run": { type: "boolean", default: false },
    },
  });
  if (!values.repo) {
    console.error("Usage: contributor-flywheel.mjs --repo owner/name [--min 3] [--dry-run]");
    process.exit(2);
  }
  try {
    runFlywheel({ gh: ghCli(), repo: values.repo, min: Number(values.min), markers: findMarkers(), dryRun: values["dry-run"] });
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}
