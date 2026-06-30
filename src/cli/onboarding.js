/**
 * PostHog-style interactive onboarding — simple defaults, advanced hidden.
 */
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { initPrompt, closePrompt, ask, choose, confirm, normalizeUrlInput } from "./prompt.js";
import { banner, box, bold, dim, cyan, green, yellow, hr, brand } from "./ansi.js";
import { executeScan, writeScanReports } from "./run-scan.js";
import { isPrivateHost } from "../utils/url.js";
import { printError } from "../reporter.js";

const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf-8"));

function countFindings(findings) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings || []) c[f.severity] = (c[f.severity] || 0) + 1;
  return c;
}

function summarize(findings) {
  const c = countFindings(findings);
  const parts = [];
  if (c.critical) parts.push(`${c.critical} critical`);
  if (c.high) parts.push(`${c.high} high`);
  if (c.medium) parts.push(`${c.medium} medium`);
  if (c.low) parts.push(`${c.low} low`);
  if (parts.length === 0) return green("No issues found — looking good!");
  return yellow(parts.join(" · "));
}

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function topFindings(findings, limit = 3) {
  return [...(findings || [])]
    .filter((f) => f.severity !== "info")
    .sort((a, b) => (SEV_RANK[a.severity] ?? 5) - (SEV_RANK[b.severity] ?? 5))
    .slice(0, limit);
}

function printTopFixes(findings) {
  const top = topFindings(findings);
  if (top.length === 0) return;
  process.stdout.write(`\n  ${bold("Start here")}\n`);
  top.forEach((f, i) => {
    process.stdout.write(`  ${i + 1}. ${f.title} ${dim(`(${f.severity})`)}\n`);
  });
}

async function runSimpleScan(config) {
  process.stdout.write(`\n  ${dim("Scanning")}${dim("...")}\n\n`);
  const result = await executeScan({ ...config, version: pkg.version });
  const paths = writeScanReports(
    { merged: result.merged },
    result.paths,
    result.mdOpts,
    { verbose: false, quiet: true, writeSarif: true },
  );
  return { ...result, paths };
}

function printScanFailure(url, err) {
  if (/unreachable/i.test(err.message)) {
    printError(`Couldn't reach ${url}. Is your app running?`);
    process.stdout.write(
      `\n  ${dim("Tip:")} start your dev server, then run ${bold("penthera")} again.\n\n`,
    );
    return;
  }
  printError(err.message);
}

export async function runOnboarding() {
  await initPrompt();

  process.stdout.write(banner());
  process.stdout.write(box("Welcome", [
    "Shipped something you vibecoded? Pressure-test it before attackers do.",
    "Penthera checks your live app + repo for the gaps that get apps owned —",
    "exposed APIs, missing headers, weak auth, leaked secrets.",
    "",
    dim("Only scan apps you own or have permission to test."),
  ]));
  process.stdout.write(
    `  ${dim("Expert?")} ${dim("skip the wizard with")} ${brand("penthera <url> --profile deep")} ${dim("· see")} ${brand("penthera --help")}\n\n`,
  );

  // ── Step 1: URL (required) ─────────────────────────────────────────────
  process.stdout.write(`  ${bold("Step 1")}  ${dim("Where is your app running?")}\n\n`);
  const urlRaw = await ask(`  ${cyan(">")} URL ${dim("(e.g. https://myapp.com or localhost:3000)")}: `);
  const url = normalizeUrlInput(urlRaw);

  if (!url) {
    printError("A URL is required. Example: localhost:3000 or https://staging.myapp.com");
    closePrompt();
    process.exit(2);
  }

  // ── Step 2: Source code (optional, default yes if package.json) ────────
  const hasProject = existsSync(resolve("package.json"));
  let repo = null;

  if (hasProject) {
    process.stdout.write(`\n  ${bold("Step 2")}  ${dim("Scan your source code too?")}\n`);
    process.stdout.write(`  ${dim("Finds hardcoded secrets and risky API routes in this folder.")}\n\n`);
    const scanRepo = await confirm(`  ${cyan(">")} Scan ./`, true);
    if (scanRepo) repo = ".";
  } else {
    process.stdout.write(`\n  ${dim("Step 2 skipped — no package.json in current folder.")}\n`);
  }

  // ── Permission check for remote targets ────────────────────────────────
  if (!isPrivateHost(url)) {
    process.stdout.write(`\n  ${yellow("Note")}  ${dim("We'll send safe checks to")} ${cyan(url)}\n`);
    process.stdout.write(`  ${dim("No attack payloads in the default scan.")}\n\n`);
    const ok = await confirm(`  ${cyan(">")} You have permission to scan this URL`, true);
    if (!ok) {
      process.stdout.write(`\n  ${dim("Aborted.")}\n\n`);
      closePrompt();
      process.exit(0);
    }
  }

  closePrompt();

  // ── Run default scan (standard profile) ────────────────────────────────
  let scanResult;
  try {
    scanResult = await runSimpleScan({ url, repo, profile: "standard" });
  } catch (e) {
    printScanFailure(url, e);
    process.exit(2);
  }

  const { merged, paths, hasSevere } = scanResult;

  process.stdout.write(`\n  ${hr()}\n`);
  process.stdout.write(`  ${green("Done!")}  ${summarize(merged.findings)}\n`);
  printTopFixes(merged.findings);
  process.stdout.write(`\n  ${bold("Read your report")}\n`);
  process.stdout.write(`  ${cyan(paths.markdown)}  ${dim("← start here (plain English)")}\n`);
  process.stdout.write(`  ${dim(paths.json)}  ${dim("(machine-readable)")}\n`);
  process.stdout.write(`\n  ${hr()}\n`);

  // ── Post-scan menu (re-open prompt) ────────────────────────────────────
  await initPrompt();

  const next = await choose("What next?", [
    { id: "done", label: "Looks good — I'm done" },
    { id: "deeper", label: "Run a deeper scan (sends test payloads — needs permission)" },
    { id: "custom", label: "Custom setup (profiles, auth tokens, advanced flags)" },
  ]);

  if (next === "done") {
    closePrompt();
    process.stdout.write(`\n  ${dim("Tip:")} re-run anytime with ${bold("penthera")} or ${bold("penthera <url>")}\n\n`);
    process.exit(hasSevere ? 1 : 0);
  }

  if (next === "deeper") {
    process.stdout.write(`\n  ${yellow("Deep scan")} sends SQLi, XSS, and fuzz payloads.\n`);
    const ok = await confirm(`  ${cyan(">")} I have permission to run destructive tests`, false);
    closePrompt();
    if (!ok) {
      process.stdout.write(`\n  ${dim("Skipped deep scan.")}\n\n`);
      process.exit(hasSevere ? 1 : 0);
    }

    try {
      const deep = await runSimpleScan({ url, repo, profile: "deep" });
      process.stdout.write(`\n  ${green("Deep scan complete.")}  ${summarize(deep.merged.findings)}\n`);
      process.stdout.write(`  ${cyan(deep.paths.markdown)}\n\n`);
      process.exit(deep.hasSevere ? 1 : 0);
    } catch (e) {
      printScanFailure(url, e);
      process.exit(2);
    }
  }

  // ── Custom setup (hidden power-user path) ──────────────────────────────
  process.stdout.write(box("Custom setup", [
    "Power-user options. Most people never need this.",
    dim("Press enter to keep defaults shown in [brackets]."),
  ]));

  const profileAns = await ask(`  Profile ${dim("[standard]")} quick | standard | deep: `);
  const profile = ["quick", "standard", "deep"].includes(profileAns) ? profileAns : "standard";

  const repoAns = await ask(`  Repo path ${dim("[.]")}: `);
  const customRepo = repoAns || repo || null;

  const bearer = await ask(`  Bearer token ${dim("(optional, for logged-in routes)")}: `);
  const cookie = await ask(`  Session cookie ${dim("(optional)")}: `);

  const customUrl = await ask(`  URL ${dim(`[${url}]`)}: `);
  closePrompt();

  try {
    const custom = await runSimpleScan({
      url: customUrl || url,
      repo: customRepo,
      profile,
      authBearer: bearer || null,
      authCookie: cookie || null,
    });
    process.stdout.write(`\n  ${green("Custom scan complete.")}  ${summarize(custom.merged.findings)}\n`);
    process.stdout.write(`  ${cyan(custom.paths.markdown)}\n\n`);
    process.stdout.write(`  ${dim("Expert mode:")} penthera --help\n\n`);
    process.exit(custom.hasSevere ? 1 : 0);
  } catch (e) {
    printScanFailure(customUrl || url, e);
    process.exit(2);
  }
}
