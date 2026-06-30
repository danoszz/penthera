/**
 * Penthera — CLI
 *
 * Argument parsing, dispatch to scanners, report output.
 */
import { parseArgs } from "node:util";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { scanUrl } from "./scan-url.js";
import { scanRepo } from "./scan-repo.js";
import { mergeResults } from "./cli/merge-results.js";
import { resolveScanOptions } from "./cli/profiles.js";
import { compareWithBaseline } from "./cli/baseline.js";
import { normalizeBaseUrl } from "./utils/url.js";
import { printReport, printFindings, writeJsonReport, writeSarifReport, createProgress, printError } from "./reporter.js";
import { writeMarkdownReport, markdownPathFromJson } from "./report/markdown.js";
import { parseTemplatePaths } from "../lib/plugins.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf-8"));

function shouldRunOnboarding(positionals, opts) {
  if (process.env.PENTHERA_NO_ONBOARDING) return false;
  if (positionals.length > 0) return false;
  if (opts.repo || opts.machine) return false;
  return process.stdin.isTTY && process.stdout.isTTY;
}

const HELP = `
  ${bold("penthera")} v${pkg.version} \u2014 lightweight security scanner

  ${dim("Usage")}
    $ penthera                        Interactive setup (TTY — no args needed)
    $ penthera <url>                 Scan a live URL (black-box)
    $ penthera --repo <path>         Scan a local repo (white-box)
    $ penthera <url> --repo <path>   Full scan (both)

  ${dim("Scan modes")}
        --profile <name>        quick | standard | deep (default: standard)
    ${dim("(default)")}                    TLS + fingerprint + discovery + templates + CORS
                               + cookies + Retire.js + param discovery + OpenAPI/auth
        --recon                 + OSINT recon (subdomains, historical URLs)
        --deep                  + Injection probes (SQLi, SSTI, SSRF, XSS, CMDi)
        --fuzz                  + Property-based API fuzzing
        --nuclei <path>         + Community Nuclei YAML templates (alias for --templates)
        --templates <paths>     Comma-separated dirs of Nuclei-compatible YAML templates
        --adaptive              Knowledge-graph adaptive probes on discovered routes
        --all                   Enable all modes (recon + deep + fuzz)
        --machine               macOS machine audit (keyloggers, trojans, rootkits)

  ${dim("Options")}
    -r, --repo <path>       Path to repo for source analysis
        --api-root <path>   API routes directory (default: auto-detect)
    -o, --output <file>     Write JSON report (+ companion .md if .json)
        --markdown <file>   Write Markdown report (human-readable)
        --sarif <file>      Write SARIF report (GitHub Security tab)
        --baseline <file>   Compare against previous JSON report
        --auth-cookie <v>   Cookie header for authenticated scans
        --auth-bearer <v>   Bearer token for authenticated scans
        --json              Output JSON to stdout
        --timeout <ms>      Request timeout (default: 10000)
        --concurrency <n>   Concurrent requests (default: 15)
    -v, --verbose           Detailed output
    -q, --quiet             Findings only (for piping)
    -h, --help              Show this help
        --version           Show version

  ${dim("Examples")}
    $ penthera https://myapp.com
    $ penthera https://myapp.com --recon --deep
    $ penthera https://myapp.com --profile quick -o report.json
    $ penthera https://myapp.com --profile deep -o report.json --markdown report.md
    $ penthera https://myapp.com --baseline reports/previous.json
    $ penthera --repo ./my-nextjs-app
    $ penthera https://staging.myapp.com --repo . --fuzz
    $ penthera https://myapp.com --adaptive -o report.json
    $ penthera https://myapp.com --templates ./my-templates -o report.json
    $ penthera https://myapp.com --sarif results.sarif --json | jq '.findings[]'

  ${dim("Exit codes")}
    0  No critical or high findings
    1  Critical or high findings detected
    2  Scan failed (unreachable target, bad config)
`;

function bold(s) { return `\x1b[1m${s}\x1b[0m`; }
function dim(s) { return `\x1b[2m${s}\x1b[0m`; }

export async function run() {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        repo:        { type: "string",  short: "r" },
        "api-root":  { type: "string" },
        output:      { type: "string",  short: "o" },
        markdown:    { type: "string" },
        sarif:       { type: "string" },
        baseline:    { type: "string" },
        profile:     { type: "string" },
        "auth-cookie": { type: "string" },
        "auth-bearer": { type: "string" },
        json:        { type: "boolean", default: false },
        recon:       { type: "boolean", default: false },
        deep:        { type: "boolean", default: false },
        fuzz:        { type: "boolean", default: false },
        nuclei:      { type: "string" },
        templates:   { type: "string" },
        adaptive:    { type: "boolean", default: false },
        all:         { type: "boolean", default: false },
        machine:     { type: "boolean", default: false },
        timeout:     { type: "string",  default: "10000" },
        concurrency: { type: "string",  default: "15" },
        verbose:     { type: "boolean", short: "v", default: false },
        quiet:       { type: "boolean", short: "q", default: false },
        help:        { type: "boolean", short: "h", default: false },
        version:     { type: "boolean", default: false },
      },
    });
  } catch (e) {
    printError(e.message);
    process.exit(2);
  }

  const { values: opts, positionals } = parsed;

  if (opts.help) {
    console.log(HELP);
    process.exit(0);
  }
  if (opts.version) {
    console.log(`penthera v${pkg.version}`);
    process.exit(0);
  }

  if (shouldRunOnboarding(positionals, opts)) {
    const { runOnboarding } = await import("./cli/onboarding.js");
    await runOnboarding();
    return;
  }

  const url = positionals[0] ? normalizeBaseUrl(positionals[0]) : null;
  const repo = opts.repo || null;

  if (!url && !repo && !opts.machine) {
    printError("No target specified. Provide a URL, --repo, --machine, or combine them.");
    console.log(HELP);
    process.exit(2);
  }

  // Resolve scan profile
  let profileOpts;
  try {
    profileOpts = resolveScanOptions({
      profile: opts.profile,
      recon: opts.recon,
      deep: opts.deep,
      fuzz: opts.fuzz,
      all: opts.all,
    });
  } catch (e) {
    printError(e.message);
    process.exit(2);
  }

  const recon = profileOpts.recon;
  const deep = profileOpts.deep;
  const fuzz = profileOpts.fuzz;

  // Warning for destructive modes
  if (deep && !opts.quiet && !opts.json) {
    process.stderr.write(
      "\n  \x1b[33mWARN\x1b[0m --deep sends attack payloads (SQLi, SSTI, SSRF, XSS, CMDi).\n" +
      "       Only scan targets you have permission to test.\n\n",
    );
  }

  const scanOpts = {
    timeout: parseInt(opts.timeout, 10),
    concurrency: parseInt(opts.concurrency, 10),
    fuzz,
    recon,
    deep,
    profile: profileOpts.profile,
    skipRetireJs: profileOpts.skipRetireJs,
    skipParamDiscovery: profileOpts.skipParamDiscovery,
    nucleiPath: opts.nuclei ? resolve(opts.nuclei) : null,
    templatePaths: parseTemplatePaths(opts.templates).map((p) => resolve(p)),
    adaptive: opts.adaptive,
    verbose: opts.verbose,
    authCookie: opts["auth-cookie"] || null,
    authBearer: opts["auth-bearer"] || null,
    onPhase: createProgress(opts.quiet || opts.json),
  };

  const results = [];

  try {
    if (url) {
      const urlResult = await scanUrl(url, scanOpts);
      results.push(urlResult);

      if (!urlResult.reachable && !repo) {
        printError(`Target unreachable: ${url}`);
        process.exit(2);
      }
    }

    if (repo) {
      const repoResult = await scanRepo(resolve(repo), {
        ...scanOpts,
        apiRoot: opts["api-root"] ? resolve(opts["api-root"]) : null,
      });
      results.push(repoResult);
    }

    if (opts.machine) {
      const { auditMachine } = await import("../lib/machine.js");
      const machineResult = await auditMachine({ onPhase: scanOpts.onPhase });
      results.push({
        target: "this machine",
        mode: "machine",
        timestamp: new Date().toISOString(),
        duration: 0,
        machine: machineResult,
        findings: machineResult.findings,
      });
    }
  } catch (e) {
    printError(`Scan failed: ${e.message}`);
    if (opts.verbose) console.error(e.stack);
    process.exit(2);
  }

  const merged = mergeResults(results);
  merged.profile = profileOpts.profile;

  // Baseline comparison
  let baselineStats = null;
  if (opts.baseline) {
    const comparison = compareWithBaseline(merged.findings, resolve(opts.baseline));
    baselineStats = comparison.stats;
    if (opts.quiet) {
      merged.findings = comparison.newFindings;
    } else if (!opts.json) {
      process.stderr.write(
        `\n  Baseline: ${comparison.stats.newCount} new, ` +
        `${comparison.stats.resolvedCount} resolved, ${comparison.stats.unchangedCount} unchanged\n\n`,
      );
    }
  }

  const mdOpts = { version: pkg.version, baseline: baselineStats };

  // Output
  if (opts.json) {
    console.log(JSON.stringify(merged, null, 2));
  } else if (opts.quiet) {
    printFindings(merged.findings);
  } else {
    printReport(merged, { verbose: opts.verbose });
  }

  if (opts.output) {
    writeJsonReport(merged, opts.output);
    const companionMd = markdownPathFromJson(opts.output);
    writeMarkdownReport(merged, companionMd, mdOpts);
    if (!opts.quiet && !opts.json) {
      process.stderr.write(`  JSON report    ${opts.output}\n`);
      process.stderr.write(`  Markdown report ${companionMd}\n`);
    }
  }

  if (opts.markdown) {
    writeMarkdownReport(merged, opts.markdown, mdOpts);
    if (!opts.quiet && !opts.json) {
      process.stderr.write(`  Markdown report ${opts.markdown}\n`);
    }
  }

  if (opts.sarif) {
    writeSarifReport(merged, opts.sarif);
    if (!opts.quiet && !opts.json) {
      process.stderr.write(`  SARIF report   ${opts.sarif}\n`);
    }
  }

  if ((opts.output || opts.markdown || opts.sarif) && !opts.quiet && !opts.json) {
    process.stderr.write("\n");
  }

  // Exit code: 1 if critical or high findings
  const hasSevere = merged.findings.some(
    (f) => f.severity === "critical" || f.severity === "high",
  );
  process.exit(hasSevere ? 1 : 0);
}

export { mergeResults };
