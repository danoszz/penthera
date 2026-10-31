/**
 * Penthera, CLI
 *
 * Argument parsing, dispatch to scanners, report output.
 */
import { parseArgs } from "node:util";
import { resolve, dirname } from "node:path";
import { readFileSync, writeFileSync, mkdirSync, existsSync, realpathSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { scanUrl } from "./scan-url.js";
import { scanRepo } from "./scan-repo.js";
import { mergeResults } from "./cli/merge-results.js";
import { resolveScanOptions } from "./cli/profiles.js";
import { compareWithBaseline } from "./cli/baseline.js";
import { targetFromArg } from "./utils/url.js";
import { printReport, printFindings, writeJsonReport, writeSarifReport, createProgress, printError } from "./reporter.js";
import { writeMarkdownReport, markdownPathFromJson } from "./report/markdown.js";
import { prepareReportOptions, customReport, writeEvidence } from "./cli/report-outputs.js";
import { parseTemplatePaths } from "../lib/plugins.js";
import { buildComplianceCoverage, listFrameworks } from "../lib/compliance/index.js";
import { buildActionPlan } from "../lib/remediation/index.js";
import { buildReadiness, formatReadinessMarkdown } from "../lib/compliance/readiness.js";
import { blankAssessment } from "../lib/compliance/self-assessment.js";
import { buildPolicyPack, policyPackIndex } from "../lib/compliance/policy-pack.js";
import { parseQuestionnaire, answerQuestionnaire, formatQuestionnaireMarkdown } from "../lib/compliance/questionnaire.js";
import { buildIncidentReports, formatIncidentMarkdown, incidentTemplate } from "../lib/compliance/incident.js";
import { buildSbom } from "../lib/whitebox/sbom.js";
import { buildCraReports, craTemplate, formatCraMarkdown, readCraInput } from "../lib/compliance/cra.js";
import { emptyHistory, updateHistory, buildAuditLoop } from "../lib/audit-loop.js";
import { rateSuppliers, parseSupplierList, formatSuppliersMarkdown } from "../lib/supply-chain.js";
import { bold, dim, yellow } from "./cli/ansi.js";
import { wantBrief, wantExitNote, briefReports } from "./cli/brief.js";
import { buildBrief, formatBrief, NOT_PROVEN_NOTE } from "./report/brief.js";
import { exitCodeOf } from "./report/exit.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf-8"));

// Jurisdiction data (NL today), loaded once. Add BE/others as more JSON files.
let _jurisdiction = null;
function loadJurisdiction() {
  if (!_jurisdiction) {
    _jurisdiction = JSON.parse(
      readFileSync(new URL("../lib/jurisdictions/nl.json", import.meta.url), "utf-8"),
    );
  }
  return _jurisdiction;
}

function shouldRunOnboarding(positionals, opts) {
  if (process.env.PENTHERA_NO_ONBOARDING) return false;
  if (positionals.length > 0) return false;
  if (opts.repo || opts.machine) return false;
  return process.stdin.isTTY && process.stdout.isTTY;
}

/**
 * No target, and no terminal for the wizard (an agent, CI, a pipe). A few
 * commands that work as they are, not the whole help. Exit 2, as before.
 */
function printNoTarget(noArgs) {
  const p = process.env.npm_command === "exec" ? "npx penthera" : "penthera";
  printError(noArgs
    ? "No target. The setup wizard needs a terminal, so it did not start."
    : "No target. Give a URL, --repo <path>, or a command.");
  process.stderr.write([
    "  Run one of these in your project folder:",
    `    ${p} init --yes --dry-run   show what setup would check and write; changes nothing`,
    `    ${p} init --yes             run the offline checks and set up with safe defaults`,
    `    ${p} --repo .               scan this repo's code`,
    "",
    `  Every option: ${p} --help`,
    "",
  ].join("\n") + "\n");
}

const HELP = `
  ${bold("penthera")} v${pkg.version}: your open-source cyber security agent. The security review you never had time for

  ${dim("Usage")}
    $ penthera                        Setup wizard: detect, check, set up (TTY, no args)
    $ penthera init [--yes] [--dry-run]  The same wizard, also non-interactive
    $ penthera <url>                 Scan a live URL (black-box)
    $ penthera --repo <path>         Scan a local repo (white-box)
    $ penthera <url> --repo <path>   Full scan (both)
    $ penthera agents [path]         Audit AI agent config: skills, MCP, hooks (offline)
    $ penthera deps [path]           What your npm and Python dependencies can do (offline)
    $ penthera install <pkg...>      Check what an npm install adds before anything runs
    $ penthera hook install          Pre-commit hook: staged secrets, agent config, lockfiles
    $ penthera memory show|verify|forget  Local learning store (never leaves the machine)
    $ penthera fix --plan            Plan local fix recipes (penthera fix --help)
    $ penthera evidence verify <dir> Check an evidence bundle's hashes and signature
    $ penthera verify <findings.json>  Check a model's findings against Penthera's rules
    $ penthera ai models|consent     AI mode: local models, and the consent log (penthera ai --help)
    $ penthera rules list|verify <dir>  Signed detection rule packs (penthera rules --help)
    $ penthera agent --loop          Scan, fix, verify, learn; local commits only (--help)
    $ penthera ui [--open] [--demo]  Local dashboard on 127.0.0.1 (penthera ui --help)
    $ penthera mcp                   MCP server on stdio for your agent (penthera mcp --help)
    $ penthera giants                Which free scanners --giants can run here (penthera giants --help)
    $ penthera brief <report.json...>  One short brief from JSON reports, for your AI assistant

  ${dim("Scan modes")}
        --profile <name>        quick | standard | deep (default: standard)
    ${dim("(default)")}                    TLS + fingerprint + discovery + templates + CORS
                               + cookies + Retire.js + param discovery + OpenAPI/auth
                               (one invalid login POST, no attack payloads; quick: none)
        --recon                 + OSINT recon (subdomains, historical URLs)
        --deep                  + Injection probes (SQLi, SSTI, SSRF, XSS, CMDi); asks first
                               + login rate-limit burst and SQL error check on /api/login
        --fuzz                  + Property-based API fuzzing
        --nuclei <path>         + Community Nuclei YAML templates (alias for --templates;
                               with --giants, also the folder the nuclei tool runs)
        --templates <paths>     Comma-separated dirs of Nuclei-compatible YAML templates
        --rules <dir>           + Signed rule pack (repeatable; scans, agents, deps)
        --rules-signers <file>  Also trust packs signed by these keys (allowed_signers)
        --allow-unsigned-rules  Load a pack whose signature does not verify (warns)
        --adaptive              Knowledge-graph adaptive probes on discovered routes
        --all                   Enable all modes (recon + deep + fuzz)
        --machine               macOS machine audit (keyloggers, trojans, rootkits)
        --offline               Contact only the scan target: no recon sources, no
                               Retire.js download (uses the vendored snapshot),
                               no DNS lookups for SPF/DMARC

  ${dim("Other tools")}  ${dim("(--giants; runs the free scanners you have installed; docs/commands/giants.md)")}
        --giants                Also run gitleaks, TruffleHog, Semgrep, osv-scanner, Trivy, Checkov
                               (repo) or nuclei and the ZAP baseline (URL), if installed
        --with <list>           Run only these tools, e.g. --with gitleaks,trivy (implies --giants)
        --without <list>        Skip these tools
        --giants-online         Also run tools or features that contact a service (pip-audit,
                               TruffleHog key verification, osv-scanner via its API)
        --giants-timeout <s>    Seconds per tool (default 300)

  ${dim("AI mode")}  ${dim("(with --repo; opt-in, asks every run; docs/ai-mode.md)")}
        --ai                    A model reads your code for what rules can't see; Penthera checks its findings
        --ai-model <name>       An Ollama model on 127.0.0.1 (penthera ai models lists them)
        --ai-budget <spec>      Hard caps, e.g. units=200,tokens=2M,time=20m (the default)
        --ai-consent <route>    Consent for a run that cannot ask: local, or ollama-cloud
        --ai-scope <folder>     Only read files under this folder of the repo

  ${dim("Agents mode")}  ${dim("(penthera agents [path], offline, read-only)")}
        --home                  Also audit ~/.claude, ~/.cursor and Claude Desktop config
        --pin                   Write penthera.lock (SHA-256 of skills, MCP servers, hooks)

  ${dim("Deps mode")}  ${dim("(penthera deps [path], reads package-lock.json, Python lockfiles or a .venv, offline)")}
        --diff <lock|dir>       Capability diff against an old lockfile or installed tree
        --base <git-ref>        Capability diff against the lockfile at a git ref
        --online                Also check npm registry metadata (the only network use)
        --prod                  Skip dev dependencies
        --venv <path>           Python virtualenv to read (default: .venv or venv)
        --pr-comment <file>     Write a short Markdown capability diff for a PR comment
        --license-policy <p>    permissive | weak-copyleft-ok | no-agpl, or a policy file

  ${dim("Install mode")}  ${dim("(penthera install [pkg...]; penthera install --help for all options)")}
        --yes / --dry-run       Install only if nothing breaches the policy / report only

  ${dim("Hook mode")}  ${dim("(penthera hook install|uninstall|run; penthera hook --help)")}
                                Pre-commit: staged secrets, agent config, lockfile diff

  ${dim("Options")}
    -r, --repo <path>       Path to repo for source analysis
        --api-root <path>   API routes directory (default: auto-detect)
        --library           Scan the repo as a library: parameters of exported functions
                            are untrusted (default: on for a publishable package.json)
        --no-library        Scan the repo as an app, even if package.json is publishable
    -o, --output <file>     Write JSON report (+ companion .md if .json)
        --markdown <file>   Write Markdown report (human-readable)
        --sarif <file>      Write SARIF report (GitHub Security tab)
        --audit-seeds <file>  Write repo findings as seeds for an AI audit (security-audit-skill findings.json)
        --audience <who>    developer | owner | auditor | agent report (for --markdown or stdout)
        --brief             Print the agent brief to stdout (the default when stdout is
                            not a terminal and not CI; PENTHERA_BRIEF=0 turns that off)
        --report-template <file.md>  Your own Markdown template ({{summary.critical}}, {{#each findings}})
        --evidence <dir>    Evidence bundle: all reports + manifest.json with SHA-256s
        --no-footer         Leave the one-line "Checked by Penthera" footer off Markdown output
        --sign-key <key>    Sign the bundle's manifest with an SSH key (ssh-keygen -Y sign)
        --baseline <file>   Compare against previous JSON report
        --framework <name>  Add a compliance mapping to reports (nis2)
        --readiness         NIS2 readiness report (scan + self-assessment)
        --assessment <file> Self-assessment answers JSON (used by --readiness)
        --questionnaire <file>  Draft answers to a customer security questionnaire
        --assessment-init <file>  Write a blank self-assessment template and exit
        --policy-pack <dir> Generate proportionate NIS2 policy templates into <dir>
        --org <name>        Organisation name for readiness/policy documents
        --incident <file>   Generate NIS2 incident-report drafts + timeline
        --incident-init <file>  Write a blank incident template and exit
        --sbom <file>       Write a CycloneDX software bill of materials (from --repo)
        --aibom <file>      Write a CycloneDX 1.6 AI-BOM: AI SDKs, models, MCP servers, skills, prompts
        --cra <file>        Generate CRA Article 14 report drafts + timeline (writes cra-reports.md)
        --cra-init <file>   Write a blank CRA reporting template and exit
        --history <file>    Track findings over time (time-to-fix, ageing, drift)
        --memory            Learn from this scan locally; apply suppressions + ranking
        --suppliers <file>  Passively rate suppliers' public domains (RAG, measure d)
        --auth-cookie <v>   Cookie header for authenticated scans
        --auth-bearer <v>   Bearer token for authenticated scans
        --json              Output JSON to stdout
        --timeout <ms>      Request timeout (default: 10000)
        --concurrency <n>   Concurrent requests (default: 15)
        --rate <n>          Max requests per second (default: no limit; 10 with
                            --deep, --fuzz or --adaptive; 0 removes the limit)
        --confirm-target <host>  Confirm an active scan (--deep, --fuzz, --adaptive)
                            of this hostname without a prompt, for CI and scripts
        --user-agent <ua>   User-Agent header (default: penthera/${pkg.version} (+https://github.com/danoszz/penthera))
    -v, --verbose           Detailed output
    -q, --quiet             Findings only (for piping)
    -h, --help              Show this help
        --version           Show version

  ${dim("Examples")}
    $ penthera https://myapp.com
    $ penthera https://myapp.com --recon --deep
    $ penthera http://localhost:3000 --offline
    $ penthera https://myapp.com --profile quick -o report.json
    $ penthera https://myapp.com --profile deep -o report.json --markdown report.md
    $ penthera https://myapp.com --baseline reports/previous.json
    $ penthera --repo ./my-nextjs-app
    $ penthera https://staging.myapp.com --repo . --fuzz
    $ penthera https://myapp.com --adaptive -o report.json
    $ penthera https://myapp.com --templates ./my-templates -o report.json
    $ penthera https://myapp.com --sarif results.sarif --json | jq '.findings[]'
    $ penthera agents . --home
    $ penthera agents --pin
    $ penthera deps --base origin/main
    $ penthera deps --diff ../base-checkout --pr-comment deps.md
    $ penthera --repo . --giants
    $ penthera --repo . --with gitleaks,trivy

  ${dim("Exit codes")}
    0  No critical or high rule fired. This run does not prove login, access rules or payments are right
    1  Critical or high findings detected (other tools' too, with --giants)
    2  Scan failed (unreachable target, bad config, a tool the policy requires did not run)
`;


/** `penthera init ...`, or bare `penthera --yes` / `--dry-run`: the setup wizard. */
function initArgs(argv) {
  if (argv[0] === "init") return argv.slice(1);
  if (argv.length && argv.every((a) => ["--yes", "-y", "--dry-run"].includes(a))) return argv;
  return null;
}

export async function run() {
  const init = initArgs(process.argv.slice(2));
  if (init) {
    const { runInit } = await import("./cli/onboarding.js");
    process.exit(await runInit(init, { version: pkg.version }));
  }

  if (process.argv[2] === "memory") {
    const { runMemoryCommand } = await import("./cli/memory.js");
    process.exit(await runMemoryCommand(process.argv.slice(3)));
  }

  if (process.argv[2] === "install") {
    const { runInstall } = await import("./cli/install.js");
    process.exitCode = await runInstall(process.argv.slice(3));
    return;
  }

  if (process.argv[2] === "hook") {
    const { runHookCommand } = await import("./cli/hook.js");
    process.exitCode = await runHookCommand(process.argv.slice(3));
    return;
  }

  if (process.argv[2] === "evidence") {
    const { runEvidence } = await import("./cli/evidence.js");
    process.exit(runEvidence(process.argv.slice(3)));
  }

  if (process.argv[2] === "ai") {
    const { runAiCommand } = await import("./cli/ai.js");
    process.exit(await runAiCommand(process.argv.slice(3)));
  }

  if (process.argv[2] === "verify") {
    const { runVerify } = await import("./cli/verify.js");
    process.exit(await runVerify(process.argv.slice(3)));
  }

  if (process.argv[2] === "fix") {
    const { runFix } = await import("./cli/fix.js");
    return runFix(process.argv.slice(3));
  }

  if (process.argv[2] === "rules") {
    const { runRules } = await import("./cli/rules.js");
    process.exit(await runRules(process.argv.slice(3)));
  }

  if (process.argv[2] === "ui") {
    const { runUi } = await import("./cli/ui.js");
    process.exit(await runUi(process.argv.slice(3), { version: pkg.version }));
  }

  if (process.argv[2] === "mcp") {
    const { runMcp } = await import("./cli/mcp.js");
    process.exitCode = await runMcp(process.argv.slice(3), { version: pkg.version });
    return;
  }

  if (process.argv[2] === "brief") {
    const { runBrief } = await import("./cli/brief.js");
    process.exit(runBrief(process.argv.slice(3)));
  }

  if (process.argv[2] === "giants") {
    const { runGiantsCommand } = await import("./cli/giants.js");
    process.exitCode = await runGiantsCommand(process.argv.slice(3));
    return;
  }

  if (process.argv[2] === "agent") {
    const { runAgent } = await import("./cli/agent.js");
    process.exit(await runAgent(process.argv.slice(3)));
  }

  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        repo:        { type: "string",  short: "r" },
        "api-root":  { type: "string" },
        library:     { type: "boolean", default: false },
        "no-library": { type: "boolean", default: false },
        output:     { type: "string",  short: "o" },
        markdown:    { type: "string" },
        sarif:       { type: "string" },
        "audit-seeds": { type: "string" },
        audience:    { type: "string" },
        brief:       { type: "boolean", default: false },
        "no-footer": { type: "boolean", default: false },
        "report-template": { type: "string" },
        evidence:    { type: "string" },
        "sign-key":  { type: "string" },
        baseline:    { type: "string" },
        framework:   { type: "string" },
        readiness:   { type: "boolean", default: false },
        assessment:  { type: "string" },
        questionnaire: { type: "string" },
        "assessment-init": { type: "string" },
        "policy-pack": { type: "string" },
        org:         { type: "string" },
        incident:    { type: "string" },
        "incident-init": { type: "string" },
        sbom:        { type: "string" },
        aibom:       { type: "string" },
        cra:         { type: "string" },
        "cra-init":  { type: "string" },
        history:     { type: "string" },
        memory:      { type: "boolean", default: false },
        suppliers:   { type: "string" },
        diff:        { type: "string" },
        base:        { type: "string" },
        online:      { type: "boolean", default: false },
        "pr-comment": { type: "string" },
        prod:        { type: "boolean", default: false },
        "license-policy": { type: "string" },
        venv:        { type: "string" },
        profile:     { type: "string" },
        "auth-cookie": { type: "string" },
        "auth-bearer": { type: "string" },
        json:        { type: "boolean", default: false },
        recon:       { type: "boolean", default: false },
        deep:        { type: "boolean", default: false },
        fuzz:        { type: "boolean", default: false },
        nuclei:      { type: "string" },
        templates:   { type: "string" },
        rules:       { type: "string", multiple: true },
        "rules-signers": { type: "string", multiple: true },
        "allow-unsigned-rules": { type: "boolean", default: false },
        adaptive:    { type: "boolean", default: false },
        all:         { type: "boolean", default: false },
        machine:     { type: "boolean", default: false },
        home:        { type: "boolean", default: false },
        pin:         { type: "boolean", default: false },
        offline:     { type: "boolean", default: false },
        ai:          { type: "boolean", default: false },
        "ai-model":  { type: "string" },
        "ai-budget": { type: "string" },
        "ai-consent": { type: "string" },
        "ai-scope":  { type: "string" },
        "user-agent": { type: "string" },
        timeout:     { type: "string",  default: "10000" },
        concurrency: { type: "string",  default: "15" },
        rate:        { type: "string" },
        "confirm-target": { type: "string" },
        giants:      { type: "boolean", default: false },
        with:        { type: "string" },
        without:     { type: "string" },
        "giants-online": { type: "boolean", default: false },
        "giants-timeout": { type: "string" },
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

  // --rules <dir>: verified rule packs, added before any engine runs.
  if (opts.rules) {
    const { activateRules, printRuleWarnings } = await import("./cli/rules.js");
    try {
      printRuleWarnings(await activateRules(opts));
    } catch (e) {
      printError(e.message);
      process.exit(2);
    }
  }

  if (opts["assessment-init"]) {
    const path = resolve(opts["assessment-init"]);
    writeFileSync(path, JSON.stringify(blankAssessment(), null, 2) + "\n");
    console.log(`Wrote a blank NIS2 self-assessment to ${path}`);
    console.log(`Fill each answer (yes | partial | no | na), then run:`);
    console.log(`  penthera <url> --repo . --readiness --assessment ${opts["assessment-init"]}`);
    process.exit(0);
  }

  if (opts["incident-init"]) {
    const path = resolve(opts["incident-init"]);
    writeFileSync(path, JSON.stringify(incidentTemplate(), null, 2) + "\n");
    console.log(`Wrote a blank incident template to ${path}`);
    console.log(`Fill it in (set aware_at, ISO 8601), then run:  penthera --incident ${opts["incident-init"]}`);
    process.exit(0);
  }

  if (opts.incident) {
    let incident;
    try {
      incident = JSON.parse(readFileSync(resolve(opts.incident), "utf-8"));
    } catch (e) {
      printError(`Could not read --incident file: ${e.message}`);
      process.exit(2);
    }
    const jurisdiction = loadJurisdiction();
    const result = buildIncidentReports(incident, jurisdiction);
    const nowIso = new Date().toISOString();
    result.generated_at = nowIso;
    const outPath = resolve("incident-reports.md");
    writeFileSync(outPath, formatIncidentMarkdown(result, { now: nowIso }));
    console.log(`Incident report drafts written to ${outPath}`);
    for (const t of result.timeline) {
      console.log(`  ${t.within} (${t.id}): due ${t.dueBy || "set aware_at"}`);
    }
    process.exit(0);
  }

  if (opts["cra-init"]) {
    const path = resolve(opts["cra-init"]);
    writeFileSync(path, JSON.stringify(craTemplate(), null, 2) + "\n");
    console.log(`Wrote a blank CRA reporting template to ${path}`);
    console.log(`Set type and aware_at (ISO 8601), then run:  penthera --cra ${opts["cra-init"]}`);
    process.exit(0);
  }

  if (opts.cra) {
    let input;
    try {
      input = readCraInput(resolve(opts.cra));
    } catch (e) {
      printError(`Could not read --cra file: ${e.message}`);
      process.exit(2);
    }
    for (const err of input.errors) printError(err);
    const result = buildCraReports(input.cra, loadJurisdiction(), { now: new Date().toISOString(), prefilled: input.prefilled });
    const outPath = resolve("cra-reports.md");
    writeFileSync(outPath, formatCraMarkdown(result));
    console.log(`CRA Article 14 report drafts written to ${outPath}`);
    for (const t of result.timeline) console.log(`  ${t.title} (${t.within}): ${t.dueBy ? `due ${t.dueBy}` : t.basis || "n/a"}, ${t.status}`);
    for (const w of result.warnings) console.log(`  ⚠️ ${w}`);
    process.exit(0);
  }

  if (opts.suppliers && opts.offline) {
    printError("--suppliers rates third-party domains, which --offline forbids.");
    process.exit(2);
  }

  if (opts.suppliers) {
    let text;
    try {
      text = readFileSync(resolve(opts.suppliers), "utf-8");
    } catch {
      text = opts.suppliers; // treat the value itself as an inline list
    }
    const domains = parseSupplierList(text);
    if (domains.length === 0) {
      printError("No supplier domains found in --suppliers input.");
      process.exit(2);
    }
    process.stderr.write(`  Rating ${domains.length} supplier domain(s), passive, public-data-only...\n`);
    const report = await rateSuppliers(domains, { generatedAt: new Date().toISOString() });
    const outPath = resolve("supplier-ratings.md");
    writeFileSync(outPath, formatSuppliersMarkdown(report));
    console.log(`Supplier ratings written to ${outPath}`);
    for (const r of report.suppliers) {
      console.log(`  ${String(r.rating).padEnd(7)} ${r.domain}${r.score != null ? ` (${r.score})` : ""}`);
    }
    process.exit(0);
  }

  // `penthera deps [path]`: offline dependency capability scan and diff.
  if (positionals[0] === "deps") {
    const { runDeps } = await import("./cli/deps.js");
    await runDeps(positionals.slice(1), opts, { version: pkg.version });
    return;
  }
  if (opts.diff || opts.base || opts.online || opts["pr-comment"] || opts.prod || opts["license-policy"] || opts.venv) {
    printError("--diff, --base, --online, --prod, --pr-comment, --license-policy and --venv only apply to `penthera deps`.");
    process.exit(2);
  }

  if (shouldRunOnboarding(positionals, opts)) {
    const { runInit } = await import("./cli/onboarding.js");
    process.exit(await runInit([], { version: pkg.version }));
  }

  // `penthera agents [path]`: offline audit of skills, MCP servers, hooks, plugins.
  const agentsMode = positionals[0] === "agents";
  let agentsRoot = agentsMode ? resolve(positionals[1] || ".") : null;
  if (agentsMode && positionals.length > 2) {
    printError(`agents takes one path, got: ${positionals.slice(1).join(" ")}`);
    process.exit(2);
  }
  if ((opts.home || opts.pin) && !agentsMode) {
    printError("--home and --pin only apply to `penthera agents`.");
    process.exit(2);
  }

  let url = null;
  if (positionals[0] && !agentsMode) {
    const target = targetFromArg(positionals[0]);
    if (target.error) {
      printError(target.error);
      process.exit(2);
    }
    url = target.url;
  }
  const repo = opts.repo || null;
  const aiFlags = ["ai-model", "ai-budget", "ai-consent", "ai-scope"].filter((k) => opts[k] != null);
  if (aiFlags.length && !opts.ai) {
    printError(`--${aiFlags[0]} only applies with --ai.`);
    process.exit(2);
  }
  if (opts.ai && !repo) {
    printError("--ai needs --repo <path>: the model reads source code, and never probes a live URL.");
    process.exit(2);
  }
  // AI mode asks before anything is scanned, so a "no" costs nothing.
  let aiPlan = null;
  if (opts.ai) {
    const { preflightAi } = await import("./cli/ai.js");
    aiPlan = await preflightAi({ opts, repo: resolve(repo) });
    if (aiPlan.exit) {
      printError(aiPlan.message);
      process.exit(aiPlan.exit);
    }
    if (aiPlan.skip && !opts.quiet) process.stderr.write(`\n  ${yellow("AI mode off")} ${aiPlan.reason}\n\n`);
  }

  if (opts["audit-seeds"] && !repo && !agentsMode) {
    printError("--audit-seeds needs --repo <path> (or `penthera agents <path>`): seeds point at files in a repository.");
    process.exit(2);
  }

  if (!agentsMode && !url && !repo && !opts.machine && !opts.readiness && !opts["policy-pack"] && !opts.sbom && !opts.aibom && !opts.questionnaire) {
    printNoTarget(process.argv.length <= 2);
    process.exit(2);
  }

  let giantsOpts = null;
  try {
    const { giantsOptions } = await import("./cli/giants.js");
    giantsOpts = giantsOptions(opts, { url, repo });
  } catch (e) {
    printError(e.message);
    process.exit(2);
  }

  let reportCtx;
  try {
    reportCtx = prepareReportOptions(opts);
  } catch (e) {
    printError(e.message);
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

  // Payload modes need an explicit confirmation bound to the target host
  // (docs/METHODOLOGY.md, "Non-destructive by default"), and are rate-limited.
  const { activeModes, confirmActiveScan, resolveRate } = await import("./cli/active-gate.js");
  const modes = activeModes({ deep, fuzz, adaptive: opts.adaptive });
  if (opts["confirm-target"] != null && !url) {
    printError("--confirm-target names the URL being scanned; give a URL.");
    process.exit(2);
  }
  let rateLimit;
  try {
    rateLimit = resolveRate(opts.rate, modes.length > 0);
  } catch (e) {
    printError(e.message);
    process.exit(2);
  }
  if (url && modes.length) {
    const consent = await confirmActiveScan({ url, modes, confirmTarget: opts["confirm-target"] ?? null });
    if (!consent.ok) {
      printError(consent.reason);
      process.exit(2);
    }
  }

  const scanOpts = {
    timeout: parseInt(opts.timeout, 10),
    concurrency: parseInt(opts.concurrency, 10),
    rateLimit,
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
    offline: opts.offline,
    userAgent: opts["user-agent"] || null,
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
        library: opts.library ? true : opts["no-library"] ? false : undefined,
      });
      results.push(repoResult);
    }

    if (agentsMode) {
      if (!existsSync(agentsRoot)) {
        printError(`Path not found: ${agentsRoot}`);
        process.exit(2);
      }
      const { scanAgents, agentsTarget } = await import("../lib/agents/index.js");
      const target = agentsTarget(agentsRoot);
      if (!target) {
        printError(`Not a folder or a SKILL.md file: ${agentsRoot}`);
        process.exit(2);
      }
      // A folder the user named can be a skill. The working folder is a project
      // scan, spelled `.` or not (the Action and CI pass $GITHUB_WORKSPACE).
      const skillTarget = positionals[1] !== undefined && (target !== agentsRoot || realpathSync(target) !== realpathSync(process.cwd()));
      agentsRoot = target;
      results.push(await scanAgents(agentsRoot, { home: opts.home, pin: opts.pin, onPhase: scanOpts.onPhase, skillTarget }));
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

  if (aiPlan?.run) {
    const { runAiMode, attachProposals } = await import("../lib/ai/index.js");
    const { createOllama } = await import("../lib/ai/ollama.js");
    const { aiHeader } = await import("./cli/ai.js");
    const repoResult = results.find((r) => r.mode === "repo") || merged;
    const quietAi = opts.quiet || opts.json;
    if (!quietAi) process.stderr.write(`\n${aiHeader(aiPlan.model)}\n`);
    const stop = new AbortController();
    const onSigint = () => stop.abort();
    process.once("SIGINT", onSigint);
    try {
      merged.ai = await runAiMode({
        repoPath: resolve(repo),
        scanResult: { ...repoResult, findings: merged.findings },
        model: aiPlan.model,
        ollama: createOllama(),
        budget: aiPlan.budget,
        consent: aiPlan.consent,
        scope: aiPlan.scope,
        signal: stop.signal,
        onUnit: quietAi ? undefined : (u, i, n) => process.stderr.write(`\r\x1b[2K  AI ${i}/${n} ${u.id.slice(0, 70)}`),
      });
      if (!quietAi) process.stderr.write("\r\x1b[2K");
      merged.findings = attachProposals(merged.findings, merged.ai);
    } finally {
      process.removeListener("SIGINT", onSigint);
    }
  } else if (aiPlan?.skip) {
    merged.ai = { schema: "penthera.ai/1", ran: false, reason: aiPlan.reason };
  }
  merged.profile = profileOpts.profile;

  // --giants: the free tools installed here, after Penthera's own scan.
  let giantsRaw = [];
  if (giantsOpts) {
    const { runGiantsForScan } = await import("./cli/giants.js");
    try {
      giantsRaw = await runGiantsForScan(merged, giantsOpts, { opts, url, repo, deep, rateLimit, onPhase: scanOpts.onPhase });
    } catch (e) {
      printError(`--giants: ${e.message}`);
      process.exit(2);
    }
  }

  // Local learning store (opt-in): suppress + rank from ~/.penthera/memory, then record this scan.
  if (opts.memory && (url || repo)) {
    const { applyMemoryToScan } = await import("../lib/memory/index.js");
    const { warnings } = applyMemoryToScan(merged, { repo: repo ? resolve(repo) : null, url });
    for (const w of warnings) process.stderr.write(`  \x1b[33mWARN\x1b[0m ${w}\n`);
  }

  // Compliance framework mapping (e.g. --framework nis2)
  if (opts.framework) {
    const coverage = buildComplianceCoverage(merged, opts.framework);
    if (!coverage) {
      printError(`Unknown --framework "${opts.framework}". Supported: ${listFrameworks().join(", ")}.`);
      process.exit(2);
    }
    merged.compliance = coverage;
  }

  // Prioritised, owner-actionable remediation plan (also consumed by the Agent
  // Skill to draft questionnaire answers and remediation documents).
  merged.actionPlan = buildActionPlan(merged.findings);

  // NIS2 readiness report (scan evidence + local self-assessment, provenance-linked).
  // Also built when --questionnaire is set, since the answerer maps to it.
  if (opts.readiness || opts.questionnaire) {
    let answers = {};
    if (opts.assessment) {
      try {
        answers = JSON.parse(readFileSync(resolve(opts.assessment), "utf-8"));
      } catch (e) {
        printError(`Could not read --assessment file: ${e.message}`);
        process.exit(2);
      }
    }
    const jurisdiction = loadJurisdiction();
    merged.readiness = buildReadiness(merged, {
      answers,
      jurisdiction,
      generatedAt: new Date().toISOString(),
      assessedAt: answers?._assessedAt || null,
    });
  }

  // Remediation / audit-loop tracking over time (measure f)
  if (opts.history) {
    const histPath = resolve(opts.history);
    let history;
    try {
      history = JSON.parse(readFileSync(histPath, "utf-8"));
    } catch {
      history = emptyHistory();
    }
    const now = new Date().toISOString();
    history = updateHistory(history, merged.findings, now);
    mkdirSync(dirname(histPath), { recursive: true });
    writeFileSync(histPath, JSON.stringify(history, null, 2) + "\n");
    merged.auditLoop = buildAuditLoop(history, now);
  }

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

  const mdOpts = { version: pkg.version, baseline: baselineStats, footer: !opts["no-footer"] };
  merged.brief = buildBrief(merged, { reports: briefReports(opts) });
  const custom = customReport(merged, opts, { version: pkg.version, template: reportCtx.template });

  // Output
  if (opts.json) {
    console.log(JSON.stringify(merged, null, 2));
  } else if (custom && !opts.markdown) {
    process.stdout.write(custom);
  } else if (wantBrief(opts)) {
    process.stdout.write(formatBrief(merged.brief));
  } else if (opts.quiet) {
    printFindings(merged.findings);
    printFindings((merged.giants?.findings || []).map((f) => ({ ...f, title: `${f.title} [${f.foundBy.join(", ")}]` })));
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
    if (custom) writeFileSync(resolve(opts.markdown), custom);
    else writeMarkdownReport(merged, opts.markdown, mdOpts);
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

  if (opts["audit-seeds"]) {
    const seedRoot = repo ? resolve(repo) : agentsRoot;
    const { toSecurityAuditFindings } = await import("../lib/llm-audit/export.js");
    const seeds = toSecurityAuditFindings(merged, seedRoot);
    mkdirSync(dirname(resolve(opts["audit-seeds"])), { recursive: true });
    writeFileSync(resolve(opts["audit-seeds"]), JSON.stringify(seeds.findings, null, 2) + "\n");
    if (!opts.quiet && !opts.json) {
      process.stderr.write(`  Audit seeds    ${opts["audit-seeds"]} (${seeds.exported} finding${seeds.exported === 1 ? "" : "s"}; ${seeds.skipped} without a file in the repo left out)\n`);
    }
  }

  if (merged.readiness) {
    const rdPath = opts.output
      ? opts.output.replace(/\.json$/i, "") + "-readiness.md"
      : opts.markdown
        ? opts.markdown.replace(/\.md$/i, "") + "-readiness.md"
        : "nis2-readiness.md";
    writeFileSync(resolve(rdPath), formatReadinessMarkdown(merged.readiness));
    if (!opts.quiet && !opts.json) {
      const s = merged.readiness.summary;
      process.stderr.write(
        `  NIS2 readiness  ${s.met} met · ${s.partial} partial · ${s.gap} gap · ${s["not-assessed"]} not assessed\n`,
      );
      process.stderr.write(`  Readiness report ${rdPath}\n`);
    }
  }

  let sbom = null;
  if (opts.sbom) {
    const sbomRepo = resolve(opts.repo || ".");
    sbom = buildSbom(sbomRepo, {
      serialNumber: `urn:uuid:${randomUUID()}`,
      timestamp: new Date().toISOString(),
    });
    if (!sbom) {
      printError(`No dependency manifest found in ${sbomRepo} (looked for package-lock.json, package.json, requirements.txt).`);
    } else {
      writeFileSync(resolve(opts.sbom), JSON.stringify(sbom, null, 2) + "\n");
      if (!opts.quiet && !opts.json) {
        process.stderr.write(`  SBOM (CycloneDX) ${sbom.components.length} components → ${opts.sbom}\n`);
      }
    }
  }

  if (opts.aibom) {
    // Loaded here: aibom.js needs the `yaml` dependency, which deps and URL
    // scans must run without (the GitHub Action has no node_modules).
    const { buildAiBom, aiBomSummary } = await import("../lib/whitebox/aibom.js");
    const aibom = buildAiBom(resolve(opts.repo || "."), {
      serialNumber: `urn:uuid:${randomUUID()}`,
      timestamp: new Date().toISOString(),
      toolVersion: pkg.version,
    });
    writeFileSync(resolve(opts.aibom), JSON.stringify(aibom, null, 2) + "\n");
    if (!opts.quiet && !opts.json) {
      const n = aiBomSummary(aibom);
      process.stderr.write(`  AI-BOM (CycloneDX 1.6) ${n.sdks} SDKs, ${n.models} models, ${n.mcpServers} MCP servers, ${n.skills} skills, ${n.prompts} prompts → ${opts.aibom}\n`);
    }
  }

  if (opts["policy-pack"]) {
    const dir = resolve(opts["policy-pack"]);
    mkdirSync(dir, { recursive: true });
    const jurisdiction = loadJurisdiction();
    const ctx = {
      org: opts.org || (url ? new URL(url).hostname : "Your organisation"),
      date: new Date().toISOString().slice(0, 10),
      jurisdiction,
      readiness: merged.readiness || null,
    };
    const pack = buildPolicyPack(ctx);
    for (const p of pack) writeFileSync(resolve(dir, p.filename), p.content);
    writeFileSync(resolve(dir, "README.md"), policyPackIndex(pack, ctx));
    if (!opts.quiet && !opts.json) {
      process.stderr.write(`  Policy pack     ${pack.length} templates → ${dir}/\n`);
    }
  }

  if (opts.questionnaire) {
    let qtext;
    try {
      qtext = readFileSync(resolve(opts.questionnaire), "utf-8");
    } catch (e) {
      printError(`Could not read --questionnaire file: ${e.message}`);
      process.exit(2);
    }
    const answered = answerQuestionnaire(parseQuestionnaire(qtext), merged.readiness || { measures: [] });
    const qPath = opts.output
      ? opts.output.replace(/\.json$/i, "") + "-questionnaire.md"
      : "questionnaire-response.md";
    writeFileSync(resolve(qPath), formatQuestionnaireMarkdown(answered));
    if (!opts.quiet && !opts.json) {
      process.stderr.write(
        `  Questionnaire   ${answered.summary.answered}/${answered.total} drafted` +
        ` (${answered.summary.needsHuman} need human input) → ${qPath}\n`,
      );
    }
  }

  if (opts.evidence) {
    try {
      const bundle = writeEvidence(merged, opts, { version: pkg.version, template: reportCtx.template, mdOpts, sbom, argv: process.argv.slice(2), giantsRaw });
      if (!opts.quiet && !opts.json) {
        process.stderr.write(`  Evidence bundle ${bundle.manifest.artifacts.length} files${bundle.signed ? ", signed" : ""} → ${opts.evidence}/ (penthera evidence verify ${opts.evidence})\n`);
      }
    } catch (e) {
      printError(`Could not write the evidence bundle: ${e.message}`);
      process.exit(2);
    }
  }

  if (merged.auditLoop && !opts.quiet && !opts.json) {
    const a = merged.auditLoop;
    process.stderr.write(
      `  Audit loop      ${a.openCount} open · ${a.resolvedCount} resolved` +
      `${a.medianTimeToFixDays != null ? ` · median fix ${a.medianTimeToFixDays}d` : ""}\n`,
    );
  }

  if ((opts.output || opts.markdown || opts.sarif || opts["audit-seeds"] || opts.evidence || opts.readiness || opts["policy-pack"] || opts.sbom || opts.aibom || opts.history || opts.questionnaire) && !opts.quiet && !opts.json) {
    process.stderr.write("\n");
  }

  // Exit code: 1 if critical or high findings, other tools' included unless
  // the policy says giants.failOn: never; 2 if a tool the policy requires did not run.
  if (merged.giants?.requiredNotRun?.length) printError(`The policy file requires ${merged.giants.requiredNotRun.join(", ")}, which did not run (see Coverage by area).`);
  const code = exitCodeOf(merged);
  if (wantExitNote({ code, url, repo, opts, custom })) {
    process.stderr.write(`  No critical or high rule fired. ${NOT_PROVEN_NOTE}\n\n`);
  }
  // Exit only once stdout has drained: on a pipe the write is asynchronous, and
  // exiting at once cut `--json` output off at the pipe buffer (64 KiB).
  process.stdout.write("", () => process.exit(code));
}

export { mergeResults };
