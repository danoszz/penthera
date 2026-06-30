/**
 * Shared scan execution — used by CLI and interactive onboarding.
 */
import { resolve, join } from "node:path";
import { existsSync, mkdirSync } from "node:fs";
import { scanUrl } from "../scan-url.js";
import { scanRepo } from "../scan-repo.js";
import { mergeResults } from "./merge-results.js";
import { resolveScanOptions } from "./profiles.js";
import { compareWithBaseline } from "./baseline.js";
import { normalizeBaseUrl, urlToFilename } from "../utils/url.js";
import {
  printReport,
  printFindings,
  writeJsonReport,
  writeSarifReport,
  createProgress,
} from "../reporter.js";
import { writeMarkdownReport, markdownPathFromJson } from "../report/markdown.js";

export async function executeScan(config) {
  const {
    url = null,
    repo = null,
    machine = false,
    profile = "standard",
    recon = false,
    deep = false,
    fuzz = false,
    output = null,
    markdown = null,
    sarif = null,
    baseline = null,
    authCookie = null,
    authBearer = null,
    apiRoot = null,
    quiet = false,
    verbose = false,
    json = false,
    version = "0.2.0",
    onPhase = null,
  } = config;

  const profileOpts = resolveScanOptions({ profile, recon, deep, fuzz, all: false });

  const scanOpts = {
    timeout: config.timeout || 10_000,
    concurrency: config.concurrency || 15,
    fuzz: profileOpts.fuzz,
    recon: profileOpts.recon,
    deep: profileOpts.deep,
    profile: profileOpts.profile,
    skipRetireJs: profileOpts.skipRetireJs,
    skipParamDiscovery: profileOpts.skipParamDiscovery,
    nucleiPath: config.nucleiPath || null,
    templatePaths: config.templatePaths || [],
    adaptive: config.adaptive || false,
    verbose,
    authCookie,
    authBearer,
    onPhase: onPhase || createProgress(quiet || json),
  };

  const results = [];

  if (url) {
    const urlResult = await scanUrl(normalizeBaseUrl(url), scanOpts);
    results.push(urlResult);
    if (!urlResult.reachable && !repo) {
      throw new Error(`Target unreachable: ${url}`);
    }
  }

  if (repo) {
    const repoResult = await scanRepo(resolve(repo), {
      ...scanOpts,
      apiRoot: apiRoot ? resolve(apiRoot) : null,
    });
    results.push(repoResult);
  }

  if (machine) {
    const { auditMachine } = await import("../../lib/machine.js");
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

  const merged = mergeResults(results);
  merged.profile = profileOpts.profile;

  let baselineStats = null;
  if (baseline) {
    const comparison = compareWithBaseline(merged.findings, resolve(baseline));
    baselineStats = comparison.stats;
    if (quiet) merged.findings = comparison.newFindings;
  }

  const mdOpts = { version, baseline: baselineStats };

  // Default report paths
  let jsonPath = output;
  let mdPath = markdown;
  let sarifPath = sarif;

  if (!jsonPath && !json) {
    const reportsDir = resolve("reports");
    if (!existsSync(reportsDir)) mkdirSync(reportsDir, { recursive: true });
    const ts = new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-");
    const base = url ? urlToFilename(normalizeBaseUrl(url)) : repo ? "repo" : "scan";
    jsonPath = join(reportsDir, `${base}_${ts}.json`);
    mdPath = mdPath || markdownPathFromJson(jsonPath);
    sarifPath = sarifPath || join(reportsDir, `${base}_${ts}.sarif`);
  } else if (jsonPath && !mdPath) {
    mdPath = markdownPathFromJson(jsonPath);
  }

  return {
    merged,
    profileOpts,
    paths: { json: jsonPath, markdown: mdPath, sarif: sarifPath },
    mdOpts,
    hasSevere: merged.findings.some((f) => f.severity === "critical" || f.severity === "high"),
  };
}

export function writeScanReports(result, paths, mdOpts, opts = {}) {
  const { quiet = false, json = false, writeSarif = true } = opts;

  if (json) {
    console.log(JSON.stringify(result.merged, null, 2));
  } else if (!quiet) {
    printReport(result.merged, { verbose: opts.verbose });
  } else {
    printFindings(result.merged.findings);
  }

  if (paths.json) writeJsonReport(result.merged, paths.json);
  if (paths.markdown) writeMarkdownReport(result.merged, paths.markdown, mdOpts);
  if (writeSarif && paths.sarif) writeSarifReport(result.merged, paths.sarif);

  return paths;
}
