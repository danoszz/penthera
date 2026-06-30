#!/usr/bin/env node
/**
 * Validate a Penthera JSON scan report.
 * Usage: node skills/penthera/scripts/validate-report.mjs [report.json]
 */
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

const reportPath = resolve(process.argv[2] || "reports/scan.json");

function fail(msg) {
  console.error(`validate-report: ERROR: ${msg}`);
  process.exit(1);
}

function ok(msg) {
  console.log(`validate-report: OK: ${msg}`);
}

if (!existsSync(reportPath)) {
  fail(`Report not found: ${reportPath}`);
}

let report;
try {
  report = JSON.parse(readFileSync(reportPath, "utf-8"));
} catch (e) {
  fail(`Invalid JSON: ${e.message}`);
}

if (!report.timestamp || typeof report.timestamp !== "string") {
  fail("Missing or invalid 'timestamp' field");
}

if (!Array.isArray(report.findings)) {
  fail("Missing or invalid 'findings' array");
}

const requiredFindingFields = ["severity", "title"];
for (const [i, f] of report.findings.entries()) {
  for (const field of requiredFindingFields) {
    if (!f[field]) fail(`Finding #${i} missing '${field}'`);
  }
  const validSev = ["critical", "high", "medium", "low", "info"];
  if (!validSev.includes(f.severity)) {
    fail(`Finding #${i} has invalid severity: ${f.severity}`);
  }
}

const mdPath = reportPath.replace(/\.json$/i, ".md");
if (existsSync(mdPath)) ok(`Companion Markdown found: ${mdPath}`);

ok(`${report.findings.length} findings in ${reportPath}`);
