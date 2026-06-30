/**
 * Penthera — Report Formatter
 *
 * Terminal output with ANSI colors, JSON export, SARIF export.
 */
import { writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { resolveWstgTags } from "../lib/owasp-wstg.js";

const PKG_VERSION = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf-8"),
).version;

// ── ANSI helpers ─────────────────────────────────────────────────────────

const NO_COLOR = !!process.env.NO_COLOR;

const ansi = (code) => (s) => NO_COLOR ? s : `\x1b[${code}m${s}\x1b[0m`;

const c = {
  bold:    ansi("1"),
  dim:     ansi("2"),
  red:     ansi("31"),
  green:   ansi("32"),
  yellow:  ansi("33"),
  cyan:    ansi("36"),
  magenta: ansi("35"),
  bgRed:   (s) => NO_COLOR ? s : `\x1b[41;37;1m${s}\x1b[0m`,
  bgYellow:(s) => NO_COLOR ? s : `\x1b[43;30;1m${s}\x1b[0m`,
};

const SEV_COLOR = {
  critical: c.bgRed,
  high:     c.red,
  medium:   c.yellow,
  low:      c.cyan,
  info:     c.dim,
};

const SEV_LABEL = {
  critical: "CRIT",
  high:     "HIGH",
  medium:   "MED ",
  low:      "LOW ",
  info:     "INFO",
};

function pad(s, n) { return (s + " ".repeat(n)).slice(0, n); }
function line(char = "\u2500", len = 58) { return char.repeat(len); }

// ── Terminal report ──────────────────────────────────────────────────────

export function printReport(result, opts = {}) {
  const out = process.stdout;
  const w = (s) => out.write(s + "\n");

  w("");
  w(`  ${c.bold("penthera")} ${c.dim("security scanner")}`);
  w("");

  // Target info
  if (result.target) w(`  Target     ${c.cyan(result.target)}`);
  if (result.timestamp) w(`  Started    ${result.timestamp.replace("T", " ").slice(0, 19)}`);
  if (result.duration) w(`  Duration   ${(result.duration / 1000).toFixed(1)}s`);
  if (result.modes) w(`  Modes      ${result.modes.join(", ")}`);
  else if (result.mode) w(`  Mode       ${result.mode}`);
  w("");

  // TLS
  if (result.tls && result.tls.protocol) {
    w(`  ${c.dim(line())}`);
    w(`  ${c.bold("TLS/SSL")}`);
    w("");
    const t = result.tls;
    w(`  Protocol   ${t.protocol === "TLSv1.3" ? c.green(t.protocol) : t.protocol}`);
    w(`  Cipher     ${t.cipher}`);
    w(`  Issuer     ${t.issuer}`);
    w(`  Subject    ${t.subject}`);
    w(`  Expires    ${t.validTo?.slice(0, 10) || "unknown"} ${t.daysUntilExpiry != null ? c.dim(`(${t.daysUntilExpiry}d)`) : ""}`);
    w(`  Valid      ${t.valid ? c.green("yes") : c.red("no" + (t.error ? ` — ${t.error}` : ""))}`);
    w("");
  }

  // Fingerprint
  if (result.fingerprint) {
    w(`  ${c.dim(line())}`);
    w(`  ${c.bold("Fingerprint")}`);
    w("");
    const fp = result.fingerprint;
    if (fp.framework) w(`  Framework  ${fp.framework}`);
    if (fp.server)    w(`  Server     ${fp.server}`);
    if (fp.cdn)       w(`  CDN        ${fp.cdn}`);
    if (fp.security?.length > 0) {
      w(`  Headers    ${c.green(fp.security.join(", "))}`);
    } else {
      w(`  Headers    ${c.yellow("no security headers detected")}`);
    }
    w("");
  }

  // OSINT Recon
  if (result.recon) {
    w(`  ${c.dim(line())}`);
    w(`  ${c.bold("OSINT Recon")}`);
    w("");
    const r = result.recon;
    if (r.subdomains?.length > 0) {
      w(`  Subdomains ${c.bold(String(r.subdomains.length))} discovered ${c.dim("(crt.sh)")}`);
      if (opts.verbose) {
        for (const sub of r.subdomains.slice(0, 20)) {
          w(`    ${c.dim(sub)}`);
        }
        if (r.subdomains.length > 20) w(`    ${c.dim(`... and ${r.subdomains.length - 20} more`)}`);
      }
    }
    if (r.endpoints?.length > 0) {
      w(`  Endpoints  ${c.bold(String(r.endpoints.length))} historical paths ${c.dim("(Wayback + OTX)")}`);
    }
    if (r.parameters?.length > 0) {
      w(`  Parameters ${r.parameters.length} unique names ${c.dim(r.parameters.slice(0, 8).join(", "))}`);
    }
    const src = r.sources || {};
    w(`  Sources    crt.sh:${src.crtsh || 0}  wayback:${src.wayback || 0}  otx:${src.otx || 0}`);
    w("");
  }

  // Endpoints
  if (result.endpoints && result.endpoints.discovered > 0) {
    w(`  ${c.dim(line())}`);
    w(`  ${c.bold("Discovery")}`);
    w("");
    w(`  Probed     ${result.endpoints.total} paths`);
    w(`  Found      ${c.bold(String(result.endpoints.discovered))} live endpoints`);
    const byStatus = result.endpoints.byStatus || {};
    const statusLine = Object.entries(byStatus)
      .sort(([a], [b]) => Number(a) - Number(b))
      .map(([s, n]) => `${s}:${n}`)
      .join("  ");
    if (statusLine) w(`  Status     ${c.dim(statusLine)}`);
    w("");
  }

  // Attack surface (repo scan)
  if (result.attackSurface && result.attackSurface.length > 0) {
    w(`  ${c.dim(line())}`);
    w(`  ${c.bold("Attack Surface")}`);
    w("");
    const b = result.boundaries || {};
    w(`  Routes     ${c.bold(String(result.attackSurface.length))} discovered`);
    if (b.public)    w(`  Public     ${b.public.length}`);
    if (b.userAuth)  w(`  User auth  ${b.userAuth.length}`);
    if (b.adminAuth) w(`  Admin auth ${b.adminAuth.length}`);
    if (b.cronAuth)  w(`  Cron auth  ${b.cronAuth.length}`);

    if (opts.verbose && result.attackSurface.length > 0) {
      w("");
      for (const r of result.attackSurface) {
        const methods = r.methods.join(",");
        const auth = r.auth.join(",");
        w(`  ${c.dim(pad(methods, 12))} ${pad(r.url, 30)} ${c.dim(auth)}`);
      }
    }
    w("");
  }

  // Machine Audit
  if (result.machine) {
    const m = result.machine;
    w(`  ${c.dim(line())}`);
    w(`  ${c.bold("Machine Audit")}`);
    w("");

    // System posture
    for (const check of m.checks || []) {
      if (check.status) {
        const ok = check.status === "enabled" || check.status === "on" || check.status.startsWith("Version");
        const display = check.status.length > 30 ? check.status.slice(0, 30) + "..." : check.status;
        w(`  ${pad(check.name, 36)} ${ok ? c.green(display) : c.red(display)}`);
      }
    }
    w("");

    // Persistence
    if (m.persistence?.length > 0) {
      const unknown = m.persistence.filter((p) => !p.known);
      const known = m.persistence.filter((p) => p.known);
      w(`  Persistence  ${c.bold(String(m.persistence.length))} items ${c.dim(`(${known.length} known, ${unknown.length} unknown)`)}`);
      if (opts.verbose) {
        for (const p of unknown) {
          const sig = p.signed === false ? c.red(" UNSIGNED") : p.signed ? c.green(" signed") : "";
          w(`    ${c.yellow("?")} ${p.label}${sig}`);
          w(`      ${c.dim(p.program)}`);
        }
      }
    }

    // Network
    if (m.network?.length > 0) {
      w(`  Connections  ${c.bold(String(m.network.length))} established outbound`);
      if (opts.verbose) {
        const byProcess = {};
        for (const conn of m.network) {
          byProcess[conn.process] = (byProcess[conn.process] || 0) + 1;
        }
        const top = Object.entries(byProcess).sort((a, b) => b[1] - a[1]).slice(0, 10);
        for (const [proc, count] of top) {
          w(`    ${c.dim(pad(proc, 20))} ${count} connection${count > 1 ? "s" : ""}`);
        }
      }
    }

    // Browser extensions
    if (m.browserExtensions?.length > 0) {
      w(`  Extensions   ${c.bold(String(m.browserExtensions.length))} Chrome extensions`);
      if (opts.verbose) {
        for (const ext of m.browserExtensions) {
          w(`    ${c.dim(pad(ext.name, 30))} v${ext.version}`);
        }
      }
    }

    // Login items
    if (m.loginItems?.length > 0) {
      w(`  Login items  ${m.loginItems.join(", ")}`);
    }

    // rkhunter stats
    const rkCheck = (m.checks || []).find((c) => c.name === "rkhunter");
    if (rkCheck) {
      const fp = rkCheck.filteredFalsePositives || 0;
      const real = rkCheck.realWarnings || 0;
      w(`  rkhunter     ${real === 0 ? c.green("clean") : c.yellow(real + " warning" + (real > 1 ? "s" : ""))}${fp > 0 ? c.dim(` (${fp} macOS false positives filtered)`) : ""}`);
    }

    // ClamAV stats
    const clamCheck = (m.checks || []).find((c) => c.name === "ClamAV");
    if (clamCheck) {
      w(`  ClamAV       ${clamCheck.infected === 0 ? c.green("clean") : c.red(clamCheck.infected + " infected")} ${c.dim(`(scanned ${clamCheck.scanned})`)}`);
    }

    // Optional tools status
    if (m.tools) {
      const toolStatus = Object.entries(m.tools)
        .map(([name, ok]) => ok ? c.green(name) : c.dim(name))
        .join(c.dim(" · "));
      w(`  Tools        ${toolStatus}`);
    }

    // Missing tools advisory
    if (m.missing?.length > 0) {
      w("");
      w(`  ${c.dim("Install for deeper scans:")}`);
      for (const t of m.missing) {
        w(`    ${c.dim("brew install " + t.split("(")[0].trim().toLowerCase())}`);
      }
    }

    w("");
  }

  // Cookies
  if (result.cookies && result.cookies.length > 0) {
    w(`  ${c.dim(line())}`);
    w(`  ${c.bold("Cookies")}`);
    w("");
    for (const ck of result.cookies) {
      const flags = [];
      flags.push(ck.httpOnly ? c.green("HttpOnly") : c.red("HttpOnly"));
      flags.push(ck.secure ? c.green("Secure") : (result.local ? c.dim("Secure") : c.red("Secure")));
      flags.push(ck.sameSite ? c.green(`SameSite=${ck.sameSite}`) : c.yellow("SameSite"));
      w(`  ${pad(ck.name, 24)} ${flags.join(c.dim(" · "))}`);
    }
    w("");
  }

  // JS Libraries (Retire.js)
  if (result.jsLibraries && result.jsLibraries.length > 0) {
    w(`  ${c.dim(line())}`);
    w(`  ${c.bold("JS Libraries")}`);
    w("");
    for (const lib of result.jsLibraries) {
      const vulnCount = lib.vulnerabilities?.length || 0;
      const status = vulnCount > 0
        ? c.red(`${vulnCount} known vuln${vulnCount > 1 ? "s" : ""}`)
        : c.green("no known vulns");
      w(`  ${pad(lib.name, 20)} ${c.dim("v")}${lib.version}  ${status}`);
      if (opts.verbose && lib.vulnerabilities) {
        for (const v of lib.vulnerabilities) {
          const cves = v.cves?.join(", ") || "no CVE";
          w(`    ${c.dim(`↳ ${v.severity} — ${cves} (< ${v.below || "latest"})`)}`);
        }
      }
    }
    w("");
  }

  // Parameter Discovery
  if (result.paramDiscovery && result.paramDiscovery.length > 0) {
    w(`  ${c.dim(line())}`);
    w(`  ${c.bold("Parameters")}`);
    w("");
    for (const pd of result.paramDiscovery) {
      w(`  ${pad(pd.path, 30)} ${c.bold(String(pd.params.length))} active ${c.dim(pd.params.slice(0, 6).join(", "))}`);
    }
    w("");
  }

  // Findings
  if (result.findings && result.findings.length > 0) {
    w(`  ${c.dim(line())}`);
    w(`  ${c.bold("Findings")}`);
    w("");

    const sorted = [...result.findings].sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
    });

    for (const f of sorted) {
      const colorFn = SEV_COLOR[f.severity] || c.dim;
      const label = SEV_LABEL[f.severity] || "    ";
      w(`  ${colorFn(label)}  ${f.title}`);
      if (f.url)  w(`  ${" ".repeat(6)} ${c.dim(f.url)}${f.status ? c.dim(` \u2192 ${f.status}`) : ""}`);
      if (f.description && opts.verbose) w(`  ${" ".repeat(6)} ${c.dim(f.description)}`);
    }
    w("");
  } else if (result.findings) {
    w(`  ${c.dim(line())}`);
    w(`  ${c.green("No findings")} \u2014 looking good.`);
    w("");
  }

  // Summary
  w(`  ${c.dim(line())}`);
  printSummaryLine(result, w);
  w("");
}

function printSummaryLine(result, w) {
  const findings = result.findings || [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  const parts = [];
  if (counts.critical) parts.push(c.bgRed(` ${counts.critical} critical `));
  if (counts.high)     parts.push(c.red(`${counts.high} high`));
  if (counts.medium)   parts.push(c.yellow(`${counts.medium} medium`));
  if (counts.low)      parts.push(c.cyan(`${counts.low} low`));
  if (counts.info)     parts.push(c.dim(`${counts.info} info`));

  if (parts.length === 0) {
    w(`  ${c.green("\u2713")} Clean scan \u2014 no issues found`);
  } else {
    w(`  ${parts.join(c.dim(" \u00b7 "))}`);
  }
}

// ── Findings-only output (--quiet) ───────────────────────────────────────

export function printFindings(findings) {
  if (!findings || findings.length === 0) return;
  const sorted = [...findings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
  });
  for (const f of sorted) {
    const label = (SEV_LABEL[f.severity] || "INFO").trim();
    console.log(`[${label}] ${f.title}${f.url ? ` (${f.url})` : ""}`);
  }
}

// ── JSON export ──────────────────────────────────────────────────────────

export function writeJsonReport(result, filePath) {
  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, JSON.stringify(result, null, 2) + "\n");
}

// ── SARIF export (GitHub Security tab integration) ───────────────────────

const SARIF_SEV_MAP = {
  critical: "error",
  high:     "error",
  medium:   "warning",
  low:      "note",
  info:     "note",
};

/**
 * Generate SARIF 2.1.0 report from scan results.
 * SARIF = Static Analysis Results Interchange Format
 * Uploads to GitHub via: gh api repos/{owner}/{repo}/code-scanning/sarifs
 */
export function writeSarifReport(result, filePath) {
  const rules = new Map();
  const results = [];

  for (const f of result.findings || []) {
    const ruleId = f.templateId || f.category || "unknown";

    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: f.title,
        shortDescription: { text: f.title },
        fullDescription: { text: f.description || f.title },
        defaultConfiguration: {
          level: SARIF_SEV_MAP[f.severity] || "note",
        },
        properties: {
          "security-severity": sevToScore(f.severity),
          tags: ["security", f.category || "general", ...(f.wstg || resolveWstgTags(f))].filter(Boolean),
        },
      });
    }

    results.push({
      ruleId,
      level: SARIF_SEV_MAP[f.severity] || "note",
      message: {
        text: `${f.title}${f.description ? `: ${f.description}` : ""}`,
      },
      locations: f.url ? [{
        physicalLocation: {
          artifactLocation: {
            uri: f.url,
            uriBaseId: "%SRCROOT%",
          },
        },
      }] : [],
      properties: {
        severity: f.severity,
        source: f.source,
        httpStatus: f.status,
        wstg: f.wstg || resolveWstgTags(f),
      },
    });
  }

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "penthera",
          version: PKG_VERSION,
          informationUri: "https://github.com/danoszz/penthera",
          rules: [...rules.values()],
        },
      },
      results,
      invocations: [{
        executionSuccessful: true,
        startTimeUtc: result.timestamp,
        endTimeUtc: new Date().toISOString(),
      }],
    }],
  };

  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, JSON.stringify(sarif, null, 2) + "\n");
}

function sevToScore(severity) {
  switch (severity) {
    case "critical": return "9.5";
    case "high":     return "7.5";
    case "medium":   return "5.0";
    case "low":      return "2.5";
    default:         return "1.0";
  }
}

// ── Progress logger ──────────────────────────────────────────────────────

export function createProgress(quiet) {
  if (quiet) return () => {};
  return (msg) => process.stderr.write(`  ${c.dim("\u25b8")} ${msg}\n`);
}

export function printError(msg) {
  process.stderr.write(`\n  ${c.red("error")} ${msg}\n\n`);
}
