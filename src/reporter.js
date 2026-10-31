/**
 * Penthera, Report Formatter
 *
 * Terminal output with ANSI colors, JSON export, SARIF export.
 */
import { writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { resolveWstgTags } from "../lib/owasp-wstg.js";
import { referencesFor } from "../lib/references.js";
import { formatDepsTerminal, uncheckedDeps } from "../lib/deps/report.js";
import { describeCoverage } from "../lib/coverage.js";
import { giantsTerminalLines, foundByText } from "./report/giants.js";
import { exitCodeOf, exitNote, exitReason } from "./report/exit.js";
import { toolById } from "../lib/giants/tools.js";

const PKG_VERSION = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf-8"),
).version;

// ── ANSI helpers ─────────────────────────────────────────────────────────

// TODO(good-first-issue): also drop colors when stdout is not a TTY (piped output gets escape codes); let FORCE_COLOR=1 override.
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
  if (result.giants) {
    const ran = result.giants.tools.filter((t) => t.status === "ran").map((t) => t.id);
    w(`  Others     ${ran.length ? ran.join(", ") : "no other tool ran"}${c.dim(result.giants.online ? " (--giants-online: online features on)" : " (offline)")}`);
  }
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
    w(`  Valid      ${t.valid ? c.green("yes") : c.red("no" + (t.error ? `, ${t.error}` : ""))}`);
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

  // Dependencies (penthera deps)
  if (result.deps) {
    w(`  ${c.dim(line())}`);
    w(`  ${c.bold("Dependencies")}`);
    w("");
    for (const l of formatDepsTerminal(result.deps, c, opts)) w(l);
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
          w(`    ${c.dim(`↳ ${v.severity}, ${cves} (< ${v.below || "latest"})`)}`);
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

  // Agent configuration (penthera agents)
  if (result.agents) {
    const a = result.agents;
    const inv = a.inventory || {};
    const gradeColor = { A: c.green, B: c.green, C: c.yellow, D: c.red, F: c.bgRed }[a.grade] || ((s) => s);
    w(`  ${c.dim(line())}`);
    w(`  ${c.bold("Agent Config")}${a.home ? c.dim("  repo + home") : c.dim("  repo")}`);
    w("");
    w(`  Grade      ${a.grade ? `${gradeColor(` ${a.grade} `)} ${c.dim(`(${a.score}/100)`)}` : c.dim("none, nothing found to assess")}`);
    w(`  Found      ${inv.skills || 0} skills · ${inv.mcpServers || 0} MCP servers · ${inv.hooks || 0} hooks · ${inv.plugins || 0} plugins · ${inv.instructionFiles || 0} rule files`);
    if (a.lock) {
      const l = a.lock;
      const status = l.status === "pinned" ? c.green(`pinned ${l.entries} entries → ${l.path}`)
        : l.status === "checked" ? (l.changed || l.added ? c.yellow(`${l.changed} changed · ${l.added} new · ${l.removed} removed`) : c.green(`all ${l.entries} entries match`))
        : l.status === "corrupt" ? c.red("corrupt") : l.status === "unknown-version" ? c.yellow("unknown version, not compared") : c.dim("none (run with --pin)");
      w(`  Lock       ${status}`);
    }
    for (const n of a.notChecked || []) w(`  ${c.yellow("Not read")}   ${c.dim(String(n).replace(/[\u0000-\u001f\u007f-\u009f]/g, ""))}`);
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
      // Flag the ones a scanner genuinely can't adjudicate, so nobody reads a
      // heuristic as a confirmed break. Certainties stay unannotated.
      const needsReview = f.confidence === "needs-human-review" || f.confidence === "potential";
      const tag = needsReview ? c.dim(` [${f.confidence}]`) : "";
      const ai = f.alsoProposedBy?.length ? c.dim(" [also proposed by AI]") : "";
      const by = foundByText(f) ? c.dim(` [${foundByText(f)}]`) : "";
      w(`  ${colorFn(label)}  ${printable(f.title)}${tag}${ai}${by}${f.fid ? c.dim(`  ${f.fid}`) : ""}`);
      if (f.url)  w(`  ${" ".repeat(6)} ${c.dim(printable(f.url) + (f.line ? `:${f.line}` : "") + (f.lines?.length > 1 ? ` (+${f.lines.length - 1} more)` : ""))}${f.status ? c.dim(` \u2192 ${f.status}`) : ""}`);
      if (f.description && opts.verbose) w(`  ${" ".repeat(6)} ${c.dim(printable(f.description))}`);
    }
    w("");
  } else if (result.findings) {
    w(`  ${c.dim(line())}`);
    const un = uncheckedDeps(result.deps);
    if (un?.none) w(`  ${c.yellow("Not checked")}: no package code was read. See "Not read" above.`);
    else if (exitNote(result)) { /* the summary says why the run fails */ }
    else if (un) w(`  ${c.green("No findings")} in the ${un.total - un.missing} packages read; ${c.yellow(`${un.missing} were not read`)} (see above).`);
    else if (nothingToAssess(result)) w(`  ${c.yellow("Not checked")}: no agent config was read. See "Not read" above.`);
    else w(`  ${c.green("No findings")}.`);
    w("");
  }

  // Suppressed by local memory or the repo's penthera.suppress.json (--memory).
  // Always listed with who suppressed it and why, so nothing disappears silently.
  if (result.suppressed?.length) {
    w(`  ${c.dim(line())}`);
    w(`  ${c.bold("Suppressed")} ${c.dim(`(${result.suppressed.length}, not counted above)`)}`);
    w("");
    for (const f of result.suppressed) {
      w(`  ${c.dim(SEV_LABEL[f.severity] || "    ")}  ${f.title}${c.dim(`  ${f.fid}`)}`);
      w(`  ${" ".repeat(6)} ${c.yellow(suppressionLabel(f.suppression))}: ${c.dim(stripControl(f.suppression?.reason))}`);
    }
    w("");
  }

  // Compliance summary
  if (result.compliance) {
    const s = result.compliance.summary;
    w(`  ${c.dim(line())}`);
    w(`  ${c.bold("Compliance")} ${c.dim(result.compliance.name)}`);
    w("");
    w(`  Coverage   ${c.bold(`${s.coveredThisScan}/${s.testable}`)} testable Article 21 measures exercised this scan`);
    w(`  ${c.dim("Technical evidence toward the duty of care, not a certification. Full mapping in the Markdown report.")}`);
    w("");
  }

  // Coverage: what the repo scan read, and where it did not look
  if (result.coverage) {
    const cov = result.coverage;
    w(`  ${c.dim(line())}`);
    w(`  ${c.bold("Coverage")} ${c.dim("what was read, and what was not")}`);
    w("");
    for (const { family, text } of describeCoverage(cov)) w(`  ${pad(family, 32)} ${text}`);
    if (cov.blindSpots.count > 0) {
      w(`  ${c.yellow(`${cov.blindSpots.count} of ${cov.sourceFiles}`)} source files not analysed by route analysis ${c.dim("(listed in the Markdown and JSON reports)")}`);
    }
    w(`  ${c.dim(`Not part of a repo scan: ${cov.notRun.map((n) => n.command).join(", ")}`)}`);
    w("");
  }

  // --giants: what each area had besides Penthera, and what other tools reported
  if (result.giants) {
    w(`  ${c.dim(line())}`);
    for (const l of giantsTerminalLines(result.giants, c, { pad, sevLabel: SEV_LABEL, sevColor: SEV_COLOR })) w(l);
    w("");
  }

  // AI mode: what the model proposed, and what Penthera's rules made of it
  if (result.ai) {
    w(`  ${c.dim(line())}`);
    for (const l of aiTerminalLines(result.ai, c)) w(l);
    w("");
  }

  // Network egress: which hosts this scan talked to besides the target
  if (result.egress) {
    const e = result.egress;
    w(`  ${c.dim(line())}`);
    w(`  ${c.bold("Network")}${e.offline ? c.dim(" --offline") : ""}`);
    w("");
    if (e.thirdPartyHosts.length === 0) {
      w(`  Contacted  ${c.green("scan target only")} ${c.dim(`(${e.target})`)}`);
    } else {
      w(`  Contacted  ${e.thirdPartyHosts.length} third-party host${e.thirdPartyHosts.length > 1 ? "s" : ""} besides the target`);
      for (const h of e.thirdPartyHosts) w(`    ${c.dim(pad(h.host, 36))} ${h.requests} request${h.requests > 1 ? "s" : ""}`);
    }
    if (e.blocked.length > 0) {
      w(`  Blocked    ${e.blocked.map((h) => h.host).join(", ")}`);
    }
    if (result.retireDb) {
      w(`  Retire.js  ${result.retireDb.source === "snapshot" ? `vendored snapshot ${c.dim(`(${String(result.retireDb.snapshotDate).slice(0, 10)})`)}` : "live database"}`);
    }
    w("");
  }

  // Summary
  w(`  ${c.dim(line())}`);
  printSummaryLine(result, w);
  printInconclusiveLine(result, w, opts);
  w("");
}

/** The AI section of the terminal report. Model text is stripped of control characters. */
export function aiTerminalLines(ai, colors = c) {
  const L = [];
  if (ai.ran === false) {
    L.push(`  ${colors.bold("AI mode")} ${colors.dim("did not run")}`);
    L.push(`  ${stripControl(ai.reason)}`);
    return L;
  }
  const where = ai.route === "local" ? "on this computer · nothing sent off it" : `on ${ai.forwardedTo} · code sent there through your local Ollama`;
  L.push(`  ${colors.bold("AI mode")} ${colors.dim(`${ai.model.name} ${where}`)}`);
  L.push("");
  L.push(`  Read       ${ai.units.examined} of ${ai.units.units} code parts${ai.partial ? colors.yellow(` (partial: ${ai.stopReason})`) : ""}`);
  L.push(`  Confirmed  ${colors.green(String(ai.counts["confirmed-by-rule"]))} by a Penthera rule ${colors.dim("(marked in the findings above)")}`);
  L.push(`  Unverified ${colors.yellow(String(ai.counts.unverified))} model-proposed ${colors.dim("(a person should look; never fails CI)")}`);
  const notKept = ai.counts["location-not-found"] + ai.counts["out-of-scope"];
  if (notKept) L.push(`  Not kept   ${notKept} pointed at a line or file that is not there`);
  for (const f of ai.findings.slice(0, 10)) {
    L.push(`    ${colors.dim("?")} ${stripControl(f.title)} ${colors.dim(`${stripControl(f.url)}:${f.line}`)}`);
  }
  if (ai.findings.length > 10) L.push(colors.dim(`    …and ${ai.findings.length - 10} more in the reports`));
  return L;
}

export function suppressionLabel(s) {
  return s?.source === "repo-file" ? "suppressed by repo file (penthera.suppress.json)" : "suppressed by local memory";
}

function stripControl(str) {
  return String(str ?? "").replace(/[\u0000-\u001f\u007f-\u009f]/g, "?");
}

/** Probes whose requests failed: the scan could not decide, so say so. */
function printInconclusiveLine(result, w, opts = {}) {
  const errors = result.errors || [];
  if (errors.length === 0) return;
  const probes = [...new Set(errors.map((e) => e.probe))];
  w(`  ${c.yellow(`${probes.length} probe${probes.length > 1 ? "s" : ""} inconclusive`)} ${c.dim(`(${probes.join(", ")})`)}`);
  if (opts.verbose) {
    for (const e of errors) {
      w(`    ${c.dim(`${e.probe}: ${e.message}${e.count > 1 ? ` (x${e.count})` : ""}, ${e.url}`)}`);
    }
  }
}

/** File names and skill names reach titles: no terminal escapes from a scanned repo. */
const printable = (s) => String(s).replace(/[\u0000-\u001f\u007f-\u009f]/g, "");

/** An agents run that read no config has no grade: silence is not a pass. */
function nothingToAssess(result) {
  return !!result.agents && result.agents.grade == null;
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

  const un = uncheckedDeps(result.deps);
  const note = exitNote(result);
  if (parts.length === 0 && note) {
    // The note below stands alone: nothing here reads as clean.
  } else if (parts.length === 0 && un) {
    w(`  ${c.yellow(un.none ? `Not checked: 0 of ${un.total} packages read` : `No issues in what was read; ${un.missing} of ${un.total} packages not read`)}`);
  } else if (parts.length === 0 && nothingToAssess(result)) {
    w(`  ${c.yellow("Nothing to assess, which is not a clean result")}`);
  } else if (parts.length === 0) {
    w(`  ${c.green("\u2713")} Clean scan, no issues found`);
  } else {
    w(`  ${parts.join(c.dim(" \u00b7 "))}`);
  }
  if (note) w(`  ${c.red(printable(note))}`);
  // A person at a terminal gets the same next step the brief gives an agent.
  const first = findings.find((f) => f.severity === "critical") || findings.find((f) => f.severity === "high");
  if (first) {
    w("");
    w(`  ${c.bold("Fix first:")} ${printable(first.title)}`);
    if (first.remediation) w(`  ${printable(first.remediation)}`);
    w(`  ${c.dim("Next:")} npx penthera ui --open ${c.dim("walks you through every problem")}`);
  }
  const other = result.giants?.findings || [];
  if (other.length) {
    const o = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of other) o[f.severity] = (o[f.severity] || 0) + 1;
    const op = Object.entries(o).filter(([, n]) => n).map(([s, n]) => `${n} ${s}`);
    w(`  ${c.dim(`and from other tools: ${op.join(" \u00b7 ")}${result.giants.failOn === "never" ? " (not counted toward the exit code)" : ""}`)}`);
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
    console.log(`[${label}] ${printable(f.title)}${f.url ? ` (${printable(f.url)})` : ""}`);
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
 * Convert a finding location (target URL or path) into a SARIF-safe relative
 * URI. GitHub Code Scanning rejects absolute http(s) URIs ("scheme http did
 * not match checkout scheme file"), so strip the scheme and port and keep a
 * host/path string. The full original URL is preserved in properties.url.
 */
function toSarifUri(location) {
  if (!location) return undefined;
  try {
    const u = new URL(location);
    const path = `${u.hostname}${u.pathname}`.replace(/\/+$/, "").replace(/^\/+/, "");
    return path || u.hostname;
  } catch {
    return String(location).replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/^\/+/, "");
  }
}

/**
 * Generate SARIF 2.1.0 report from scan results.
 * SARIF = Static Analysis Results Interchange Format
 * Uploads to GitHub via: gh api repos/{owner}/{repo}/code-scanning/sarifs
 */
export function writeSarifReport(result, filePath) {
  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, JSON.stringify(formatSarif(result), null, 2) + "\n");
}

/** The SARIF 2.1.0 object for a scan result. */
export function formatSarif(result) {
  const rules = new Map();
  const results = [];

  // GitHub code scanning requires a location on every result. Findings about
  // the target as a whole (no SPF record, no API routes found) point at the
  // scanned host, or at the repository root for a repo scan.
  const fallbackUri = /^https?:\/\//i.test(result.target || "") ? toSarifUri(result.target) : ".";

  for (const f of result.findings || []) {
    const ruleId = f.templateId || f.category || "unknown";

    const refs = referencesFor(f);

    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: f.title,
        shortDescription: { text: f.title },
        fullDescription: { text: f.description || f.title },
        // Research and standards behind the rule (lib/references.json), so a
        // reviewer in GitHub code scanning can see why it is reported.
        ...(refs.length && {
          helpUri: refs[0].url,
          help: {
            text: `Sources: ${refs.map((r) => `${r.cite}, ${r.title} (${r.url})`).join("; ")}`,
            markdown: `**Sources:** ${refs.map((r) => `[${r.cite}](${r.url}), *${r.title}*`).join("; ")}`,
          },
        }),
        defaultConfiguration: {
          level: SARIF_SEV_MAP[f.severity] || "note",
        },
        properties: {
          "security-severity": sevToScore(f.severity),
          tags: ["security", f.category || "general", ...(f.wstg || resolveWstgTags(f))].filter(Boolean),
          ...(refs.length && { references: refs.map((r) => r.key) }),
        },
      });
    }

    results.push({
      ruleId,
      level: SARIF_SEV_MAP[f.severity] || "note",
      message: {
        text: `${f.title}${f.description ? `: ${f.description}` : ""}`,
      },
      locations: [{
        physicalLocation: {
          artifactLocation: {
            uri: f.url ? toSarifUri(f.url) : fallbackUri,
          },
          ...(f.url && Number.isInteger(f.line) && f.line > 0 ? { region: { startLine: f.line } } : {}),
        },
      }],
      // Every other place the same rule hit in this file (secret scan `lines`).
      ...(f.url && Array.isArray(f.lines) && f.lines.length > 1 ? {
        relatedLocations: f.lines.filter((l) => Number.isInteger(l) && l > 0 && l !== f.line).slice(0, 50).map((l, id) => ({
          id,
          physicalLocation: { artifactLocation: { uri: toSarifUri(f.url) }, region: { startLine: l } },
        })),
      } : {}),
      properties: {
        severity: f.severity,
        // Provenance travels with the finding into GitHub code scanning, so a
        // heuristic result stays labelled as one wherever it is consumed.
        confidence: f.confidence,
        source: f.source,
        method: f.method,
        collectedAt: f.collected_at,
        url: f.url,
        httpStatus: f.status,
        wstg: f.wstg || resolveWstgTags(f),
        ...(f.foundBy?.length > 1 ? { foundBy: f.foundBy } : {}),
        ...(f.sources?.length ? { sources: f.sources } : {}),
        ...(f.alsoReportedBy?.length ? { alsoReportedBy: f.alsoReportedBy } : {}),
      },
    });
  }

  // Model-proposed findings (AI mode) get their own run, as notes, so code
  // scanning can filter them and they never pass for rule findings.
  const aiRun = result.ai?.findings?.length && !result._aiRun
    ? formatSarif({ timestamp: result.timestamp, findings: result.ai.findings.map((f) => ({ ...f, templateId: `llm-audit/${f.class}` })), _aiRun: true }).runs[0]
    : null;
  if (aiRun) {
    aiRun.tool.driver.name = "penthera-ai";
    for (const r of aiRun.results) r.level = "note";
    for (const d of aiRun.tool.driver.rules) d.defaultConfiguration.level = "note";
  }

  // --giants: one run per other tool, with that tool's name and version, so
  // code scanning shows each tool honestly. A finding several tools reported
  // goes in the run of the first; properties.foundBy names the others.
  const toolRuns = [];
  if (!result._aiRun && !result._toolRun) {
    for (const t of result.giants?.tools || []) {
      if (t.status !== "ran") continue;
      const mine = (result.giants.findings || []).filter((f) => f.sources?.[0]?.tool === t.id);
      const run = formatSarif({ timestamp: result.timestamp, target: result.target, findings: mine.map((f) => ({ ...f, templateId: f.sources[0].ruleId })), _toolRun: true }).runs[0];
      run.tool.driver = { name: t.id, ...(t.version ? { version: t.version } : {}), informationUri: toolById(t.id)?.homepage, rules: run.tool.driver.rules };
      for (const r of run.tool.driver.rules) {
        const f = mine.find((x) => x.sources[0].ruleId === r.id);
        if (f?.sources[0].ruleUrl) r.helpUri = f.sources[0].ruleUrl;
      }
      run.invocations = [{ executionSuccessful: true, exitCode: t.exitCode ?? undefined, commandLine: t.command || undefined }];
      toolRuns.push(run);
    }
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
        executionSuccessful: exitCodeOf(result) !== 2,
        startTimeUtc: result.timestamp,
        endTimeUtc: new Date().toISOString(),
        // No result, so no alert: an empty run must still say it read nothing,
        // and a run with a required tool missing must say so.
        ...(exitCodeOf(result) === 2 ? { toolExecutionNotifications: [{ level: "error", message: { text: exitReason(result) } }] } : {}),
        ...(exitCodeOf(result) !== 2 && nothingToAssess(result) ? { toolExecutionNotifications: [{ level: "warning", message: { text: result.agents.notChecked?.[0] || "Nothing to assess. This is not a clean result." } }] } : {}),
      }],
    }, ...(aiRun ? [aiRun] : []), ...toolRuns],
  };
  return sarif;
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
