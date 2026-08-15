/**
 * Compliance coverage mapping.
 *
 * Maps a Penthera scan result to a regulatory framework's technical measures,
 * based on which probes ACTUALLY ran (result.executedProbes) and what they
 * found. This is automated technical EVIDENCE toward a duty of care — not a
 * compliance determination, an audit, or a certification. Organisational
 * measures (governance, incident process, training) require human process.
 * See the README "Compliance: NIS2 and the cyberwetgeving" section.
 *
 * Frameworks are declarative so national transpositions and other regimes
 * (CyFun, ISO 27001) can be added as data without touching the engine.
 */

// NIS2 Directive, Article 21(2) risk-management measures. National transpositions
// — NL Cyberbeveiligingswet, BE NIS2-wet — implement these same measures.
//
// level = the inherent ceiling of what a scanner can contribute to the measure:
//   strong   — automated technical testing is the heart of it
//   partial  — a scanner covers part of it
//   evidence — output feeds it, but there is no direct test
//   planned  — not implemented yet
//   out-of-scope — organisational/physical; a scanner cannot do it
const NIS2_MEASURES = [
  { id: "a", title: "Risk analysis & information-security policy", level: "evidence",
    probes: [], categories: [],
    note: "Findings, severity, and baseline history feed your risk analysis." },
  { id: "b", title: "Incident handling", level: "planned",
    probes: [], categories: [],
    note: "Incident-report helper drafts the required 24h/72h/1-month reports (--incident); incident detection itself is not automated." },
  { id: "c", title: "Business continuity, backup & crisis management", level: "out-of-scope",
    probes: [], categories: [],
    note: "Organisational — outside a scanner's reach." },
  { id: "d", title: "Supply-chain security", level: "partial",
    probes: ["retirejs", "secret-scanning"],
    categories: ["cve", "secrets", "js-vulnerability"],
    note: "JS dependency CVEs (Retire.js), leaked credentials (secret scan), a CycloneDX SBOM (--sbom), and passive supplier rating (--suppliers)." },
  { id: "e", title: "Secure acquisition, development & maintenance; vulnerability handling", level: "strong",
    probes: ["reachability", "endpoint-discovery", "openapi", "sensitive-files", "cors",
      "security-headers", "email-dns", "sqli", "ssti", "ssrf", "xss", "cmdi", "open-redirect",
      "api-fuzzing", "risky-patterns"],
    categories: ["*"],
    note: "The core scan: black- and white-box testing mapped to OWASP WSTG, with SARIF and baseline regression." },
  { id: "f", title: "Assessing the effectiveness of measures", level: "evidence",
    probes: [], categories: [],
    note: "Baseline diff plus remediation/audit-loop tracking (--history): time-to-fix, ageing, and drift over time." },
  { id: "g", title: "Cyber hygiene & training", level: "evidence",
    probes: [], categories: [],
    note: "Remediation playbook and secure-defaults guidance feed hygiene (guidance, not a training programme)." },
  { id: "h", title: "Cryptography & encryption", level: "partial",
    probes: ["tls"], categories: ["tls", "cookie"],
    note: "TLS protocol/cipher/certificate audit, HSTS, cookie Secure (transport layer only)." },
  { id: "i", title: "HR security, access control & asset management", level: "partial",
    probes: ["auth-hardening", "client-auth", "jwt", "idor", "oauth", "trust-boundary"],
    categories: ["auth", "auth-bypass"],
    note: "Access control tested (auth hardening, JWT, IDOR/BOLA, OAuth, trust boundaries). HR & asset management out of scope." },
  { id: "j", title: "Multi-factor authentication & secure communications", level: "planned",
    probes: [], categories: [],
    note: "An MFA probe is on the roadmap." },
];

const FRAMEWORKS = {
  nis2: {
    id: "nis2",
    name: "NIS2 Directive — Article 21(2) duty of care",
    measures: NIS2_MEASURES,
  },
};

/** List supported framework ids. */
export function listFrameworks() {
  return Object.keys(FRAMEWORKS);
}

/**
 * Build a per-scan compliance coverage object for a framework.
 * Returns null for an unknown framework id.
 */
export function buildComplianceCoverage(result, frameworkId = "nis2") {
  const fw = FRAMEWORKS[String(frameworkId).toLowerCase()];
  if (!fw) return null;

  const executed = new Set(result?.executedProbes || []);
  const findings = result?.findings || [];

  const measures = fw.measures.map((m) => {
    const probesRun = m.probes.filter((p) => executed.has(p));
    const relevant = m.categories.includes("*")
      ? findings.filter((f) => f.severity !== "info")
      : findings.filter((f) => m.categories.includes(f.category));

    let status;
    if (m.level === "out-of-scope") status = "out-of-scope";
    else if (m.level === "planned") status = "planned";
    else if (m.level === "evidence") status = "evidence";
    else if (probesRun.length > 0) status = relevant.length > 0 ? "tested-findings" : "tested-clean";
    else status = "not-run";

    return {
      id: m.id,
      title: m.title,
      ceiling: m.level,
      status,
      probesRun,
      findings: relevant.length,
      note: m.note,
    };
  });

  const testable = measures.filter((m) => m.ceiling === "strong" || m.ceiling === "partial");
  const coveredThisScan = testable.filter(
    (m) => m.status === "tested-clean" || m.status === "tested-findings",
  );

  return {
    framework: fw.id,
    name: fw.name,
    measures,
    summary: {
      total: measures.length,
      testable: testable.length,
      coveredThisScan: coveredThisScan.length,
      findings: findings.filter((f) => f.severity !== "info").length,
    },
  };
}

const STATUS_LABEL = {
  "tested-clean": "Tested — no gaps found",
  "tested-findings": "Tested — gaps found",
  "not-run": "Not run this scan",
  evidence: "Evidence only",
  planned: "Planned",
  "out-of-scope": "Out of scope",
};

/** Render a compliance coverage object as a Markdown section. */
export function formatComplianceMarkdown(coverage) {
  if (!coverage) return "";
  const L = [];
  L.push(`## Compliance mapping — ${coverage.name}`);
  L.push("");
  L.push(
    "> Automated technical **evidence** toward the duty of care — **not** a compliance " +
    "determination, an audit, or a certification. Organisational measures (governance, " +
    "incident process, supply-chain contracts, training) require human process. Consult " +
    "your national authority (NCSC in the Netherlands, CCB in Belgium) or a qualified jurist.",
  );
  L.push("");
  L.push(
    `This scan exercised technical coverage for **${coverage.summary.coveredThisScan}** of ` +
    `**${coverage.summary.testable}** testable Article 21 measures.`,
  );
  L.push("");
  L.push("| Art. 21(2) | Measure | This scan | Findings |");
  L.push("|-----------|---------|-----------|----------|");
  for (const m of coverage.measures) {
    const label = STATUS_LABEL[m.status] || m.status;
    L.push(`| **(${m.id})** | ${m.title} | ${label} | ${m.findings || "—"} |`);
  }
  L.push("");
  return L.join("\n");
}
