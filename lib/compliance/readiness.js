/**
 * NIS2 readiness report, the "forms/data they need" core.
 *
 * Combines what the scan can measure (technical measures) with a local
 * self-assessment (the organisational measures a scanner can't test) into a
 * per-measure met / partial / gap / n-a report, with proportionality notes and
 * the jurisdiction's incident-reporting duties.
 *
 * Provenance is first-class: every piece of evidence carries
 * `{ source, method, collected_at, confidence }`, so the whole report is
 * reproducible and defensible. Nothing here asserts compliance, it is
 * readiness and self-assessment tooling only.
 */
import { buildComplianceCoverage } from "./index.js";
import { normalizeAnswers, questionsForMeasure } from "./self-assessment.js";

const PROPORTIONALITY = {
  a: "A short written policy plus a basic risk list is proportionate for a small entity.",
  b: "A one-page runbook with roles, contacts, and the NIS2 deadlines is enough to start.",
  c: "Regular backups plus one real restore test per year.",
  d: "A supplier list plus basic security checks or contractual clauses.",
  e: "A patch cadence and a vulnerability-reporting channel; Penthera covers the technical scan.",
  f: "Periodic re-scan and incident review; baseline diffs are your evidence.",
  g: "A short onboarding briefing and occasional reminders.",
  h: "Encryption in transit (scanned) plus encryption at rest for sensitive stores.",
  i: "Least privilege, a joiner/leaver process, and a simple asset list.",
  j: "MFA on email and admin/privileged accounts is the highest-value control here.",
};

function scanStatusOf(coverageStatus) {
  // Maps the scan's per-measure coverage to a readiness contribution. Note that
  // a measure the scanner can't test ("out-of-scope"/"evidence") returns "none",
  // NOT "n/a": it still matters to the company and is driven by attestation. A
  // true N/A only comes from the user attesting "na".
  switch (coverageStatus) {
    case "tested-clean": return "met";
    case "tested-findings": return "partial";
    default: return "none"; // evidence / planned / not-run / out-of-scope
  }
}

function attestStatusOf(measure, answers) {
  const vals = questionsForMeasure(measure).map((q) => answers[q.id]?.answer).filter(Boolean);
  if (vals.length === 0) return "none";
  const real = vals.filter((v) => v !== "na");
  if (real.length === 0) return "na";
  if (real.includes("no")) return "gap";
  if (real.includes("partial")) return "partial";
  return "met";
}

function combine(scanS, attestS) {
  const known = [];
  if (scanS === "met" || scanS === "partial") known.push(scanS);
  if (["met", "partial", "gap"].includes(attestS)) known.push(attestS);
  if (known.length === 0) return attestS === "na" ? "n/a" : "gap";
  if (known.includes("gap")) return "gap";
  if (known.includes("partial")) return "partial";
  return "met";
}

/**
 * Build a readiness report from a scan result and optional self-assessment.
 * @param {object} scanResult - merged scan result (may be near-empty for attestation-only)
 * @param {object} opts - { answers, jurisdiction, generatedAt, assessedAt }
 */
export function buildReadiness(scanResult, opts = {}) {
  const answers = normalizeAnswers(opts.answers || {});
  const coverage = buildComplianceCoverage(scanResult, "nis2") || { measures: [] };
  const scanTs = scanResult?.timestamp || null;

  const measures = coverage.measures.map((m) => {
    const scanS = scanStatusOf(m.status);
    const attestS = attestStatusOf(m.id, answers);
    const status = combine(scanS, attestS);

    const evidence = [];
    for (const p of m.probesRun || []) {
      evidence.push({ source: "scan", method: `probe:${p}`, collected_at: scanTs, confidence: "measured" });
    }
    for (const q of questionsForMeasure(m.id)) {
      const a = answers[q.id];
      if (a) {
        evidence.push({
          source: "self-assessment",
          method: "attestation",
          collected_at: opts.assessedAt || null,
          confidence: "attested",
          question: q.text,
          answer: a.answer,
          note: a.note || "",
        });
      }
    }

    const gaps = [];
    for (const q of questionsForMeasure(m.id)) {
      const a = answers[q.id];
      if (!a) gaps.push({ type: "unanswered", question: q.text });
      else if (a.answer === "no") gaps.push({ type: "not-in-place", question: q.text, note: a.note || "" });
      else if (a.answer === "partial") gaps.push({ type: "partial", question: q.text, note: a.note || "" });
    }

    return {
      id: m.id,
      title: m.title,
      status,
      basis: { scan: scanS, attestation: attestS },
      findings: m.findings,
      evidence,
      gaps,
      proportionality: PROPORTIONALITY[m.id] || "",
    };
  });

  const summary = { met: 0, partial: 0, gap: 0, "n/a": 0 };
  for (const m of measures) summary[m.status] = (summary[m.status] || 0) + 1;
  const assessed = measures.filter((m) => m.basis.attestation !== "none" || m.basis.scan !== "none").length;

  const j = opts.jurisdiction || null;
  return {
    framework: "nis2",
    jurisdiction: j && {
      id: j.id, name: j.name, law: j.law, authorities: j.authorities,
      incidentDeadlines: j.incidentDeadlines, penalties: j.penalties, disclaimer: j.disclaimer,
    },
    generated_at: opts.generatedAt || null,
    measures,
    summary,
    assessedCount: assessed,
    totalMeasures: measures.length,
  };
}

const STATUS_LABEL = { met: "Met", partial: "Partial", gap: "Gap", "n/a": "N/A" };

/** Render a readiness report as Markdown. */
export function formatReadinessMarkdown(readiness) {
  if (!readiness) return "";
  const L = [];
  const j = readiness.jurisdiction;
  L.push(`# NIS2 readiness report${j ? `, ${j.name}` : ""}`);
  L.push("");
  if (j?.law) L.push(`> Framework: **${j.law}** (EU NIS2, Article 21 measures).`);
  L.push("> **Readiness, evidence, and self-assessment tooling, not legal advice, not a certification, and not a guarantee of compliance.**");
  if (j?.disclaimer) { L.push(">"); L.push(`> ${j.disclaimer}`); }
  L.push("");

  const s = readiness.summary;
  L.push(`**Summary:** ${s.met} met · ${s.partial} partial · ${s.gap} gap · ${s["n/a"]} n/a, across ${readiness.totalMeasures} Article 21 measures.`);
  L.push("");
  L.push("Status combines what Penthera measured (technical) with your self-assessment (organisational). *Proportionality applies: for a small entity, a short policy or process that genuinely exists counts.*");
  L.push("");

  L.push("| Art. 21(2) | Measure | Status | Basis |");
  L.push("|-----------|---------|--------|-------|");
  for (const m of readiness.measures) {
    const basis = [
      m.basis.scan !== "none" && m.basis.scan !== "na" ? "scan" : null,
      ["met", "partial", "gap"].includes(m.basis.attestation) ? "attestation" : null,
    ].filter(Boolean).join(" + ") || "not assessed";
    L.push(`| **(${m.id})** | ${m.title} | ${STATUS_LABEL[m.status]} | ${basis} |`);
  }
  L.push("");

  // Per-measure detail
  L.push("## Measures in detail");
  L.push("");
  for (const m of readiness.measures) {
    L.push(`### (${m.id}) ${m.title}, ${STATUS_LABEL[m.status]}`);
    L.push("");
    if (m.evidence.length) {
      L.push("**Evidence**");
      for (const e of m.evidence) {
        if (e.source === "scan") {
          L.push(`- scan · \`${e.method}\` · ${e.collected_at || "-"} · confidence: ${e.confidence}`);
        } else {
          L.push(`- self-assessment · "${e.question}" → **${e.answer}**${e.note ? ` (${e.note})` : ""}`);
        }
      }
      L.push("");
    }
    if (m.gaps.length) {
      L.push("**Gaps / to confirm**");
      for (const g of m.gaps) {
        if (g.type === "unanswered") L.push(`- ❓ Not yet assessed: ${g.question}`);
        else if (g.type === "not-in-place") L.push(`- ❌ Not in place: ${g.question}${g.note ? ` (${g.note})` : ""}`);
        else L.push(`- ⚠️ Partial: ${g.question}${g.note ? ` (${g.note})` : ""}`);
      }
      L.push("");
    }
    if (m.proportionality) { L.push(`*Proportionate baseline:* ${m.proportionality}`); L.push(""); }
  }

  // Incident reporting duties (measure b, practical)
  if (j?.incidentDeadlines?.length) {
    L.push("## Incident-reporting duties");
    L.push("");
    L.push(`Report significant incidents to **${j.authorities?.csirt || "your CSIRT"}** (supervisor: ${j.authorities?.supervisor || "your supervisor"}):`);
    L.push("");
    L.push("| Deadline | When | What |");
    L.push("|----------|------|------|");
    for (const d of j.incidentDeadlines) {
      L.push(`| **${d.within}** | ${d.of} | ${d.content} |`);
    }
    L.push("");
    if (j.penalties) L.push(`> ${j.penalties}`);
    L.push("");
  }

  // What only you can confirm
  const unanswered = readiness.measures.flatMap((m) => m.gaps.filter((g) => g.type === "unanswered").map((g) => g.question));
  if (unanswered.length) {
    L.push("## What only you can confirm");
    L.push("");
    L.push("These are attestations a scan cannot make. Run the self-assessment to record them:");
    L.push("");
    unanswered.forEach((q) => L.push(`- ${q}`));
    L.push("");
    L.push("Start with: `penthera --assessment-init assessment.json`, fill it in, then re-run with `--assessment assessment.json`.");
    L.push("");
  }

  L.push("---");
  L.push("");
  L.push(`*Generated by Penthera${readiness.generated_at ? ` at ${readiness.generated_at}` : ""}. Every item above is provenance-linked (source, method, collected_at, confidence) and reproducible by re-running the scan and self-assessment.*`);
  L.push("");
  return L.join("\n");
}
