/**
 * Incident-report helper (NIS2 measure b).
 *
 * Given the facts of an incident, lay out the reporting timeline (the 24h early
 * warning, 72h notification, and 1-month final report) with real due dates, and
 * produce a draft for each against the jurisdiction's required content. Fields
 * the user hasn't provided are marked NEEDS INPUT — never invented.
 *
 * Offline. Drafts are starting points to send to your CSIRT / authority, not a
 * substitute for the authority's own form or for legal advice.
 */

/** Fields collected about an incident (all optional; blanks become NEEDS INPUT). */
export function incidentTemplate() {
  return {
    _about: "Penthera incident-report helper. Fill in what you know; leave the rest blank. `aware_at` is when you became aware (ISO 8601, e.g. 2026-08-15T09:30:00Z) — it drives the deadlines. Offline; nothing is sent anywhere.",
    title: "",
    aware_at: "",
    detected_at: "",
    description: "",
    systems_affected: "",
    data_affected: "",
    users_affected: "",
    severity: "",
    unlawful_or_malicious: "",
    cross_border: "",
    indicators: "",
    mitigations: "",
    root_cause: "",
    contact: "",
  };
}

function addOffset(date, { offsetHours, offsetMonths }) {
  const x = new Date(date.getTime());
  if (offsetHours) x.setTime(x.getTime() + offsetHours * 3600 * 1000);
  if (offsetMonths) x.setUTCMonth(x.getUTCMonth() + offsetMonths);
  return x;
}

/**
 * Build the reporting timeline and per-deadline drafts.
 * @param {object} incident - fields from incidentTemplate()
 * @param {object} jurisdiction - nl.json (uses incidentDeadlines, authorities)
 */
export function buildIncidentReports(incident = {}, jurisdiction = {}) {
  const deadlines = jurisdiction.incidentDeadlines || [];
  const awareValid = incident.aware_at && !Number.isNaN(new Date(incident.aware_at).getTime());
  const awareness = awareValid ? new Date(incident.aware_at) : null;

  const notif = deadlines.find((d) => d.id === "notification");
  const notifDue = awareness && notif ? addOffset(awareness, notif) : null;

  const dueFor = (d) => {
    if (!awareness) return null;
    const base = d.from === "notification" ? (notifDue || awareness) : awareness;
    return addOffset(base, d).toISOString();
  };

  const timeline = deadlines.map((d) => ({
    id: d.id,
    within: d.within,
    dueBy: dueFor(d),
    to: d.to,
    content: d.content,
  }));

  const v = (field) => {
    const val = incident[field];
    return val && String(val).trim() ? String(val).trim() : null;
  };

  // Which incident fields each report should surface.
  const REPORT_FIELDS = {
    "early-warning": [
      ["unlawful_or_malicious", "Suspected unlawful or malicious"],
      ["cross_border", "Possible cross-border impact"],
      ["description", "What we know so far"],
    ],
    notification: [
      ["description", "Description"],
      ["severity", "Severity"],
      ["systems_affected", "Systems affected"],
      ["data_affected", "Data affected"],
      ["users_affected", "Users affected"],
      ["cross_border", "Cross-border impact"],
      ["indicators", "Indicators of compromise"],
      ["mitigations", "Mitigations so far"],
    ],
    "final-report": [
      ["description", "Detailed description"],
      ["root_cause", "Root cause"],
      ["mitigations", "Mitigations applied and ongoing"],
      ["cross_border", "Cross-border impact"],
      ["severity", "Final severity assessment"],
    ],
  };

  const reports = deadlines.map((d) => ({
    id: d.id,
    within: d.within,
    dueBy: dueFor(d),
    content: d.content,
    fields: (REPORT_FIELDS[d.id] || []).map(([field, label]) => ({
      label,
      value: v(field),
    })),
  }));

  return {
    incident: {
      title: v("title"),
      aware_at: awareValid ? incident.aware_at : null,
      contact: v("contact"),
    },
    authority: jurisdiction.authorities || null,
    timeline,
    reports,
    generated_at: null,
  };
}

/** Render the timeline + drafts as Markdown. */
export function formatIncidentMarkdown(result, opts = {}) {
  if (!result) return "";
  const now = opts.now ? new Date(opts.now) : null;
  const L = [];
  L.push(`# Incident report drafts${result.incident?.title ? ` — ${result.incident.title}` : ""}`);
  L.push("");
  L.push("> **Draft reports to help you meet NIS2 deadlines — not a substitute for your authority's official form or for legal advice.** Fields marked NEEDS INPUT must be completed before sending.");
  L.push("");
  if (!result.incident?.aware_at) {
    L.push("> ⚠️ No valid `aware_at` timestamp provided, so deadlines can't be computed. Set when you became aware (ISO 8601) and re-run.");
    L.push("");
  }

  L.push("## Reporting timeline");
  L.push("");
  L.push(`Report to **${result.authority?.csirt || "your CSIRT"}** (supervisor: ${result.authority?.supervisor || "—"}).`);
  L.push("");
  L.push("| Report | Due by | Status |");
  L.push("|--------|--------|--------|");
  for (const t of result.timeline) {
    let status = "—";
    if (t.dueBy && now) {
      const due = new Date(t.dueBy);
      status = now > due ? "⚠️ OVERDUE" : "on track";
    }
    L.push(`| ${t.within} — ${t.id} | ${t.dueBy || "set aware_at"} | ${status} |`);
  }
  L.push("");

  for (const r of result.reports) {
    L.push(`## Draft: ${r.id} (within ${r.within}${r.dueBy ? `, by ${r.dueBy}` : ""})`);
    L.push("");
    L.push(`_${r.content}_`);
    L.push("");
    for (const f of r.fields) {
      L.push(`- **${f.label}:** ${f.value || "**NEEDS INPUT**"}`);
    }
    L.push("");
  }

  L.push("---");
  L.push("");
  L.push("*Generated by Penthera. Complete every NEEDS INPUT field, confirm the authority and its official channel, and send within the deadlines above.*");
  L.push("");
  return L.join("\n");
}
