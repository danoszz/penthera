/**
 * Incident-report helper — timeline math (24h / 72h / 1 month) and drafts.
 */
import { describe, it, expect } from "vitest";
import { incidentTemplate, buildIncidentReports, formatIncidentMarkdown } from "../lib/compliance/incident.js";

const NL = {
  authorities: { csirt: "NCSC-NL", supervisor: "RDI" },
  incidentDeadlines: [
    { id: "early-warning", within: "24 hours", from: "awareness", offsetHours: 24, to: "CSIRT", content: "early warning" },
    { id: "notification", within: "72 hours", from: "awareness", offsetHours: 72, to: "CSIRT", content: "notification" },
    { id: "final-report", within: "1 month", from: "notification", offsetMonths: 1, to: "CSIRT", content: "final report" },
  ],
};

describe("incident-report helper", () => {
  it("scaffolds a template with aware_at and key fields", () => {
    const t = incidentTemplate();
    expect(t).toHaveProperty("aware_at");
    expect(t).toHaveProperty("description");
    expect(t).toHaveProperty("cross_border");
  });

  it("computes the 24h / 72h / 1-month deadlines from aware_at", () => {
    const r = buildIncidentReports({ aware_at: "2026-08-15T09:00:00Z" }, NL);
    const due = Object.fromEntries(r.timeline.map((t) => [t.id, t.dueBy]));
    expect(due["early-warning"]).toBe("2026-08-16T09:00:00.000Z");
    expect(due["notification"]).toBe("2026-08-18T09:00:00.000Z");
    expect(due["final-report"]).toBe("2026-09-18T09:00:00.000Z"); // notification + 1 month
  });

  it("returns null deadlines when aware_at is missing or invalid", () => {
    expect(buildIncidentReports({ aware_at: "" }, NL).timeline.every((t) => t.dueBy === null)).toBe(true);
    expect(buildIncidentReports({ aware_at: "not-a-date" }, NL).timeline.every((t) => t.dueBy === null)).toBe(true);
  });

  it("surfaces provided fields and leaves the rest for NEEDS INPUT", () => {
    const r = buildIncidentReports(
      { aware_at: "2026-08-15T09:00:00Z", description: "ransomware on the app server", cross_border: "no" },
      NL,
    );
    const notif = r.reports.find((x) => x.id === "notification");
    expect(notif.fields.find((f) => f.label === "Description").value).toBe("ransomware on the app server");
    expect(notif.fields.find((f) => f.label === "Severity").value).toBeNull();
  });

  it("renders markdown with the disclaimer, timeline, drafts, and NEEDS INPUT", () => {
    const r = buildIncidentReports({ aware_at: "2026-08-15T09:00:00Z", description: "x" }, NL);
    const md = formatIncidentMarkdown(r, { now: "2026-08-15T10:00:00Z" });
    expect(md).toMatch(/not a substitute/i);
    expect(md).toContain("Reporting timeline");
    expect(md).toContain("Draft: notification");
    expect(md).toContain("NEEDS INPUT");
  });

  it("marks a deadline OVERDUE when now is past due", () => {
    const r = buildIncidentReports({ aware_at: "2026-08-15T09:00:00Z" }, NL);
    const md = formatIncidentMarkdown(r, { now: "2026-08-17T00:00:00Z" }); // past the 24h early warning
    expect(md).toMatch(/OVERDUE/);
  });
});
