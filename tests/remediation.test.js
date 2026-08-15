/**
 * Remediation action plan — turns findings into prioritised, owner-actionable
 * items with why/fix, owner-action flagging, and grouping.
 */
import { describe, it, expect } from "vitest";
import { buildActionPlan, formatActionPlanMarkdown } from "../lib/remediation/index.js";

describe("remediation action plan", () => {
  it("groups findings by remediation and sorts by severity (highest first)", () => {
    const plan = buildActionPlan([
      { severity: "low", category: "cookie", title: "Cookie missing HttpOnly" },
      { severity: "critical", category: "sqli", title: "SQL injection" },
      { severity: "medium", category: "cors", title: "CORS reflects arbitrary origin" },
    ]);
    expect(plan[0].severity).toBe("critical");
    expect(plan.map((a) => a.id)).toContain("injection");
  });

  it("excludes info findings from the plan", () => {
    const plan = buildActionPlan([{ severity: "info", category: "exposure", title: "robots.txt accessible" }]);
    expect(plan).toHaveLength(0);
  });

  it("flags owner actions (rotate secret, DNS change)", () => {
    const plan = buildActionPlan([
      { severity: "critical", category: "secrets", title: "Hardcoded password in source" },
      { severity: "medium", category: "email-auth", title: "No SPF record" },
    ]);
    expect(plan.find((a) => a.id === "secrets").ownerAction).toBe(true);
    expect(plan.find((a) => a.id === "email-spf").ownerAction).toBe(true);
  });

  it("collapses multiple findings into one action with a count", () => {
    const plan = buildActionPlan([
      { severity: "low", category: "headers", title: "Missing X-Frame-Options" },
      { severity: "low", category: "headers", title: "Missing X-Content-Type-Options" },
    ]);
    const headers = plan.find((a) => a.id === "header-generic");
    expect(headers.findings).toHaveLength(2);
  });

  it("routes a Content-Security-Policy finding to its own CSP action", () => {
    const plan = buildActionPlan([{ severity: "medium", category: "headers", title: "Missing Content-Security-Policy" }]);
    expect(plan.map((a) => a.id)).toContain("header-csp");
  });

  it("renders markdown with why and fix", () => {
    const md = formatActionPlanMarkdown(
      buildActionPlan([{ severity: "high", category: "cors", title: "CORS reflects arbitrary origin" }]),
    );
    expect(md).toContain("## Action plan");
    expect(md).toMatch(/\*\*Why:\*\*/);
    expect(md).toMatch(/\*\*Fix:\*\*/);
  });
});
