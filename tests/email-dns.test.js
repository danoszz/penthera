/**
 * Email authentication posture (SPF / DMARC / MX). The DNS resolver is injected
 * so the evaluation logic is tested without live DNS.
 */
import { describe, it, expect } from "vitest";
import { evaluateSpf, evaluateDmarc, probeEmailDns } from "../lib/blackbox/email-dns.js";

describe("email auth — SPF", () => {
  it("flags a missing SPF record", () => {
    expect(evaluateSpf([]).finding.title).toMatch(/No SPF/);
  });
  it("flags +all as high severity", () => {
    expect(evaluateSpf(["v=spf1 include:_spf.example.com +all"]).finding.severity).toBe("high");
  });
  it("accepts a restrictive -all record", () => {
    expect(evaluateSpf(["v=spf1 include:_spf.google.com -all"]).finding).toBeNull();
  });
  it("accepts a ~all (softfail) record", () => {
    expect(evaluateSpf(["v=spf1 mx ~all"]).finding).toBeNull();
  });
  it("flags a record with no all mechanism as medium", () => {
    expect(evaluateSpf(["v=spf1 include:_spf.example.com"]).finding.severity).toBe("medium");
  });
});

describe("email auth — DMARC", () => {
  it("flags a missing DMARC record", () => {
    expect(evaluateDmarc([]).finding.title).toMatch(/No DMARC/);
  });
  it("flags p=none as monitoring-only (low)", () => {
    const r = evaluateDmarc(["v=DMARC1; p=none; rua=mailto:x@y.com"]);
    expect(r.policy).toBe("none");
    expect(r.finding.severity).toBe("low");
  });
  it("accepts p=reject", () => {
    const r = evaluateDmarc(["v=DMARC1; p=reject"]);
    expect(r.policy).toBe("reject");
    expect(r.finding).toBeNull();
  });
});

describe("probeEmailDns (injected resolver)", () => {
  const resolver = (txt, dmarc, mx) => ({
    resolveTxt: async (name) => (name.startsWith("_dmarc.") ? dmarc : txt),
    resolveMx: async () => mx,
  });

  it("reports a clean posture with -all and p=reject", async () => {
    const r = await probeEmailDns("example.com", {
      resolver: resolver([["v=spf1 -all"]], [["v=DMARC1; p=reject"]], [{ exchange: "mx.example.com", priority: 10 }]),
    });
    expect(r.findings).toHaveLength(0);
    expect(r.dmarcPolicy).toBe("reject");
    expect(r.mxCount).toBe(1);
  });

  it("flags missing SPF + DMARC and nudges DKIM when MX is present", async () => {
    const r = await probeEmailDns("example.com", {
      resolver: resolver([], [], [{ exchange: "mx", priority: 10 }]),
    });
    const titles = r.findings.map((f) => f.title);
    expect(titles).toContain("No SPF record");
    expect(titles).toContain("No DMARC record");
    expect(titles.some((t) => /DKIM/i.test(t))).toBe(true);
  });

  it("does not nudge DKIM when the domain has no MX", async () => {
    const r = await probeEmailDns("example.com", { resolver: resolver([], [], []) });
    expect(r.findings.some((f) => /DKIM/i.test(f.title))).toBe(false);
  });

  it("survives DNS resolution failure", async () => {
    const r = await probeEmailDns("example.com", {
      resolver: {
        resolveTxt: async () => { throw new Error("NXDOMAIN"); },
        resolveMx: async () => { throw new Error("NXDOMAIN"); },
      },
    });
    expect(r.mxCount).toBe(0);
    expect(r.findings.some((f) => /No SPF/.test(f.title))).toBe(true);
  });
});
