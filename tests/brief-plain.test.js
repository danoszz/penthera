/**
 * The brief for vibe-coded stacks: one first step under the verdict, and a
 * "why it matters" line in plain words for Next.js, Supabase, Stripe and
 * Vercel findings (src/report/plain.js). The lines explain; the rules still
 * decide every bucket, severity and verdict.
 */
import { describe, it, expect } from "vitest";
import { buildBrief, formatBrief, VERDICTS } from "../src/report/brief.js";
import { plainWords, PLAIN_LINES } from "../src/report/plain.js";
import { buildResult, REPLY_CONTRACT } from "../src/mcp/results.js";
import { INSTRUCTIONS } from "../src/mcp/server.js";

const f = (o = {}) => ({ severity: "high", confidence: "likely", source: "static-analysis", category: "code-pattern", title: "Finding", url: "src/app/page.tsx", ...o });

const STRIPE = f({ severity: "critical", source: "secret-scan", category: "secrets", title: "Stripe secret key in source", url: "lib/stripe.ts", line: 3, description: "Possible secret in `lib/stripe.ts`: `sk_l…abcd`." });
const RLS = f({ source: "supabase-scan", category: "auth-bypass", templateId: "supabase-rls-disabled", title: "Row-level security is off on public.profiles", url: "supabase/migrations/001.sql" });
const PUBLIC_ENV = f({ source: "public-env", category: "secrets", templateId: "public-env-secret", title: "NEXT_PUBLIC_OPENAI_KEY ships to the browser", url: ".env.production" });
const ACTION = f({ severity: "medium", category: "auth", templateId: "server-action-no-auth", title: "Server Action without an auth check", url: "app/actions.ts" });
const UNKNOWN = f({ severity: "medium", category: "something-new", templateId: "brand-new-rule", title: "A rule the table does not know", description: "The engine's own words. More detail." });

describe("why it matters, in plain words", () => {
  it("explains the stacks makers ship most", () => {
    expect(plainWords(STRIPE).why).toMatch(/Stripe/);
    expect(plainWords(RLS).why).toMatch(/row-level security/);
    expect(plainWords(PUBLIC_ENV).why).toMatch(/NEXT_PUBLIC_/);
    expect(plainWords(ACTION).why).toMatch(/Server Action/);
    expect(plainWords(f({ templateId: "supabase-service-role-exposed" })).act).toMatch(/Rotate the service_role key/);
    expect(plainWords(f({ source: "secret-scan", category: "secrets", title: "OpenAI API key in source" })).why).toMatch(/you pay the bill/);
    expect(plainWords(f({ source: "secret-scan", category: "secrets", title: "Some new key in source" })).why).toMatch(/use this key as you/);
    expect(plainWords(f({ category: "code-pattern", pattern: "command-injection" })).why).toMatch(/commands/);
    expect(plainWords(UNKNOWN)).toBeNull();
  });

  it("follows the voice guide: plain, short, no em dashes, no hype", () => {
    for (const { why, act } of PLAIN_LINES) {
      for (const line of [why, act]) {
        expect(line).not.toMatch(/—/);
        expect(line).not.toMatch(/\b(?:leverage|seamless|robust|powerful|critical threat|attackers are everywhere)\b/i);
        expect(line.split(/\s+/).length, line).toBeLessThanOrEqual(30);
        expect(line).toMatch(/\.$/);
      }
    }
  });
});

describe("the brief leads with one first step", () => {
  it("names the top finding's first step, where it is and why it matters", () => {
    const b = buildBrief({ mode: "repo", findings: [ACTION, STRIPE, RLS] });
    expect(b.first).toEqual({
      title: "Stripe secret key in source",
      where: "lib/stripe.ts:3",
      action: plainWords(STRIPE).act,
      why_it_matters: plainWords(STRIPE).why,
      from: "act_on",
    });
    const lines = formatBrief(b).split("\n");
    expect(lines[0]).toMatch(/^\*\*Penthera: Fix now\.\*\*/);
    expect(lines[2]).toMatch(/^\*\*Do this first\*\* \(`lib\/stripe\.ts:3`\): Roll the key in the Stripe Dashboard/);
    expect(lines[2]).toContain("Why it matters: Anyone with this key can charge cards");
  });

  it("keeps the sections and their order", () => {
    const out = formatBrief(buildBrief({ mode: "repo", findings: [STRIPE, RLS, f({ confidence: "potential", title: "Maybe" }), f({ localOnly: true, title: "Local" })] }));
    expect(out.split("\n").filter((l) => l.startsWith("### "))).toEqual(["### Act on", "### Check first", "### Likely noise", "### Not checked", "### Next"].filter((h) => out.includes(h)));
    expect(out.indexOf("**Do this first**")).toBeLessThan(out.indexOf("### Act on"));
  });

  it("puts the plain line on each item, and keeps the finding's own words where the table has none", () => {
    const b = buildBrief({ mode: "repo", findings: [RLS, UNKNOWN] });
    expect(b.act_on[0].why_it_matters).toMatch(/row-level security/);
    expect(b.act_on[1].why_it_matters).toBeNull();
    const out = formatBrief(b);
    expect(out).toContain("Why it matters: With row-level security off");
    expect(out).toContain("The engine's own words.");
  });

  it("falls back to Check first, and has no first step when there is nothing to do", () => {
    const check = buildBrief({ mode: "repo", findings: [f({ confidence: "potential", severity: "low", category: "other", title: "Maybe" })] });
    expect(check.first.from).toBe("check_first");
    expect(check.first.action).toMatch(/^Check Maybe in /);
    const clean = buildBrief({ mode: "repo", findings: [] });
    expect(clean.first).toBeNull();
    expect(formatBrief(clean)).not.toContain("Do this first");
  });

  it("never changes a bucket, a severity or the verdict", () => {
    const findings = [STRIPE, RLS, PUBLIC_ENV, ACTION, UNKNOWN];
    const b = buildBrief({ mode: "repo", findings });
    expect(b.verdict).toBe(VERDICTS.fix);
    expect(b.counts).toMatchObject({ act: 5, check: 0, total: 5 });
    expect(b.act_on.map((i) => i.severity)).toEqual(["critical", "high", "high", "medium", "medium"]);
  });
});

describe("the MCP server and the reply contract ask to keep it", () => {
  it("names the Do this first line and the plain lines", () => {
    expect(REPLY_CONTRACT).toContain("the Do this first line");
    expect(REPLY_CONTRACT).toContain("Why it matters");
    expect(INSTRUCTIONS).toContain("Do this first");
    const r = buildResult({ tool: "scan_repo", target: ".", findings: [STRIPE], limits: [], scan: { mode: "repo" } });
    expect(r.text).toContain("**Do this first**");
    expect(r.structured.brief.first.action).toMatch(/Stripe Dashboard/);
  });
});

describe("plain words for the 2.5 missing-check rules", () => {
  it("has a why and a first step for each of the ten new rule ids", async () => {
    const { MISSING_CHECK_RULES } = await import("../lib/whitebox/missing-checks.js");
    const { SESSION_AUTH_RULES } = await import("../lib/whitebox/session-auth.js");
    const ids = [...Object.keys(MISSING_CHECK_RULES), ...Object.keys(SESSION_AUTH_RULES)];
    expect(ids).toHaveLength(10);
    for (const id of ids) {
      const words = plainWords({ templateId: id, source: "repo-scan" });
      expect(words, id).toBeTruthy();
      expect(words.why.length, id).toBeGreaterThan(20);
      expect(words.act.length, id).toBeGreaterThan(20);
    }
  });
});
