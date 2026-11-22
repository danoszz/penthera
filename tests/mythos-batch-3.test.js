/**
 * Mythos deep assessment for 2.5 (12 Nov 2026), batch 3: ranking (F) and the
 * wider example and vendored buckets (B3, B4). Order and buckets only: no
 * severity and no exit code changes.
 */
import { describe, it, expect } from "vitest";
import { buildBrief } from "../src/report/brief.js";
import { bucketOf } from "../src/report/counts.js";
import { exitCodeOf } from "../src/report/exit.js";
import { VENDORED_FILE_NAMES } from "../src/report/counts.js";
import { loadSnapshot } from "../lib/retirejs.js";

const f = (o = {}) => ({ severity: "medium", confidence: "likely", source: "static-analysis", category: "code-pattern", title: "Finding", ...o });

describe("F: reach, then input, then severity", () => {
  it("one request-tainted command injection comes before twenty sample keys of one rule (the E9 brief)", () => {
    // Real shapes: a code-sinks finding has category code-pattern, a pattern and `tainted`.
    const keys = Array.from({ length: 20 }, (_, i) => f({ file: `docs/providers/k${i}.md`, templateId: "generic-api-key", category: "secrets", severity: "critical", title: "Generic API key" }));
    const inj = f({ file: "lib/git.ts", pattern: "command-injection", category: "code-pattern", severity: "critical", tainted: true, title: "Command injection" });
    const b = buildBrief({ mode: "repo", findings: [...keys, inj] });
    expect(b.act_on[0].title).toBe("Command injection");
    expect(b.first.title).toBe("Command injection");
    expect(b.act_on[0].rank_reasons).toMatchObject({ input: "request" });
  });

  it("a high in Check first is the first step before a medium in Act on", () => {
    const pins = Array.from({ length: 4 }, (_, i) => f({ file: `.github/workflows/w${i}.yml`, rule: "gha-unpinned-action", category: "config", severity: "medium", confidence: "confirmed", title: `Unpinned action ${i}` }));
    const action = f({ file: "app/actions.ts", rule: "server-action-no-auth", category: "auth", severity: "high", confidence: "potential", title: "Server Action writes data without an auth check" });
    const b = buildBrief({ mode: "repo", findings: [...pins, action] });
    expect(b.first).toMatchObject({ title: action.title, from: "check_first" });
  });

  it("the top three hold at most one line per rule", () => {
    const same = ["a", "b", "c", "d"].map((x) => f({ file: `src/${x}/x.ts`, rule: "same-rule", title: `Same rule in ${x}`, category: `c-${x}` }));
    const other = f({ file: "src/z.ts", rule: "other-rule", title: "Other rule" });
    const b = buildBrief({ mode: "repo", findings: [...same, other] });
    // Two rules: the other rule moves up into the first two, then the same rule fills the third.
    expect(b.act_on.slice(0, 2).map((i) => i.rules.join(",")).sort()).toEqual(["other-rule", "same-rule"]);
  });

  it("no number of medium findings in route files pushes a critical below the top (blind review)", () => {
    const decoys = Array.from({ length: 6 }, (_, i) => f({ file: `app/api/d${i}/route.ts`, templateId: `decoy-${i}`, title: `Decoy ${i}` }));
    const crit = f({ file: "lib/db.ts", pattern: "command-injection", severity: "critical", title: "command-injection in lib/db.ts" });
    expect(buildBrief({ mode: "repo", findings: [...decoys, crit] }).act_on[0].title).toBe(crit.title);
  });

  it("five highs in route files never push a critical out of the top (blind review)", () => {
    const highs = Array.from({ length: 5 }, (_, i) => f({ file: `app/api/h${i}/route.ts`, templateId: `high-${i}`, severity: "high", title: `High ${i}` }));
    const crit = ["a", "b", "c"].map((x) => f({ file: `lib/${x}.ts`, pattern: "command-injection", severity: "critical", title: "command-injection", category: "code-pattern" }));
    const b = buildBrief({ mode: "repo", findings: [...highs, ...crit] });
    expect(b.act_on[0].severity).toBe("critical");
    expect(b.first.title).toBe(b.act_on[0].title);
  });

  it("a second critical of the same rule never drops below a medium", () => {
    const c1 = f({ file: "lib/a.ts", pattern: "command-injection", severity: "critical", title: "command-injection in lib/a.ts", category: "code-pattern" });
    const c2 = f({ file: "lib/b.ts", pattern: "command-injection", severity: "critical", title: "command-injection in lib/b.ts", category: "code-pattern-b" });
    const m = f({ file: "lib/c.ts", templateId: "other", severity: "medium", title: "Other medium" });
    const order = buildBrief({ mode: "repo", findings: [m, c1, c2] }).act_on.map((i) => i.severity);
    expect(order.indexOf("medium")).toBe(order.length - 1);
  });

  it("a committed secret is reachable wherever it sits", () => {
    const key = f({ file: "lib/stripe.ts", rule: "stripe-secret-key", category: "secrets", severity: "critical", title: "Stripe key" });
    const action = f({ file: "app/actions.ts", rule: "x", category: "auth", severity: "medium", title: "Medium action" });
    expect(buildBrief({ mode: "repo", findings: [action, key] }).act_on[0].title).toBe("Stripe key");
  });
});

describe("B3 and B4: wider example and vendored buckets", () => {
  const b = (file, extra = {}) => bucketOf(f({ file, severity: "critical", ...extra }));
  it("for a medium or low secret: prose, example env files, seeds, snapshots and stories are examples", () => {
    for (const p of ["README.md", "docs/setup.md", ".env.example", "seeds/users.ts", "src/__snapshots__/a.snap", "src/Button.stories.tsx"]) expect(b(p, { category: "secrets", severity: "medium" }), p).toEqual({ bucket: "noise", reason: "example" });
  });
  it("a critical secret in a README or .env.example stays in Act on (a real leak)", () => {
    for (const p of ["README.md", ".env.example", "docs/setup.md", "seeds/prod.ts"]) expect(b(p, { category: "secrets", confidence: "confirmed" }).bucket, p).toBe("act");
  });
  it("a file name never moves a code finding (blind review)", () => {
    for (const p of ["app/api/run/route.stories.ts", "docs/api/handler.cgi", "seeds/run.ts", "server/README.txt", "config/.env.example", "app/docs/route.ts"]) expect(b(p, { pattern: "command-injection" }).bucket, p).toBe("act");
  });
  it("a versioned name needs a real version", () => {
    for (const p of ["routes/vue-2fa.js", "lib/d3-3d.js"]) expect(b(p).bucket, p).toBe("act");
  });
  it("a versioned library copy is vendored below high, never a critical, a tainted or a hostile hit", () => {
    expect(b("public/js/jquery-3.4.1.js", { severity: "medium" })).toEqual({ bucket: "noise", reason: "vendored" });
    expect(b("public/js/jquery-3.4.1.js").bucket).toBe("act");
    expect(b("public/js/jquery-3.4.1.js", { tainted: true }).bucket).toBe("act");
    expect(b("public/js/jquery-3.4.1.js", { category: "malware" }).bucket).toBe("act");
  });
  it("the exit code is the same: a critical in a README still fails the run", () => {
    expect(exitCodeOf({ findings: [f({ file: "README.md", severity: "critical" })] })).toBe(1);
  });
});

describe("the vendored-name copy matches the bundled retire.js database", () => {
  it("same file-name signatures", () => {
    const fromDb = Object.values(loadSnapshot().db).flatMap((v) => v?.extractors?.filename || []).filter((n) => !n.startsWith("retire-example"));
    expect(VENDORED_FILE_NAMES).toEqual(fromDb);
  });
});
