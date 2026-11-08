// The first screen of `penthera --repo .` in a terminal: in 30 seconds a maker sees what
// was checked, what to act on, what wasn't checked and one next step. Calm when little is
// found, and never "safe", "clean" or "all good".
import { describe, it, expect, vi } from "vitest";
import { firstScreen } from "../src/report/first-screen.js";
import { buildBrief } from "../src/report/brief.js";
import { printReport } from "../src/reporter.js";

const coverage = (counts) => ({
  families: Object.entries(counts).map(([id, examined]) => ({ id, label: id, ran: true, examined, skipped: {} })),
  notRun: [], blindSpots: { count: 0 }, excludedDirs: [],
});
// As a repo scan writes them: the file in url, the line apart.
const finding = (title, severity, where, extra = {}) => {
  const [url, line] = where.split(":");
  return { title, severity, url, ...(line ? { line: Number(line) } : {}), category: "code", ...extra };
};
const scan = (findings, cov = { secrets: 7, routes: 2, "code-sinks": 2, "runtime-pins": 0 }) => {
  const r = { target: "/app", mode: "repo", timestamp: "2026-11-02T10:00:00Z", duration: 400, coverage: coverage(cov), findings };
  return { ...r, brief: buildBrief(r, { fixes: { count: 1, command: "penthera fix --plan --repo ." } }) };
};
const plain = (lines) => lines.join("\n");

const busy = scan([
  finding("Stripe secret key in source", "critical", "src/config.js:1", { category: "secrets", remediation: "Move the key to an environment variable, then replace it with your provider." }),
  finding("Stripe secret key in source", "critical", "src/pay.js:4", { category: "secrets", remediation: "Move the key to an environment variable, then replace it with your provider." }),
  finding("command-injection in routes/admin.js", "critical", "routes/admin.js:2", { remediation: "Use execFile with an argument array and no shell." }),
  finding("Missing rate limit on login", "high", "routes/login.js:3", { remediation: "Add a rate limiter to the login route." }),
  finding("Wildcard CORS", "high", "server.js:9", { remediation: "List the origins you serve." }),
  finding("Found 3 API routes", "info", "routes/"),
]);
const quiet = scan([finding("Found 3 API routes", "info", "routes/")]);

describe("the first screen", () => {
  it("says what was checked, in plain words and counts", () => {
    const s = plain(firstScreen(busy));
    expect(s).toMatch(/Checked\s+secrets in 7 files · routes and code patterns in 2 · code-execution sinks in 2/);
    for (const l of firstScreen(busy)) expect(l.length, l).toBeLessThanOrEqual(100);
    expect(s).not.toMatch(/runtime versions in 0/);
  });

  it("puts the verdict and the top three to act on first, each with a place and a fix", () => {
    const s = plain(firstScreen(busy));
    expect(s).toContain("Fix now: 4 problems to act on.");
    expect(s.indexOf("1. Stripe secret key in source")).toBeLessThan(s.indexOf("2. command-injection"));
    expect(s).toContain("src/config.js:1, src/pay.js:4");
    expect(s).toContain("Move the key to an environment variable");
    expect(s).toContain("3. ");
    expect(s).not.toContain("4. ");
    expect(s).toMatch(/\+ 1 more in the details below/);
  });

  it("says what it didn't check, and gives one next step, the brief's", () => {
    const s = plain(firstScreen(busy));
    expect(s).toMatch(/Not checked\s+your packages \(penthera deps \.\)/);
    expect(s).toContain("your AI tool config (penthera agents .)");
    expect(s).toContain("whether login, access rules and payments are right");
    expect(s).toMatch(/^ {2}Next\s+penthera fix --plan --repo \./m);
    expect(s.match(/^ {2}Next/gm)).toHaveLength(1);
  });

  it("fits one screen", () => {
    expect(firstScreen(busy).length).toBeLessThanOrEqual(24);
  });

  it("tells a maker what to do about a secret, not just where it is", () => {
    const r = scan([finding("AWS access key in source", "critical", "src/aws.js:3", { category: "secrets", source: "secrets" })]);
    expect(plain(firstScreen(r))).toContain("Move it to an environment variable, then replace the key");
  });

  it("stays calm when little is found, and never says safe", () => {
    const s = plain(firstScreen(quiet));
    expect(s).toContain("Nothing to fix first in what Penthera checked.");
    expect(s).toContain("Checked");
    expect(s).toContain("Not checked");
    expect(s).not.toMatch(/\bsafe\b|all good|clean|no issues|secure\b/i);
  });

  it("opens the terminal report, and the report's last word agrees with it", () => {
    const lines = [];
    const spy = vi.spyOn(process.stdout, "write").mockImplementation((l) => { lines.push(String(l)); return true; });
    printReport(busy, { fixes: { count: 1, command: "penthera fix --plan --repo ." } });
    spy.mockRestore();
    const out = lines.join("").replace(/\x1b\[[0-9;]*m/g, "");
    expect(out.indexOf("Fix now: 4 problems to act on.")).toBeLessThan(out.indexOf("Findings"));
    expect(out).not.toContain("npx penthera ui --open, then Check my app");
  });

  it("never prints 'Clean scan' in the terminal", () => {
    const lines = [];
    const spy = vi.spyOn(process.stdout, "write").mockImplementation((l) => { lines.push(String(l)); return true; });
    printReport(scan([]));
    spy.mockRestore();
    const out = lines.join("");
    expect(out).not.toMatch(/clean scan|no issues found/i);
    expect(out).toContain("Nothing found in what Penthera checked.");
  });
});
