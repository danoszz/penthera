/**
 * A scan a firewall refused read nothing, so no surface may call it clean. The exit code stays
 * what the findings make it. The CLI runs for real against a loopback server.
 */
import { describe, it, expect, afterEach } from "vitest";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { buildBrief, formatBrief, VERDICTS } from "../src/report/brief.js";
import { mergeResults } from "../src/cli/merge-results.js";
import { formatMarkdownReport } from "../src/report/markdown.js";
import { formatAudienceReport } from "../src/report/audience.js";

const BIN = fileURLToPath(new URL("../bin/penthera.js", import.meta.url));
const REFUSED = { target: "https://shop.example/", mode: "url", challenge: { provider: "Cloudflare", action: "challenge" }, findings: [{ severity: "info", title: "Cloudflare served a bot challenge instead of the site", category: "scan" }] };
const MEDIUM = { severity: "medium", title: "No DMARC record", category: "email" };
const REPO = { target: "/code", mode: "repo", findings: [] };

let server, home;
afterEach(async () => {
  if (home) rmSync(home, { recursive: true, force: true });
  home = null;
  if (server) await new Promise((r) => server.close(r));
  server = null;
});

function cli(status, headers, args = []) {
  home = mkdtempSync(join(tmpdir(), "penthera-refused-"));
  server = createServer((_q, res) => { res.writeHead(status, { "content-type": "text/html", ...headers }); res.end("x"); });
  return new Promise((done) => server.listen(0, "127.0.0.1", () => {
    const p = spawn(process.execPath, [BIN, `http://127.0.0.1:${server.address().port}`, "--offline", ...args], { cwd: home, env: { ...process.env, HOME: home, NO_COLOR: "1", CI: "1" } });
    let out = "";
    p.stdout.on("data", (d) => { out += d; });
    p.stderr.on("data", (d) => { out += d; });
    p.on("close", (code) => done({ code, out }));
  }));
}

describe("the brief of a refused scan", () => {
  it("says the site wasn't read", () => {
    expect(buildBrief(REFUSED).verdict).toBe(VERDICTS.unread);
    expect(formatBrief(buildBrief(REFUSED))).toContain("**Penthera: Site not read.**");
  });

  it("keeps saying so with a medium mail finding", () => {
    expect(buildBrief({ ...REFUSED, findings: [...REFUSED.findings, MEDIUM] }).verdict).toBe(VERDICTS.unread);
  });

  it("still leads with a high finding", () => {
    const high = { severity: "high", title: "SPF allows all senders (+all)", category: "email" };
    expect(buildBrief({ ...REFUSED, findings: [...REFUSED.findings, high] }).verdict).toBe(VERDICTS.fix);
  });

  it("says so when a clean repo scan ran beside it, through the merge", () => {
    expect(buildBrief(mergeResults([REFUSED, REPO])).verdict).toBe(VERDICTS.unread);
    expect(buildBrief([REFUSED, REPO]).verdict).toBe(VERDICTS.unread);
  });

  it("leaves a scan that read its target alone", () => {
    expect(buildBrief({ target: "https://shop.example/", mode: "url", findings: [] }).verdict).toBe(VERDICTS.clean);
  });

  it("names tools that didn't run", () => {
    const giants = { tools: [{ id: "nuclei", status: "not installed", reason: "install: brew install nuclei" }, { id: "gitleaks", status: "ran" }] };
    const text = buildBrief({ ...REFUSED, giants }).not_checked.join(" ");
    expect(text).toContain("nuclei: not installed");
    expect(text).not.toContain("gitleaks");
  });
});

describe("the written reports of a refused scan", () => {
  it("doesn't call the site reachable in the Markdown report", () => {
    const md = formatMarkdownReport({ ...REFUSED, reachable: true }, { version: "0" });
    expect(md).not.toMatch(/\*\*Reachable\*\* \| Yes/);
    expect(md).toContain("| **Reachable** | Site not read: Cloudflare answered instead |");
  });

  it("keeps Yes for a site it read, and No for one that didn't answer", () => {
    expect(formatMarkdownReport({ target: "https://shop.example/", mode: "url", reachable: true, findings: [] }, { version: "0" })).toContain("| **Reachable** | Yes |");
    expect(formatMarkdownReport({ target: "https://shop.example/", mode: "url", reachable: false, findings: [] }, { version: "0" })).toContain("| **Reachable** | No |");
  });

  it.each(["developer", "auditor", "agent"])("gives the %s report nothing that reads as clean", (audience) => {
    const result = { ...REFUSED, reachable: true };
    expect(formatAudienceReport(result, audience, { version: "0" })).not.toMatch(/Nothing to fix|Clean scan|no issues found/i);
  });
});

describe("the CLI on a refused scan", () => {
  it.each([["Cloudflare", 403, { "cf-mitigated": "challenge" }], ["Vercel", 429, { "x-vercel-mitigated": "challenge" }]])("%s: never says Nothing to fix, and exit stays 0", async (_name, status, headers) => {
    const plain = await cli(status, headers);
    expect(plain.code).toBe(0);
    expect(plain.out).not.toMatch(/Nothing to fix|Clean scan/);
    expect(plain.out).toContain("We couldn't see your site.");
  });

  it("gives the agent brief the same headline", async () => {
    const { out } = await cli(403, { "cf-mitigated": "challenge" }, ["--brief"]);
    expect(out).toContain("Site not read");
    expect(out).not.toContain("Nothing to fix");
  });

  it("counts a firewall's 503 as a refusal, not as down", async () => {
    const { code, out } = await cli(503, { "cf-mitigated": "challenge" });
    expect(code).toBe(0);
    expect(out).toContain("We couldn't see your site.");
    expect(out).not.toContain("unreachable");
  });
});

describe("the CLI on a server error", () => {
  it("says the server answered, and keeps exit 2", async () => {
    const { code, out } = await cli(503, {});
    expect(code).toBe(2);
    expect(out).toContain("answered HTTP 503");
    expect(out).not.toContain("unreachable");
  });
});
