/**
 * A firewall that refuses the scanner guards the site, not its DNS. SPF and DMARC come from
 * resolvers, so they still mean what they say when the page can't be read.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { createServer } from "node:http";
import { sharedHostDomain } from "../lib/blackbox/email-dns.js";
import { scanUrl } from "../src/scan-url.js";
import { buildComplianceCoverage } from "../lib/compliance/index.js";
import { pentheraRead } from "../src/cli/giants.js";
import { exitCodeOf } from "../src/report/exit.js";

const dns = vi.hoisted(() => vi.fn());
vi.mock("../lib/blackbox/email-dns.js", async (real) => ({ ...(await real()), probeEmailDns: dns }));
vi.mock("../src/utils/url.js", async (real) => ({ ...(await real()), isPrivateHost: () => false }));

const MAIL = { spf: "v=spf1 -all", dmarc: null, dmarcPolicy: null, mxCount: 1, findings: [{ severity: "medium", title: "No DMARC record", category: "email" }] };
let server;
afterEach(() => { dns.mockReset(); return new Promise((r) => (server ? server.close(r) : r())); });
const serve = (headers) => {
  server = createServer((_q, res) => { res.writeHead(403, { "content-type": "text/html", ...headers }); res.end("<html>Refused</html>"); });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r(`http://localhost:${server.address().port}`)));
};
const scan = (target, opts = {}) => scanUrl(target, { timeout: 3000, concurrency: 2, ...opts });

describe("a host on a shared platform domain", () => {
  it.each(["myapp.vercel.app", "myapp.netlify.app", "a.b.pages.dev", "MyApp.fly.dev"])("%s has no mail records of its own", (host) => {
    expect(sharedHostDomain(host)).toBeTruthy();
  });

  it.each(["vercel.app", "example.com", "shop.example.co.uk", "notvercel.app", "vercel.app.example.com"])("%s keeps its mail checks", (host) => {
    expect(sharedHostDomain(host)).toBeNull();
  });
});

describe("a scan a firewall refuses", () => {
  it("still returns SPF and DMARC, with the challenge finding", async () => {
    dns.mockResolvedValue(MAIL);
    const result = await scan(await serve({ "x-vercel-mitigated": "challenge" }));
    expect(result.challenge).toBeTruthy();
    expect(result.emailAuth).toEqual({ spf: "v=spf1 -all", dmarc: null, dmarcPolicy: null, mxCount: 1 });
    expect(result.findings.map((f) => f.title)).toEqual(["Vercel served a bot challenge instead of the site", "No DMARC record"]);
  });

  it("never reads as covered, for compliance or for the live area", async () => {
    dns.mockResolvedValue({ ...MAIL, findings: [] });
    const result = await scan(await serve({ "x-vercel-mitigated": "challenge" }));
    expect(result.emailAuth).toBeTruthy();
    expect(result.executedProbes).toEqual([]);
    expect(buildComplianceCoverage(result, "nis2").measures.filter((m) => m.status === "tested-clean")).toEqual([]);
    expect(pentheraRead(result, result.target).live).toBeUndefined();
  });

  it("exits 1 on +all SPF, as an unrefused scan does: it is a high finding from DNS", async () => {
    dns.mockResolvedValue({ ...MAIL, findings: [{ severity: "high", title: "SPF allows all senders (+all)", category: "email" }] });
    expect(exitCodeOf(await scan(await serve({ "x-vercel-mitigated": "challenge" })))).toBe(1);
  });

  it("makes no DNS lookup offline, and claims none", async () => {
    const result = await scan(await serve({ "x-vercel-mitigated": "challenge" }), { offline: true });
    expect(dns).not.toHaveBeenCalled();
    expect(result.emailAuth).toBeNull();
    expect(result.executedProbes ?? []).toEqual([]);
  });

  it("keeps the refusal's result when DNS fails", async () => {
    dns.mockRejectedValue(new Error("no resolver"));
    const result = await scan(await serve({ "x-vercel-mitigated": "challenge" }));
    expect(result.challenge).toBeTruthy();
    expect(result.emailAuth).toBeNull();
  });
});
