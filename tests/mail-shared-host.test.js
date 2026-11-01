/**
 * A customer host on a platform's domain has no mail records of its own, so a scan skips the
 * lookup, says so, and doesn't claim the probe ran. The platform check is forced, and the rest is real.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { createServer } from "node:http";
import { scanUrl } from "../src/scan-url.js";

const dns = vi.hoisted(() => vi.fn());
vi.mock("../lib/blackbox/email-dns.js", () => ({ probeEmailDns: dns, sharedHostDomain: () => "vercel.app" }));
vi.mock("../src/utils/url.js", async (real) => ({ ...(await real()), isPrivateHost: () => false }));

let server;
afterEach(() => { dns.mockReset(); return new Promise((r) => (server ? server.close(r) : r())); });
const serve = (status, headers = {}) => {
  server = createServer((_q, res) => { res.writeHead(status, { "content-type": "text/html", ...headers }); res.end("<html>Hello</html>"); });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r(`http://localhost:${server.address().port}`)));
};
const SKIPPED = "Mail checks skipped on a shared domain";
const scan = (target, opts = {}) => scanUrl(target, { timeout: 3000, concurrency: 2, skipRetireJs: true, ...opts });

describe("mail on a shared platform domain", () => {
  it("skips a normal scan's lookup, says so, and claims no probe", async () => {
    const result = await scan(await serve(200));
    expect(dns).not.toHaveBeenCalled();
    expect(result.emailAuth).toBeNull();
    expect(result.findings.find((f) => f.title === SKIPPED)).toMatchObject({ severity: "info" });
    expect(result.executedProbes).not.toContain("email-dns");
  });

  it("does the same on a refused scan", async () => {
    const result = await scan(await serve(403, { "x-vercel-mitigated": "challenge" }));
    expect(dns).not.toHaveBeenCalled();
    expect(result.findings.map((f) => f.title)).toContain(SKIPPED);
    expect(result.executedProbes).toEqual([]);
  });

  it("adds no note offline, where no lookup would run anyway", async () => {
    const result = await scan(await serve(403, { "x-vercel-mitigated": "challenge" }), { offline: true });
    expect(result.findings.map((f) => f.title)).not.toContain(SKIPPED);
  });
});
