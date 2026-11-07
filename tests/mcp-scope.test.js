/**
 * `scan_url` over MCP stays on the target or a host the user listed, on every
 * redirect hop, with or without --offline. Loopback only: a target on one port
 * redirects to a second server on another port, which counts every request.
 */
import { describe, it, expect, vi, beforeAll, afterAll, afterEach } from "vitest";
import http from "node:http";
import { startServer, structured } from "./helpers/mcp-client.js";
import { checkEgress, createEgressContext, request, runWithEgress } from "../src/utils/http.js";
import { loadDb } from "../lib/retirejs.js";

function listen(handler) {
  const server = http.createServer(handler);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({
      port: server.address().port,
      url: `http://127.0.0.1:${server.address().port}`,
      close: () => new Promise((done) => { server.closeAllConnections(); server.close(done); }),
    }));
  });
}

let outside, target, hits, fetchGuard;

beforeAll(async () => {
  hits = [];
  // The test stays offline even if a scan tries to leave loopback.
  const realFetch = globalThis.fetch;
  fetchGuard = vi.spyOn(globalThis, "fetch").mockImplementation((url, init) =>
    /^http:\/\/(?:127\.0\.0\.1|localhost)[:/]/.test(String(url))
      ? realFetch(url, init)
      : Promise.reject(new TypeError("fetch failed", { cause: { code: "ENETUNREACH" } })));
  outside = await listen((req, res) => {
    hits.push(req.url);
    res.writeHead(200, { "content-type": "text/html" });
    res.end("<html><body>outside</body></html>");
  });
  target = await listen((req, res) => {
    res.writeHead(302, { location: `${outside.url}/landing` });
    res.end();
  });
});

afterAll(async () => {
  fetchGuard.mockRestore();
  await target.close();
  await outside.close();
});

afterEach(() => { hits.length = 0; fetchGuard.mockClear(); });

async function scan(url, serverOpts) {
  const client = startServer({ roots: [process.cwd()], ...serverOpts });
  try {
    return await client.modern("tools/call", { name: "scan_url", arguments: { url, profile: "standard" } });
  } finally {
    await client.close();
  }
}

describe("scan_url redirect scope", () => {
  for (const offline of [false, true]) {
    it(`does not follow a redirect off the target (offline: ${offline})`, async () => {
      const res = await scan(target.url, { offline });
      expect(res.result.isError, res.result.content[0].text).toBeUndefined();
      expect(hits).toEqual([]);
    }, 60_000);
  }

  it("says what it refused, as something it did not check", async () => {
    const res = await scan(target.url, { offline: false });
    const r = structured(res);
    expect(r.blocked_hosts).toContain("127.0.0.1");
    expect(r.brief.not_checked.join(" ")).toMatch(/left the allowed scope/);
    expect(res.result.content[0].text).toMatch(/left the allowed scope/);
  }, 60_000);

  it("follows a redirect to a host the user listed", async () => {
    const landing = await listen((req, res) => {
      hits.push(req.url);
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<html><body>listed</body></html>");
    });
    const listed = await listen((req, res) => {
      res.writeHead(302, { location: `http://localhost:${landing.port}/landing` });
      res.end();
    });
    try {
      const res = await scan(listed.url, { offline: false, allowHosts: ["localhost"] });
      expect(res.result.isError, res.result.content[0].text).toBeUndefined();
      expect(hits).toContain("/landing");
    } finally {
      await listed.close();
      await landing.close();
    }
  }, 60_000);

  it("keeps --offline to the target even with a listed host", async () => {
    const landing = await listen((req, res) => {
      hits.push(req.url);
      res.writeHead(200);
      res.end("listed");
    });
    const listed = await listen((req, res) => {
      res.writeHead(302, { location: `http://localhost:${landing.port}/landing` });
      res.end();
    });
    try {
      await scan(listed.url, { offline: true, allowHosts: ["localhost"] });
      expect(hits).toEqual([]);
    } finally {
      await listed.close();
      await landing.close();
    }
  }, 60_000);
});

describe("the scoped egress policy", () => {
  const ctx = (extra) => createEgressContext({ target: "https://app.example.com", scoped: true, ...extra });

  it("refuses other hosts, on a first request and on a redirect", () => {
    for (const redirect of [false, true]) {
      expect(checkEgress("https://evil.test/", { redirect }, ctx()).allowed).toBe(false);
      expect(checkEgress("http://169.254.169.254/latest/meta-data", { redirect }, ctx()).allowed).toBe(false);
    }
  });

  it("keeps the subdomain allowance for a redirect only, and never moves to a sibling", () => {
    expect(checkEgress("https://eu.app.example.com/", { redirect: true }, ctx()).allowed).toBe(true);
    expect(checkEgress("https://eu.app.example.com/", { redirect: false }, ctx()).allowed).toBe(false);
    // A sibling of the target (2.3.2): on a shared platform that is another tenant.
    expect(checkEgress("https://www.example.com/", { redirect: true }, ctx()).allowed).toBe(false);
  });

  it("allows listed hosts", () => {
    expect(checkEgress("https://other.test/", { redirect: true }, ctx({ allowHosts: ["other.test"] })).allowed).toBe(true);
  });

  it("names the scope, not --offline, when it refuses", async () => {
    await expect(runWithEgress(ctx(), () => request("https://evil.test/"))).rejects.toThrow(/blocked by the allowed scope/);
  });

  it("uses the vendored Retire.js database, with no download", async () => {
    const db = await runWithEgress(ctx(), () => loadDb());
    expect(db.source).toBe("snapshot");
    expect(fetchGuard).not.toHaveBeenCalled();
  });

  it("leaves a plain scan unrestricted", () => {
    const plain = createEgressContext({ target: "https://app.example.com" });
    expect(checkEgress("https://evil.test/", { redirect: true }, plain).allowed).toBe(true);
  });
});
