/**
 * penthera.org's live quick check (api/check.mjs). The guard decides what
 * penthera.org may fetch on someone's behalf, so it is tested first and
 * hardest: no internal address, by name, literal, DNS answer or redirect.
 * Everything runs against 127.0.0.1 with a stub resolver; nothing leaves.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer } from "node:http";
import { parseTarget, isPublicIp, resolvePublic, fetchHeaders, CheckError } from "../api/_lib/guard.mjs";
import { grade } from "../api/_lib/grade.mjs";
import { createHandler } from "../api/check.mjs";

const codeOf = (fn) => { try { fn(); } catch (e) { return e.code; } return null; };
const codeOfAsync = async (p) => { try { await p; } catch (e) { return e.code; } return null; };

describe("live check guard", () => {
  it("reads a bare domain as https and keeps the path", () => {
    expect(parseTarget("example.org").href).toBe("https://example.org/");
    expect(parseTarget(" http://example.org/shop?x=1#top ").href).toBe("http://example.org/shop?x=1");
  });

  it("refuses anything that is not a public web address", () => {
    for (const bad of ["", "localhost", "http://localhost:3000", "intranet", "printer.local", "db.internal", "app.test",
      "http://127.0.0.1", "http://10.0.0.5", "http://192.168.1.1", "http://169.254.169.254/latest/meta-data", "http://[::1]/", "http://[fd00::1]/",
      "http://100.64.0.1", "http://0.0.0.0"]) {
      expect(codeOf(() => parseTarget(bad)), bad).toMatch(/invalid_url|not_public/);
    }
    expect(codeOf(() => parseTarget("file:///etc/passwd"))).toBe("invalid_url");
    expect(codeOf(() => parseTarget("https://user:pw@example.org"))).toBe("invalid_url");
    expect(codeOf(() => parseTarget("https://example.org:8443"))).toBe("invalid_url");
    expect(codeOf(() => parseTarget("https://example.org:443"))).toBeNull();
  });

  it("knows public from private addresses, including mapped IPv6", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "76.76.21.21"]) expect(isPublicIp(ip), ip).toBe(true);
    for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.0.1", "169.254.169.254", "100.100.100.100",
      "198.18.0.1", "224.0.0.1", "255.255.255.255", "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "2001:db8::1"]) {
      expect(isPublicIp(ip), ip).toBe(false);
    }
    expect(isPublicIp("172.32.0.1")).toBe(true);
  });

  it("refuses a name if any of its DNS answers is private", async () => {
    const lookup = async () => [{ address: "93.184.216.34", family: 4 }, { address: "10.0.0.1", family: 4 }];
    expect(await codeOfAsync(resolvePublic("mixed.example.org", { lookup }))).toBe("not_public");
    const ok = async () => [{ address: "93.184.216.34", family: 4 }];
    expect((await resolvePublic("ok.example.org", { lookup: ok })).address).toBe("93.184.216.34");
    const none = async () => { throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }); };
    expect(await codeOfAsync(resolvePublic("nope.example.org", { lookup: none }))).toBe("not_found");
  });
});

describe("live check fetch", () => {
  let server, port;
  beforeAll(async () => {
    server = createServer((req, res) => {
      if (req.url === "/to-metadata") { res.writeHead(302, { Location: "http://169.254.169.254/latest/meta-data/" }); return res.end(); }
      if (req.url === "/to-home") { res.writeHead(301, { Location: "/" }); return res.end(); }
      res.writeHead(200, { "Content-Type": "text/html", "X-Powered-By": "Express", "Set-Cookie": "sid=abc; Path=/" });
      res.end("<!doctype html>" + "x".repeat(100_000));
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    port = server.address().port;
  });
  afterAll(() => new Promise((r) => server.close(r)));

  // The stub resolver sends the public-looking name to the local server.
  const opts = () => ({ lookup: async () => [{ address: "127.0.0.1", family: 4 }], allowPrivate: true, anyPort: true, timeout: 2000 });

  it("reads the status and headers once and follows a safe redirect", async () => {
    const res = await fetchHeaders(new URL(`http://site.example.org:${port}/to-home`), opts());
    expect(res.status).toBe(200);
    expect(res.headers["x-powered-by"]).toBe("Express");
    expect(res.hops.map((h) => h.status)).toEqual([301, 200]);
  });

  it("refuses a redirect into an internal address", async () => {
    expect(await codeOfAsync(fetchHeaders(new URL(`http://site.example.org:${port}/to-metadata`), opts()))).toBe("not_public");
  });

  it("grades what the server sent", async () => {
    const report = grade(await fetchHeaders(new URL(`http://site.example.org:${port}/`), opts()));
    const byId = Object.fromEntries(report.checks.map((c) => [c.id, c]));
    expect(byId.https.passed).toBe(false);
    expect(byId.disclosure.passed).toBe(false);
    expect(byId.disclosure.evidence).toContain("x-powered-by: Express");
    expect(byId.cookies.passed).toBe(false);
    expect(report.score).toBeLessThan(45);
    expect(report.scope).toMatch(/One passive GET/);
  });
});

describe("live check grade", () => {
  const good = {
    url: "https://example.org/", status: 200, hops: [{ url: "https://example.org/", status: 200 }],
    tls: { protocol: "TLSv1.3", validTo: "Dec 31 23:59:59 2030 GMT", issuer: "Let's Encrypt" },
    headers: {
      "strict-transport-security": "max-age=63072000; includeSubDomains",
      "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
      "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "permissions-policy": "camera=()",
      "set-cookie": ["sid=1; Secure; HttpOnly; SameSite=Lax"],
    },
  };

  it("gives a well-configured site a full score, with frame-ancestors counting for framing", () => {
    const r = grade(good, { now: Date.parse("2026-10-23") });
    expect(r.score).toBe(100);
    expect(r.verdict).toBe("Solid basics");
    expect(r.checks.every((c) => c.passed)).toBe(true);
  });

  it("flags a weak HSTS, unsafe scripts, a near-expiry certificate and wide CORS, each with a fix and a check", () => {
    const r = grade({ ...good, tls: { ...good.tls, validTo: "Oct 30 00:00:00 2026 GMT" }, headers: {
      ...good.headers, "strict-transport-security": "max-age=300",
      "content-security-policy": "script-src 'self' 'unsafe-inline'",
      "access-control-allow-origin": "*", "access-control-allow-credentials": "true",
    } }, { now: Date.parse("2026-10-23") });
    const failed = r.checks.filter((c) => !c.passed).map((c) => c.id).sort();
    expect(failed).toEqual(["cert", "cors", "csp-scripts", "framing", "hsts"]);
    for (const c of r.checks.filter((c) => !c.passed)) {
      expect(c.fix.length, c.id).toBeGreaterThan(20);
      expect(c.verify, c.id).toMatch(/^(curl|openssl|echo)/);
    }
  });
});

describe("live check endpoint", () => {
  let server, base;
  beforeAll(async () => {
    // The stub resolver fails fast, so nothing here reaches the network.
    const lookup = async () => { throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }); };
    server = createServer(createHandler({ lookup }));
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${server.address().port}`;
  });
  afterAll(() => new Promise((r) => server.close(r)));

  const post = (body, ip) => fetch(base, {
    method: "POST", body: typeof body === "string" ? body : JSON.stringify(body),
    headers: { "Content-Type": "application/json", ...(ip ? { "X-Forwarded-For": ip } : {}) },
  });

  it("answers errors as JSON with a code, a message and a hint", async () => {
    for (const [res, status, code] of [
      [await fetch(base), 405, "method_not_allowed"],
      [await post("not json"), 400, "invalid_json"],
      [await post({ url: "example.org" }), 400, "consent_required"],
      [await post({ url: "example.org", consent: "yes" }), 400, "consent_required"],
      [await post({ url: "http://169.254.169.254/", consent: true }), 400, "not_public"],
      [await post({ url: "localhost:3000", consent: true }), 400, "invalid_url"],
    ]) {
      expect(res.status, code).toBe(status);
      expect(res.headers.get("content-type")).toMatch(/^application\/json/);
      expect(res.headers.get("cache-control")).toBe("no-store");
      const { error } = await res.json();
      expect(error.code).toBe(code);
      expect(error.message.length).toBeGreaterThan(5);
      expect(error.hint.length).toBeGreaterThan(5);
    }
  });

  it("limits checks of one site to 30 an hour, from any number of visitors", async () => {
    const codes = [];
    for (let i = 0; i < 31; i++) {
      const res = await post({ url: "www.limited.example.org", consent: true }, `203.0.113.${i + 1}`);
      codes.push((await res.json()).error.code);
    }
    expect(codes.slice(0, 30).every((c) => c === "not_found")).toBe(true);
    expect(codes[30]).toBe("rate_limited");
    // www. is stripped: the bare name shares the same limit.
    const res = await post({ url: "limited.example.org", consent: true }, "203.0.113.200");
    expect(res.status).toBe(429);
    const wait = Number(res.headers.get("retry-after"));
    expect(Number.isInteger(wait)).toBe(true);
    expect(wait).toBeGreaterThan(0);
    expect(wait).toBeLessThanOrEqual(3600);
  });

  it("waits for the slowest full limit, not the first one it finds", async () => {
    const { limited } = await import("../api/check.mjs");
    const minute = { window: 60_000, max: 1, hint: "Wait a minute." };
    const day = { window: 86_400_000, max: 1, hint: "Come back tomorrow." };
    const rules = [["wait:m", minute], ["wait:d", day]];
    expect(limited(rules, 0)).toBeNull();
    const rule = limited(rules, 7_000);
    expect(rule.retryAfter).toBe(86_393);
    expect(rule.hint).toBe("Come back tomorrow.");
    // Once the minute has passed, the day still holds.
    expect(limited(rules, 61_000).retryAfter).toBe(86_339);
  });

  it("CheckError carries an HTTP status", () => {
    expect(new CheckError("x", "m", 418, "h").status).toBe(418);
  });
});
