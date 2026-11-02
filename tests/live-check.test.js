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
import { createHandler, RATE_LIMIT_POLICY } from "../api/check.mjs";

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

describe("live check guard, IPv6 forms of internal addresses", () => {
  // new URL() writes the embedded IPv4 in hex: [::ffff:127.0.0.1] becomes [::ffff:7f00:1].
  const internal = [
    "[::ffff:127.0.0.1]", "[::ffff:169.254.169.254]", "[::ffff:10.0.0.1]", "[64:ff9b::7f00:1]", "[::127.0.0.1]",
    "[2002:7f00:1::]", "[::ffff:0:127.0.0.1]", "[64:ff9b:1::a00:1]", "[100::1]", "[2001:0:4136:e378:8000:63bf:80ff:fffe]",
    "[::ffff:192.168.1.1]", "[64:ff9b::a9fe:a9fe]", "[2002:a9fe:a9fe::1]", "[fec0::1]", "[::2]",
  ];
  it("refuses each one as a typed address", () => {
    for (const host of internal) expect(codeOf(() => parseTarget(`http://${host}/`)), host).toBe("not_public");
  });
  it("refuses each one as a DNS answer", async () => {
    for (const host of internal) {
      const address = new URL(`http://${host}/`).hostname.slice(1, -1);
      expect(await codeOfAsync(resolvePublic("site.example-dns.org", { lookup: async () => [{ address, family: 6 }] })), address).toBe("not_public");
    }
  });
  it("still allows public addresses written the same ways", () => {
    for (const ip of ["::ffff:808:808", "64:ff9b::808:808", "2002:808:808::1", "2606:4700:4700::1111", "2a00:1450:4001:80b::200e"]) {
      expect(isPublicIp(ip), ip).toBe(true);
    }
  });
});

describe("the CLI's guards, for the same forms", () => {
  it("refuses them where only loopback or a named host may go", async () => {
    const { checkTarget } = await import("../src/mcp/workspace.js");
    const { checkLiveTarget } = await import("../lib/giants/index.js");
    for (const host of ["[::ffff:169.254.169.254]", "[64:ff9b::7f00:1]", "[2002:a00:1::]"]) {
      expect(() => checkTarget(`http://${host}/`, []), host).toThrow();
      expect(checkLiveTarget(`http://${host}/`, { typedUrl: "http://127.0.0.1:3000/" }).ok, host).toBe(false);
    }
  });
  it("counts them as local, as their IPv4 forms are", async () => {
    const { isPrivateHost } = await import("../src/utils/url.js");
    for (const host of ["[::ffff:10.0.0.1]", "[::ffff:127.0.0.1]", "[fd00::1]", "[::1]"]) expect(isPrivateHost(`http://${host}/`), host).toBe(true);
    expect(isPrivateHost("http://[2606:4700:4700::1111]/")).toBe(false);
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
      expect(res.headers.get("ratelimit-policy")).toBe(RATE_LIMIT_POLICY);
      expect(res.headers.get("ratelimit-remaining")).toBeNull();
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
    expect(res.headers.get("ratelimit-policy")).toBe(RATE_LIMIT_POLICY);
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

  it("refuses an IPv6 form of loopback before any byte leaves", async () => {
    const res = await post({ url: "http://[::ffff:127.0.0.1]/", consent: true }, "203.0.113.77");
    expect((await res.json()).error.code).toBe("not_public");
  });
  it("counts every name under one registrable domain as one site", async () => {
    const codes = [];
    for (let i = 0; i < 31; i++) {
      const res = await post({ url: `${i % 2 ? "shop" : "blog"}.limited-site.org`, consent: true }, `198.51.100.${i + 1}`);
      codes.push((await res.json()).error.code);
    }
    expect(codes[30]).toBe("rate_limited");
  });

  it("keys a site by registrable domain, but each app on a shared host apart", async () => {
    const { siteKey } = await import("../api/check.mjs");
    expect(siteKey("www.shop.example-site.co.uk")).toBe("example-site.co.uk");
    expect(siteKey("api.example-site.org")).toBe(siteKey("example-site.org"));
    expect(siteKey("one.vercel.app")).not.toBe(siteKey("two.vercel.app"));
    expect(siteKey("preview.one.vercel.app")).toBe("one.vercel.app");
    expect(siteKey("me.github.io")).toBe("me.github.io");
  });

  it("counts an IPv6 visitor by their /64, as one visitor", async () => {
    const codes = [];
    for (let i = 0; i < 7; i++) {
      const res = await post({ url: `v6-${i}.example-visitor.org`, consent: true }, `2001:db8:77:1::${(i + 1).toString(16)}`);
      codes.push((await res.json()).error.code);
    }
    expect(codes[6]).toBe("rate_limited");
  });

  it("drops the oldest entries when full, not every limit at once", async () => {
    const { limited, MAX_KEYS } = await import("../api/check.mjs");
    const rule = { window: 60_000, max: 1, hint: "Wait a minute." };
    for (let i = 0; i < MAX_KEYS; i++) limited([[`fill:${i}`, rule]], 0);
    expect(limited([["fill:last", rule]], 0)).toBeNull();
    // The store went over its size: the newest limit must still hold.
    expect(limited([["fill:last", rule]], 1)).not.toBeNull();
  });

  it("CheckError carries an HTTP status", () => {
    expect(new CheckError("x", "m", 418, "h").status).toBe(418);
  });
});
