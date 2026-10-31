import { createHash } from "node:crypto";
/**
 * E20 runner (bench/front-door/run.mjs): the guard that keeps it on loopback
 * until the protocol is registered, and a loopback-only visit. Every name is
 * pinned to 127.0.0.1 and DNS is stubbed, so nothing leaves the machine.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  authorize, recordedHash, isRegistered, readList, readExclusions, exclusionFor, wilson, newcombe, aggregate, runStudy, selfTest, visit,
  USER_AGENT, LIMITS, sha256,
  CONFIRMATORY_CLAIMS, Z_DECISION, SESOI, HYPOTHESES, Q8, bandDecision, directionDecision, bootstrap, benjaminiHochberg, twoProportionP, compare,
  platformOf, appPageAdopted, findAppLink, robotsVerdict, redact,
} from "../bench/front-door/run.mjs";
import { optedOut } from "../api/_lib/page.mjs";

const HASH = sha256("1,example.com\n");
const EX = sha256("gov government\n");
const prereg = ({ status = "**Registered.** Accepted", tranco = HASH, yc = "pending", ex = EX } = {}) => `
| | |
|---|---|
| Status | ${status} |
| Tranco list SHA-256 | \`${tranco}\` |
| YC list SHA-256 | \`${yc}\` |
| Exclusion list SHA-256 | \`${ex}\` |
`;
const reg = (o = {}) => ({ loopback: false, registered: "E20", cohort: "tranco", listHash: HASH, excludeHash: EX, preregText: prereg(), ...o });

describe("E20 guard", () => {
  it("allows a loopback run", () => {
    expect(authorize({ loopback: true })).toEqual({ mode: "loopback" });
  });

  it("B6: refuses every run that would leave loopback, even one with the registered flag and hashes", () => {
    expect(() => authorize(reg())).toThrow(/E20 is closed/);
    expect(() => authorize({})).toThrow(/E20 is closed/);
  });

  it("keeps the registered rate", () => {
    expect(LIMITS.concurrency).toBe(4);
    expect(LIMITS.delayMs).toBe(1000);
  });

  it("the prereg records the hashes of the lists in the repo", () => {
    const root = join(__dirname, "..");
    const text = readFileSync(join(root, "docs", "research", "prereg", "E20-front-door.md"), "utf8");
    const sha = (f) => createHash("sha256").update(readFileSync(join(root, "bench", "front-door", "lists", f))).digest("hex");
    expect(recordedHash(text, "tranco")).toBe(sha("tranco-ZJ8PG-top1000.csv"));
    expect(recordedHash(text, "yc")).toBe(sha("yc-fall2026-summer2026-2026-10-29.csv"));
    expect(recordedHash(text, "exclusions")).toBe(sha("exclusions.txt"));
    expect(isRegistered(text)).toBe(true);
    expect(recordedHash(prereg(), "tranco")).toBe(HASH);
  });
});

describe("E20 list and statistics", () => {
  it("reads Tranco and YC lists, one row per host", () => {
    expect(readList("1,google.com\n2,Example.co.uk\n3,google.com\n", "tranco")).toEqual([
      { rank: 1, host: "google.com", group: "com" },
      { rank: 2, host: "example.co.uk", group: "uk" },
    ]);
    expect(readList("batch,company,domain\nF26,Acme,https://acme.ai/about\nS26,Beta,beta.dev\n", "yc")).toEqual([
      { rank: 1, host: "acme.ai", group: "F26" },
      { rank: 2, host: "beta.dev", group: "S26" },
    ]);
  });

  it("reads the exclusion list and matches a listed domain and its subdomains", () => {
    const ex = readExclusions("# comment\ngov government\nExample-Casino.com gambling  # note\n\nclinic.example health\n");
    expect([...ex]).toEqual([["gov", "government"], ["example-casino.com", "gambling"], ["clinic.example", "health"]]);
    expect(exclusionFor("ministry.example.gov", ex)).toBe("government");
    expect(exclusionFor("www.example-casino.com", ex)).toBe("gambling");
    expect(exclusionFor("example-casino.com.evil.net", ex)).toBe(null);
    expect(exclusionFor("notgov", ex)).toBe(null);
    expect(() => readExclusions("example.com shopping\n")).toThrow(/category must be one of/);
    expect(() => readExclusions("example.com\n")).toThrow(/category must be one of/);
    expect(() => readExclusions("https://example.com/ adult\n")).toThrow(/expected/);
  });

  it("the exclusion list in the repo parses", () => {
    const f = join(__dirname, "..", "bench", "front-door", "lists", "exclusions.txt");
    expect(() => readExclusions(readFileSync(f, "utf8"))).not.toThrow();
  });

  it("computes Wilson and Newcombe intervals", () => {
    const w = wilson(81, 263);
    expect(w.lo).toBeCloseTo(0.2553, 3);
    expect(w.hi).toBeCloseTo(0.3662, 3);
    expect(wilson(0, 0).p).toBe(null);
    const d = newcombe(56, 70, 48, 80);
    expect(d.diff).toBeCloseTo(0.2, 6);
    expect(d.ci95[0]).toBeCloseTo(0.0524, 3);
    expect(d.ci95[1]).toBeCloseTo(0.3339, 3);
  });

  it("aggregates without site names and suppresses small groups", () => {
    const rec = (host, passed) => ({ host, group: "xx", status: "ok", score: passed ? 90 : 30, checks: [
      { id: "https", passed: true, weight: 22 }, { id: "hsts", passed, weight: 12 }, { id: "spf", passed: false, weight: 0 },
    ] });
    const agg = aggregate([rec("secret-name-a.xx", true), rec("secret-name-b.xx", false), { host: "c.xx", status: "opted_out" }]);
    expect(JSON.stringify(agg)).not.toMatch(/secret-name/);
    expect(agg.checks["https+hsts"]).toMatchObject({ n: 2, passed: 1 });
    expect(agg.checks.spf).toMatchObject({ n: 0, unknown: 2 });
    expect(agg.sites).toMatchObject({ listed: 3, visited: 2, opted_out: 1 });
    expect(agg.byGroup).toEqual({});
    expect(agg.groupsSuppressed).toBe(1);
  });
});

describe("E20 visit, loopback only", () => {
  let server, port;
  const seen = [];
  beforeAll(async () => {
    server = createServer((req, res) => {
      const host = String(req.headers.host).split(":")[0];
      seen.push({ host, url: req.url, ua: req.headers["user-agent"] });
      if (req.url === "/robots.txt" && host === "optout.e20-test.example.com") {
        res.writeHead(200, { "Content-Type": "text/plain" });
        return res.end("User-agent: Penthera-Research\nDisallow: /\n");
      }
      if (req.url === "/robots.txt" && host === "nobots.e20-test.example.com") {
        res.writeHead(200, { "Content-Type": "text/plain" });
        return res.end("User-agent: *\nDisallow: /\n");
      }
      if (req.url === "/robots.txt" && host === "partial.e20-test.example.com") {
        res.writeHead(200, { "Content-Type": "text/plain" });
        return res.end("User-agent: *\nDisallow: /private/\n");
      }
      if (req.url === "/") {
        res.writeHead(200, { "Content-Type": "text/html", "Strict-Transport-Security": "max-age=63072000" });
        return res.end('<!doctype html><script src="/app.js"></script>');
      }
      res.writeHead(404); res.end();
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    port = server.address().port;
  });
  afterAll(() => new Promise((r) => server.close(r)));

  it("honors a robots.txt group naming Penthera-Research, and the live check's token", () => {
    expect(optedOut("User-agent: Penthera-Research\nDisallow: /\n", ["penthera-research", "penthera-quickcheck"])).toBe(true);
    expect(optedOut("User-agent: Penthera-QuickCheck\nDisallow: /\n", ["penthera-research", "penthera-quickcheck"])).toBe(true);
    expect(optedOut("User-agent: Penthera-Research\nDisallow: /\n")).toBe(false);   // the live check keeps its own token
  });

  it("stops at an opt-out and fetches no scripts, with the study's User-Agent", async () => {
    seen.length = 0;
    const out = await visit({ rank: 1, host: "optout.e20-test.example.com", group: "com" }, { loopbackPort: port });
    expect(out.status).toBe("opted_out");
    expect(seen.map((s) => s.url)).toEqual(["/robots.txt"]);

    seen.length = 0;
    const ok = await visit({ rank: 2, host: "fine.e20-test.example.com", group: "com" }, { loopbackPort: port });
    expect(ok.status).toBe("ok");
    expect(seen.map((s) => s.url).sort()).toEqual(["/", "/.well-known/security.txt", "/robots.txt"]);
    expect(seen.every((s) => s.ua === USER_AGENT)).toBe(true);
    expect(ok.checks.some((c) => c.id === "secrets")).toBe(false);
  });

  it("treats User-agent: * with Disallow: / as an opt-out, counted as excluded, and stops at robots.txt", async () => {
    seen.length = 0;
    const out = await visit({ rank: 3, host: "nobots.e20-test.example.com", group: "com" }, { loopbackPort: port });
    expect(out).toMatchObject({ status: "excluded", reason: "robots_disallow_all" });
    expect(seen.map((s) => s.url)).toEqual(["/robots.txt"]);
    const agg = aggregate([out]);
    expect(agg.sites).toMatchObject({ listed: 1, visited: 0, "excluded:robots_disallow_all": 1 });

    seen.length = 0;
    const partial = await visit({ rank: 4, host: "partial.e20-test.example.com", group: "com" }, { loopbackPort: port });
    expect(partial.status).toBe("ok");
  });

  it("leaves the live check alone: it still ignores the * group", () => {
    expect(optedOut("User-agent: *\nDisallow: /\n")).toBe(false);
  });

  it("runs the self-test against the mock server and writes results outside git", async () => {
    const dir = mkdtempSync(join(tmpdir(), "e20-"));
    const r = await selfTest({ out: dir });
    expect(r.problems).toEqual([]);
    expect(existsSync(join(dir, "raw.jsonl"))).toBe(true);
    expect(readFileSync(join(dir, ".gitignore"), "utf8")).toBe("*\n");
  });

  it("caps concurrency and keeps one visit per listed host", async () => {
    seen.length = 0;
    const dir = mkdtempSync(join(tmpdir(), "e20-"));
    const rows = readList("1,a.e20-test.example.com\n2,a.e20-test.example.com\n3,b.e20-test.example.com\n", "tranco");
    const { records, aggregate: agg } = await runStudy(rows, { cohort: "tranco", out: dir, loopbackPort: port, concurrency: 50, delayMs: 0, exclude: readExclusions("b.e20-test.example.com adult\n") });
    expect(records.map((r) => r.status)).toEqual(["ok", "excluded"]);
    expect(agg.sites["excluded:exclusion_list"]).toBe(1);
    expect(agg.exclusionCategories).toEqual({ adult: 1 });
    expect(JSON.stringify(agg)).not.toContain("b.e20-test");
    expect(seen.filter((s) => s.url === "/").length).toBe(1);
    expect(agg.concurrency).toBe(8);
  });
});

describe("E20 decisions and statistics (§ 6)", () => {
  it("uses the Bonferroni decision level for 11 confirmatory claims", () => {
    // z for 1 - 0.05/22, one tail: 2.8376 (Python statistics.NormalDist().inv_cdf).
    expect(CONFIRMATORY_CLAIMS).toBe(11);
    expect(Z_DECISION).toBeCloseTo(2.8376, 4);
    const w = wilson(50, 100, Z_DECISION);
    expect(w.hi - w.lo).toBeGreaterThan(wilson(50, 100).hi - wilson(50, 100).lo);
  });

  it("decides a band hypothesis from its interval", () => {
    expect(bandDecision([0.55, 0.7], [0.5, 0.8])).toBe("supported");
    expect(bandDecision([0.81, 0.9], [0.5, 0.8])).toBe("refuted");
    expect(bandDecision([0.1, 0.3], [0.5, 0.8])).toBe("refuted");
    expect(bandDecision([0.45, 0.6], [0.5, 0.8])).toBe("inconclusive");
    expect(bandDecision([null, null], [0, 0.4])).toBe("no_data");
  });

  it("decides a predicted direction, and calls a tight interval around 0 no meaningful difference", () => {
    expect(directionDecision([0.02, 0.2], +1)).toBe("supported");
    expect(directionDecision([-0.2, -0.02], +1)).toBe("refuted");
    expect(directionDecision([-0.2, -0.02], -1)).toBe("supported");
    expect(directionDecision([-0.06, 0.08], -1)).toBe("no_meaningful_difference");
    expect(directionDecision([-0.15, 0.08], -1)).toBe("inconclusive");
    expect(SESOI).toBe(0.1);
  });

  it("bootstraps with a fixed seed, so a re-run gives the same interval", () => {
    const xs = Array.from({ length: 200 }, (_, i) => (i * 37) % 101);
    const a = bootstrap(xs, null, { resamples: 2000 });
    const b = bootstrap(xs, null, { resamples: 2000 });
    expect(a).toEqual(b);
    expect(a.ci[0]).toBeLessThanOrEqual(a.estimate);
    expect(a.ci[1]).toBeGreaterThanOrEqual(a.estimate);
    expect(bootstrap([], null).ci).toEqual([null, null]);
  });

  it("adjusts secondary p-values with Benjamini–Hochberg", () => {
    const q = benjaminiHochberg([0.01, 0.04, 0.03, null]);
    expect(q[0]).toBeCloseTo(0.03, 10);
    expect(q[1]).toBeCloseTo(0.04, 10);
    expect(q[2]).toBeCloseTo(0.04, 10);
    expect(q[3]).toBe(null);
    expect(twoProportionP(50, 100, 50, 100)).toBeCloseTo(1, 6);
    expect(twoProportionP(70, 100, 50, 100)).toBeCloseTo(0.0039, 3);
  });

  it("compares startups minus top sites, with Q8 decisions on the four confirmatory checks", () => {
    const top = { cohort: "tranco", checks: { "https+hsts": { n: 700, passed: 420 }, csp: { n: 700, passed: 280 }, nosniff: { n: 700, passed: 400 } } };
    const yc = { cohort: "yc", checks: { "https+hsts": { n: 300, passed: 240 }, csp: { n: 300, passed: 60 }, nosniff: { n: 300, passed: 170 } } };
    for (const c of [top, yc]) for (const v of Object.values(c.checks)) v.share = v.passed / v.n;
    const r = compare(top, yc);
    expect(r.direction).toBe("b minus a");
    expect(r.checks["https+hsts"]).toMatchObject({ confirmatory: true, predicted: "higher", decision: "supported" });
    expect(r.checks["https+hsts"].diff).toBeCloseTo(0.2, 6);
    expect(r.checks.csp).toMatchObject({ predicted: "lower", decision: "supported" });
    expect(r.checks.nosniff.p).toBeGreaterThan(0.05);
    expect(r.checks.nosniff.q).toBeGreaterThan(0.05);
    expect(Object.keys(Q8).sort()).toEqual(["caa", "csp", "https+hsts", "spf+dmarc"]);
  });

  it("evaluates Q1 to Q7 in the aggregate and adds the one-per-site sensitivity", () => {
    const rec = (host, finalHost, hsts) => ({ host, finalHost, group: "xx", status: "ok", score: 60, checks: [
      { id: "https", passed: true, weight: 22 }, { id: "hsts", passed: hsts, weight: 12 },
    ] });
    const agg = aggregate([rec("a.xx", "a.xx", true), rec("www.a.xx", "a.xx", true), rec("b.xx", "b.xx", false)]);
    expect(Object.keys(agg.hypotheses)).toEqual(Object.keys(HYPOTHESES));
    expect(agg.hypotheses.Q1).toMatchObject({ check: "https+hsts", band: [0.45, 0.75] });
    expect(agg.hypotheses.Q7.estimate).toBe(60);
    expect(agg.sensitivity.onePerFinalSite.sites).toBe(2);
    expect(agg.score.medianCi95).toEqual([60, 60]);
  });
});

describe("E20 raw records hold no email addresses (§ 8.7)", () => {
  it("keeps the domain and drops the local part", () => {
    expect(redact("Contact: mailto:jane.doe@acme.dev; Expires: 2027")).toBe("Contact: mailto:<redacted>@acme.dev; Expires: 2027");
    expect(redact("v=DMARC1; p=reject; rua=mailto:dmarc+x@reports.example.com")).toBe("v=DMARC1; p=reject; rua=mailto:<redacted>@reports.example.com");
    expect(redact("max-age=63072000")).toBe("max-age=63072000");
  });
});

describe("E20 hosting platform (§ 6.7)", () => {
  it("reads the edge from headers and the builder from the generator tag", () => {
    expect(platformOf({ "x-vercel-id": "fra1::abc", server: "Vercel" }, "")).toEqual({ edge: "vercel", builder: "none" });
    expect(platformOf({ "CF-RAY": "1-AMS" }, '<meta name="generator" content="Webflow">')).toEqual({ edge: "cloudflare", builder: "webflow" });
    expect(platformOf({ server: "nginx" }, "<meta content='Framer 1a2b' name='generator'>")).toEqual({ edge: "other", builder: "framer" });
    expect(platformOf({}, '<meta name="generator" content="Hugo 0.1">')).toEqual({ edge: "other", builder: "other" });
  });
});

describe("E20 sub-measure B, adopted (§ 4.2)", () => {
  it("is on for a registered run only because the prereg row says Adopted (29 Oct 2026)", () => {
    const text = readFileSync(join(__dirname, "..", "docs", "research", "prereg", "E20-front-door.md"), "utf8");
    expect(appPageAdopted(text)).toBe(true);
    expect(appPageAdopted("| Sub-measure B (app page) | **Pending the maintainer's decision.** |")).toBe(false);
    expect(appPageAdopted("| Sub-measure B (app page) | **Adopted** 1 Nov |")).toBe(true);
  });

  it("finds one same-site login or app link, never an outside sign-in provider or the homepage", () => {
    const page = "https://acme.dev/";
    expect(findAppLink('<a href="https://accounts.google.com/login">Log in</a><a href="/pricing">Pricing</a><a href="https://app.acme.dev/?ref=nav#top">Open app</a>', page)).toBe("https://app.acme.dev/");
    expect(findAppLink('<a class="btn" href="/login"><span>Sign&nbsp;in</span></a>', page)).toBe("https://acme.dev/login");
    expect(findAppLink('<a href="/dashboard/">Go</a>', page)).toBe("https://acme.dev/dashboard/");
    expect(findAppLink('<a href="/">Log in</a><a href="mailto:x@acme.dev">Login</a><!-- <a href="/login">Log in</a> -->', page)).toBe(null);
    expect(findAppLink('<a href="https://acme.dev.evil.net/login">Log in</a>', page)).toBe(null);
    expect(findAppLink('<a href="/signup">Sign up</a>', page)).toBe(null);
  });

  it("reads robots.txt for one path: our group first, then *, longest rule wins", () => {
    expect(robotsVerdict("User-agent: *\nDisallow: /login\n", "/login")).toBe("disallowed");
    expect(robotsVerdict("User-agent: *\nDisallow: /login\n", "/app")).toBe("allowed");
    expect(robotsVerdict("User-agent: *\nDisallow: /\nAllow: /login\n", "/login")).toBe("allowed");
    expect(robotsVerdict("User-agent: Penthera-Research\nAllow: /\n\nUser-agent: *\nDisallow: /app\n", "/app")).toBe("allowed");
    expect(robotsVerdict("User-agent: Penthera-Research\nDisallow: /\n", "/login")).toBe("opted_out");
    expect(robotsVerdict("User-agent: *\nDisallow: /*.php$\n", "/login.php")).toBe("disallowed");
    expect(robotsVerdict("", "/login")).toBe("allowed");
  });

  describe("on loopback", () => {
    let server, port;
    const seen = [];
    beforeAll(async () => {
      server = createServer((req, res) => {
        const host = String(req.headers.host).split(":")[0];
        seen.push({ host, url: req.url, ua: req.headers["user-agent"], method: req.method });
        const link = (href) => `<!doctype html><a href="${href}">Log in</a>`;
        if (req.url === "/robots.txt" && host === "app.b-blocked.example.com") {
          res.writeHead(200, { "Content-Type": "text/plain" });
          return res.end("User-agent: *\nDisallow: /login\n");
        }
        if (req.url === "/" && host === "b-ok.example.com") {
          res.writeHead(200, { "Content-Type": "text/html" });
          return res.end(link(`http://app.b-ok.example.com:${port}/login`));
        }
        if (req.url === "/" && host === "b-blocked.example.com") {
          res.writeHead(200, { "Content-Type": "text/html" });
          return res.end(link(`http://app.b-blocked.example.com:${port}/login`));
        }
        if (req.url === "/" && host === "b-away.example.com") {
          res.writeHead(200, { "Content-Type": "text/html" });
          return res.end(link("/login"));
        }
        if (req.url === "/login" && host === "b-away.example.com") {
          res.writeHead(302, { Location: `http://idp.elsewhere.example.org:${port}/authorize` });
          return res.end();
        }
        if (req.url === "/login") {
          res.writeHead(200, { "Content-Type": "text/html", "Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY" });
          return res.end("<form method=post><input name=password type=password></form>");
        }
        res.writeHead(404);
        res.end();
      });
      await new Promise((r) => server.listen(0, "127.0.0.1", r));
      port = server.address().port;
    });
    afterAll(() => new Promise((r) => server.close(r)));

    it("is not sent unless asked for", async () => {
      seen.length = 0;
      const out = await visit({ rank: 1, host: "b-ok.example.com", group: "com" }, { loopbackPort: port });
      expect(out.app).toBeUndefined();
      expect(seen.some((s) => s.url === "/login")).toBe(false);
    });

    it("sends robots.txt and one GET for the linked page, no form, and grades its headers", async () => {
      seen.length = 0;
      const out = await visit({ rank: 1, host: "b-ok.example.com", group: "com" }, { loopbackPort: port, appPage: true });
      expect(out.app).toMatchObject({ status: "ok", httpStatus: 200, sameHost: false });
      const appReqs = seen.filter((s) => s.host === "app.b-ok.example.com").map((s) => `${s.method} ${s.url}`);
      expect(appReqs).toEqual(["GET /robots.txt", "GET /login"]);
      expect(seen.every((s) => s.method === "GET" && s.ua === USER_AGENT)).toBe(true);
      const byId = Object.fromEntries(out.app.checks.map((c) => [c.id, c]));
      expect(byId.csp.passed).toBe(true);
      expect(byId.framing.passed).toBe(true);
      expect(out.app.checks.some((c) => ["spf", "dmarc", "caa", "security-txt"].includes(c.id))).toBe(false);
    });

    it("honors a robots.txt Disallow for that path and sends nothing more", async () => {
      seen.length = 0;
      const out = await visit({ rank: 2, host: "b-blocked.example.com", group: "com" }, { loopbackPort: port, appPage: true });
      expect(out.app).toEqual({ status: "excluded", reason: "robots_disallow_path" });
      expect(seen.filter((s) => s.host === "app.b-blocked.example.com").map((s) => s.url)).toEqual(["/robots.txt"]);
    });

    it("does not follow a redirect to another site", async () => {
      seen.length = 0;
      const out = await visit({ rank: 3, host: "b-away.example.com", group: "com" }, { loopbackPort: port, appPage: true });
      expect(out.app).toEqual({ status: "error", error: "off_site" });
      expect(seen.some((s) => s.host.includes("elsewhere"))).toBe(false);
    });

    it("skips a linked host on the exclusion list", async () => {
      seen.length = 0;
      const out = await visit({ rank: 4, host: "b-ok.example.com", group: "com" }, { loopbackPort: port, appPage: true, exclude: readExclusions("app.b-ok.example.com health\n") });
      expect(out.app).toEqual({ status: "excluded", reason: "exclusion_list", category: "health" });
      expect(seen.some((s) => s.host === "app.b-ok.example.com")).toBe(false);
    });

    it("aggregates B apart from the homepage, with the paired comparison and no site names", async () => {
      const dir = mkdtempSync(join(tmpdir(), "e20b-"));
      const rows = readList("1,b-ok.example.com\n2,b-blocked.example.com\n", "tranco");
      const { aggregate: agg } = await runStudy(rows, { cohort: "tranco", out: dir, loopbackPort: port, delayMs: 0, appPage: true });
      expect(agg.appPage).toBe(true);
      expect(agg.app.sites).toMatchObject({ withHomepage: 2, visited: 1, "excluded:robots_disallow_path": 1 });
      expect(agg.app.paired.csp).toMatchObject({ n: 1, appOnly: 1, discordant: 1, hypothesis: "HB2", decision: "inconclusive" });
      expect(agg.app.paired.framing.hypothesis).toBe("HB1");
      expect(JSON.stringify(agg)).not.toMatch(/b-ok|b-blocked/);
    });
  });
});
