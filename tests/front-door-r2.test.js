/**
 * E20-R2 regressions, one per review finding. `http.request` and `https.request`
 * are replaced in this file, so https, redirects and failures run with no socket.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import http from "node:http";
import https from "node:https";
import { EventEmitter } from "node:events";
import { createServer } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { gzipSync } from "node:zlib";
import { classify, classifyRegistered, cookieNames, cspEvidence, evidenceOf, looksIpv6, pageExcerpt, scrub, scrubMisses, signatureMatches, traitsOf, SOFT_MAX_CHARS } from "../bench/front-door/classify.mjs";
import { authorize, exclusionFor, percentDecoded, globMatch, ipv4Lookup, percentForm, platformOf, readExclusions, robotsAccess, robotsBinary, robotsVerdict, strictRobots, visit, wholeSiteStop } from "../bench/front-door/run.mjs";
import { optedOut } from "../api/_lib/page.mjs";
import { CheckError, resolvePublic } from "../api/_lib/guard.mjs";
import { amendment3Adopted, mergeSkips, MAX_LIVE_ROUNDS, PASS_SEED, PREREG_R, recordedHashR, STUDY_PAGE, caaTree, checkPilotDropped, codeFiles, codeHash, dmarcReading, mergeCohorts, PILOT_MIN, ROLLING_WINDOW, siteDns, normalizeHost, pilotRounds, readDomain, readHostList, readRemovals, runPass, NO_DNS, unmatchedHosts, V2_LIMITS, visitInWorker } from "../bench/front-door/replicate.mjs";
import { orgDomain, publicSuffix, PSL_VERSION, pslSha256, siteKey, siteOrg } from "../bench/front-door/psl.mjs";
import { claims, clusterDiff, combine, coverageBounds, decide, diffClaim, dnsCoverage, e20Index, fisherExact, intervalOutcomes, isEligible, standardizedDiff, traitsByCohort } from "../bench/front-door/analyze-r.mjs";
import { legacyFindings } from "../bench/front-door/legacy-findings.mjs";
import { decidePilot, replayRaw, main as reportMain, pilotReport, sealPilot, stopRules, privacyReport } from "../bench/front-door/pilot-report.mjs";
import { falseFireReviewed, LEGACY_CLASSIFIER_SHA256, legacyProblem, PRIVACY_STOP, withheldCounts, withholdText, MIN_ELIGIBLE, MIN_GRADED, NO_PRIVACY, pageTextMissed, purgeState, recordMisses, resolverFailed, unfinishedRun } from "../bench/front-door/record-checks.mjs";
import { main as analyzeMain, challengeByEdge, secondaryCohorts, skipsByCohort } from "../bench/front-door/analyze-r.mjs";
import { main as validationMain, purgeRun, stateOf, auditFrame, overWithheldLimit, worstCaseBounds, blindSheet, drawSample, parseLabels, pruneExcerpt, prunePilot, rewriteRun, scoreLabels, stratumOf, weightedMetrics } from "../bench/front-door/validation-sample.mjs";
import { runAcceptance } from "../bench/front-door/acceptance.mjs";
import { passiveReport } from "../api/_lib/tier1.mjs";
import { scoreOf } from "../api/_lib/grade.mjs";

// A fixture run names a stand-in state, so the analysis is told to run under it.
const runState = (dir) => stateOf(JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8")));

// A run mode, named so a scanner for hardcoded passwords reads no literal after `pass:`.
const PILOT_RUN = "pilot";
const rules = (report) => stopRules(report, { floors: false });
const realHttp = http.request, realHttps = https.request;
const realServer = (route) => http.createServer((req, res) => {
  const r = route(req.headers.host.split(":")[0], req.url) ?? { status: 404 };
  res.writeHead(r.status, { "content-type": "text/html", ...r.headers });
  res.end(r.body ?? "");
});
let web = {};
let log = [];

const fake = (url, opts, cb) => {
  const req = new EventEmitter();
  req.destroy = (e) => { if (e) req.emit("error", e); };
  req.end = () => {
    const u = new URL(url);
    log.push(u.href);
    const r = web[u.href] ?? web[u.origin + u.pathname] ?? { status: 404, body: "" };
    setImmediate(() => {
      if (r.err) return req.emit("error", Object.assign(new Error(r.err), { code: r.err }));
      const res = Readable.from([Buffer.from(r.body ?? "")]);
      res.statusCode = r.status;
      res.headers = r.headers || {};
      res.socket = { getPeerCertificate: () => ({}), getProtocol: () => "TLSv1.3" };
      cb(res);
    });
  };
  return req;
};
beforeAll(() => { http.request = fake; https.request = fake; });
afterAll(() => { http.request = realHttp; https.request = realHttps; });
beforeEach(() => { log = []; });

const ROBOTS = { status: 200, body: "User-agent: *\nAllow: /\n", headers: { "content-type": "text/plain" } };
const HOME = { status: 200, body: "<html><title>t</title>hello</html>", headers: { "content-type": "text/html" } };
const look = async (h) => { if (/dead/.test(h)) throw new Error("ENOTFOUND"); return [{ address: "93.184.216.34", family: 4 }]; };
const exclude = readExclusions("gov government\nbad.org adult\n");
const go = (w, host = "a.org", opts = {}) => { web = w; return visit({ host, cohorts: {} }, { strict: true, exclude, lookup: look, budgetMs: 15_000, hardCapMs: 30_000, ...opts }); };

describe("redirects and origins", () => {
  it("B1: stops a robots.txt redirect into an excluded host before it reaches it", async () => {
    const r = await go({ "https://a.org/robots.txt": { status: 301, headers: { location: "https://ministry.gov/robots.txt" } }, "https://ministry.gov/robots.txt": ROBOTS, "https://a.org/": HOME });
    expect(r).toMatchObject({ status: "excluded", reason: "exclusion_redirect" });
    expect(log.some((u) => u.includes("ministry"))).toBe(false);
  });
  it("B2: a trailing dot does not get past the exclusion list", async () => {
    expect(exclusionFor("ministry.gov.", exclude)).toBe("government");
    expect(exclusionFor("www.bad.org..", exclude)).toBe("adult");
    const r = await go({ "https://a.org/robots.txt": ROBOTS, "https://a.org/": { status: 302, headers: { location: "https://ministry.gov./" } } });
    expect(r).toMatchObject({ status: "excluded", reason: "exclusion_redirect" });
    expect(log.some((u) => u.includes("ministry"))).toBe(false);
  });
  it("B9: no www retry after the listed origin answered and a redirect's target is dead", async () => {
    const r = await go({ "https://a.org/robots.txt": ROBOTS, "https://a.org/": { status: 301, headers: { location: "https://dead.net/" } }, "https://www.a.org/robots.txt": ROBOTS, "https://www.a.org/": HOME });
    expect(r.status).toBe("error");
    expect(log.some((u) => u.includes("www.a.org"))).toBe(false);
  });
  it("B9: the www retry still runs when the listed name does not resolve", async () => {
    const r = await go({ "https://www.dead.org/robots.txt": ROBOTS }, "dead.org");
    expect(r.error).toBe("not_found");
    web = { "https://www.a.org/robots.txt": ROBOTS, "https://www.a.org/": HOME };
    const lookup = async (h) => { if (h === "a.org") throw new Error("ENOTFOUND"); return [{ address: "93.184.216.34", family: 4 }]; };
    const ok = await visit({ host: "a.org", cohorts: {} }, { strict: true, exclude, lookup });
    expect(ok.status).toBe("ok");
  });
  it("B9: no http retry after a reset, which may be a refusal", async () => {
    const r = await go({ "https://a.org/robots.txt": ROBOTS, "https://a.org/": { err: "ECONNRESET" }, "http://a.org/robots.txt": ROBOTS, "http://a.org/": HOME });
    expect(r).toMatchObject({ status: "error", error: "unreachable" });
    expect(log.some((u) => u.startsWith("http://"))).toBe(false);
    const before = await go({ "https://a.org/robots.txt": { err: "ECONNRESET" }, "http://a.org/robots.txt": ROBOTS, "http://a.org/": HOME });
    expect(before.status).toBe("error");
  });
  it("B9: no http retry after a site answered and its redirect target refused the connection", async () => {
    const r = await go({ "https://a.org/robots.txt": ROBOTS, "https://a.org/": { status: 301, headers: { location: "https://b.net/" } }, "https://b.net/robots.txt": { err: "ECONNREFUSED" }, "http://a.org/robots.txt": ROBOTS, "http://a.org/": HOME });
    expect(r.status).toBe("error");
    expect(log.some((u) => u.startsWith("http://"))).toBe(false);
  });
  it("B9: http still runs when nothing answers on https, and the record says why", async () => {
    const r = await go({ "https://a.org/robots.txt": { err: "ECONNREFUSED" }, "http://a.org/robots.txt": ROBOTS, "http://a.org/": HOME });
    expect(r.status).toBe("ok");
    expect(r.httpsFailed).toMatchObject({ error: "unreachable" });
  });
  it("B10: a redirect back to an origin whose robots.txt failed stops", async () => {
    const r = await go({ "https://a.org/robots.txt": { err: "ECONNREFUSED" }, "http://a.org/robots.txt": ROBOTS, "http://a.org/": { status: 301, headers: { location: "https://a.org/" } }, "https://a.org/": HOME });
    expect(r).toMatchObject({ status: "excluded", reason: "robots_unavailable" });
    expect(log).not.toContain("https://a.org/");
  });
  it("stops a redirect to a literal IPv4 address, and stores no trace of it", async () => {
    const r = await go({ "https://a.org/robots.txt": ROBOTS, "https://a.org/": { status: 302, headers: { location: "https://93.184.216.34/" } } });
    expect(r).toMatchObject({ status: "excluded", reason: "ipv4_literal" });
    expect(log.some((u) => u.includes("93.184.216.34"))).toBe(false);
    expect(JSON.stringify(r)).not.toContain("93.184.216.34");
  });
  it("S6: stops a redirect to a literal IPv6 address", async () => {
    const r = await go({ "https://a.org/robots.txt": ROBOTS, "https://a.org/": { status: 302, headers: { location: "https://[2606:4700:4700::1111]/" } } });
    expect(r).toMatchObject({ status: "excluded", reason: "ipv6_literal" });
    expect(log.some((u) => u.includes("2606"))).toBe(false);
  });
  it("S12: a bad certificate stays the outcome when there is no port 80", async () => {
    const cert = { err: "CERT_HAS_EXPIRED" };
    const r = await go({ "https://a.org/robots.txt": cert, "http://a.org/robots.txt": { err: "ECONNREFUSED" } });
    expect(r).toMatchObject({ status: "error", error: "tls_invalid", tlsReason: "CERT_HAS_EXPIRED" });
  });
  it("S12: a bad certificate with a working http keeps its reason on the record", async () => {
    const r = await go({ "https://a.org/robots.txt": { err: "CERT_HAS_EXPIRED" }, "http://a.org/robots.txt": ROBOTS, "http://a.org/": HOME });
    expect(r.status).toBe("ok");
    expect(r.httpsFailed).toEqual({ error: "tls_invalid", tlsReason: "CERT_HAS_EXPIRED" });
  });
  it("stops at a hop into an origin that opted out by path rules", async () => {
    const r = await go({ "https://a.org/robots.txt": { status: 200, body: "User-agent: Penthera-Research\nDisallow: /private\n" }, "https://a.org/": { status: 302, headers: { location: "/private/x" } } });
    expect(r).toMatchObject({ status: "excluded", reason: "robots_disallow_path" });
  });
  it("reads a 2xx robots.txt that is not a 200 as rules", async () => {
    const r = await go({ "https://a.org/robots.txt": { status: 203, body: "User-agent: Penthera-Research\nDisallow: /\n" }, "https://a.org/": HOME });
    expect(r.status).toBe("opted_out");
    expect(log).not.toContain("https://a.org/");
  });
  it("B4: does not repeat a failed robots.txt request, and keeps the certificate outcome", async () => {
    const cert = { err: "CERT_HAS_EXPIRED" };
    const r = await go({ "https://a.org/robots.txt": cert, "http://a.org/robots.txt": { status: 301, headers: { location: "https://a.org/robots.txt" } }, "https://a.org/": cert, "http://a.org/": HOME });
    expect(r).toMatchObject({ status: "error", error: "tls_invalid", tlsReason: "CERT_HAS_EXPIRED" });
    expect(log.filter((u) => u === "https://a.org/robots.txt")).toHaveLength(1);
    const back = await go({ "https://a.org/robots.txt": cert, "http://a.org/robots.txt": ROBOTS, "http://a.org/": { status: 301, headers: { location: "https://a.org/" } } });
    expect(back).toMatchObject({ error: "tls_invalid", tlsReason: "CERT_HAS_EXPIRED" });
  });
  it("16: another organization's opt-out at a redirect is its own reason, not the listed site's", async () => {
    const other = await go({ "https://a.org/robots.txt": ROBOTS, "https://a.org/": { status: 301, headers: { location: "https://parent.com/" } }, "https://parent.com/robots.txt": { status: 200, body: "User-agent: *\nDisallow: /\n" } });
    expect(other).toMatchObject({ status: "excluded", reason: "redirect_opted_out" });
    const same = await go({ "https://a.org/robots.txt": ROBOTS, "https://a.org/": { status: 301, headers: { location: "https://www.a.org/" } }, "https://www.a.org/robots.txt": { status: 200, body: "User-agent: Penthera-Research\nDisallow: /\n" } });
    expect(same.status).toBe("opted_out");
  });
  it("note: the budget spans the www attempt", async () => {
    web = { "https://www.a.org/robots.txt": ROBOTS, "https://www.a.org/": HOME };
    const lookup = async (h) => { if (h === "a.org") throw new Error("ENOTFOUND"); return [{ address: "93.184.216.34", family: 4 }]; };
    expect((await visit({ host: "a.org", cohorts: {} }, { strict: true, exclude, lookup, budgetMs: 200 })).status).not.toBe("ok");
  });
  it("item 3: the study's visit reads no DNS, and the live check still does", async () => {
    let asked = 0;
    const dns = { resolveTxt: async () => { asked++; return []; }, resolveCaa: async () => { asked++; return []; } };
    web = { "https://a.org/robots.txt": ROBOTS, "https://a.org/": HOME };
    const target = new URL("https://a.org/");
    await passiveReport(target, { lookup: look, dns, skipDns: true });
    expect(asked).toBe(0);
    await passiveReport(target, { lookup: look, dns });
    expect(asked).toBeGreaterThan(0);
    const r = await go({ "https://a.org/robots.txt": ROBOTS, "https://a.org/": HOME });
    expect(r.checks.some((c) => ["spf", "dmarc", "caa"].includes(c.id))).toBe(false);
  });
  it("item 3: the pass adds the DNS checks back, so the score means what it did", async () => {
    const server = realServer((_h, url) => (url === "/robots.txt" ? ROBOTS : HOME));
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    try {
      const stub = () => Promise.reject(Object.assign(new Error("x"), { code: "ENODATA" }));
      const { records } = await runPass(mergeCohorts({ T1k: [{ host: "a.selftest.example.com", rank: 1, group: "x" }] }), { pass: 2, out: mkdtempSync(join(tmpdir(), "e20r2-")), loopbackPort: server.address().port, delayMs: 0, dns: { mx: stub, ns: stub, resolveTxt: stub, resolveCaa: stub } });
      const ids = records[0].checks.map((c) => c.id);
      expect(ids).toEqual(expect.arrayContaining(["spf", "dmarc", "caa", "csp"]));
      expect(records[0].score).toBe(scoreOf(records[0].checks));
      expect(records[0].dns.listed.registeredChecks).toBeUndefined();
    } finally { await new Promise((r) => server.close(r)); }
  });
  it("B2: a lookup failure keeps its code, so a resolver fault differs from a name that doesn't exist", async () => {
    const fail = (code) => async () => { throw Object.assign(new Error(code), { code }); };
    expect((await visit({ host: "a.org", cohorts: {} }, { strict: true, exclude, lookup: fail("ESERVFAIL") }))).toMatchObject({ error: "not_found", netCode: "ESERVFAIL" });
    expect((await visit({ host: "a.org", cohorts: {} }, { strict: true, exclude, lookup: fail("ENOTFOUND") })).netCode).toBe("ENOTFOUND");
  });
  it("note: a TLS alert that denies access is a refusal, with no fallback", async () => {
    const r = await go({ "https://a.org/robots.txt": { err: "ERR_SSL_TLSV1_ALERT_ACCESS_DENIED" }, "http://a.org/robots.txt": ROBOTS, "http://a.org/": HOME });
    expect(r).toMatchObject({ error: "unreachable", netCode: "ERR_SSL_TLSV1_ALERT_ACCESS_DENIED" });
    expect(log.some((u) => u.startsWith("http://"))).toBe(false);
  });
  it("S1: a failed handshake is its own outcome, and keeps its code", async () => {
    const r = await go({ "https://a.org/robots.txt": { err: "EPROTO" }, "http://a.org/robots.txt": { err: "ECONNREFUSED" } });
    expect(r).toMatchObject({ status: "error", error: "tls_handshake", netCode: "EPROTO" });
    const fell = await go({ "https://a.org/robots.txt": { err: "ERR_SSL_WRONG_VERSION_NUMBER" }, "http://a.org/robots.txt": ROBOTS, "http://a.org/": HOME });
    expect(fell).toMatchObject({ status: "ok", httpsFailed: { error: "tls_handshake", netCode: "ERR_SSL_WRONG_VERSION_NUMBER" } });
    expect((await go({ "https://a.org/robots.txt": { err: "ECONNRESET" } })).netCode).toBe("ECONNRESET");
  });
  it("S2: a timeout gets no http fallback, as the amendment says", () => {
    expect(strictRobots().allowFallback(new CheckError("timeout", "x", 504, ""))).toBe(false);
    expect(readFileSync(join(import.meta.dirname, "..", "docs", "research", "prereg", "E20r-front-door-replication.md"), "utf8")).toContain("timeout, as in pass 1");
  });
  it("S11: another organization's path rule keeps the listed site eligible", async () => {
    const r = await go({ "https://a.org/robots.txt": ROBOTS, "https://a.org/": { status: 301, headers: { location: "https://parent.com/x" } }, "https://parent.com/robots.txt": { status: 200, body: "User-agent: *\nDisallow: /x\n" } });
    expect(r).toMatchObject({ status: "excluded", reason: "redirect_disallow_path" });
    expect(isEligible(r)).toBe(true);
    expect(NO_DNS).not.toContain("redirect_disallow_path");
    const own = await go({ "https://a.org/robots.txt": { status: 200, body: "User-agent: *\nDisallow: /x\n" }, "https://a.org/": { status: 301, headers: { location: "/x" } } });
    expect(own.reason).toBe("robots_disallow_path");
    expect(isEligible(own)).toBe(false);
  });
  it("note: the real lookup path works through the guard", async () => {
    expect(await resolvePublic("localhost", { lookup: ipv4Lookup, allowPrivate: true })).toMatchObject({ family: 4 });
  });
  it("records each host it requested", async () => {
    const r = await go({ "https://a.org/robots.txt": ROBOTS, "https://a.org/": HOME });
    expect(r.hops).toEqual(["a.org", "a.org", "a.org"]);
  });
  it("counts requests, redirects and bytes per site", async () => {
    const r = await go({ "https://a.org/robots.txt": ROBOTS, "https://a.org/": { status: 301, headers: { location: "/home" } }, "https://a.org/home": HOME });
    expect(r.counters.requests).toBe(4);
    expect(r.counters.redirects).toBe(1);
    expect(r.counters.bytes).toBe(ROBOTS.body.length + HOME.body.length);
  });
});

describe("robots.txt reading", () => {
  it("B1: a line of stars costs nothing, and globs still match", async () => {
    const started = performance.now();
    expect(robotsVerdict(`User-agent: *\nDisallow: /${"*".repeat(40)}Z\n`, `/${"a".repeat(1500)}`)).toBe("allowed");
    expect(robotsVerdict(`User-agent: *\nDisallow: /${"*a".repeat(5000)}Z\n`, `/${"a".repeat(100_000)}`)).toBe("allowed");
    expect(performance.now() - started).toBeLessThan(200);
    expect(globMatch("/a*c", "/abc")).toBe(true);
    expect(globMatch("/a*c", "/abd")).toBe(false);
    expect(globMatch("/a*c$", "/abcd")).toBe(false);
    expect(globMatch("/a*c$", "/abc")).toBe(true);
    expect(globMatch("/$", "/")).toBe(true);
    expect(globMatch("/$", "/x")).toBe(false);
    expect(globMatch("/*.php$", "/x.php")).toBe(true);
    expect(globMatch("/a*b*c", "/aXbYc/z")).toBe(true);
    expect(globMatch("/ab*ba$", "/aba")).toBe(false);
    expect(globMatch("/x", "/xy")).toBe(true);
    const r = await go({ "https://a.org/robots.txt": { status: 200, body: `User-agent: *\nDisallow: /${"*".repeat(40)}Z\n` }, "https://a.org/": HOME });
    expect(r.status).toBe("ok");
  });
  it("B3: a bare CR ends a line, and the opt-out holds, in the live check's reader too", async () => {
    expect(optedOut("User-agent: Penthera-QuickCheck\rDisallow: /\r")).toBe(true);
    expect(optedOut("\uFEFFUser-agent: Penthera-QuickCheck\nDisallow: /\n")).toBe(true);
    expect(robotsVerdict("User-agent: *\rDisallow: /x\r", "/x")).toBe("disallowed");
    expect((await go({ "https://a.org/robots.txt": { status: 200, body: "User-agent: *\rDisallow: /\r" }, "https://a.org/": HOME })).reason).toBe("robots_disallow_all");
    expect((await go({ "https://a.org/robots.txt": { status: 200, body: "User-agent: Penthera-Research\rDisallow: /\r" }, "https://a.org/": HOME })).status).toBe("opted_out");
  });
  it("B3: UTF-16 or NUL bytes can't be read as rules, so the visit stops", async () => {
    expect(robotsBinary("User\0agent")).toBe(true);
    expect(robotsBinary("\uFFFD\uFFFDU")).toBe(true);
    expect(robotsBinary("User-agent: *")).toBe(false);
    const utf16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from("User-agent: Penthera-Research\nDisallow: /\n", "utf16le")]);
    const r = await go({ "https://a.org/robots.txt": { status: 200, body: utf16 }, "https://a.org/": HOME });
    expect(r).toMatchObject({ status: "excluded", reason: "robots_unavailable" });
    expect(r.robots[0].binary).toBe(true);
    expect(log).not.toContain("https://a.org/");
  });
  it("S4: rule and path compare in one form, and a malformed escape fails closed", () => {
    expect(percentForm("/%7Ea%41b")).toBe("/~aAb");
    expect(percentForm("/a%2fb")).toBe("/a%2Fb");
    expect(percentForm("/a b")).toBe("/a%20b");
    expect(percentForm("/😀")).toBe("/%F0%9F%98%80");
    expect(percentForm("/*.php$")).toBe("/*.php$");
    expect(robotsVerdict("User-agent: *\nDisallow: /~x\n", "/%7Ex")).toBe("disallowed");
    expect(robotsVerdict("User-agent: *\nDisallow: /%7Ex\n", "/~x")).toBe("disallowed");
    expect(robotsVerdict("User-agent: *\nDisallow: /a b\n", "/a%20b")).toBe("disallowed");
    expect(robotsVerdict("User-agent: *\nDisallow: /a%zz\n", "/a%zz/b")).toBe("disallowed");
  });
  it("S7: a Disallow also matches on the decoded form, and a reserved character fails closed", () => {
    expect(robotsVerdict("User-agent: *\nDisallow: /a%2Fb\n", "/a/b")).toBe("disallowed");
    expect(robotsVerdict("User-agent: *\nDisallow: /a/b\n", "/a%2Fb")).toBe("disallowed");
    expect(robotsVerdict("User-agent: *\nDisallow: /a?x=https://b\n", "/a?x=https%3A%2F%2Fb")).toBe("disallowed");
    expect(robotsVerdict("User-agent: *\nAllow: /a%2Fb\n", "/a/b")).toBe("allowed");
    expect(robotsVerdict("User-agent: *\nDisallow: /%2561\n", "/a")).toBe("allowed");
    expect(percentDecoded("/a%2Fb%2561")).toBe("/a/b%61");
  });
  it("note: a 3xx with no Location is unavailable", () => {
    expect(robotsAccess({ status: 304 })).toBe("disallow");
  });
  it("note: a User-agent name ends at a space, in the live reader too", () => {
    expect(optedOut("User-agent: Penthera-QuickCheck bot\nDisallow: /\n")).toBe(true);
    expect(robotsVerdict("User-agent: Penthera-Research bot\nDisallow: /x\n", "/x")).toBe("disallowed");
  });
  it("item 11: the longest rule is measured in percent-encoded form", () => {
    expect(robotsVerdict("User-agent: *\nDisallow: /caf%C3\nAllow: /café\n", "/caf%C3%A9")).toBe("allowed");
  });
  it("17: compares rules in percent-encoded form", async () => {
    expect(percentForm("/café")).toBe("/caf%C3%A9");
    expect(percentForm("/caf%c3%a9")).toBe("/caf%C3%A9");
    expect(robotsVerdict("User-agent: *\nDisallow: /café\n", "/caf%C3%A9")).toBe("disallowed");
    expect(robotsVerdict("User-agent: *\nDisallow: /caf%c3%a9\n", "/caf%C3%A9")).toBe("disallowed");
  });
  it("B8: a compressed robots.txt can't be read, so the visit stops", async () => {
    const r = await go({ "https://a.org/robots.txt": { status: 200, headers: { "content-encoding": "gzip" }, body: gzipSync("User-agent: Penthera-Research\nDisallow: /\n") }, "https://a.org/": HOME });
    expect(r).toMatchObject({ status: "excluded", reason: "robots_unavailable" });
    expect(r.robots[0]).toMatchObject({ encoded: true, access: "disallow" });
    expect(log).not.toContain("https://a.org/");
  });
  it("B8: an opt-out past 64 KB is found", async () => {
    const r = await go({ "https://a.org/robots.txt": { status: 200, body: `${"# pad\n".repeat(12_000)}User-agent: Penthera-Research\nDisallow: /\n` }, "https://a.org/": HOME });
    expect(r.status).toBe("opted_out");
  });
  it("B8: a file past the cap counts as unreadable", async () => {
    const r = await go({ "https://a.org/robots.txt": { status: 200, body: "# pad\n".repeat(100_000) }, "https://a.org/": HOME });
    expect(r).toMatchObject({ status: "excluded", reason: "robots_unavailable" });
    expect(r.robots[0].truncated).toBe(true);
  });
  it("B11: rules match on path plus search, for a redirect the site chose", async () => {
    expect(robotsVerdict("User-agent: *\nDisallow: /*?\n", "/?sid=1")).toBe("disallowed");
    const r = await go({ "https://a.org/robots.txt": { status: 200, body: "User-agent: *\nDisallow: /*?\n" }, "https://a.org/": { status: 302, headers: { location: "/?sid=SECRET" } } });
    expect(r).toMatchObject({ status: "excluded", reason: "robots_disallow_path" });
    expect(log.some((u) => u.includes("sid="))).toBe(false);
  });
  it("B11: the study page words it as the code behaves", () => {
    const page = readFileSync(join(import.meta.dirname, "..", "site", "pages", "research-e20.md"), "utf8");
    expect(page).toContain("adds no query string of its own, and follows a site's redirect as given");
    expect(page).not.toMatch(/never IP addresses|never committed or shared|passive/);
    expect(page).toContain("Per site, in this order");
    expect(page).toContain("178.104.243.225");
  });
});

describe("what reaches the disk", () => {
  it("B4: check evidence loses query strings, tokens and long numbers, end to end", async () => {
    const r = await go({ "https://a.org/robots.txt": ROBOTS, "https://a.org/": { status: 200, headers: { "content-type": "text/html", "content-security-policy": "default-src 'self'; report-uri https://o1.ingest.sentry.io/api/1/security/?sentry_key=abc123secret&x=4915123456789", "set-cookie": ["sessionvalueabc123; Path=/; HttpOnly", "sid=VALUE; Path=/"] }, body: "<html></html>" } });
    const text = JSON.stringify(r.checks);
    expect(text).not.toMatch(/abc123secret|4915123456789|sessionvalue/);
  });
  it("B9: every written form of an address comes out, and the detector catches each raw", () => {
    const forms = ["&#106;&#111;&#104;&#110;&#64;&#101;&#120;&#46;&#110;&#108;", "&#x6a;&#x6f;&#x68;&#x6e;&#x40;&#x65;&#x78;&#x2e;&#x6e;&#x6c;", "john&#46;doe&#64;x&#46;nl", "john [at] example [dot] com", "john (at) example (dot) com", "john AT example DOT com", "john {at} example.com", "john\\x40example.com", "john＠example.com", "john@example", "john.doe@exam", "redacted.bob@x.nl", "redacted@x.nl", "jos\uFFFD@x.nl", "john&#64example.com", "john&commat;x&period;nl", "john%2540x.nl", "j\u200bohn@x.nl", "john(at)example.com", "info @ example.com", "info at example.com"];
    for (const dirty of forms) {
      const clean = scrub(dirty);
      expect(clean, dirty).not.toMatch(/john|bob|info|jos/i);
      expect(clean, dirty).toContain("<email>");
      expect(Object.values(scrubMisses(clean)).every((v) => v === 0), `${dirty} -> ${clean}`).toBe(true);
    }
    for (const raw of ["&#106;&#111;&#104;&#110;", "&#64;", "john [at] example.com", "john(at)example.com", "john\\x40example.com", "john&commat;x", "john＠x.nl", "john@exam", "redacted.bob@x.nl"]) expect(scrubMisses(raw).email, raw).toBeGreaterThan(0);
  });
  it("B1: ordinary typography is no miss, and spelled-out ASCII still is", () => {
    const wordpress = "It&#8217;s &#8220;fine&#8221; &#8212; really &#8230; &#8217;s &#169; &#xA0;";
    expect(Object.values(scrubMisses(scrub(wordpress))).every((v) => v === 0)).toBe(true);
    expect(scrubMisses(wordpress).email).toBe(0);
    expect(scrubMisses("&#106;&#111;&#104;&#110;").email).toBe(1);
  });
  it("note: the last written forms of an address come out", () => {
    for (const dirty of ["john&amp;#64;example.com", "john&#x00000040;example.com", "john﹫example.com", '"john smith"@acme.com', "john at acme . com", "john-at-acme.com", "john<b>@</b>acme.com", "john\\100acme.com", "jose\u0301@example.com"]) {
      const clean = scrub(dirty);
      expect(clean, dirty).toContain("<email>");
      expect(clean, dirty).not.toMatch(/john|jose|acme/);
    }
    expect(scrub("DB_PASS=hunter2")).toBe("DB_PASS=<token>");
    expect(scrub("pwd: hunter2")).toBe("pwd: <token>");
  });
  it("note: code is left alone", () => {
    expect(scrub("std::map<int> and a::b")).toContain("std::map");
    expect(scrub("std::vector")).toBe("std::vector");
    expect(scrub("fe80::1")).toBe("<ip>");
    expect(scrub("::1")).toBe("<ip>");
  });
  it("B3: a bracketed at is an address unless prose follows it", () => {
    for (const dirty of ["john (at) example dot com", "john [at] example dot com", "j.doe {at} example dot org", "john (at) sub_domain.example.com", "john (at) localhost", "john(at)example", "mailto:john(at)example", "john (at) example . com", "john(at)example(dot)com", "john[at]example[.]com", "Email: (at) example.com", "john_at_example.com"]) {
      const clean = scrub(dirty);
      expect(clean, dirty).not.toMatch(/john|j\.doe|example\s*(\.|dot)|localhost/);
      expect(Object.values(scrubMisses(clean)).every((v) => v === 0), `${dirty} -> ${clean}`).toBe(true);
    }
    for (const raw of ["john (at) example dot com", "john [at] localhost", "john(at)example", "name {at} label"]) expect(scrubMisses(raw).email, raw).toBeGreaterThan(0);
  });
  it("a bracketed at takes both neighbouring words, with no exceptions, and the detector is as strict", () => {
    for (const dirty of ["sales [at] 3m.com", "john (at) 1password.com", "info(at)123.nl", "john (at) home.nl", "(AT) Wien", "look (at) this", "john ( at ) x.nl"]) {
      const clean = scrub(dirty);
      expect(clean, dirty).toContain("<email>");
      expect(clean, dirty).not.toMatch(/\((at)\)|\[at\]|sales|john|info|3m|home|this|Wien/i);
      expect(scrubMisses(dirty).email, dirty).toBeGreaterThan(0);
      expect(Object.values(scrubMisses(clean)).every((v) => v === 0), `${dirty} -> ${clean}`).toBe(true);
    }
  });
  it("a bare at counts only before something with a dot, spaced or not", () => {
    for (const dirty of ["john at example.com", "john at example .com", "john at example . com", "john at example dot com"]) {
      expect(scrub(dirty), dirty).toBe("<email>");
      expect(scrubMisses(dirty).email, dirty).toBeGreaterThan(0);
    }
    for (const prose of ["Meet me at home", "at the end of the day", "Open at 9. Closed soon."]) {
      expect(scrubMisses(scrub(prose)).email, prose).toBe(0);
    }
    expect(scrub("Meet me at home")).toBe("Meet me at home");
  });
  it("S4: the scrub and the detector agree on IPv6, by one rule", () => {
    for (const a of ["dead:beef::cafe", "fdab::cdef", "abcd:ef::", "2001:db8::1"]) {
      expect(looksIpv6(a), a).toBe(true);
      expect(scrub(a), a).toBe("<ip>");
      expect(scrubMisses(a).ipv6, a).toBe(1);
    }
    for (const c of ["a::b", "ad::be", "std::map", "Foo::Bar"]) {
      expect(scrub(c), c).toBe(c);
      expect(scrubMisses(c).ipv6, c).toBe(0);
    }
    expect(scrub("2001:db8::1and")).not.toContain("2001");
  });
  it("B9: address forms in host names come out", () => {
    for (const dirty of ["static.225.243.104.178.clients.your-server.de", "ip-2-31-141-178.eu-central-1.compute.amazonaws.com", "2%2E31%2E141%2E178", "0x021F8DB2", "decade:2a01:4f8:c17:1234::1", "fe80::1%25en0", "2a01:4f8:c17:1234:0:0:0:1%eth0", "[::ffff:2.31.141.178]:8080", "x-forwarded-for: 2.31.141.178, 10.0.0.1"]) {
      expect(scrub(dirty), dirty).toContain("<ip>");
      expect(scrub(dirty), dirty).not.toMatch(/2\.31|2-31|243\.104|2a01|fe80::1|021F/i);
    }
  });
  it("B9: evidence the grader cut keeps no partial address", async () => {
    const r = await go({ "https://a.org/robots.txt": ROBOTS, "https://a.org/": { status: 200, headers: { "content-type": "text/html", "content-security-policy": `default-src 'self'; report-uri https://x.example.com/a; ${"x".repeat(100)} mailto:jan.de.vries@persoonlijk-domein.nl` }, body: "<html></html>" } });
    expect(JSON.stringify(r.checks)).not.toMatch(/jan\.de|persoonlijk/);
  });
  it("B8: U+0130 does not shift the parser into form fields or scripts", () => {
    const tr = `<html><head><title>Ana Sayfa</title></head><body>${"<p>İLETİŞİM İLE İLGİLİ</p>".repeat(8)}<form><input type="hidden" name="_csrf" value="SECRETVALUE9"><input name="email" value="jan@x.nl"></form><script>var user={name:"Jan de Vries",phone:"secret"};</script><p>Hoşgeldiniz</p></body></html>`;
    const pe = pageExcerpt(tr);
    expect(pe.text).toContain("Hoşgeldiniz");
    expect(pe.text).not.toMatch(/SECRETVALUE|jan@|Jan de Vries|secret/);
    expect(scrub(`${"İ".repeat(50)}<input value="SECRET">x`)).not.toContain("SECRET");
  });
  it("privacy 1: drops the partial token at the input cap", () => {
    const body = `${"word ".repeat(13_107)}x jan.devries@example.nl and more`;
    expect(scrub(body)).not.toMatch(/jan|devries|example\.nl/);
    expect(scrub("a".repeat(70_000))).toBe("");
  });
  it("privacy 2: keeps real cookie names, and drops token-shaped or address-shaped ones", () => {
    const c = (v) => cookieNames({ "set-cookie": [v] });
    expect(c("session=1; Path=/")).toEqual(["session"]);
    expect(c("__cf_bm=1")).toEqual(["__cf_bm"]);
    for (const bad of ["sess_8f14e45fceea167a5a36dedd4bea2543=1", "2.31.141.178=1", "john.doe@x.nl=1; Path=/", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc=1", "=valueonly; Path=/", "dGVzdHRva2VuMTIzNDU2Nzg=; path=/"]) expect(c(bad), bad).toEqual([]);
    expect(pilotReport([{ status: "ok", evidence: { class: {}, classRegistered: {}, others: [], cookieNames: c("sess_8f14e45fceea167a5a36dedd4bea2543=1"), pageExcerpt: {}, values: {} } }]).scrubMisses.longHex).toBe(0);
  });
  it("privacy 3, 4: scrubs the DMARC record and tags, CAA issuers and header names", async () => {
    const d = await readDomain("x.nl", { resolveTxt: async (n) => (n.startsWith("_dmarc") ? [["v=DMARC1;p=joe@x.nl;sp=reject;rua=mailto:josé@x.nl,mailto:jan@x"]] : [["v=spf1 ip4:1.2.3.4 -all"]]), resolveCaa: async () => [{ critical: 0, issue: "letsencrypt.org;accounturi=https://acme.example/acct/123456789012" }], mx: async () => [], ns: async () => ["a.ns.cloudflare.com"] });
    expect(JSON.stringify(d.dmarcTags)).not.toContain("joe");
    expect(d.dmarcRecord).not.toMatch(/josé|jan@/);
    expect(d.caaTree.issuers).toEqual(["letsencrypt.org"]);
    expect(d.spfRecord).toContain("ip4:1.2.3.4");
    expect(evidenceOf({ status: 200, headers: { "x-ip-2.31.141.178": "1", "x-ok": "1" }, body: "" }).headerNames).toEqual(["x-ok"]);
  });
  it("privacy 5: long fields, textarea and select leave no value", () => {
    for (const dirty of [`<input type="hidden" name="__VIEWSTATE" value="${"Ab/9+x".repeat(600)}">`, '<input value="a>joe@x.nl secret123">', "<textarea name=msg>Jan de Vries, BSN</textarea>", "<select name=a><option selected>Jan</option></select>", '<input name=q value="x']) {
      expect(scrub(dirty), dirty).not.toMatch(/Ab\/9|joe|Jan|secret|value="x/);
    }
    expect(pageExcerpt("<p>hi</p><textarea>Jan</textarea><select><option>Piet</option></select>").text).toBe("hi");
  });
  it("privacy 7: scrubs a bare fragment and other token forms", () => {
    expect(scrub("https://x.nl/#john.doe")).not.toContain("john");
    expect(scrub("https://x.nl/p;jsessionid=ABCDEF1234567890ABCD")).not.toContain("ABCDEF");
    expect(scrub("Authorization: Token abcdefgh12345678")).not.toContain("abcdefgh");
    expect(scrub("/track/ab12cd34ef56gh78ij90")).not.toContain("ab12");
    expect(scrub("sess=abc")).toBe("sess=<token>");
    expect(scrub("color:#fff; https://x.nl/page")).toContain("#fff");
  });
  it("note: reads valid HTML with no closing head", () => {
    expect(pageExcerpt("<html><head><meta charset=utf8><title>Hi</title><body><p>Real page text</p></body>")).toMatchObject({ title: "Hi", text: "Real page text" });
  });
  it("S2: every form in the review's list comes out, and the detector agrees", () => {
    for (const dirty of ["Your IP: 2.31.141.178.", "(2.31.141.178)", "ip=2.31.141.178&x=1", "IP:2a01:4f8:c17:1234::1", "client:2a01:4f8:c17:1234::1 blocked", "addr=2a01:4f8:c17:1234::1", "Your IP: 2a01:4f8:c17:1234::1.", "[2a01:4f8::1]:443", "::ffff:2.31.141.178", "2A01:04F8:0C17:1234:0000:0000:0000:0001", "2a01%3A4f8%3A%3A1", "x_2a01:4f8::1",
      "john@example.com", "josé@example.com", "müller@example.de", "john&#64;example.com", "john%40example.com", "john [at] example.com", "john\\u0040example.com", '<a data-cfemail="1b7174737535">',
      "mailto:john.doe@sub.example.co.uk?subject=Hi", 'href="?token=abc123"', "/é/x?token=abc123", "https://x.nl/reset?t=abc&u=john@x.nl", "https://x.nl/#access_token=eyJhbGciOi.abc.def", "https://x.nl/reset/8f14e45fceea167a5a36dedd4bea2543", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc", "call +31 6 12 34 56 78 now"]) {
      const clean = scrub(dirty);
      expect(Object.values(scrubMisses(clean)).every((v) => v === 0), `${dirty} -> ${clean}`).toBe(true);
      expect(clean, dirty).not.toMatch(/2\.31\.141|2a01|john|josé|müller|abc123|SECRET|8f14|eyJ|12 34 56|1b7174/i);
    }
    expect(scrub("2024-10-30 12:30:45")).toBe("2024-10-30 12:30:45");
  });
  it("S2: the detector catches each kind on its own, sharing no pattern with the scrub", () => {
    expect(scrubMisses("you are 203.0.113.7").ipv4).toBe(1);
    expect(scrubMisses("addr=2a01:4f8::1").ipv6).toBe(1);
    expect(scrubMisses("mail jan@example.nl").email).toBe(1);
    expect(scrubMisses("jan%40example.nl").email).toBe(1);
    expect(scrubMisses("/a?token=x").query).toBe(1);
    expect(scrubMisses("/#access_token=x").fragment).toBe(1);
    expect(scrubMisses("eyJhbGci.eyJzdWIi.sig").jwt).toBe(1);
    expect(scrubMisses("8f14e45fceea167a5a36dedd4bea2543").longHex).toBe(1);
    expect(scrubMisses("493012345678").longNumber).toBe(1);
    expect(Object.values(scrubMisses("<redacted>@example.com <ip> ?<query>")).every((v) => v === 0)).toBe(true);
  });
  it("S2: a secret at the cut is scrubbed, because scrubbing comes first", () => {
    const e = evidenceOf({ status: 500, headers: {}, body: `${"x ".repeat(2043)} john.doe@example.com rest` });
    expect(e.excerpt).not.toContain("john");
  });
  it("item 8: scrubs a realistic error page and interstitial, with tokens and identifiers", () => {
    const block = `<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title></head><body><div id="cf-error-details">Sorry, you have been blocked. Your IP: 178.104.243.225 Ray ID: 8f14e45fceea1672
      <form><input type="hidden" name="csrf_token" value="Xk29slQ0vbT7dd"><input name="session" value="s%3Aabc123def456"></form>
      <script>window._cf_chl_opt={cRay:'8f14e45fceea1672',cH:'eVHGQ3ZX9f2mLq8Tn0pRs7Wb1Yc4Ud6K',cUPMDTk:"/?__cf_chl_tk=aZ09-_x"};</script>
      <a href="/cdn-cgi/l/email-protection#1b7174737535">mail</a> user 123e4567-e89b-12d3-a456-426614174000 jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln</div></body></html>`;
    const e = evidenceOf({ status: 403, headers: {}, body: block });
    expect(e.excerpt).toContain("Sorry, you have been blocked");
    expect(e.excerpt).not.toMatch(/178\.104|8f14e45f|Xk29|abc123def|eVHGQ3|aZ09|1b7174|123e4567|eyJ/);
    expect(Object.values(scrubMisses(e.excerpt)).every((v) => v === 0)).toBe(true);
  });
  it("item 8: tells a page, a JS challenge, a soft block and an interstitial apart", () => {
    const js = pageExcerpt('<html><title>Just a moment...</title><noscript>Enable JavaScript and cookies to continue</noscript><script src="/x.js"></script></html>');
    expect(js).toMatchObject({ title: "Just a moment...", noscript: "Enable JavaScript and cookies to continue", scripts: 1, hard: ["cloudflare"] });
    const soft = pageExcerpt("<html><body><h1>Unusual traffic</h1><p>We could not verify you.</p><form action=/x></form></body></html>");
    expect(soft).toMatchObject({ forms: 1, links: 0 });
    expect(soft.text).toContain("Unusual traffic");
    const wall = pageExcerpt('<html><head><meta http-equiv="refresh" content="1;url=/x"></head><body>Checking your browser</body></html>');
    expect(wall.metaRefresh).toBe(true);
    const page = pageExcerpt(`<html><body>${"<p>content words</p>".repeat(500)}<a href=/a>x</a></body></html>`);
    expect(page.text.length).toBe(4096);
    expect(page.links).toBe(1);
  });
  it("S4: keeps a cookie name only when = comes before the first ;", () => {
    expect(cookieNames({ "set-cookie": ["tokenVALUE123; Path=/", "a=1", "b; c=2"] })).toEqual(["a"]);
  });
  it("S5: drops an unclosed script and an unclosed comment", () => {
    expect(pageExcerpt("<html><body>hi<script>var secret='k3y'; fetch('/x')").text).toBe("hi");
    expect(pageExcerpt("<body>hi<!-- secret").text).toBe("hi");
  });
  it("S3: long hostile input stays quick", () => {
    const start = performance.now();
    for (const body of ["a1-_".repeat(400_000), "<".repeat(1_000_000), "<!--".repeat(300_000), "<script ".repeat(200_000), "1 ".repeat(800_000), `${"a".repeat(1_000_000)}@`]) {
      pageExcerpt(body);
      scrub(body);
      traitsOf(body);
      classify({ status: 403, body });
    }
    traitsOf("<a ".repeat(400_000));
    expect(performance.now() - start).toBeLessThan(3000);
  });
  const rec = { status: "ok", httpStatus: 200, checks: [], counters: { requests: 3, bytes: 1, redirects: 0 }, hops: ["a.org"], evidence: { class: { label: "candidate-page", rule: "status" }, classRegistered: { label: "page" }, cookieNames: [], headerNames: [], others: [], pageExcerpt: { title: "t", text: "x" }, values: {} }, dns: { listed: { dmarcRecord: "" } } };
  it("stops the run on a miss, and scans what DNS stored, header names and cookie names", () => {
    expect(rules(pilotReport([rec]))).toEqual([]);
    const miss = (o) => pilotReport([{ ...rec, ...o }]).scrubMisses;
    expect(miss({ dns: { listed: { dmarcRecord: "v=DMARC1; rua=mailto:jan@example.nl" } } }).email).toBe(1);
    expect(miss({ dns: { listed: { dmarcRecord: "", dmarcTags: { p: "joe@x.nl" } } } }).email).toBe(1);
    expect(miss({ dns: { listed: { dmarcRecord: "", caaTree: { issuers: ["jan@x.nl"] } } } }).email).toBe(1);
    expect(miss({ dns: { listed: { dmarcRecord: "", spfRecord: "v=spf1 ip4:1.2.3.4 redirect=jan@x.nl -all" } } })).toMatchObject({ email: 1, ipv4: 0 });
    expect(miss({ evidence: { ...rec.evidence, headerNames: ["x-2.31.141.178"], cookieNames: ["8f14e45fceea167a5a36dedd4bea2543"] } }).longHex).toBe(1);
    expect(rules(pilotReport([{ ...rec, dns: { listed: { dmarcRecord: "jan@x.nl" } } }]))).toContain("a privacy scrub missed something");
  });
  it("8: a single site over the limit stops the run, not the average", () => {
    const many = Array.from({ length: 49 }, () => rec);
    expect(rules(pilotReport([...many, { ...rec, counters: { requests: 40, bytes: 1, redirects: 0 } }]))).toEqual(["a site took more than 20 requests"]);
  });
  const dead = (n, o) => Array.from({ length: n }, () => ({ status: "error", dns: { listed: { dmarcRecord: "" } }, counters: { requests: 1 }, ...o }));
  it("B4: any failed query counts, and unanswered SPF or DMARC stops", () => {
    for (const q of ["txt", "dmarc", "mx", "caa"]) expect(resolverFailed({ dns: { listed: { outcomes: { [q]: "resolver-failure:ETIMEOUT" } } } }), q).toBe(true);
    expect(resolverFailed({ dns: { listed: { outcomes: { txt: "nodata", ns: "nxdomain" } } } })).toBe(false);
    const unanswered = Array.from({ length: 10 }, () => ({ ...rec, dns: { listed: { dmarcRecord: "", spf: null, dmarc: true, caa: true } } }));
    expect(rules(pilotReport(unanswered))).toEqual(["over 20% of SPF reads got no answer"]);
  });
  it("B5: a pilot needs a size, and a run with nothing eligible stops", () => {
    expect(stopRules(pilotReport([{ status: "opted_out", counters: { requests: 1 } }]))).toContain("no eligible site");
    expect(stopRules(pilotReport(Array.from({ length: 29 }, () => rec)))).toContain("under 30 eligible sites");
    expect(stopRules(pilotReport([...Array.from({ length: 19 }, () => rec), ...dead(11, { error: "timeout" })]))).toContain("under 25 graded sites");
    expect(stopRules(pilotReport(Array.from({ length: 40 }, () => rec))).filter((m) => !/no usable output/.test(m))).toEqual([]);
    expect(PILOT_MIN).toBe(50);
  });
  it("B2: a run that reached nothing stops", () => {
    expect(rules(pilotReport(dead(50, { error: "not_found", netCode: "ESERVFAIL" })))).toEqual(expect.arrayContaining(["under half of the eligible sites were graded", "over 20% of sites hit a resolver failure", "no site answered with a 2xx"]));
    expect(rules(pilotReport(dead(50, { error: "not_found", netCode: "ENOTFOUND" })))).not.toContain("over 20% of sites hit a resolver failure");
    const blocked = Array.from({ length: 50 }, () => ({ ...rec, httpStatus: 403 }));
    expect(rules(pilotReport(blocked))).toEqual(["no site answered with a 2xx"]);
    const bad = [...Array.from({ length: 79 }, () => rec), ...Array.from({ length: 21 }, () => ({ ...rec, dns: { listed: { dmarcRecord: "", outcomes: { ns: "resolver-failure:ETIMEOUT" } } } }))];
    expect(rules(pilotReport(bad))).toEqual(["over 20% of sites hit a resolver failure"]);
    expect(rules(pilotReport([...Array.from({ length: 50 }, () => rec), ...dead(50, { error: "timeout" })]))).toEqual([]);
  });
  it("S10: the report reads a pruned run with no false stop, and sealing after pruning is refused", () => {
    const shaped = { ...rec, evidence: { ...rec.evidence, pageExcerpt: { chars: 9, scripts: 1 } } };
    expect(rules(pilotReport([shaped]))).toEqual(["under 90% of 2xx responses have an excerpt"]);
    expect(rules(pilotReport([shaped], { pruned: true }))).toEqual([]);
    const dir = mkdtempSync(join(tmpdir(), "e20r2-"));
    const raw = `${JSON.stringify(rec)}\n`;
    writeFileSync(join(dir, "raw.jsonl"), raw);
    const ex = Buffer.from("gov government\n");
    const sum = (b) => createHash("sha256").update(b).digest("hex");
    writeFileSync(join(dir, "manifest.json"), JSON.stringify({ finishedAt: "x", rawSha256: sum(raw), immutableAtFinish: { ok: true }, exclusionSha256: sum(ex) }));
    expect(sealPilot(dir, { exclusionBytes: ex }).stop.filter((m) => !/no usable output/.test(m))).toEqual(["under 10 2xx responses", "under 30 eligible sites", "under 25 graded sites"]);
    expect(JSON.parse(readFileSync(join(dir, "pilot-result.json"), "utf8")).sealSha256).toMatch(/^[0-9a-f]{64}$/);
    writeFileSync(join(dir, "prune-manifest.json"), "{}");
    expect(sealPilot(dir, { exclusionBytes: ex }).stop).toContain("sealed after pruning: seal first, while the excerpts exist");
  });
  it("S6: a hop meets every skip list", () => {
    const skip = readRemovals("removed.example.com\n", "removed");
    expect(pilotReport([{ ...rec, hops: ["removed.example.com"] }], { exclude: skip }).excludedHops).toBe(1);
  });
  it("9: any hop to an excluded host stops the run", () => {
    const r = pilotReport([{ ...rec, hops: ["a.org", "ministry.gov"] }], { exclude });
    expect(r.excludedHops).toBe(1);
    expect(rules(r)).toContain("a request reached an excluded host");
  });
});

describe("the classifier", () => {
  it("S1: a long 2xx page may quote any block or error line", () => {
    const pad = "z ".repeat(SOFT_MAX_CHARS);
    for (const text of ["Request blocked by the court", "Sorry, you have been blocked", "<H1>Access Denied</H1>", "The request could not be satisfied"]) {
      expect(classify({ status: 200, body: pad + text }).label, text).toBe("candidate-page");
    }
    expect(classify({ status: 200, body: "Sorry, you have been blocked" }).label).toBe("block");
    expect(classify({ status: 403, body: `Sorry, you have been blocked${pad}` }).label).toBe("block");
  });
  it("stores every signature as a boolean, so a label can be replayed", () => {
    const s = signatureMatches("<title>Just a moment...</title> Request blocked");
    expect(s.hardChallenge.cloudflare).toBe(true);
    expect(s.registeredChallenge.cloudflare).toBe(true);
    expect(s.block.cloudfront).toBe(true);
    expect(s.block.akamai).toBe(false);
    expect(s.registeredBlock.cloudfront).toBe(false);
    expect(signatureMatches("error code: 1010").cloudflareCode).toBe("1010");
    expect(evidenceOf({ status: 403, headers: {}, body: "x" }).signatures.softChallenge).toBeDefined();
  });
  it("item 6: the platform reading knows Akamai as the classifier does", () => {
    for (const h of [{ server: "AkamaiGHost" }, { "x-akamai-transformed": "9" }, { "akamai-grn": "0.1" }]) expect(platformOf(h, "").edge).toBe("akamai");
    expect(classify({ status: 403, headers: { "akamai-grn": "0.1" }, body: "" }).vendor).toBe("akamai");
  });
  it("keeps the registered labels by their old names", () => {
    expect(classifyRegistered({ status: 200, body: "hi" }).label).toBe("page");
    expect(classifyRegistered({ status: 404, body: "" }).label).toBe("origin-error");
  });
  it("reads the whole CSP, past the grader's 160 characters", () => {
    const long = `upgrade-insecure-requests; report-uri /r${"x".repeat(300)}; script-src 'self' 'nonce-abc'`;
    expect(cspEvidence({ "Content-Security-Policy": long })).toMatchObject({ present: true, controlsScripts: true, openScripts: false });
    expect(cspEvidence({ "content-security-policy": "frame-ancestors 'self'" })).toMatchObject({ controlsScripts: false, directives: ["frame-ancestors"] });
    expect(cspEvidence({ "content-security-policy": "default-src * 'unsafe-inline'" })).toMatchObject({ controlsScripts: true, openScripts: true });
    expect(cspEvidence({ "content-security-policy": "script-src 'unsafe-inline' 'sha256-abc'" }).openScripts).toBe(false);
    expect(cspEvidence({})).toMatchObject({ present: false, controlsScripts: false });
    expect(JSON.stringify(cspEvidence({ "content-security-policy": "default-src https://secret.example.com" }))).not.toContain("secret");
  });
});

describe("a visit in its own thread", () => {
  it("item 12: keeps bytes from a response cut off by the hard cap", async () => {
    const server = realServer((_h, url) => (url === "/robots.txt" ? ROBOTS : null));
    server.removeAllListeners("request");
    server.on("request", (req, res) => {
      if (req.url === "/robots.txt") { res.writeHead(200); res.end("User-agent: *\nAllow: /\n"); return; }
      res.writeHead(200, { "content-type": "text/html" });
      const drip = setInterval(() => res.write("x".repeat(2000)), 20);
      res.on("close", () => clearInterval(drip));
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    try {
      const r = await visitInWorker({ host: "a.selftest.example.com", cohorts: {} }, { loopbackPort: server.address().port, budgetMs: 3000, hardCapMs: 500 });
      expect(r.counters.bytes).toBeGreaterThan(2000);
    } finally { server.closeAllConnections(); await new Promise((r) => server.close(r)); }
  });
  it("item 12: counts redirect and encoded bodies, and keeps neither", async () => {
    const server = realServer((_h, url) => {
      if (url === "/robots.txt") return ROBOTS;
      if (url === "/") return { status: 301, headers: { location: "/b" }, body: "r".repeat(100) };
      return { status: 200, headers: { "content-encoding": "gzip" }, body: "z".repeat(200) };
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    try {
      const r = await visitInWorker({ host: "a.selftest.example.com", cohorts: {} }, { loopbackPort: server.address().port });
      expect(r.counters.bytes).toBeGreaterThanOrEqual(ROBOTS.body.length + 300);
      expect(JSON.stringify(r.evidence)).not.toContain("zzzz");
    } finally { await new Promise((r) => server.close(r)); }
  });
  it("S6: a redirect is followed at its headers, whatever its body does", async () => {
    const server = http.createServer((req, res) => {
      if (req.url === "/robots.txt") { res.writeHead(404); res.end(); return; }
      if (req.url === "/") { res.writeHead(301, { location: "/h" }); res.write("partial"); return; }
      res.writeHead(200, { "content-type": "text/html" }); res.end("<title>t</title>");
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    try {
      const started = Date.now();
      const r = await visitInWorker({ host: "a.selftest.example.com", cohorts: {} }, { loopbackPort: server.address().port });
      expect(r.status).toBe("ok");
      expect(Date.now() - started).toBeLessThan(3000);
    } finally { server.closeAllConnections(); await new Promise((r) => server.close(r)); }
  });
  it("note: a hard-capped record keeps the bytes the thread reported", async () => {
    const dir = mkdtempSync(join(tmpdir(), "e20r2-"));
    const file = join(dir, "fx.mjs");
    writeFileSync(file, 'import { parentPort } from "node:worker_threads"; parentPort.postMessage({ progress: { requests: 2, bytes: 900, redirects: 1, hosts: ["x.example.com"] } }); await new Promise((r) => setTimeout(r, 50)); for (;;) {}');
    const r = await visitInWorker({ host: "a.selftest.example.com", cohorts: {} }, { hardCapMs: 100, workerFile: file });
    expect(r).toMatchObject({ reason: "hard_cap", counters: { requests: 2, bytes: 900, redirects: 1 }, hops: ["x.example.com"] });
  });
  it("B2: ends a visit whose thread is stuck, at the hard cap, and keeps the rest of the run going", async () => {
    const started = Date.now();
    let ticks = 0;
    const tick = setInterval(() => { ticks++; }, 50);
    const r = await visitInWorker({ host: "a.selftest.example.com", cohorts: {} }, { hardCapMs: 100, workerFile: join(import.meta.dirname, "fixtures", "hang-worker.mjs") });
    clearInterval(tick);
    expect(r).toMatchObject({ status: "error", error: "timeout", reason: "hard_cap" });
    expect(Date.now() - started).toBeLessThan(6000);
    expect(ticks).toBeGreaterThan(5);
  });
  it("B2: a hostile page's real regex is ended the same way", async () => {
    const server = realServer((_h, url) => (url === "/robots.txt" ? ROBOTS : { status: 200, headers: { "content-type": "text/html" }, body: "<meta ".repeat(40_000) }));
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    try {
      const started = Date.now();
      const r = await visitInWorker({ host: "a.selftest.example.com", cohorts: {} }, { loopbackPort: server.address().port, budgetMs: 800, hardCapMs: 800 });
      expect(Date.now() - started).toBeLessThan(6000);
      expect(r.host).toBe("a.selftest.example.com");
      expect(r.counters.requests).toBeGreaterThan(0);
    } finally { server.closeAllConnections(); await new Promise((r) => server.close(r)); }
  });
});

describe("hosts and lists", () => {
  it("item 1: reads the pinned list, private suffixes and wildcards included", () => {
    expect(PSL_VERSION.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(pslSha256()).toMatch(/^[0-9a-f]{64}$/);
    expect(orgDomain("www.example.co.uk")).toBe("example.co.uk");
    expect(orgDomain("user.github.io")).toBe("user.github.io");
    expect(orgDomain("a.b.user.github.io")).toBe("user.github.io");
    expect(orgDomain("foo.vercel.app")).toBe("foo.vercel.app");
    expect(orgDomain("github.io")).toBe("github.io");
    expect(publicSuffix("a.b.kobe.jp")).toBe("b.kobe.jp");
    expect(orgDomain("www.city.kobe.jp")).toBe("city.kobe.jp");
    expect(orgDomain("x.y.ck")).toBe("x.y.ck");
    expect(orgDomain("www.ck")).toBe("www.ck");
    expect(orgDomain("example.com.")).toBe("example.com");
    expect(orgDomain("127.0.0.1")).toBe("127.0.0.1");
    expect(orgDomain("[2606:4700::1]")).toBe("2606:4700::1");
    expect(orgDomain("EXAMPLE.unknowntld")).toBe("example.unknowntld");
  });
  it("item 8: the list decides which www is a real label, before anything is stripped", () => {
    expect(siteKey("www.example.com")).toBe("example.com");
    expect(siteKey("www.example.co.uk")).toBe("example.co.uk");
    expect(siteKey("www.github.io")).toBe("www.github.io");
    expect(siteKey("www.co.uk")).toBe("www.co.uk");
    expect(siteOrg("www.github.io")).toBe("www.github.io");
    expect(siteOrg("github.io")).toBe("github.io");
    const rows = mergeCohorts({ T1k: [{ host: "www.example.com", rank: 1, group: "x" }, { host: "www.co.uk", rank: 2, group: "x" }], "YC-new": [{ host: "example.com", rank: 1, group: "y" }, { host: "co.uk", rank: 2, group: "y" }] });
    expect(rows.map((r) => r.host).sort()).toEqual(["co.uk", "www.co.uk", "www.example.com"]);
  });
  it("B3: reads a homepage-only line as a URL, and reports an entry that matches no row", () => {
    const entries = readHostList("clinic.example.nl\nhttps://www.hospital.example.nl/?utm_source=yc\n");
    expect([...entries]).toEqual(["clinic.example.nl", "hospital.example.nl"]);
    const rows = mergeCohorts({ T1k: [{ host: "www.clinic.example.nl", rank: 1, group: "x" }] });
    expect(unmatchedHosts(entries, rows)).toEqual(["hospital.example.nl"]);
  });
  it("B7: takes a URL, a trailing dot and www, and covers the apex", () => {
    for (const line of ["https://example.com/", "example.com.", "www.example.com", "EXAMPLE.com"]) {
      const m = readRemovals(line);
      expect(exclusionFor("example.com", m), line).toBe("removed");
      expect(exclusionFor("www.example.com", m), line).toBe("removed");
    }
  });
  it("B7: throws on a line it can't read, so it never silently does nothing", () => {
    expect(() => readRemovals("example.com removed")).toThrow(/one host per line/);
    expect(() => readRemovals("not a host")).toThrow();
    expect(() => normalizeHost("localhost")).toThrow(/not a host name/);
    expect(readRemovals("# only a comment\n\n").size).toBe(0);
  });
  it("stores listed and final organization apart, and classes the redirect", async () => {
    const server = realServer((host, url) => {
      if (url === "/robots.txt") return ROBOTS;
      return host === "www.co.uk" ? { status: 301, headers: { location: `http://other.example.net:${server.address().port}/` } } : HOME;
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    try {
      const out = mkdtempSync(join(tmpdir(), "e20r2-"));
      const stub = () => Promise.reject(Object.assign(new Error("x"), { code: "ENODATA" }));
      const { records } = await runPass(mergeCohorts({ T1k: [{ host: "www.co.uk", rank: 1, group: "uk" }] }), { pass: 2, out, loopbackPort: server.address().port, delayMs: 0, dns: { mx: stub, ns: stub, resolveTxt: stub, resolveCaa: stub } });
      expect(records[0]).toMatchObject({ listedHost: "www.co.uk", finalHost: "other.example.net", finalOrg: "example.net", redirectClass: "other-org" });
      expect(records[0].dns.final.domain).toBe("example.net");
      expect(records[0].hops).toEqual(["www.co.uk", "www.co.uk", "other.example.net", "other.example.net", "other.example.net"]);
    } finally { await new Promise((r) => server.close(r)); }
  });
});

describe("mail and CAA readings", () => {
  const read = (t) => dmarcReading([t]);
  it("item 3: separates declared from enforcing, and pct=0 never enforces", () => {
    expect(read("v=DMARC1; p=reject")).toMatchObject({ valid: true, declared: true, enforcing: true, reject: true, partial: false });
    expect(read("v=DMARC1; p=quarantine")).toMatchObject({ declared: true, enforcing: true, reject: false });
    expect(read("v=DMARC1; p=reject; pct=0")).toMatchObject({ declared: true, enforcing: false, reject: false });
    expect(read("v=DMARC1; p=quarantine; pct=50")).toMatchObject({ enforcing: true, partial: true, pct: 50 });
    expect(read("v=DMARC1; p=none")).toMatchObject({ valid: true, declared: false, enforcing: false });
    expect(read("v=DMARC1; p=bogus")).toMatchObject({ valid: false, declared: false });
    expect(read("v=DMARC1; p=reject; sp=none")).toMatchObject({ enforcing: true, spNone: true });
    expect(dmarcReading(["v=DMARC1; p=reject", "v=DMARC1; p=none"])).toMatchObject({ valid: false, enforcing: false, records: 2 });
  });
  it("item 3: a subdomain inherits from the organization, under sp when it is set", async () => {
    expect(dmarcReading(["v=DMARC1; p=reject; sp=none"], { inherited: true })).toMatchObject({ policy: "none", enforcing: false, declared: true });
    const none = Object.assign(new Error("x"), { code: "ENODATA" });
    const txt = async (n) => { if (n === "_dmarc.example.com") return [["v=DMARC1; p=reject"]]; if (n === "example.com") return [["v=spf1 -all"]]; throw none; };
    const d = await readDomain("shop.example.com", { resolveTxt: txt, resolveCaa: () => Promise.reject(none), mx: () => Promise.reject(none), ns: async () => ["a.ns.cloudflare.com."] });
    expect(d.dmarcReading).toMatchObject({ inherited: true, enforcing: true });
    const own = async (n) => { if (n === "_dmarc.shop.example.com") return [["v=DMARC1; p=none"]]; return txt(n); };
    expect((await readDomain("shop.example.com", { resolveTxt: own, resolveCaa: () => Promise.reject(none), mx: () => Promise.reject(none), ns: async () => ["a.ns.cloudflare.com."] })).dmarcReading).toMatchObject({ inherited: false, enforcing: false });
  });
  it("item 4: keeps every query, by exact name, with what came back", async () => {
    const none = Object.assign(new Error("x"), { code: "ENODATA" }), gone = Object.assign(new Error("x"), { code: "ENOTFOUND" });
    const d = await readDomain("a.b.example.com", { resolveTxt: async (n) => { if (n === "example.com") return [["v=spf1 -all"]]; throw none; }, resolveCaa: async (n) => { if (n === "com") return [{ issue: "x" }]; throw gone; }, mx: () => Promise.reject(none), ns: async () => ["a.ns.cloudflare.com."] });
    const of = (type, name) => d.queries.find((q) => q.type === type && q.name === name);
    expect(of("TXT", "example.com")).toMatchObject({ outcome: "answer", answers: 1 });
    expect(of("TXT", "_dmarc.a.b.example.com").outcome).toBe("nodata");
    expect(of("TXT", "_dmarc.example.com").outcome).toBe("nodata");
    for (const n of ["a.b.example.com", "b.example.com", "example.com"]) expect(of("CAA", n).outcome).toBe("nxdomain");
    expect(of("CAA", "com").outcome).toBe("answer");
    expect(of("MX", "example.com").outcome).toBe("nodata");
    expect(of("NS", "example.com").outcome).toBe("answer");
    expect(new Set(d.queries.map((q) => `${q.type} ${q.name}`)).size).toBe(d.queries.length);
  });
  it("S9: one organization asks each name once, and keeps each name's result", async () => {
    let asked = 0;
    const none = Object.assign(new Error("x"), { code: "ENODATA" });
    const count = async () => { asked++; throw none; };
    const d = await siteDns("example.com", "www.example.com", { resolveTxt: count, resolveCaa: count, mx: count, ns: count });
    const names = [...d.listed.queries, ...d.final.queries].map((q) => `${q.type} ${q.name}`);
    expect(asked).toBe(new Set(names).size);
    expect(d.final.queries.some((q) => q.type === "TXT" && q.name === "example.com")).toBe(true);
    expect(d.final.outcomes.txt).toBe("nodata");
  });
  it("item 4: climbs CAA to the parent tree, TLD included, and stops at a failure", async () => {
    const asked = [];
    const nodata = Object.assign(new Error("x"), { code: "ENODATA" });
    const res = async (n) => { asked.push(n); if (n === "example.co.uk") return [{ issue: "letsencrypt.org" }]; throw nodata; };
    expect(await caaTree("a.b.example.co.uk", res)).toMatchObject({ found: true, at: "example.co.uk", inherited: true, issuers: ["letsencrypt.org"] });
    expect(asked).toEqual(["a.b.example.co.uk", "b.example.co.uk", "example.co.uk"]);
    asked.length = 0;
    expect(await caaTree("a.example.com", async (n) => { asked.push(n); throw nodata; })).toEqual({ found: false });
    expect(asked).toEqual(["a.example.com", "example.com", "com"]);
    expect(await caaTree("a.example.com", async () => { throw Object.assign(new Error("x"), { code: "ESERVFAIL" }); })).toMatchObject({ found: null, outcome: "resolver-failure:ESERVFAIL" });
  });
});

describe("the analysis", () => {
  const mk = (host, p, extra = {}) => ({ host, status: "ok", cohorts: { T1k: {} }, checks: p === null ? [] : [{ id: "csp", weight: 14, passed: p }], ...extra });
  it("S10: skips a draw with nothing judged, and an empty side is inconclusive", () => {
    const a = Array.from({ length: 30 }, (_, i) => mk(`a${i}.example.com`, i % 2 === 0));
    const r = clusterDiff(a, [mk("b0.example.net", true), mk("b1.example.org", null), mk("b2.example.io", null)], "csp", { resamples: 500 });
    expect(r.skipped).toBeGreaterThan(0);
    expect(r.ci.every(Number.isFinite)).toBe(true);
    expect(decide(clusterDiff([], [mk("a.example.com", true)], "csp", { resamples: 50 }).ci, 1)).toBe("inconclusive");
    expect(decide([NaN, 1], 1)).toBe("inconclusive");
  });
  const site = (host, cohort, passes, extra = {}) => ({ host, finalHost: host, status: "ok", cohorts: { [cohort]: { rank: 1, group: "x" } }, score: 50, checks: [{ id: "csp", weight: 14, passed: passes }], evidence: { class: { label: "candidate-page", rule: "status" }, classRegistered: { label: "page" }, traits: { login: true, payments: false, shop: false, securityPage: false } }, ...extra });
  it("item 7: each E20 file keeps its own record, and apex and www find each other", () => {
    const t = [site("www.a.example.com", "T1k", true, { httpStatus: 403 })], y = [site("a.example.com", "YC-new", true, { httpStatus: 200 })];
    const e20 = { T1k: e20Index(t), "YC-new": e20Index(y) };
    const p = [site("a.example.com", "T1k", true), site("www.a.example.com", "YC-new", true)];
    const out = claims(p, null, e20, { resamples: 20 });
    expect(out.find((c) => c.id === "C12")).toMatchObject({ n: 1, diff: -1 });
    expect(out.find((c) => c.id === "C13")).toMatchObject({ n: 1, diff: 0 });
  });
  it("item 10: gives Newcombe, the exact test, and direction apart from equivalence", () => {
    const a = Array.from({ length: 30 }, (_, i) => site(`a${i}.example${i}.com`, "T1k", i < 15)), b = Array.from({ length: 30 }, (_, i) => site(`b${i}.other${i}.com`, "YC-new", i < 30));
    const c = diffClaim("C1", "x", a, b, "csp", -1, { resamples: 200 });
    expect(c.S.newcombe.ci95).toHaveLength(2);
    expect(c.S.exactP).toBeLessThan(0.01);
    expect(c.S).toMatchObject({ direction: "above zero", equivalence: "not shown" });
    expect(intervalOutcomes([-0.05, 0.05])).toEqual({ direction: "includes zero", equivalence: "within the margin" });
    expect(intervalOutcomes([0.02, 0.05])).toEqual({ direction: "above zero", equivalence: "within the margin" });
    expect(intervalOutcomes([NaN, 1]).direction).toBe("unknown");
    expect(fisherExact(1, 9, 11, 3)).toBeCloseTo(0.0028, 3);
  });
  it("item 10: an organization on both sides is one draw, which keeps the covariance", () => {
    const both = (i, p) => [site(`s${i}.example${i}.com`, "T1k", p), site(`s${i}.example${i}.com`, "YC-new", p)];
    const rows = Array.from({ length: 40 }, (_, i) => both(i, i % 2 === 0));
    const r = clusterDiff(rows.map((x) => x[0]), rows.map((x) => x[1]), "csp", { resamples: 500, level: 0.95 });
    expect(r.ci).toEqual([0, 0]);
    const disjoint = clusterDiff(rows.map((x) => x[0]), rows.map((x, i) => ({ ...x[1], host: `o${i}.elsewhere${i}.org`, finalHost: `o${i}.elsewhere${i}.org` })), "csp", { resamples: 500, level: 0.95 });
    expect(disjoint.ci[1]).toBeGreaterThan(0.1);
  });
  it("item 10: the floor counts organizations, not rows", () => {
    const many = Array.from({ length: 30 }, (_, i) => site(`s${i}.one.example.com`, "T1k", i % 2 === 0));
    const orgs = Array.from({ length: 30 }, (_, i) => site(`o${i}.example${i}.com`, "YC-new", i % 2 === 0));
    expect(diffClaim("C1", "x", many, orgs, "csp", -1, { resamples: 50 }).S.decision).toBe("not estimable");
    expect(standardizedDiff(many, orgs, "csp", { resamples: 50 }).supported).toEqual([]);
  });
  it("item 10: reports traits per cohort", () => {
    const rows = [...Array.from({ length: 20 }, (_, i) => site(`a${i}.example.com`, "T1k", true)), ...Array.from({ length: 5 }, (_, i) => site(`b${i}.example.com`, "YC-new", true))];
    const t = traitsByCohort(rows);
    expect(t.T1k.login.sites).toBe(20);
    expect(t["YC-new"].login).toMatchObject({ sites: 5, suppressed: true });
  });
  it("item 10: bounds and standardization don't need DNS data, and cover C3 and C4", () => {
    const dir = mkdtempSync(join(tmpdir(), "e20r2-"));
    const rows = [...Array.from({ length: 25 }, (_, i) => site(`a${i}.example${i}.com`, "T1k", i < 5, { platform: { edge: "cloudflare" } })), ...Array.from({ length: 25 }, (_, i) => site(`b${i}.other${i}.com`, "YC-new", i < 20, { platform: { edge: "cloudflare" } }))];
    const lines = (r) => r.map((x) => JSON.stringify(x)).join("\n") + "\n";
    writeFileSync(join(dir, "p.jsonl"), lines(rows));
    writeFileSync(join(dir, "manifest.json"), JSON.stringify({ kind: "pass", finishedAt: "x", immutableAtFinish: { ok: true }, rawSha256: "wrong" }));
    writeFileSync(join(dir, "raw.jsonl"), lines(rows));
    writeFileSync(join(dir, "t.jsonl"), lines(rows.slice(0, 25)));
    writeFileSync(join(dir, "y.jsonl"), lines(rows.slice(25)));
    writeFileSync(join(dir, "i.csv"), "domain,industry\n");
    writeFileSync(join(dir, "x.txt"), "\n");
    const hashOf = (f) => createHash("sha256").update(readFileSync(join(dir, f))).digest("hex");
    const preregText = [["Pass 1 raw", "p.jsonl"], ["E20 Tranco raw", "t.jsonl"], ["E20 YC raw", "y.jsonl"], ["Industry map", "i.csv"], ["E20 exclusion file", "x.txt"]].map(([l, f]) => `| ${l} SHA-256 | \`${hashOf(f)}\` |`).join("\n");
    const analyze = () => analyzeMain(["--pass1", join(dir, "raw.jsonl"), "--pass2", join(dir, "p.jsonl"), "--e20", join(dir, "t.jsonl"), join(dir, "y.jsonl"), "--industries", join(dir, "i.csv"), "--e20-excluded", join(dir, "x.txt"), "--out", join(dir, "o.json")], { state: runState(dir), fail: () => undefined, preregText });
    expect(analyze()).toBe(3);
    writeFileSync(join(dir, "manifest.json"), JSON.stringify({ kind: "pass", finishedAt: "x", immutableAtFinish: { ok: true }, rawSha256: createHash("sha256").update(lines(rows)).digest("hex") }));
    expect(analyze()).toBe(3);
    expect(privacyReport(dir).clean).toBe(true);
    expect(analyze()).toBe(0);
    const o = JSON.parse(readFileSync(join(dir, "o.json"), "utf8"));
    expect(o.bounds.C1.low).toBeDefined();
    expect(o.bounds).toHaveProperty("C3");
    expect(o.standardized).toHaveProperty("C3");
    expect(o.standardized).toHaveProperty("C4");
    expect(o.traitsByCohort.T1k).toBeDefined();
    expect(o.dnsBeside).toBeUndefined();
  }, 60_000);
  it("19: S and R must agree; anything else unequal is inconclusive or view-dependent", () => {
    expect(combine("no meaningful difference", "inconclusive")).toBe("inconclusive");
    expect(combine("inconclusive", "no meaningful difference")).toBe("inconclusive");
    expect(combine("supported", "no meaningful difference")).toBe("view-dependent");
    expect(combine("no meaningful difference", "no meaningful difference")).toBe("no meaningful difference");
  });
  it("20: our own stops stay in the denominator; an owner's choice leaves", () => {
    for (const reason of ["robots_unavailable", "exclusion_redirect", "ipv6_literal", "redirect_opted_out"]) expect(isEligible({ status: "excluded", reason }), reason).toBe(true);
    expect(isEligible({ status: "error", error: "timeout" })).toBe(true);
    for (const reason of ["exclusion_list", "robots_disallow_all", "robots_disallow_path", "not_a_homepage"]) expect(isEligible({ status: "excluded", reason }), reason).toBe(false);
    expect(isEligible({ status: "opted_out" })).toBe(false);
  });
  it("22: counts domains DNS couldn't answer for", () => {
    const row = (exists) => ({ cohorts: { T1k: {} }, dns: { listed: { exists } } });
    expect(dnsCoverage([row(true), row(false), row(null), row(null)]).T1k).toEqual({ read: 4, exists: 1, nxdomain: 1, unknown: 2 });
  });
  it("bounds a whole list, with ungraded sites either way", () => {
    const a = [mk("a.example.com", true), mk("b.example.com", null)], b = [mk("c.example.com", false), mk("d.example.com", null)];
    expect(coverageBounds(a, b, "csp")).toEqual({ low: -1, high: 0, coverageA: 0.5, coverageB: 0.5 });
  });
  it("standardizes to the pooled edge mix on strata above the floor, and names what it dropped", () => {
    const rows = (prefix, pa, edge, n) => Array.from({ length: n }, (_, i) => mk(`${prefix}${i}.${edge}${prefix}.example.com`.replace(/\./g, "-") + ".com", i < pa, { platform: { edge } }));
    const a = [...rows("a", 10, "cloudflare", 20), ...rows("c", 5, "akamai", 5)], b = [...rows("b", 20, "cloudflare", 20), ...rows("d", 5, "akamai", 5)];
    const r = standardizedDiff(a, b, "csp", { resamples: 200 });
    expect(r.supported).toEqual(["cloudflare"]);
    expect(r.dropped).toEqual(["akamai"]);
    expect(r.diff).toBeCloseTo(0.5);
  });
});

describe("the validation draw", () => {
  const rec = (i, label, rule = "status") => ({ host: `s${i}.example.com`, status: "ok", evidence: { class: { label, rule }, pageExcerpt: { title: "t", text: "hello", noscript: "n", scripts: 1 } } });
  it("draws fixed strata with weights", () => {
    const records = Array.from({ length: 400 }, (_, i) => rec(i, "candidate-page"));
    records.push(rec(1000, "block", "unrecognized-403"), rec(1001, "block", "body"));
    const a = drawSample(records);
    expect(a.filter((s) => s.stratum === "candidate-page")).toHaveLength(150);
    expect(a[0].stratumSize).toBe(400);
    expect(drawSample([...records].reverse())).toEqual(a);
    expect(stratumOf(records.at(-1))).toBe("block-signature");
  });
  it("23, S7: gives the labeler a blind sheet, with no rule's verdict on it", () => {
    const records = [rec(1, "candidate-page"), rec(2, "block", "body"), rec(3, "challenge")].map((r) => ({ ...r, evidence: { ...r.evidence, status: 200, headerNames: [], values: {}, pageExcerpt: { ...r.evidence.pageExcerpt, soft: ["cloudflare"], hard: ["akamai"] } } }));
    const { sheet, key } = blindSheet(drawSample(records), records);
    expect(JSON.stringify(sheet)).not.toMatch(/soft|hard|cloudflare|akamai/);
    expect(sheet).toHaveLength(3);
    expect(JSON.stringify(sheet)).not.toMatch(/example\.com|block|stratum|candidate/);
    expect(key[0]).toHaveProperty("stratumSize");
  });
  const row = (stratum, ruleLabel, human, stratumSize) => ({ stratum, stratumSize, ruleLabel, human });
  it("item 5: weights over answered rows, and unsure invents no class", () => {
    const rows = [row("candidate-page", "page", "page", 20), row("candidate-page", "page", "challenge", 20), row("challenge", "challenge", "challenge", 2), row("challenge", "challenge", "unsure", 2)];
    const m = weightedMetrics(rows, { resamples: 200 });
    expect(m).toMatchObject({ rows: 4, unsure: 1 });
    expect(m.metrics.page.precision).toBeCloseTo(0.5);
    // The challenge stratum keeps its full size of 2 on its one answered row.
    expect(m.metrics.challenge.recall).toBeCloseTo(2 / 12);
    expect(m.kappaUnsureAsDisagreement).toBeLessThan(m.kappa);
    const all = [row("candidate-page", "page", "page", 2), row("candidate-page", "page", "unsure", 2), row("challenge", "challenge", "challenge", 1)];
    // po 2/3, pe (1/3)(2/3)+(1/3)(1/3) = 1/3: a third class would change this.
    expect(weightedMetrics(all, { resamples: 10 }).kappaUnsureAsDisagreement).toBeCloseTo(0.5);
  });
  it("note: an empty key is refused, and a stratum with no answers is named", () => {
    expect(() => scoreLabels([], "id,label\n", "id,label\n")).toThrow(/key is empty/);
    expect(weightedMetrics([row("challenge", "challenge", "unsure", 2), row("candidate-page", "page", "page", 2)], { resamples: 10 }).strataWithoutAnswers).toEqual(["challenge"]);
  });
  it("item 5: reads human and model labels, and reports where they differ", () => {
    const key = [1, 2].map((id) => ({ id, stratum: "challenge", stratumSize: 2, ruleLabel: "challenge" }));
    const r = scoreLabels(key, "id,label\n1,challenge\n2,page\n", "id,label\n1,challenge\n2,block\n", { resamples: 10 });
    expect(r.humanVsAgent).toMatchObject({ disagreements: 1, pairs: { "human page, agent block": 1 } });
  });
  it("item 5, S8: refuses a missing, duplicate, unknown or invalid label, and names missing ids", () => {
    expect(() => parseLabels("id,label\n1,page\n", [1, 2, 3])).toThrow(/2 ids have no label: 2, 3/);
    expect(() => weightedMetrics([{ stratum: "challenge", stratumSize: 1, ruleLabel: "block", human: "Block " }], { resamples: 1 })).toThrow(/invalid label/);
    expect(() => parseLabels("id,label\n1,page\n1,page\n", [1])).toThrow(/duplicate/);
    expect(() => parseLabels("id,label\n9,page\n", [1])).toThrow(/unknown id/);
    expect(() => parseLabels("id,label\n1,maybe\n", [1])).toThrow(/invalid label/);
    expect(() => parseLabels("x,y\n1,page\n", [1])).toThrow(/id,label/);
  });
  it("privacy 6: pruning with no sample removes all page text, for a pilot", () => {
    expect(pruneExcerpt(rec(1, "candidate-page")).evidence.pageExcerpt.title).toBeUndefined();
  });
  it("deletes the text of an unsampled page and keeps its shape", () => {
    const r = rec(1, "candidate-page");
    expect(pruneExcerpt(r, new Set())).toMatchObject({ evidence: { pageExcerpt: { scripts: 1 } } });
    expect(pruneExcerpt(r, new Set()).evidence.pageExcerpt.text).toBeUndefined();
    expect(pruneExcerpt(r, new Set([r.host])).evidence.pageExcerpt.text).toBe("hello");
  });
});

describe("what ties a run to its code", () => {
  it("item 9: the code hash reaches every file the study imports", () => {
    const files = codeFiles().map((f) => f.split("/penthera/").pop());
    const has = (end) => files.some((f) => f.endsWith(end));
    for (const f of ["bench/front-door/visit-worker.mjs", "bench/front-door/psl.mjs", "api/_lib/grade.mjs", "lib/blackbox/headers.js", "lib/advisories/index.js", "src/utils/url.js"]) expect(has(f), f).toBe(true);
    expect(codeHash()).toMatch(/^[0-9a-f]{64}$/);
  });
  it("item 9: a run marks what changed under it", async () => {
    const out = mkdtempSync(join(tmpdir(), "e20r2-"));
    await runPass([], { pass: 2, out, loopbackPort: 9, delayMs: 0, manifest: { listSha256: { T1k: "a" } }, recheck: () => ({ listSha256: { T1k: "b" } }) });
    expect(JSON.parse(readFileSync(join(out, "manifest.json"), "utf8")).immutableAtFinish).toEqual({ ok: false, changed: ["listSha256"] });
  });
  it("S3: a killed round counts by its list, and its text can still go", () => {
    const dir = mkdtempSync(join(tmpdir(), "e20r2-"));
    const run = join(dir, "e20r-pilot-1");
    mkdirSync(run);
    const list = "a.example.com\n";
    writeFileSync(join(run, "pilot-sites.txt"), list);
    writeFileSync(join(run, "manifest.json"), JSON.stringify({ pilotSitesSha256: createHash("sha256").update(list).digest("hex") }));
    writeFileSync(join(run, "raw.jsonl"), `${JSON.stringify({ host: "a.example.com", evidence: { excerpt: "x" } })}\n`);
    const rounds = pilotRounds(dir);
    expect(rounds[0]).toMatchObject({ ok: true, hosts: ["a.example.com"] });
    expect(checkPilotDropped(readRemovals(list, "pilot"), rounds, { need: false }).ok).toBe(true);
    expect(checkPilotDropped(new Map(), rounds, { need: false }).ok).toBe(false);
    expect(prunePilot(run).kind).toBe("pilot");
    expect(readFileSync(join(run, "raw.jsonl"), "utf8")).not.toContain("excerpt");
  });
  it("in flight: only page and error text can stop a run, never DNS records", () => {
    expect(pageTextMissed({ evidence: { excerpt: "you are 203.0.113.7" } })).toBe(true);
    expect(pageTextMissed({ evidence: { pageExcerpt: { text: "jan@example.nl" } } })).toBe(true);
    expect(pageTextMissed({ dns: { listed: { spfRecord: "v=spf1 ip4:203.0.113.7 include:a@b -all" } } })).toBe(false);
    expect(pageTextMissed({ evidence: { pageExcerpt: { text: scrub("(AT) Wien") } } })).toBe(false);
  });
  it("in flight: a scrub miss stops pass 2 at once, and the run says it is partial", async () => {
    const dir = mkdtempSync(join(tmpdir(), "e20r2-"));
    const file = join(dir, "leak.mjs");
    writeFileSync(file, 'import { parentPort, workerData } from "node:worker_threads"; parentPort.postMessage({ record: { ...workerData.row, status: "ok", checks: [], evidence: { excerpt: "you are 203.0.113.7" }, finalHost: workerData.row.host, score: 1, counters: {}, hops: [], robots: [] } });');
    const rows = mergeCohorts({ T1k: Array.from({ length: 20 }, (_, i) => ({ host: `s${i}.selftest.example.com`, rank: i, group: "x" })) });
    const stub = () => Promise.reject(Object.assign(new Error("x"), { code: "ENODATA" }));
    const out = join(dir, "run");
    const { records, stoppedFor } = await runPass(rows, { pass: 2, out, loopbackPort: 9, delayMs: 0, concurrency: 1, workerFile: file, dns: { mx: stub, ns: stub, resolveTxt: stub, resolveCaa: stub } });
    expect(stoppedFor).toMatch(/scrub/);
    expect(records.length).toBeLessThan(20);
    expect(JSON.parse(readFileSync(join(out, "manifest.json"), "utf8"))).toMatchObject({ partial: true, stoppedFor, records: records.length });
    expect(JSON.parse(readFileSync(join(out, "aggregate.json"), "utf8")).partial).toBe(true);
    expect(unfinishedRun(out)).toMatch(/stopped/);
    expect(ROLLING_WINDOW).toBe(200);
  });
  it("note: results are private to the account", async () => {
    const out = join(mkdtempSync(join(tmpdir(), "e20r2-")), "run");
    await runPass([], { pass: PILOT_RUN, out, loopbackPort: 9, delayMs: 0 });
    expect(statSync(out).mode & 0o777).toBe(0o700);
    for (const f of ["raw.jsonl", "manifest.json", "aggregate.json", "pilot-sites.txt"]) expect(statSync(join(out, f)).mode & 0o777, f).toBe(0o600);
  });
  it("S5: a loopback run asks no remote", () => {
    const src = readFileSync(join(import.meta.dirname, "..", "bench", "front-door", "replicate.mjs"), "utf8");
    expect(src).toContain("{ remote: !extra.loopback }");
    expect(src).toContain("{ remote: !loopbackPort }");
  });
  it("item 2: pruning leaves the run's manifest alone, and links the old and new raw hash", () => {
    const dir = mkdtempSync(join(tmpdir(), "e20r2-"));
    const text = `${JSON.stringify({ host: "a.example.com", evidence: { pageExcerpt: { text: "x" } } })}\n`;
    writeFileSync(join(dir, "raw.jsonl"), text);
    const sum = createHash("sha256").update(text).digest("hex");
    writeFileSync(join(dir, "manifest.json"), JSON.stringify({ finishedAt: "x", rawSha256: sum }));
    const proof = rewriteRun(dir, [{ host: "a.example.com" }], "pilot");
    expect(proof.rawSha256Before).toBe(sum);
    expect(proof.rawSha256After).not.toBe(sum);
    expect(JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8")).rawSha256).toBe(sum);
    expect(JSON.parse(readFileSync(join(dir, "prune-manifest.json"), "utf8"))).toMatchObject(proof);
    expect(() => rewriteRun(dir, [], "pilot")).toThrow(/not the one the manifest hashed/);
  });
});

describe("acceptance", () => {
  it("every stop condition refuses pass 2, for its own reason, and a clean pilot is allowed", async () => {
    const rows = await runAcceptance();
    expect(rows.filter((r) => !r.pass)).toEqual([]);
    expect(rows.length).toBeGreaterThanOrEqual(290);
  }, 400_000);
});

describe("limits", () => {
  it("gives pass 2 its registered time per site", () => {
    expect(V2_LIMITS).toEqual({ siteBudgetMs: 15_000, siteHardCapMs: 30_000 });
  });
  it("B6: the legacy runner refuses to leave loopback", () => {
    expect(() => authorize({ registered: "E20", cohort: "tranco" })).toThrow(/E20 is closed/);
  });
  it("keeps the vendored list out of the npm package", () => {
    const pkg = JSON.parse(readFileSync(join(import.meta.dirname, "..", "package.json"), "utf8"));
    expect(pkg.files.some((f) => f.startsWith("bench"))).toBe(false);
  });
});

describe("the outside reviewer's conditions", () => {
  const sum = (b) => createHash("sha256").update(b).digest("hex");
  const folder = () => mkdtempSync(join(tmpdir(), "e20r2-cond-"));
  const stoppers = { opted: "User-agent: Penthera-Research\nDisallow: /\n", all: "User-agent: *\nDisallow: /\n" };

  it("a compressed answer with no read body is body-unavailable, not a page", () => {
    expect(classify({ status: 200, headers: { "Content-Encoding": "gzip" }, body: "" })).toMatchObject({ label: "body-unavailable", rule: "content-encoding" });
    expect(classify({ status: 200, headers: { "content-encoding": "identity" }, body: "" }).label).toBe("candidate-page");
    expect(classify({ status: 200, body: "" }).label).toBe("candidate-page");
    expect(classify({ status: 403, headers: { "content-encoding": "br" }, body: "" }).label).toBe("block");
    expect(stratumOf({ evidence: { class: { label: "body-unavailable" } } })).toBeNull();
  });

  it("the study's early opt-out agrees with the matcher on longest match and ties", () => {
    expect(wholeSiteStop(stoppers.opted)).toBe(true);
    expect(wholeSiteStop(stoppers.all)).toBe(false);
    expect(wholeSiteStop(stoppers.all, undefined, true)).toBe(true);
    for (const allowed of ["User-agent: Penthera-Research\nDisallow: /\nAllow: /\n", "User-agent: Penthera-Research\nDisallow: /\nAllow: /$\n"]) {
      expect(wholeSiteStop(allowed), allowed).toBe(false);
      expect(robotsVerdict(allowed, "/"), allowed).toBe("allowed");
    }
    // A group naming us overrides the `*` group, in the early check too.
    const ours = "User-agent: Penthera-Research\nAllow: /\n\nUser-agent: *\nDisallow: /\n";
    expect(wholeSiteStop(ours, undefined, true)).toBe(false);
    expect(robotsVerdict("User-agent: Penthera-Research\nDisallow: /\nAllow: /$\n", "/x")).toBe("disallowed");
    expect(robotsVerdict(stoppers.opted, "/x")).toBe("opted_out");
  });

  it("the live check's reading did not change", () => {
    expect(optedOut("User-agent: penthera\nDisallow: /\nAllow: /\n", ["penthera"])).toBe(true);
  });

  it("analysis reads only the file the gate checked", () => {
    const dir = folder();
    const raw = "{}\n";
    writeFileSync(join(dir, "raw.jsonl"), raw);
    writeFileSync(join(dir, "sibling.jsonl"), raw);
    writeFileSync(join(dir, "manifest.json"), JSON.stringify({ kind: "pass", finishedAt: "x", immutableAtFinish: { ok: true }, rawSha256: sum(raw) }));
    privacyReport(dir);
    const said = [];
    expect(analyzeMain(["--pass1", join(dir, "sibling.jsonl"), "--e20", "a", "b"], { fail: (m) => said.push(m) })).toBe(3);
    expect(said.join()).toMatch(/raw\.jsonl/);
  });

  it("condition 1: a tenant of a shared suffix is its own organization", () => {
    expect(siteOrg("www.github.io")).toBe("www.github.io");
    expect(siteOrg("a.www.github.io")).toBe("www.github.io");
    expect(siteOrg("github.io")).toBe("github.io");
    expect(siteOrg("www.example.com")).toBe("example.com");
    expect(siteKey("www.github.io")).toBe("www.github.io");
  });

  it("condition 1: DNS asks the tenant, never the shared suffix, and a move to the suffix is another organization", async () => {
    const asked = [];
    const none = (n) => { asked.push(n); return Promise.reject(Object.assign(new Error("x"), { code: "ENODATA" })); };
    const dns = { resolveTxt: none, resolveCaa: () => Promise.resolve([]), mx: none, ns: none };
    const read = await siteDns("www.github.io", "github.io", dns);
    expect(read.listed.domain).toBe("www.github.io");
    expect(read.finalOtherOrg).toBe(true);
    expect(mergeCohorts({ T1k: [{ host: "www.github.io", rank: 1 }, { host: "github.io", rank: 2 }] })).toHaveLength(2);
  });

  it("condition 2: any exact query fails a site, for the listed or the final name", () => {
    const fine = { outcomes: { txt: "answer" }, queries: [{ outcome: "answer" }] };
    expect(resolverFailed({ dns: { listed: fine } })).toBe(false);
    expect(resolverFailed({ dns: { listed: { ...fine, queries: [{ name: "_dmarc.www.a.org", outcome: "resolver-failure:servfail" }] } } })).toBe(true);
    expect(resolverFailed({ dns: { listed: { ...fine, outcomes: { other: "resolver-failure:timeout" } } } })).toBe(true);
    expect(resolverFailed({ dns: { listed: fine, final: { outcomes: { dmarc: "resolver-failure:timeout" } } } })).toBe(true);
    expect(resolverFailed({ dns: { listed: fine, final: { queries: [{ outcome: "resolver-failure:refused" }] } } })).toBe(true);
    expect(resolverFailed({ dns: { listed: { outcomes: { txt: "nxdomain" }, queries: [{ outcome: "nxdomain" }] } } })).toBe(false);
  });

  it("condition 3: the git state is kept from both ends and compared", async () => {
    const out = join(folder(), "run");
    const server = createServer((_q, res) => res.end("x"));
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    let calls = 0;
    await runPass([{ host: "a.example.com", cohorts: { T1k: { rank: 1 } } }], { pass: 2, out, loopbackPort: server.address().port, delayMs: 0, gitNow: () => ({ commit: `c${calls++}`, dirty: false, hidden: false }) });
    await new Promise((r) => server.close(r));
    const m = JSON.parse(readFileSync(join(out, "manifest.json"), "utf8"));
    expect(m.gitAtStart).toBeDefined();
    expect(m.gitAtFinish.commit).toBe("c0");
    expect(m.immutableAtFinish).toEqual({ ok: false, changed: ["git"] });
  });

  it("condition 4: prune reads the file back, and a whole pass isn't pruned by hand", () => {
    const dir = folder();
    const raw = `${JSON.stringify({ host: "a.org", evidence: { excerpt: "text", pageExcerpt: { text: "t" } } })}\n`;
    writeFileSync(join(dir, "raw.jsonl"), raw);
    writeFileSync(join(dir, "manifest.json"), JSON.stringify({ kind: "pass", startedAt: "x" }));
    expect(prunePilot(dir)).toMatchObject({ kind: "stopped", verified: true });
    const whole = folder();
    writeFileSync(join(whole, "raw.jsonl"), raw);
    writeFileSync(join(whole, "manifest.json"), JSON.stringify({ kind: "pass", finishedAt: "x", immutableAtFinish: { ok: true }, rawSha256: sum(raw) }));
    expect(unfinishedRun(whole)).toBe(NO_PRIVACY);
    const said = [];
    expect(validationMain(["prune", whole], { log: () => undefined, fail: (m) => said.push(m) })).toBe(3);
    expect(readFileSync(join(whole, "raw.jsonl"), "utf8")).toBe(raw);
  });

  it("condition 5: the privacy report covers every field, and only a clean one for this raw file counts", () => {
    const dir = folder();
    const write = (rows) => {
      const raw = rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
      writeFileSync(join(dir, "raw.jsonl"), raw);
      writeFileSync(join(dir, "manifest.json"), JSON.stringify({ kind: "pass", finishedAt: "x", immutableAtFinish: { ok: true }, rawSha256: sum(raw) }));
    };
    for (const dirty of [{ evidence: { values: { server: "you are 203.0.113.7" } } }, { evidence: { cookieNames: ["jan@example.nl"] } }, { dns: { listed: { dmarcRecord: "rua=jan@example.nl" } } }, { checks: [{ evidence: "jan@example.nl" }] }, { evidence: { excerpt: "jan@example.nl" } }]) {
      write([{ status: "ok", ...dirty }]);
      expect(privacyReport(dir).clean, JSON.stringify(dirty)).toBe(false);
      expect(unfinishedRun(dir)).toBe(NO_PRIVACY);
    }
    write([{ status: "ok" }]);
    privacyReport(dir);
    expect(unfinishedRun(dir)).toBeNull();
    write([{ status: "ok", order: 1 }]);
    expect(unfinishedRun(dir)).toBe(NO_PRIVACY);
  });

  it("condition 8: the floors, and coverage per claim cohort", () => {
    const rec = { status: "ok", httpStatus: 200, cohorts: { T1k: { rank: 1 } }, checks: [], counters: { requests: 3, bytes: 1, redirects: 0 }, hops: [], dns: { listed: { spf: true, dmarc: true, caa: true, exists: true, outcomes: {} } }, evidence: { bodySha256: "x", pageExcerpt: { text: "t" }, others: [] } };
    const blocked = { ...rec, httpStatus: 403, evidence: { ...rec.evidence, pageExcerpt: undefined, excerpt: "no" } };
    const report = pilotReport([...Array.from({ length: 9 }, () => rec), ...Array.from({ length: 41 }, () => blocked)]);
    expect(report.coverage.T1k).toEqual({ selected: 50, eligible: 50, graded: 50, twoxx: 9, dnsComplete: 50, classes: { none: 50 } });
    expect(stopRules(report)).toContain("under 10 2xx responses");
    const everyCohort = { T1k: {}, "YC-new": {}, "YC-25": {}, "YC-old": {}, T100k: {} };
    const across = (r) => ({ ...r, cohorts: everyCohort });
    expect(stopRules(pilotReport([...Array.from({ length: 10 }, () => across(rec)), ...Array.from({ length: 40 }, () => across(blocked))]))).toEqual([]);
    expect(stopRules(report)).toContain("no usable output in YC-old");
    expect(MIN_GRADED).toBe(25);
    expect(MIN_ELIGIBLE).toBe(30);
    expect(MAX_LIVE_ROUNDS).toBe(2);
  });

  it("the prune proof needs the draw's kind and this manifest", () => {
    const dir = folder();
    const raw = "{}\n", pruned = "{ }\n";
    const manifest = JSON.stringify({ kind: "pass", finishedAt: "x", immutableAtFinish: { ok: true }, rawSha256: sum(raw) });
    writeFileSync(join(dir, "manifest.json"), manifest);
    writeFileSync(join(dir, "raw.jsonl"), pruned);
    writeFileSync(join(dir, "privacy-report.json"), JSON.stringify({ clean: true, rawSha256: sum(raw), manifestSha256: sum(manifest) }));
    const proof = { kind: "validation-draw", manifestSha256: sum(manifest), rawSha256Before: sum(raw), rawSha256After: sum(pruned) };
    const check = (p) => { writeFileSync(join(dir, "prune-manifest.json"), JSON.stringify(p)); return unfinishedRun(dir); };
    expect(check(proof)).toBeNull();
    expect(check({ ...proof, kind: "stopped" })).toMatch(/not the one/);
    expect(check({ ...proof, manifestSha256: "x" })).toMatch(/not the one/);
  });

  it("the score refuses a key this run's draw didn't write", () => {
    const dir = folder();
    writeFileSync(join(dir, "validation-key.json"), "[]");
    writeFileSync(join(dir, "prune-manifest.json"), JSON.stringify({ keySha256: sum("[ ]") }));
    const said = [];
    expect(validationMain(["score", dir], { log: () => undefined, fail: (m) => said.push(m) })).toBe(3);
    expect(said.join()).toMatch(/Refused/);
  });

  it("secondary cohorts are reported per check, and a thin side is not estimable", () => {
    const row = (i, cohort, passed) => ({ host: `h${i}.org`, finalHost: `h${i}.org`, cohorts: { [cohort]: { rank: 1 } }, status: "ok", checks: [{ id: "csp", passed, weight: 1 }] });
    const rows = [...Array.from({ length: 25 }, (_, i) => row(i, "SP500", true)), ...Array.from({ length: 25 }, (_, i) => row(100 + i, "T1k", false)), row(200, "ShowHN", true)];
    const out = secondaryCohorts(rows);
    expect(out.find((c) => c.cohort === "SP500" && c.against === "T1k")).toMatchObject({ check: "csp", judgedA: 25, judgedB: 25, source: "http", interval: "naive row-level" });
    expect(out.find((c) => c.cohort === "SP500" && c.against === "T1k").exactP).toBeLessThan(0.001);
    expect(out.find((c) => c.cohort === "ShowHN" && c.against === "T1k").decision).toBe("not estimable");
  });
});

describe("package 3 criteria", () => {
  const sum = (b) => createHash("sha256").update(b).digest("hex");
  const folder = () => mkdtempSync(join(tmpdir(), "e20r2-p3-"));

  it("1: a stop that lands during the last site makes the run partial", async () => {
    const out = join(folder(), "run");
    const server = createServer((_q, res) => res.end("x"));
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    let stop = null;
    const { stoppedFor } = await runPass([{ host: "a.example.com", cohorts: { T1k: { rank: 1 } } }], { pass: 2, out, loopbackPort: server.address().port, delayMs: 0, stopCheck: () => stop, onRecord: () => { stop = "the stop file exists"; } });
    await new Promise((r) => server.close(r));
    expect(stoppedFor).toBe("the stop file exists");
    const m = JSON.parse(readFileSync(join(out, "manifest.json"), "utf8"));
    expect(m).toMatchObject({ partial: true, stoppedFor, records: 1 });
    expect(JSON.parse(readFileSync(join(out, "aggregate.json"), "utf8")).partial).toBe(true);
  });

  it("2: the scan walks every stored string, keys too, with hashes and SPF addresses as the only exceptions", () => {
    expect(recordMisses({ a: { b: [{ c: "jan@example.nl" }] } }).email).toBe(1);
    expect(recordMisses({ "jan@example.nl": 1 }).email).toBe(1);
    expect(recordMisses({ finalHost: "203.0.113.9", hops: ["203.0.113.9"] }).ipv4).toBe(2);
    expect(recordMisses({ evidence: { bodySha256: "a".repeat(64), others: [{ bodySha256: "b".repeat(64) }] } }).longHex).toBe(0);
    expect(recordMisses({ evidence: { etag: "a".repeat(64) } }).longHex).toBe(1);
    expect(recordMisses({ evidence: { otherSha256: "a".repeat(64) } }).longHex).toBe(1);
    expect(recordMisses({ bodySha256: "a".repeat(64) }).longHex).toBe(1);
    expect(recordMisses({ evidence: { bodySha256: "jan@example.nl" } }).email).toBe(1);
    expect(recordMisses({ spfRecord: "203.0.113.7" }).ipv4).toBe(1);
    expect(recordMisses({ dns: { listed: { spfRecord: "v=spf1 ip4:203.0.113.7 -all" } } }).ipv4).toBe(0);
    expect(recordMisses({ dns: { listed: { spfRecord: "v=spf1 jan@example.nl" } } }).email).toBe(1);
  });

  it("3: purge takes the whole file for a miss in a header, cookie, finalHost or DNS field, and the run decides nothing", () => {
    for (const leak of [{ evidence: { values: { server: "jan@example.nl" } } }, { evidence: { cookieNames: ["jan@example.nl"] } }, { finalHost: "203.0.113.9" }, { dns: { listed: { dmarcRecord: "rua=jan@example.nl" } } }]) {
      const dir = folder();
      const raw = `${JSON.stringify({ status: "ok", ...leak })}\n`;
      writeFileSync(join(dir, "raw.jsonl"), raw);
      writeFileSync(join(dir, "manifest.json"), JSON.stringify({ kind: "pass", finishedAt: "x", immutableAtFinish: { ok: true }, rawSha256: sum(raw) }));
      writeFileSync(join(dir, "validation-key.json"), "[]");
      expect(privacyReport(dir).clean).toBe(false);
      expect(() => purgeRun(dir)).toThrow(/--confirm/);
      expect(() => purgeRun(dir, "0".repeat(12))).toThrow(/--confirm/);
      expect(existsSync(join(dir, "raw.jsonl"))).toBe(true);
      expect(privacyReport(dir).purgeConfirm).toBe(sum(raw).slice(0, 12));
      expect(purgeRun(dir, sum(raw).slice(0, 12))).toMatchObject({ disposition: "privacy-failed", rawSha256: sum(raw), verified: true });
      expect(existsSync(join(dir, "raw.jsonl"))).toBe(false);
      expect(existsSync(join(dir, "validation-key.json"))).toBe(false);
      expect(unfinishedRun(dir)).toBe("the raw file was purged");
      expect(() => purgeRun(dir)).toThrow(/no raw file/);
    }
  });

  it("the report names flagged fields only in its private file, and a reviewed false fire keeps the run", () => {
    const dir = folder();
    const raw = `${JSON.stringify({ status: "ok", evidence: { values: { server: "(AT) Wien" } }, "jan@example.nl": 1 })}\n`;
    writeFileSync(join(dir, "raw.jsonl"), raw);
    writeFileSync(join(dir, "manifest.json"), JSON.stringify({ kind: "pass", finishedAt: "x", immutableAtFinish: { ok: true }, rawSha256: sum(raw) }));
    const printed = [];
    expect(reportMain(["--privacy", dir], { log: (m) => printed.push(m) })).toBe(1);
    expect(printed.join()).not.toMatch(/flaggedFields|Wien|jan@/);
    const stored = readFileSync(join(dir, "privacy-report.json"), "utf8");
    expect(JSON.parse(stored).flaggedFields).toEqual({ "evidence.values.server email": 1, "record (a key) email": 1 });
    expect(stored).not.toMatch(/Wien|jan@/);
    expect(unfinishedRun(dir)).toBe(NO_PRIVACY);
    expect(() => privacyReport(dir, { falseFire: Buffer.alloc(0) })).toThrow(/empty/);
    expect(() => privacyReport(dir, { falseFire: Buffer.from("checked") })).toThrow(/--reviewer/);
    expect(() => privacyReport(dir, { falseFire: Buffer.from("checked"), reviewer: " " })).toThrow(/--reviewer/);
    expect(privacyReport(dir, { falseFire: Buffer.from("checked"), reviewer: "a person" }).reviewed).toMatchObject({ noteSha256: sum("checked"), reviewer: "a person" });
    expect(unfinishedRun(dir)).toBeNull();
  });
  it("prune refuses a stored miss, in any field, unless a person reviewed it as false", () => {
    for (const leak of [{ evidence: { values: { server: "jan@example.nl" } } }, { evidence: { cookieNames: ["jan@example.nl"] } }, { finalHost: "203.0.113.9" }, { hops: ["203.0.113.9"] }, { dns: { listed: { dmarcRecord: "rua=jan@example.nl" } } }]) {
      const dir = folder();
      writeFileSync(join(dir, "raw.jsonl"), `${JSON.stringify({ status: "ok", ...leak })}\n`);
      writeFileSync(join(dir, "manifest.json"), JSON.stringify({ kind: "pilot", startedAt: "x" }));
      expect(() => prunePilot(dir)).toThrow(/privacy miss/);
      privacyReport(dir, { falseFire: Buffer.from("checked"), reviewer: "a person" });
      expect(prunePilot(dir).verified).toBe(true);
    }
  });
  it("purge writes its proof last, and a proof holds only while everything stays gone", () => {
    const dir = folder();
    const raw = "{}\n";
    writeFileSync(join(dir, "raw.jsonl"), raw);
    writeFileSync(join(dir, "manifest.json"), JSON.stringify({ kind: "pilot", finishedAt: "x", rawSha256: sum(raw) }));
    purgeRun(dir, sum(raw).slice(0, 12));
    expect(existsSync(join(dir, "purge-manifest.json.tmp"))).toBe(false);
    expect(purgeState(dir)).toBe("proved");
    writeFileSync(join(dir, "validation-key.json"), "[]");
    expect(purgeState(dir)).toBe("validation-key.json still there");
    expect(unfinishedRun(dir)).toMatch(/purge proof does not hold/);
  });
  it("a decision binds to its report and seal, and a failed round can't be a go", () => {
    const dir = folder();
    writeFileSync(join(dir, "pilot-report.json"), "{}\n");
    writeFileSync(join(dir, "pilot-result.json"), JSON.stringify({ passed: false, sealSha256: "s" }));
    expect(() => decidePilot(dir, { decision: "go", reviewer: "a" })).toThrow(/can't be a go/);
    expect(() => decidePilot(dir, { decision: "maybe", reviewer: "a" })).toThrow(/--decision/);
    expect(() => decidePilot(dir, { decision: "no-go" })).toThrow(/--reviewer/);
    expect(decidePilot(dir, { decision: "no-go", reviewer: "a" })).toMatchObject({ decision: "no-go", reportSha256: sum("{}\n"), sealSha256: "s", reviewer: "a" });
  });
  it("3: the disposition says what the run was", () => {
    const go = (manifest) => {
      const dir = folder();
      writeFileSync(join(dir, "raw.jsonl"), "{}\n");
      writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest));
      return purgeRun(dir, sum("{}\n").slice(0, 12)).disposition;
    };
    expect(go({ kind: "pilot" })).toBe("crashed");
    expect(go({ kind: "pass", finishedAt: "x", partial: true })).toBe("partial");
    expect(go({ kind: "pass", finishedAt: "x" })).toBe("finished");
  });

  it("6: secondary DNS reads DNS records, for sites HTTP never graded", () => {
    const dnsSite = (i, cohort, spf) => ({ host: `d${i}.org`, listedOrg: `d${i}.org`, cohorts: { [cohort]: { rank: 1 } }, status: "error", checks: [], dns: { listed: { exists: true, spfRecordPresent: spf, dmarcReading: { enforcing: spf }, caa: spf } } });
    const all = [...Array.from({ length: 25 }, (_, i) => dnsSite(i, "SP500", true)), ...Array.from({ length: 25 }, (_, i) => dnsSite(100 + i, "YC-new", false))];
    const row = secondaryCohorts([], all).find((c) => c.cohort === "SP500" && c.against === "YC-new" && c.check === "spf");
    expect(row).toMatchObject({ source: "dns", interval: "naive row-level", judgedA: 25, judgedB: 25 });
    expect(row.exactP).toBeLessThan(0.001);
  });

  it("6: the challenge share by edge keeps edges of at least 20 sites", () => {
    const rows = Array.from({ length: 20 }, (_, i) => ({ platform: { edge: "cloudflare" }, evidence: { class: { label: i < 5 ? "challenge" : "candidate-page" } } }));
    const edge = challengeByEdge(rows).cloudflare;
    expect(edge).toMatchObject({ n: 20, share: 0.25, interval: "naive row-level" });
    expect(edge.ci95[0]).toBeCloseTo(0.112, 2);
    expect(edge.ci95[1]).toBeCloseTo(0.469, 2);
    expect(challengeByEdge(rows.slice(0, 19))).toEqual({});
  });

  it("7: analysis refuses a registered input that is missing or doesn't match", () => {
    const dir = folder();
    const raw = "{}\n";
    writeFileSync(join(dir, "raw.jsonl"), raw);
    writeFileSync(join(dir, "manifest.json"), JSON.stringify({ kind: "pass", finishedAt: "x", immutableAtFinish: { ok: true }, rawSha256: sum(raw) }));
    privacyReport(dir);
    writeFileSync(join(dir, "one.txt"), "x");
    const said = [];
    const fail = (m) => said.push(m);
    expect(analyzeMain(["--pass1", join(dir, "raw.jsonl"), "--e20", "a", "b"], { fail, state: runState(dir), preregText: "" })).toBe(3);
    expect(said.at(-1)).toMatch(/Pass 1 raw" was not given/);
    expect(analyzeMain(["--pass1", join(dir, "raw.jsonl"), "--pass2", join(dir, "one.txt"), "--e20", "a", "b"], { fail, state: runState(dir), preregText: "| Pass 1 raw SHA-256 | `" + "0".repeat(64) + "` |" })).toBe(3);
    expect(said.at(-1)).toMatch(/does not match its frozen hash/);
  });

  it("7: the protocol records every private input", () => {
    const prereg = readFileSync(PREREG_R, "utf8");
    for (const label of ["Pass 1 raw", "E20 Tranco raw", "E20 YC raw", "Industry map", "E20 exclusion file"]) expect(recordedHashR(prereg, label), label).toMatch(/^[0-9a-f]{64}$/);
  });

  it("8: unsure totals stand apart, and the main kappa skips any unsure row", () => {
    const key = [1, 2, 3, 4, 5, 6].map((id) => ({ id, stratum: "candidate-page", stratumSize: 6, ruleLabel: "page" }));
    const csv = (a) => `id,label\n${a.map((l, i) => `${i + 1},${l}`).join("\n")}\n`;
    const human = ["page", "page", "block", "block", "unsure", "unsure"];
    const agent = ["page", "page", "block", "block", "unsure", "page"];
    const v = scoreLabels(key, csv(human), csv(agent), { resamples: 10 }).humanVsAgent;
    expect(v).toMatchObject({ rows: 6, humanUnsure: 2, agentUnsure: 1, bothAnswered: 4, kappa: 1, disagreements: 0 });
    expect(v.kappaUnsureAsDisagreement).toBeLessThan(1);
  });

  it("the pilot rejects a claim cohort with no usable output", () => {
    const report = { scrubMisses: {}, outcomes: {}, sites: 50, evidence: { graded: 50, twoxx: 50, twoxxWithExcerpt: 50 }, dns: { read: 50, answered: { spf: 50, dmarc: 50 } }, resolverFailures: 0, counters: { maxRequestsPerSite: 3 }, excludedHops: 0, coverage: { T1k: { graded: 10, dnsComplete: 0 }, "YC-new": { graded: 0, dnsComplete: 10 }, T100k: { graded: 10, dnsComplete: 10 } } };
    expect(stopRules(report)).toEqual(["no usable output in T1k", "no usable output in YC-new"]);
  });

  it("10: the preflight runs the real checks, and the run sheet says so", () => {
    const { scripts } = JSON.parse(readFileSync(join(import.meta.dirname, "..", "package.json"), "utf8"));
    for (const step of ["npm test", "e20r:acceptance", "--self-test"]) expect(scripts["e20r:preflight"]).toContain(step);
    const sheet = readFileSync(join(import.meta.dirname, "..", "bench", "front-door", "run-sheet.md"), "utf8");
    for (const step of ["npm run e20r:preflight", "uniq -d", "pilot-sites-all.txt", "--skip", "validation-sample.mjs purge", "--confirm", "--false-fire", "flaggedFields"]) expect(sheet).toContain(step);
  });

  it("the public page makes no absolute privacy claim", () => {
    const page = readFileSync(STUDY_PAGE, "utf8");
    expect(page).not.toMatch(/no email addresses/);
    expect(page).toMatch(/99\.55%/);
    expect(page).toMatch(/prospective corrected remeasurement/);
  });
});

describe("Amendment 3", () => {
  const folder = () => mkdtempSync(join(tmpdir(), "e20r2-a3-"));
  const email = (text) => scrubMisses(text).email;

  it("the detector leaves our own tokens alone, at any sentence ending", () => {
    for (const text of [
      "Reach us at <email>.", "Reach us at <email>", "Reach us at <email>, or call.", "Reach us at <email>; we reply.", "Reach us at <email>! Thanks.", "Reach us at <email>? Yes.",
      "Reach us at <email>. Open daily", "Reach us (at <email>).", "Write to us at (<email>). We reply.", "Reach us at [<email>]. Thanks.", "Reach us at \"<email>\". Thanks.", "Our server is at <ip>. It is fine.", "Call us at <number>. We answer.",
      "(at) <email>", "(at) <email>.", "us (at) <email>, thanks", "[at] <email>.", "{at} <email>.", "( at ) <email>.", "us (at)<email>.",
    ]) expect(email(text), text).toBe(0);
  });

  it("the detector is as strict as before for anything else", () => {
    for (const text of ["john at example.com", "john at example .com", "john at example . com", "john at example dot com", "john (at) home.nl", "(at) home", "sales [at] 3m.com", "at (at) example.com", "john at emailx.com", "(at) <emailx.com", "john at <emailx.com", "john at <email.com"]) expect(email(text), text).toBeGreaterThan(0);
  });

  it("a bracketed or quoted domain survives the scrub and is always found: the reviewer's matrix", () => {
    const locals = ["john", "a.b", "first+tag", "jan_de-vries"];
    const shapes = [(d) => `(${d})`, (d) => `[${d}]`, (d) => `{${d}}`, (d) => `"${d}"`, (d) => `'${d}'`];
    const domains = ["example.com", "example dot com", "example . com"];
    let forms = 0;
    for (const local of locals) for (const shape of shapes) for (const domain of domains) {
      const text = `${local} at ${shape(domain)}`;
      expect(email(scrub(text)), text).toBeGreaterThan(0);
      forms++;
    }
    expect(forms).toBe(60);
  });

  it("each exemption has both sides", () => {
    // Our own tokens: no finding.
    for (const text of ["Reach us at <email>. Open daily", "(at) <email>. Open daily", "[at] <ip>. Open daily", "Reach at (<email>). Open daily", 'Reach at "<email>". Open daily', "Reach at '<number>'. Open daily"]) expect(email(text), text).toBe(0);
    // A bracketed `at` exempts our tokens alone.
    for (const text of ["(at) <emails>. Open daily", "(at) <email.com"]) expect(email(text), text).toBeGreaterThan(0);
    // A URL or path holds characters no domain label can.
    for (const text of ["Available at https://example.com. Open daily", "Docs at http://docs.example.com/a.html", "Mirror at ftp://example.com/a.zip", "See at (https://example.com). Open daily", "See it at /docs/guide.html. Open daily"]) expect(email(text), text).toBe(0);
    for (const text of ["john at https.example.com", "john at <example.com>", "john at «example.com»", "john at “example.com”"]) expect(email(text), text).toBeGreaterThan(0);
  });

  it("after a bare `at`, only a label that could be a domain counts: both sides of the rule", () => {
    for (const text of ["Plans starting at $29. Cancel anytime", "Starts at $29/mo. Cancel anytime", "Doors open at 5:30. Tickets on sale", "Dinner at Joe's. Then drinks", "Reach us at 24/7. Support is free", "Grade at 100%. Great work", "Sold at ₹99. Buy now", "Open at 9:30am. Closed Sunday", "a_b at c_d.com"]) expect(scrubMisses(scrub(text)).email, text).toBe(0);
    for (const text of ["john at example.com", "john at 3m.com", "john at my-shop.nl", "john at (my-shop.nl)", "jan at münchen.de", "jan at 例え.テスト", "jan at (müller.at)", "jan at example.ελ"]) expect(email(text), text).toBeGreaterThan(0);
    expect(email("jan at example.c")).toBe(0);
    // A label starts and ends with a letter or number, hyphens inside, punycode included.
    for (const text of ["john at xn--bcher-kva.de", "john at a-b-c.com", "john at 3-m.nl", "john at (xn--mnchen-3ya.de)"]) expect(email(text), text).toBeGreaterThan(0);
    for (const text of ["john at -name.com", "john at name-.com", "john at (-name.com)", "john at --x--.com", "john at $29.com", "john at 5:30.com", "john at joe's.com", "john at /docs/guide.html", "john at a/b.com"]) expect(email(text), text).toBe(0);
  });

  it("a JWT counts at a token's edge, not inside a word", () => {
    const sample = ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxIn0", "abc"].join(".");
    for (const text of ["keyJ.value", "monkeyJ.wrench", "okeyJ.x"]) expect(scrubMisses(text).jwt, text).toBe(0);
    for (const text of [sample, `token=${sample}`, `/a/${sample}`, `x.${sample}`, "eyJh.b"]) expect(scrubMisses(text).jwt, text).toBeGreaterThan(0);
  });

  it("withholding removes every text field, keeps the rest, and logs kinds as counts", () => {
    const record = { host: "a.org", cohorts: { T1k: {}, "YC-new": {} }, status: "ok", score: 7, checks: [{ id: "csp", passed: true }], evidence: { bodySha256: "h", class: { label: "candidate-page", rule: "status" }, classRegistered: { label: "page" }, excerpt: "bad#a=b", pageExcerpt: { title: "t", text: "Look at (example.com). Open daily", noscript: "n", chars: 9, forms: 1 }, others: [{ kind: "security", bodySha256: "s", excerpt: "e" }] } };
    const out = withholdText(record);
    expect(JSON.stringify(out)).not.toMatch(/example\.com|bad#|"e"|"n"/);
    expect(out.evidence.textWithheld).toEqual({ kinds: { fragment: 1, email: 1 }, fields: 2 });
    expect(out.evidence.pageExcerpt).toEqual({ chars: 9, forms: 1 });
    expect(out.evidence.others).toEqual([{ kind: "security", bodySha256: "s" }]);
    expect(out.evidence.class).toEqual(record.evidence.class);
    expect(out.score).toBe(7);
    expect(out.checks).toEqual(record.checks);
    const counts = withheldCounts([out, { ...out, cohorts: { T1k: {} } }, record]);
    expect(counts).toMatchObject({ records: 2, kinds: { fragment: 2, email: 2 } });
    // Both cohorts are under 20, so they fold into `other`.
    expect(counts.byCohort).toEqual({ other: { records: 3, of: 5, kinds: { fragment: 3, email: 3 }, share: 0.6 } });
    const big = withheldCounts(Array.from({ length: 20 }, (_, i) => ({ ...(i ? record : out), httpStatus: 503, cohorts: { T1k: {} } })));
    expect(big.byCohort.T1k).toMatchObject({ records: 1, of: 20, share: 0.05 });
    expect(big.byStatus).toHaveProperty("5xx");
    for (const group of ["byStratum", "byLabel", "byStatus", "byEdge"]) expect(Object.values(counts[group]).reduce((n, g) => n + g.records, 0), group).toBe(2);
    expect(withholdText(out)).toBe(out);
    expect(pageTextMissed(out)).toBe(false);
  });

  it("the 90% rule reads the 2xx responses that could have an excerpt", () => {
    const rec = (over) => ({ status: "ok", httpStatus: 200, cohorts: {}, checks: [], counters: { requests: 3, bytes: 1, redirects: 0 }, hops: [], evidence: { bodySha256: "x", pageExcerpt: { text: "t" }, others: [], ...over } });
    const withheld = rec({ pageExcerpt: {}, textWithheld: { kinds: { email: 1 }, fields: 1 } });
    const blank = rec({ pageExcerpt: {} });
    expect(rules(pilotReport([...Array.from({ length: 8 }, () => rec()), withheld, withheld])).filter((m) => /90%/.test(m))).toEqual([]);
    expect(pilotReport([rec(), withheld]).evidence).toMatchObject({ twoxx: 2, twoxxWithExcerpt: 1, twoxxWithheld: 1 });
    expect(rules(pilotReport([...Array.from({ length: 8 }, () => rec()), blank, withheld]))).toContain("under 90% of 2xx responses have an excerpt");
  });

  it("the audit-quality rule, on the exact fraction", () => {
    const stratum = (eligible, withheld) => Array.from({ length: eligible }, (_, i) => ({ host: `h${i}.org`, status: "ok", evidence: { class: { label: "candidate-page" }, ...(i < withheld ? { textWithheld: { kinds: { email: 1 }, fields: 1 } } : {}) } }));
    for (const [eligible, withheld, over] of [[50, 1, false], [49, 1, true], [100, 2, false], [99, 2, true], [150, 3, false], [149, 3, true], [1000, 20, false], [1000, 21, true], [50000, 1000, false], [50000, 1001, true], [10, 0, false]]) {
      expect(overWithheldLimit(withheld, eligible), `${withheld} of ${eligible}`).toBe(over);
      expect(auditFrame(stratum(eligible, withheld)).notEstimable, `${withheld} of ${eligible}`).toBe(over);
    }
    // A small frame loses its own figures, and that alone doesn't decide the headline.
    expect(auditFrame(stratum(10, 0))).toMatchObject({ headline: "stands, on its frame", notEstimable: false });
    expect(auditFrame(stratum(10, 0)).labels.page).toMatchObject({ frame: 10, figures: false });
  });

  it("the score says the headline first, and keeps the frame's figures beside it", () => {
    const key = [1, 2, 3].map((id) => ({ id, stratum: "candidate-page", stratumSize: 3, ruleLabel: "page" }));
    const csv = "id,label\n1,page\n2,page\n3,page\n";
    const frame = auditFrame(Array.from({ length: 49 }, (_, i) => ({ host: `h${i}.org`, status: "ok", evidence: { class: { label: "candidate-page" }, ...(i ? {} : { textWithheld: { kinds: { email: 1 }, fields: 1 } }) } })));
    const scored = scoreLabels(key, csv, csv, { frame, resamples: 10 });
    expect(Object.keys(scored)[0]).toBe("headline");
    expect(scored).toMatchObject({ headline: "not estimable", kappaWorstCase: "no bound" });
    expect(scored.note).toMatch(/not the audit's result/);
    expect(scored.metrics.page.precision).toBe(1);
    expect(scored.frame.share).toBeCloseTo(1 / 49);
  });

  it("the audit frame says what's left", () => {
    const rec = (i, label, withheld) => ({ host: `h${i}.org`, status: "ok", evidence: { class: { label, rule: "x" }, ...(withheld ? { textWithheld: { kinds: { email: 1 }, fields: 1 } } : {}) } });
    const frame = auditFrame([...Array.from({ length: 100 }, (_, i) => rec(i, "candidate-page", i < 5)), ...Array.from({ length: 30 }, (_, i) => rec(200 + i, "challenge", i < 10)), ...Array.from({ length: 10 }, (_, i) => rec(300 + i, "unrecognized-error-response", false))]);
    expect(frame.scope).toBe("non-withheld records");
    expect(frame.strata["candidate-page"]).toMatchObject({ eligible: 100, frame: 95, withheld: 5, overLimit: true });
    expect(frame.strata.challenge).toMatchObject({ eligible: 30, frame: 20, withheld: 10, overLimit: true });
    expect(frame.strata["unrecognized-error-response"]).toMatchObject({ frame: 10, overLimit: false, drawn: 10, shortfall: 10 });
    expect(frame.labels).toMatchObject({ page: { frame: 95, figures: true }, error: { frame: 10, figures: false }, block: { frame: 0, figures: false } });
    expect(frame).toMatchObject({ headline: "not estimable", notEstimable: true, eligible: 140 });
    expect(frame.withheld).toBe(15);
    expect(frame.withheldByRule).toEqual({ page: 5, challenge: 10, block: 0, error: 0 });
  });

  it("worst-case bounds count every withheld row against the rule", () => {
    const rows = Array.from({ length: 10 }, (_, i) => ({ id: i, stratum: "candidate-page", stratumSize: 10, ruleLabel: "page", human: "page" }));
    const bounds = worstCaseBounds(rows, { page: 5, challenge: 5, block: 0, error: 0 });
    expect(bounds.page.precision).toBeCloseTo(10 / 15);
    expect(bounds.page.recall).toBeCloseTo(10 / 15);
    expect(weightedMetrics(rows, { resamples: 10 }).metrics.page.precision).toBe(1);
  });

  it("the legacy gate reads the findings, not the summary", () => {
    const orders = new Set([1, 2]);
    const good = { order: 1, path: "evidence.pageExcerpt.text", kind: "email", count: 1 };
    expect(legacyProblem({ findings: [good], reproducesStop: true }, orders)).toBeNull();
    const cases = [
      [[{ ...good, path: "evidence.values.server" }], true, /summary/],
      [[{ ...good, path: "evidence.values.server" }], false, /does not reproduce/],
      [[{ ...good, order: "1" }], true, /record/],
      [[{ ...good, order: 9 }], true, /record/],
      [[{ ...good, path: "nowhere.at.all" }], true, /unknown field/],
      [[{ ...good, kind: "shape" }], true, /unknown kind/],
      [[{ ...good, count: 0 }], true, /count/],
      [[{ ...good, count: -1 }], true, /count/],
      [[good, good], true, /twice/],
      [[], true, /summary/],
      [[good], false, /summary/],
      [undefined, true, /no list/],
    ];
    for (const [findings, reproducesStop, why] of cases) expect(legacyProblem({ findings, reproducesStop }, orders), JSON.stringify(findings)).toMatch(why);
  });

  it("a review refuses a report the raw file doesn't back, even a well-formed one", () => {
    const dir = stoppedRun();
    legacyFindings(dir);
    const file = join(dir, "legacy-findings.json");
    const report = JSON.parse(readFileSync(file, "utf8"));
    writeFileSync(file, JSON.stringify({ ...report, findings: [{ ...report.findings[0], count: 2 }] }));
    expect(() => privacyReport(dir, { falseFire: Buffer.from("checked"), reviewer: "a person" })).toThrow(/nothing to call a false fire/);
  });

  it("labels, grades and claims don't care that text was withheld", () => {
    const row = (i, cohort, passed) => ({ host: `h${i}.org`, finalHost: `h${i}.org`, status: "ok", cohorts: { [cohort]: { rank: 1 } }, checks: [{ id: "csp", passed, weight: 1 }], evidence: { class: { label: "candidate-page" } } });
    const plain = [...Array.from({ length: 25 }, (_, i) => row(i, "T1k", i < 5)), ...Array.from({ length: 25 }, (_, i) => row(100 + i, "YC-new", i < 15))];
    const marked = plain.map((r, i) => (i % 3 ? r : { ...r, evidence: { ...r.evidence, textWithheld: { kinds: { email: 1 }, fields: 1 } } }));
    expect(JSON.stringify(claims(marked, null, {}, { resamples: 50 }))).toBe(JSON.stringify(claims(plain, null, {}, { resamples: 50 })));
  });

  it("the audit's frame leaves withheld records out, and the strata still fill", () => {
    const rec = (i, withheld) => ({ host: `h${i}.org`, status: "ok", evidence: { class: { label: "candidate-page" }, ...(withheld ? { textWithheld: { kinds: { email: 1 } } } : {}) } });
    const rows = Array.from({ length: 400 }, (_, i) => rec(i, i % 5 === 0));
    const sample = drawSample(rows);
    expect(sample).toHaveLength(150);
    expect(sample.every((s) => Number(s.host.slice(1, -4)) % 5 !== 0)).toBe(true);
    expect(sample[0].stratumSize).toBe(320);
  });

  it("the price of strictness: prose that looks like a bracketed domain still fires", () => {
    for (const text of ["Look at (example.com). Open daily", 'Look at "example.com". Open daily']) expect(email(text), text).toBeGreaterThan(0);
  });

  it("the token list is the detector's own, and the scrub stays as strict", () => {
    for (const [dirty, clean] of [["sales [at] 3m.com", "<email>"], ["john at example .com", "<email>"], ["Reach us at info@example.com.", "Reach us at <email>."], ["(at) Wien", "<email>"]]) expect(scrub(dirty), dirty).toBe(clean);
  });

  it("common contact sentences come through the scrub with no false fire", () => {
    const corpus = [
      "Contact us at info@example.com.", "Email us at sales@example.co.uk, or call.", "Questions? Write to support@example.org!", "Reach our team (support@example.com).", "Mail: jan.de.vries@example.nl.",
      "Send your CV to jobs@example.com, we reply within a week.", "E-mail: info [at] example [dot] com.", "info (at) example (dot) com", "Contact john at example dot com for more.", "Write to us at info at example.com.",
      "You can reach us at privacy@example.com. We answer within 30 days.", "For press, contact press@example.com; for sales, sales@example.com.", "Call +31 20 123 4567 or email hello@example.nl.",
      '<a href="mailto:info@example.com">Email us</a>', "Email: <a href=mailto:a@b.co>a@b.co</a>.", "We are at home. Today we work.", "Our office is at 12 Main St. in London.", "Visit us at www.example.com.",
      "Find us at example.com, or on X.", "Meet us at booth 12. See you there.", "Support is at help.example.com. Open daily.", "at example.com", "Follow us at @example.", "Available at https://example.com/a?b=c#d.",
      "Reach us at info@example.com. Or at sales@example.com.", "Contact: info@example.com (sales), billing@example.com (billing).", "Mail ons op info@voorbeeld.nl.", "Schrijf naar info (at) voorbeeld.nl.",
      "Kontakt: info[at]beispiel.de.", "contact [at] example.fr", "Écrivez-nous à contact@exemple.fr.", "Our server 192.0.2.10 is at capacity.", "Your IP is 203.0.113.7.", "Order 123456789012 shipped.",
      "Open at 9. Closed at 5.", "Look at this. Then look at that.", "Our rate is at 4.5 percent.", "Reach us at: info@example.com.", "Contact at info@example.com, sales at sales@example.com.", "Reach us at INFO@EXAMPLE.COM.",
      "Read more at https://example.com.", "Docs at http://docs.example.com/guide.html.", "Available at ftp://example.com/a.zip.", "Starts at 9.30 a.m. sharp.", "Priced at $4.99. Buy now.",
      "Located at No. 5 High St.", "Arrives at 10 a.m. today.", "Sold at Amazon.com and eBay.", "Look at Node.js today.", "Built at Acme Inc. in 2020.", "Treated at St. Mary's Hospital.", "Download it at report.pdf.",
      "We're at it. Again.", "Stay at home. Stay safe.", "Sign in at app.example.com/login.", "At Example.com we care.", "Good at Python. Good at Rust.", "Get it at the App Store. Free.",
      "He is at work . Back soon.", "Mail to: a.b@c.de (a.b@c.de)", "Support: help@example.com | Sales: sales@example.com | Press: press@example.com",
    ];
    for (const text of corpus) {
      const stored = scrub(text);
      expect(scrubMisses(stored), `${text} -> ${stored}`).toEqual({ ipv4: 0, ipv6: 0, email: 0, query: 0, fragment: 0, jwt: 0, longHex: 0, longNumber: 0 });
    }
  });

  it("replay counts misses in a raw file and prints no text, field or site", () => {
    const dir = folder();
    const file = join(dir, "raw.jsonl");
    writeFileSync(file, [{ host: "a.org", evidence: { pageExcerpt: { text: "Reach us at <email>. Thanks." } } }, { host: "b.org", evidence: { values: { server: "jan@example.nl" } } }].map((r) => JSON.stringify(r)).join("\n") + "\n");
    expect(replayRaw(file)).toMatchObject({ records: 2, flagged: 1 });
    expect(replayRaw(file).scrubMisses.email).toBeGreaterThan(0);
    const printed = [];
    expect(reportMain(["--replay", file], { log: (m) => printed.push(m) })).toBe(1);
    expect(printed.join()).not.toMatch(/a\.org|b\.org|jan@|server/);
  });

  const stoppedRun = (text = "Reach us at <email>. Open daily") => {
    const dir = folder();
    const raw = `${JSON.stringify({ pass: 2, order: 7, host: "a.org", status: "ok", evidence: { pageExcerpt: { text } } })}\n`;
    writeFileSync(join(dir, "raw.jsonl"), raw);
    writeFileSync(join(dir, "manifest.json"), JSON.stringify({ kind: "pass", pass: 2, finishedAt: "x", partial: true, stoppedFor: PRIVACY_STOP, records: 1, rawSha256: createHash("sha256").update(raw).digest("hex") }));
    return dir;
  };

  it("the frozen detector is kept under its hash, reproduces the stop, and reports place and no text", () => {
    expect(createHash("sha256").update(readFileSync(join(import.meta.dirname, "..", "bench", "front-door", "legacy", "classify-7023106f.mjs"))).digest("hex")).toBe(LEGACY_CLASSIFIER_SHA256);
    expect(recordedHashR(readFileSync(PREREG_R, "utf8"), "Legacy classifier")).toBe(LEGACY_CLASSIFIER_SHA256);
    const dir = stoppedRun();
    const report = legacyFindings(dir);
    expect(report).toMatchObject({ records: 1, reproducesStop: true, legacyDetectorSha256: LEGACY_CLASSIFIER_SHA256 });
    expect(report.findings).toEqual([{ order: 7, path: "evidence.pageExcerpt.text", kind: "email", count: 1 }]);
    expect(readFileSync(join(dir, "legacy-findings.json"), "utf8")).not.toMatch(/Reach|Open daily|a\.org/);
    const printed = [];
    expect(reportMain(["--legacy-findings", dir], { log: (m) => printed.push(m) })).toBe(0);
    expect(printed.join()).not.toMatch(/evidence|a\.org/);
  });

  it("the old trigger needs the period and a word after it, and the new detector is quiet on it", () => {
    const dir = stoppedRun("Reach us at <email>.");
    expect(legacyFindings(dir).findings).toEqual([]);
    expect(reportMain(["--legacy-findings", dir], { log: () => undefined })).toBe(1);
    expect(email("Reach us at <email>. Open daily")).toBe(0);
  });

  it("a legacy report needs the original raw file", () => {
    const dir = stoppedRun();
    writeFileSync(join(dir, "raw.jsonl"), "{}\n");
    expect(() => legacyFindings(dir)).toThrow(/original raw file/);
  });

  it("a clean scan can't be a false fire without a legacy finding for this run", () => {
    const dir = stoppedRun("Nothing here.");
    expect(() => privacyReport(dir, { falseFire: Buffer.from("checked"), reviewer: "a person" })).toThrow(/nothing to call a false fire/);
    legacyFindings(dir);
    expect(() => privacyReport(dir, { falseFire: Buffer.from("checked"), reviewer: "a person" })).toThrow(/nothing to call a false fire/);
    const found = stoppedRun();
    legacyFindings(found);
    const bytes = readFileSync(join(found, "legacy-findings.json"));
    const report = privacyReport(found, { falseFire: Buffer.from("checked"), reviewer: "a person" });
    expect(report.clean).toBe(true);
    expect(report.reviewed.legacyFindingsSha256).toBe(createHash("sha256").update(bytes).digest("hex"));
    expect(falseFireReviewed(found)).toBe(true);
  });

  it("prune refuses a privacy stop before the review, even when the new detector is clean", () => {
    const dir = stoppedRun();
    expect(() => prunePilot(dir)).toThrow(/before any prune/);
    legacyFindings(dir);
    privacyReport(dir, { falseFire: Buffer.from("checked"), reviewer: "a person" });
    expect(prunePilot(dir).verified).toBe(true);
  });

  it("a site keeps the first reason it was skipped", () => {
    const merged = mergeSkips(new Map([["a.org", "stopped-pass"], ["b.org", "stopped-pass"]]), new Map([["a.org", "opted-out-earlier"]]), new Map([["c.org", "pilot"]]));
    expect(Object.fromEntries(merged)).toEqual({ "a.org": "opted-out-earlier", "b.org": "stopped-pass", "c.org": "pilot" });
  });

  it("skipped sites are reported per cohort and reason", () => {
    const skipped = (cohort, category) => ({ reason: "exclusion_list", category, cohorts: { [cohort]: {} } });
    expect(skipsByCohort([skipped("T1k", "stopped-pass"), skipped("T1k", "pilot"), skipped("YC-new", "pilot"), { status: "ok", cohorts: { T1k: {} } }])).toEqual({ T1k: { "stopped-pass": 1, pilot: 1 }, "YC-new": { pilot: 1 } });
  });

  it("pass 3 needs its own amendment, in both places", () => {
    expect(amendment3Adopted("| Amendment 3 | **Adopted.** x |\n## Amendment 3\n**Status: adopted.** x\n")).toBe(true);
    expect(amendment3Adopted("| Amendment 3 | **Draft.** x |\n## Amendment 3\n**Status: adopted.** x\n")).toBe(false);
    expect(amendment3Adopted("| Amendment 3 | **Adopted.** x |\n**Status: adopted.** x\n## Amendment 3\n**Status: draft.** x\n")).toBe(false);
    expect(amendment3Adopted("| Amendment 3 | **Adopted.** x |\n\n## Amendment 3\n\n**Status: draft.** x\n\n## Amendment 4\n\n**Status: adopted.** x\n")).toBe(false);
    expect(amendment3Adopted("| Amendment 3 | **Adopted.** x |\n\n## Amendment 3\n\n**Status: adopted.** x\n\n## Amendment 4\n\n**Status: draft.** x\n")).toBe(true);
    expect(amendment3Adopted(readFileSync(PREREG_R, "utf8"))).toBe(false);
    expect(PASS_SEED[3]).toBe(PASS_SEED[2]);
  });

  it("the page and the run sheet say what happened", () => {
    expect(readFileSync(STUDY_PAGE, "utf8")).toContain("each site is visited once in the run itself");
    const sheet = readFileSync(join(import.meta.dirname, "..", "bench", "front-door", "run-sheet.md"), "utf8");
    for (const step of ["--pass 3", "--replay", "--legacy-findings", "--false-fire ~/study/false-fire-note.txt --reviewer <who>", "export RUN=$R/e20r-pass3", "--privacy $RUN", "draw $RUN", "prune $RUN", "purge $RUN", "--pass1 <private run folder>/raw.jsonl", "~/study/lists", "rsync"]) expect(sheet).toContain(step);
  });
});
