/**
 * E20-R (bench/front-door/replicate.mjs, classify.mjs, analyze-r.mjs): the
 * guard, the response classifier, the fixed order, and the analysis on
 * synthetic records. Loopback only; nothing leaves the machine.
 */
import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classify, classifyRegistered, cookieNames, evidenceOf, pageExcerpt, scrub, scrubAddresses, scrubMisses, traitsOf, EXCERPT_BYTES, PAGE_TEXT_CHARS, SOFT_MAX_CHARS } from "../bench/front-door/classify.mjs";
import { authorizeR, checkPilotDropped, CLAIM_COHORTS, CLASSIFIER, dmarcTags, dnsOutcome, gitState, mergeCohorts, pilotRounds, pilotSample, readDomain, readRemovals, recordedHashR, runManifest, runPass, siteDns, shuffled, seeded, dnsProviders, selfTestR, sourceAddressCount, aggregateR, R_COHORTS, ipv4Lookup, PASS_SEED, PREREG_R, REMOTE_URL, sourceAddressOf, V2_LIMITS } from "../bench/front-door/replicate.mjs";
import { robotsAccess, strictRobots, visit, LIMITS } from "../bench/front-door/run.mjs";
import { CheckError, fetchBody, parseTarget } from "../api/_lib/guard.mjs";
import { createServer as createTlsServer } from "node:tls";
import { selfSignedCert } from "./fixtures/tls/cert.js";
import { pilotReport } from "../bench/front-door/pilot-report.mjs";
import { pslSha256, PSL_VERSION } from "../bench/front-door/psl.mjs";
import { kappa, decide, combine, clusterDiff, pass, claims, dnsClaims, primaryRefusal, refusalShares, traitTable, replicationAsE20, industryTable, CLAIMS_R, LEVEL } from "../bench/front-door/analyze-r.mjs";

const tmp = () => mkdtempSync(join(tmpdir(), "e20r-"));
const HASH = "a".repeat(64);
const IP = "178.104.243.225";
const PRIOR = Buffer.from("old.example.com\n");
const priorHash = createHash("sha256").update(PRIOR).digest("hex");
const prereg = (status = "**Registered.** Accepted", amendment = "**Adopted.** Merged", own = "adopted") => `| Status | ${status} |\n| Amendment 2 | ${amendment} |\n| Source address | \`${IP}\` |\n| Frozen classifier SHA-256 | \`${HASH}\` |\n| Public Suffix List SHA-256 | \`${HASH}\` |\n| Prior opt-outs SHA-256 | \`${priorHash}\` |\n` + Object.keys(R_COHORTS).map((c) => `| ${c} list SHA-256 | \`${HASH}\` |`).join("\n") + `\n| E20-R exclusion list SHA-256 | \`${HASH}\` |\n| E20-R homepage-only list SHA-256 | \`${HASH}\` |\n\n## Amendment 2\n\n**Status: ${own}.** Text.\n`;
const allHashes = Object.fromEntries(Object.keys(R_COHORTS).map((c) => [c, HASH]));
const good = { registered: "E20R", pass: 2, listHashes: allHashes, excludeHash: HASH, homepageOnlyHash: HASH, preregText: prereg(), pageText: `A study page, from ${IP}.`, tree: { commit: "c".repeat(40), dirty: false, hidden: false, remoteTip: "c".repeat(40) }, sourceIps: [IP], removals: "", priorOptOuts: PRIOR, pilot: { ok: true }, classifierHash: HASH, pslHash: HASH };
const noDns = () => Promise.reject(Object.assign(new Error("x"), { code: "ENODATA" }));
const stubDns = { mx: noDns, ns: noDns, resolveTxt: noDns, resolveCaa: noDns };

describe("E20-R guard", () => {
  it("allows loopback, and a registered pass whose hashes all match", () => {
    expect(authorizeR({ loopback: true }).mode).toBe("loopback");
    expect(authorizeR(good).mode).toBe("registered");
  });
  it("refuses without --registered E20R, or with another study's flag", () => {
    expect(() => authorizeR({ ...good, registered: undefined })).toThrow(/Refused/);
    expect(() => authorizeR({ ...good, registered: "E20" })).toThrow(/Refused/);
  });
  it("needs Amendment 2 adopted, for the pilot as well", () => {
    expect(authorizeR({ ...good, pass: "pilot" }).mode).toBe("registered");
    expect(() => authorizeR({ ...good, preregText: prereg(undefined, "**Draft.** Not adopted") })).toThrow(/Amendment 2/);
    expect(() => authorizeR({ ...good, pass: "pilot", preregText: prereg(undefined, "**Draft.** Not adopted") })).toThrow(/Amendment 2/);
  });
  it("the repository's Amendment 2 still blocks any run until the maintainer adopts it, or names an address", () => {
    const text = readFileSync(PREREG_R, "utf8");
    const adopted = /^\|\s*Amendment 2\s*\|\s*\*\*Adopted\./m.test(text);
    if (adopted) expect(text).not.toContain("<NEW-SOURCE-ADDRESS>");
    else expect(() => authorizeR({ ...good, preregText: text })).toThrow(/Amendment 2/);
  });
  it("refuses pass 1, which already ran", () => {
    expect(() => authorizeR({ ...good, pass: 1 })).toThrow(/pass 1 ran/);
  });
  it("refuses a dirty tree, a directory with no commit, and a run without a removal list", () => {
    expect(() => authorizeR({ ...good, tree: { ...good.tree, dirty: true } })).toThrow(/dirty/);
    expect(() => authorizeR({ ...good, tree: { commit: null, dirty: null } })).toThrow(/git checkout/);
    expect(() => authorizeR({ ...good, removals: undefined })).toThrow(/--removals/);
  });
  it("B5: refuses a placeholder, a wrong or second address, and a commit off main", () => {
    expect(() => authorizeR({ ...good, preregText: `${prereg()}\n<NEW-SOURCE-ADDRESS>` })).toThrow(/placeholder/);
    expect(() => authorizeR({ ...good, pageText: "from <PROVIDER-NOTICE: x>" })).toThrow(/placeholder/);
    expect(() => authorizeR({ ...good, sourceIps: ["2.31.141.178"] })).toThrow(/exactly one public IPv4/);
    expect(() => authorizeR({ ...good, sourceIps: [IP, "8.8.8.8"] })).toThrow(/exactly one public IPv4/);
    expect(() => authorizeR({ ...good, sourceIps: [] })).toThrow(/exactly one public IPv4/);
  });
  it("B5: needs the commit to be the remote tip, asked now, and no hidden file", () => {
    expect(() => authorizeR({ ...good, tree: { ...good.tree, remoteTip: "d".repeat(40) } })).toThrow(/tip of origin main/);
    expect(() => authorizeR({ ...good, tree: { ...good.tree, remoteTip: null } })).toThrow(/could not read/);
    expect(() => authorizeR({ ...good, tree: { ...good.tree, hidden: true } })).toThrow(/assume-unchanged/);
  });
  it("12: binds the page to the address, and reads the amendment's own status", () => {
    expect(() => authorizeR({ ...good, pageText: "A study page, from 9.9.9.9." })).toThrow(/does not name the registered address/);
    expect(() => authorizeR({ ...good, preregText: prereg(undefined, undefined, "draft") })).toThrow(/own status line/);
  });
  it("B6: needs --prior-optouts for pass 2 and the pilot, and the pilot list for pass 2", () => {
    expect(() => authorizeR({ ...good, priorOptOuts: undefined })).toThrow(/--prior-optouts/);
    expect(() => authorizeR({ ...good, pass: "pilot", priorOptOuts: undefined })).toThrow(/--prior-optouts/);
    expect(() => authorizeR({ ...good, pilot: { ok: false, why: "No pilot manifest found." } })).toThrow(/No pilot manifest/);
    expect(() => authorizeR({ ...good, pilot: undefined })).toThrow(/passed pilot/);
    expect(authorizeR({ ...good, pass: "pilot", pilot: undefined }).mode).toBe("registered");
  });
  it("B7: an empty or edited prior opt-out list is refused", () => {
    expect(() => authorizeR({ ...good, priorOptOuts: Buffer.alloc(0) })).toThrow(/frozen hash/);
    expect(() => authorizeR({ ...good, priorOptOuts: Buffer.from("other.example.com\n") })).toThrow(/frozen hash/);
  });
  it("B7: the dropped file must hold exactly the pilot's sites, checked against its manifest", () => {
    const dir = tmp();
    const list = "a.example.com\nb.example.com\n";
    const round = join(dir, "e20r-pilot-1");
    mkdirSync(round);
    writeFileSync(join(round, "pilot-sites.txt"), list);
    writeFileSync(join(round, "manifest.json"), JSON.stringify({ finishedAt: "x", pilotSitesSha256: createHash("sha256").update(list).digest("hex") }));
    const rounds = pilotRounds(dir);
    expect(checkPilotDropped(readRemovals(list, "pilot"), rounds).ok).toBe(true);
    expect(checkPilotDropped(readRemovals("a.example.com\n", "pilot"), rounds).ok).toBe(false);
    expect(checkPilotDropped(readRemovals("x.example.com\ny.example.com\n", "pilot"), rounds).ok).toBe(false);
    expect(checkPilotDropped(new Map(), []).ok).toBe(false);
    expect(checkPilotDropped(new Map(), [], { need: false }).ok).toBe(true);
    writeFileSync(join(round, "pilot-sites.txt"), "c.example.com\n");
    expect(checkPilotDropped(readRemovals("c.example.com\n", "pilot"), pilotRounds(dir)).ok).toBe(false);
  });
  it("refuses a classifier or suffix list that is not the frozen one", () => {
    expect(() => authorizeR({ ...good, classifierHash: "b".repeat(64) })).toThrow(/frozen classifier/);
    expect(() => authorizeR({ ...good, pslHash: "b".repeat(64) })).toThrow(/Public Suffix List/);
  });
  it("records the live classifier, list and address in the protocol", () => {
    const text = readFileSync(PREREG_R, "utf8");
    expect(recordedHashR(text, "Frozen classifier")).toBe(createHash("sha256").update(readFileSync(CLASSIFIER)).digest("hex"));
    expect(recordedHashR(text, "Public Suffix List")).toBe(pslSha256());
    expect(recordedHashR(text, "Prior opt-outs")).toMatch(/^[0-9a-f]{64}$/);
    expect(sourceAddressOf(text)).toBe("178.104.243.225");
  });
  it("refuses a draft protocol, a third pass, a changed list or exclusion list", () => {
    expect(() => authorizeR({ ...good, preregText: prereg("**Draft**") })).toThrow(/not Registered/);
    expect(() => authorizeR({ ...good, pass: 3 })).toThrow(/--pass/);
    expect(() => authorizeR({ ...good, listHashes: { ...allHashes, Europe: "b".repeat(64) } })).toThrow(/Europe list/);
    expect(() => authorizeR({ ...good, excludeHash: "b".repeat(64) })).toThrow(/exclusion/);
    expect(() => authorizeR({ ...good, homepageOnlyHash: "b".repeat(64) })).toThrow(/homepage-only/);
  });
  it("records a hash for every list in the protocol", () => {
    const text = readFileSync(PREREG_R, "utf8");
    for (const c of Object.keys(R_COHORTS)) expect(recordedHashR(text, `${c} list`)).toMatch(/^[0-9a-f]{64}$/);
    expect(recordedHashR(text, "E20-R exclusion list")).toMatch(/^[0-9a-f]{64}$/);
    expect(recordedHashR(text, "E20-R homepage-only list")).toMatch(/^[0-9a-f]{64}$/);
  });
  it("resolves IPv4 only", async () => {
    const answers = await ipv4Lookup("localhost", { all: true });
    expect(answers.every((a) => a.family === 4)).toBe(true);
  });
});

describe("E20-R classifier", () => {
  it("trusts a header marker before the status code", () => {
    expect(classify({ status: 200, headers: { "CF-Mitigated": "challenge" } })).toMatchObject({ label: "challenge", vendor: "cloudflare", rule: "header:cf-mitigated" });
    expect(classify({ status: 202, headers: { "x-amzn-waf-action": "captcha" } }).label).toBe("challenge");
    expect(classify({ status: 403, headers: { "x-vercel-mitigated": "challenge" } }).vendor).toBe("vercel");
  });
  it("finds a challenge in a 2xx body, the gap in E20's status filter", () => {
    expect(classify({ status: 200, body: "<title>Just a moment...</title>" }).label).toBe("challenge");
    expect(classify({ status: 403, body: '<script src="https://geo.captcha-delivery.com/x"></script>' }).vendor).toBe("datadome");
  });
  it("separates a block from an origin error and a page", () => {
    expect(classify({ status: 403, body: "Sorry, you have been blocked" })).toMatchObject({ label: "block", vendor: "cloudflare" });
    expect(classify({ status: 403, body: "<H1>Access Denied</H1>" })).toMatchObject({ label: "block", vendor: "akamai" });
    expect(classify({ status: 404, body: "not here" }).label).toBe("unrecognized-error-response");
    expect(classify({ status: 200, body: "<h1>Welcome</h1>" }).label).toBe("candidate-page");
  });
  it("calls a Cloudflare text error a block, but not its DNS error, and not without Cloudflare", () => {
    const cf = { "cf-ray": "x", server: "cloudflare" };
    expect(classify({ status: 403, headers: cf, body: "error code: 1010" })).toMatchObject({ label: "block", vendor: "cloudflare", rule: "cloudflare:1010" });
    for (const code of ["1001", "1016", "1033", "1101"]) expect(classify({ status: 530, headers: cf, body: `error code: ${code}` }).label).toBe("unrecognized-error-response");
    expect(classify({ status: 500, headers: {}, body: "error code: 1010" }).label).toBe("unrecognized-error-response");
  });
  it("does not call a normal page with a bot-detection script a challenge", () => {
    const big = "<p>content</p>".repeat(1000);
    for (const script of ['<script src="/cdn-cgi/challenge-platform/h/b/scripts/jsd/main.js"></script>', '<script src="/_Incapsula_Resource?SWJIYLWA=x"></script>', '<script src="https://ct.captcha-delivery.com/c.js"></script>', "<script>AwsWafIntegration.getToken()</script>"]) {
      expect(classify({ status: 200, body: big + script }).label).toBe("candidate-page");
      expect(classify({ status: 200, body: script }).label).toBe("challenge");
      expect(classify({ status: 403, body: big + script })).toMatchObject({ label: "challenge", rule: "soft-body" });
      expect(classifyRegistered({ status: 200, body: big + script }).label).toBe("challenge");
    }
  });
  it("keeps the interstitial signatures on any size of page", () => {
    const pad = "x".repeat(SOFT_MAX_CHARS * 2);
    expect(classify({ status: 200, body: `<title>Just a moment...</title>${pad}` }).label).toBe("challenge");
    expect(classify({ status: 403, body: `<title>DDoS-Guard</title>${pad}` })).toMatchObject({ label: "challenge", vendor: "ddos-guard" });
  });
  it("calls Cloudflare's block page a block, though it carries the challenge script", () => {
    const body = 'Sorry, you have been blocked<script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>';
    expect(classify({ status: 403, body })).toMatchObject({ label: "block", vendor: "cloudflare" });
    expect(classifyRegistered({ status: 403, body }).label).toBe("challenge");
  });
  it("separates CloudFront's refusal from its error pages", () => {
    const page = (line) => `<H1>403 ERROR</H1><H2>The request could not be satisfied.</H2>${line} Generated by cloudfront (CloudFront)`;
    expect(classify({ status: 403, body: page("Request blocked.") })).toMatchObject({ label: "block", vendor: "cloudfront" });
    expect(classify({ status: 403, body: page("The Amazon CloudFront distribution is configured to block access from your country.") }).label).toBe("block");
    expect(classify({ status: 403, body: page("Bad request.") })).toMatchObject({ label: "unrecognized-error-response", rule: "cloudfront:error" });
    expect(classify({ status: 502, body: page("") }).label).toBe("unrecognized-error-response");
  });
  it("marks a bare 403 and an empty refusal at the edge, so a view can drop them", () => {
    expect(classify({ status: 403, headers: { server: "nginx" }, body: "<h1>403 Forbidden</h1>" })).toMatchObject({ label: "block", vendor: null, rule: "unrecognized-403" });
    expect(classify({ status: 429, headers: { "cf-ray": "x" }, body: " " })).toMatchObject({ label: "block", vendor: "cloudflare", rule: "empty-at-edge" });
    expect(classify({ status: 429, headers: {}, body: "" }).label).toBe("unrecognized-error-response");
  });
  it("leaves pass 1's rules as they were", () => {
    expect(classifyRegistered({ status: 403, headers: { "cf-ray": "x" }, body: "error code: 1010" }).label).toBe("origin-error");
    expect(classifyRegistered({ status: 403, body: "The request could not be satisfied" }).label).toBe("block");
    expect(classifyRegistered({ status: 403, body: "<h1>403 Forbidden</h1>" }).label).toBe("origin-error");
  });
  it("keeps cookie names, never values", () => {
    expect(cookieNames({ "set-cookie": ["__cf_bm=SECRET; Path=/", "sid=abc"] })).toEqual(["__cf_bm", "sid"]);
    expect(JSON.stringify(evidenceOf({ status: 200, headers: { "set-cookie": ["sid=SECRET"] }, body: "x" }))).not.toContain("SECRET");
  });
  it("keeps a short visible excerpt of a 2xx page, with no markup or scripts", () => {
    const body = `<html><head><title>Acme</title><script>var secret = 1;</script></head><body><!-- note --><p>Welcome ${"word ".repeat(600)}</p><script src="/a.js"></script></body></html>`;
    const e = evidenceOf({ status: 200, headers: {}, body });
    expect(e.excerpt).toBeUndefined();
    expect(e.pageExcerpt).toMatchObject({ title: "Acme", chars: body.length, scripts: 2, forms: 0, metaRefresh: false });
    expect(e.pageExcerpt.text.startsWith("Welcome")).toBe(true);
    expect(e.pageExcerpt.text.length).toBeLessThanOrEqual(PAGE_TEXT_CHARS);
    expect(JSON.stringify(e)).not.toMatch(/secret|note|<p>|a\.js/);
    expect(pageExcerpt('<script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>').soft).toEqual(["cloudflare"]);
  });
  it("scrubs addresses, emails, query strings and long numbers before anything is stored", () => {
    const dirty = "Your IP: 203.0.113.7 or 2a01:4f8:c016:1e90::1, mail ops@example.com, see https://a.example/x?token=SECRET&b=2 or /r?__cf_chl_tk=abc, call +31 6 1234 5678";
    const clean = scrub(dirty);
    expect(clean).not.toMatch(/203\.0|2a01|ops@|SECRET|__cf_chl|1234/);
    expect(clean).toContain("https://a.example/x?<query>");
    expect(Object.values(scrubMisses(clean)).every((v) => v === 0)).toBe(true);
    expect(scrubMisses(dirty)).toMatchObject({ ipv4: 1, ipv6: 1, email: 1 });
    expect(scrubAddresses("::ffff:192.0.2.1 and ::1")).not.toMatch(/192|::1/);
    expect(scrubAddresses("nginx/1.25.3 at 12:30")).toBe("nginx/1.25.3 at 12:30");
  });
  it("scrubs an address from a stored header value and an error page", () => {
    const e = evidenceOf({ status: 403, headers: { via: "1.1 198.51.100.4" }, body: "Your IP: 198.51.100.4" });
    expect(JSON.stringify(e)).not.toContain("198.51.100.4");
  });
  it("stores both labels", () => {
    const e = evidenceOf({ status: 403, headers: { "cf-ray": "x" }, body: "error code: 1010" });
    expect(e.class.label).toBe("block");
    expect(e.classRegistered.label).toBe("origin-error");
  });
  it("caps other bodies with emails redacted", () => {
    const denied = evidenceOf({ status: 403, headers: {}, body: `mail ops@example.com ${"x".repeat(9000)}` });
    expect(denied.excerpt.length).toBeLessThanOrEqual(EXCERPT_BYTES);
    expect(denied.excerpt).not.toContain("ops@example.com");
  });
  it("keeps header names and a hash for robots.txt and security.txt, and the body only outside 2xx", () => {
    const e = evidenceOf({ status: 200, headers: {}, body: "" }, [
      { kind: "robots", res: { status: 200, headers: { "strict-transport-security": "max-age=1" }, body: "User-agent: *" } },
      { kind: "security.txt", res: { status: 403, headers: {}, body: "denied from 203.0.113.9" } },
    ]);
    expect(e.others[0]).toMatchObject({ kind: "robots", headerNames: ["strict-transport-security"] });
    expect(e.others[0].bodySha256).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(e.others[0])).not.toContain("User-agent");
    expect(e.others[1].excerpt).toBe("denied from <ip>");
  });
});

describe("E20-R site traits", () => {
  it("reads a login link, a payment provider and a shop from the page", () => {
    expect(traitsOf('<a href="/x"><span>Log in</span></a>').login).toBe(true);
    expect(traitsOf('<a href="/x">Inloggen</a>').login).toBe(true);
    expect(traitsOf('<script src="https://js.stripe.com/v3/"></script>').payments).toBe(true);
    expect(traitsOf('<link href="https://cdn.shopify.com/s/a.css">').shop).toBe(true);
    expect(traitsOf('<a href="https://trust.example.com">Trust</a>').securityPage).toBe(true);
    expect(traitsOf('<a class="x" href="/security">Security</a>').securityPage).toBe(true);
    expect(traitsOf("<p>A blog about login pages</p>")).toEqual({ login: false, payments: false, shop: false, securityPage: false });
  });
  it("treats a page with no HTML as unknown, not as no", () => {
    expect(traitsOf("")).toBeNull();
    expect(evidenceOf({ status: 403, headers: {}, body: "x", html: "" }).traits).toBeNull();
  });
  it("suppresses a trait group under twenty sites", () => {
    const rows = Array.from({ length: 25 }, (_, i) => ({ checks: [{ id: "csp", passed: i % 2 === 0, weight: 14 }], evidence: { traits: { login: true, payments: i < 3, shop: false } } }));
    const t = traitTable(rows, ["csp"]);
    expect(t.login.sites).toBe(25);
    expect(t.payments).toEqual({ sites: 3, suppressed: true });
  });
});

describe("E20-R order and cohorts", () => {
  const rows = ["c.com", "a.com", "b.com", "d.com", "e.com"].map((host) => ({ host }));
  it("gives the same order for the same seed, whatever the file order", () => {
    expect(shuffled(rows, 2020)).toEqual(shuffled([...rows].reverse(), 2020));
    expect(shuffled(rows, 2020).map((r) => r.host)).not.toEqual(shuffled(rows, 2021).map((r) => r.host));
  });
  it("is a reproducible generator in [0, 1)", () => {
    const a = seeded(1), b = seeded(1);
    for (let i = 0; i < 100; i++) { const v = a(); expect(v).toBe(b()); expect(v).toBeGreaterThanOrEqual(0); expect(v).toBeLessThan(1); }
  });
  it("visits a host on two lists once and counts it in both", () => {
    const merged = mergeCohorts({ T1k: [{ host: "x.com", rank: 1, group: "com" }], Europe: [{ host: "x.com", rank: 9, group: "DAX" }, { host: "y.de", rank: 2, group: "DAX" }] });
    expect(merged).toHaveLength(2);
    expect(Object.keys(merged[0].cohorts)).toEqual(["T1k", "Europe"]);
  });
  it("treats example.com and www.example.com as one site", () => {
    const merged = mergeCohorts({ T1k: [{ host: "example.com", rank: 1, group: "com" }], "YC-new": [{ host: "www.example.com", rank: 2, group: "Fall 2026" }] });
    expect(merged).toHaveLength(1);
    expect(Object.keys(merged[0].cohorts)).toEqual(["T1k", "YC-new"]);
  });
  it("labels MX and NS providers without keeping the hostnames", async () => {
    const p = await dnsProviders("example.com", { mx: async () => [{ exchange: "aspmx.l.google.com." }], ns: async () => ["a.ns.cloudflare.com."] });
    expect(p).toEqual({ mx: "google", ns: "cloudflare" });
    const none = Object.assign(new Error("x"), { code: "ENODATA" }), bad = Object.assign(new Error("x"), { code: "ETIMEOUT" });
    expect(await dnsProviders("example.com", { mx: () => Promise.reject(none), ns: () => Promise.reject(bad) })).toEqual({ mx: "none", ns: "unknown" });
  });
  it("runs a loopback pass, once per host, with no site in the aggregate", async () => {
    const r = await selfTestR({ out: tmp() });
    expect(r.problems).toEqual([]);
    expect(Object.keys(r.aggregate.cohorts).sort()).toEqual(["T1k", "YC-new"]);
    expect(r.aggregate.cohorts.T1k.labels).toBeDefined();
  });
  it("never follows an app page on a homepage-only list, also for a host on two lists", () => {
    expect(R_COHORTS["NL-Cbw"].homepageOnly).toBe(true);
    expect(R_COHORTS.T1k.homepageOnly).toBeUndefined();
  });
  it("never requests an app page in a pass", async () => {
    const { createServer } = await import("node:http");
    const hits = [];
    const server = createServer((req, res) => { hits.push(req.url); res.setHeader("content-type", "text/html"); res.end('<a href="/login">Log in</a>'); });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    const stub = () => Promise.reject(Object.assign(new Error("x"), { code: "ENODATA" }));
    try {
      const rows = mergeCohorts({ "NL-Cbw": [{ host: "a.nl-selftest.example.com", rank: 1, group: "Energy" }], T1k: [{ host: "a.nl-selftest.example.com", rank: 2, group: "com" }, { host: "b.selftest.example.com", rank: 3, group: "com" }] });
      await runPass(rows, { pass: 2, out: tmp(), loopbackPort: server.address().port, delayMs: 0, dns: { mx: stub, ns: stub } });
      expect(hits.filter((u) => u === "/")).toHaveLength(2);
      expect(hits).not.toContain("/login");
      hits.length = 0;
      await runPass(mergeCohorts({ T1k: [{ host: "www.clinic.selftest.example.com", rank: 1, group: "com" }] }), { pass: 2, out: tmp(), loopbackPort: server.address().port, delayMs: 0, dns: { mx: stub, ns: stub } });
      expect(hits).not.toContain("/login");
    } finally {
      await new Promise((r) => server.close(r));
    }
  });
  it("never visits a site whose owner asked to be removed", async () => {
    const stub = () => Promise.reject(Object.assign(new Error("x"), { code: "ENODATA" }));
    const removals = readRemovals("# asked by email\nExample.COM\n\n");
    expect(removals.get("example.com")).toBe("removed");
    const rows = mergeCohorts({ T1k: [{ host: "www.example.com", rank: 1, group: "com" }] });
    const { records, aggregate: agg } = await runPass(rows, { pass: 2, out: tmp(), loopbackPort: 9, delayMs: 0, exclude: removals, dns: { mx: stub, ns: stub } });
    expect(records[0]).toMatchObject({ status: "excluded", reason: "exclusion_list", category: "removed" });
    expect(agg.cohorts.T1k.exclusionCategories.removed).toBe(1);
  });
  it("folds small provider groups into other", () => {
    const records = Array.from({ length: 21 }, (_, i) => ({ host: `s${i}.example`, status: "ok", score: 50, checks: [], cohorts: { T1k: { rank: i, group: "example" } }, dnsProviders: { mx: i === 0 ? "rare" : "google", ns: "other" } }));
    const a = aggregateR(records);
    expect(a.cohorts.T1k.mailProviders.google).toBe(20);
    expect(a.cohorts.T1k.mailProviders.rare).toBeUndefined();
    expect(a.cohorts.T1k.mailProviders.other).toBe(1);
  });
});

describe("E20-R robots rules", () => {
  // One server, routes per Host header. Every name resolves to 127.0.0.1.
  async function site(routes) {
    const hits = [];
    const server = createServer((req, res) => {
      const host = req.headers.host.split(":")[0];
      hits.push(`${host}${req.url}`);
      const r = routes(host, req.url) ?? { status: 404, body: "" };
      res.writeHead(r.status, { "content-type": "text/html", ...r.headers });
      res.end(r.body ?? "");
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    return { hits, port: server.address().port, close: () => new Promise((r) => server.close(r)) };
  }
  const row = (host) => ({ host, rank: 1, group: "com" });
  const go = (s, host, opts = {}) => visit(row(host), { loopbackPort: s.port, strict: true, ...opts });

  it("follows RFC 9309: 4xx means no rules; 5xx, 429 and no answer mean stop", () => {
    expect(robotsAccess({ status: 200 })).toBe("allow");
    expect(robotsAccess({ status: 404 })).toBe("allow");
    expect(robotsAccess({ status: 403 })).toBe("allow");
    expect(robotsAccess({ status: 429 })).toBe("disallow");
    expect(robotsAccess({ status: 503 })).toBe("disallow");
    expect(robotsAccess({ error: "timeout" })).toBe("disallow");
    expect(robotsAccess({ error: "budget" })).toBe("disallow");
  });
  it("keeps the site's outcome when robots.txt cannot be reached, so the fallbacks still run", () => {
    for (const code of ["not_found", "unreachable", "tls_invalid", "timeout"]) {
      const cause = new CheckError(code, "x", 500, "");
      const outcomes = [];
      expect(() => strictRobots({ outcomes }).onRobots({ origin: "https://a.example.com", error: code, cause })).toThrow(cause);
      expect(outcomes[0]).toMatchObject({ error: code, access: "disallow" });
    }
    expect(() => strictRobots().onRobots({ origin: "https://a.example.com", error: "budget" })).toThrow(/robots.txt stops/);
  });
  it("gives V2 more time per site, and leaves E20's limits and the rate alone", async () => {
    expect(V2_LIMITS).toEqual({ siteBudgetMs: 15_000, siteHardCapMs: 30_000 });
    expect(LIMITS).toMatchObject({ siteBudgetMs: 8000, siteHardCapMs: 20_000, concurrency: 4, delayMs: 1000 });
    const out = tmp();
    await runPass(mergeCohorts({ T1k: [{ host: "a.selftest.example.com", rank: 1, group: "com" }] }), { pass: 2, out, loopbackPort: 9, delayMs: 0, dns: stubDns });
    const m = JSON.parse(readFileSync(join(out, "manifest.json"), "utf8"));
    expect(m.config.limits).toEqual(V2_LIMITS);
    expect(m.config.requestTimeoutsMs).toEqual({ page: 6000, robots: 4000, securityTxt: 4000 });
  });
  it("records the reason for an invalid certificate, apart from a failure", async () => {
    const server = createTlsServer(selfSignedCert(), (sock) => sock.end());
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    try {
      const err = await fetchBody(parseTarget(`https://a.selftest.example.com:${server.address().port}/`, { anyPort: true }), { lookup: async () => [{ address: "127.0.0.1", family: 4 }], allowPrivate: true, anyPort: true, timeout: 2000 }).catch((e) => e);
      expect(err).toMatchObject({ code: "tls_invalid" });
      expect(err.tlsReason).toMatch(/CERT|SELF_SIGNED|VERIFY/);
      expect(() => strictRobots().onRobots({ origin: "https://a.example.com", error: "tls_invalid", cause: err })).toThrow(err);
    } finally { await new Promise((r) => server.close(r)); }
  });
  it("does not fetch the homepage when robots.txt answers 5xx, and records why", async () => {
    const s = await site((_h, url) => (url === "/robots.txt" ? { status: 503 } : { status: 200, body: "hi" }));
    try {
      const r = await go(s, "a.selftest.example.com");
      expect(r).toMatchObject({ status: "excluded", reason: "robots_unavailable" });
      expect(r.robots).toEqual([{ status: 503, error: null, access: "disallow" }]);
      expect(s.hits).toEqual(["a.selftest.example.com/robots.txt"]);
    } finally { await s.close(); }
  });
  it("keeps the old behaviour without strict rules, as the live check does", async () => {
    const s = await site((_h, url) => (url === "/robots.txt" ? { status: 503 } : { status: 200, body: "hi" }));
    try {
      const r = await visit(row("a.selftest.example.com"), { loopbackPort: s.port });
      expect(r.status).toBe("ok");
      expect(r.robots).toBeUndefined();
    } finally { await s.close(); }
  });
  it("visits a site whose robots.txt is missing", async () => {
    const s = await site((_h, url) => (url === "/" ? { status: 200, body: "hi" } : null));
    try {
      const r = await go(s, "a.selftest.example.com");
      expect(r.status).toBe("ok");
      expect(r.robots).toEqual([{ status: 404, error: null, access: "allow" }]);
    } finally { await s.close(); }
  });
  it("honors a rule that disallows the homepage's path", async () => {
    const s = await site((_h, url) => (url === "/robots.txt" ? { status: 200, body: "User-agent: *\nDisallow: /$\n" } : { status: 200, body: "hi" }));
    try {
      expect(await go(s, "a.selftest.example.com")).toMatchObject({ status: "excluded", reason: "robots_disallow_path" });
      expect(s.hits).toEqual(["a.selftest.example.com/robots.txt"]);
    } finally { await s.close(); }
  });
  it("reads robots.txt at a new origin before following a redirect there", async () => {
    const s = await site((host, url) => {
      if (host === "a.selftest.example.com") return url === "/" ? { status: 301, headers: { location: `http://b.selftest.example.com:${s.port}/` } } : null;
      return url === "/robots.txt" ? { status: 200, body: "User-agent: Penthera-Research\nDisallow: /\n" } : { status: 200, body: "hi" };
    });
    try {
      expect((await go(s, "a.selftest.example.com")).status).toBe("opted_out");
      expect(s.hits).toContain("b.selftest.example.com/robots.txt");
      expect(s.hits).not.toContain("b.selftest.example.com/");
    } finally { await s.close(); }
  });
  it("stops when a redirect leads to a site on the exclusion list, and sends it nothing", async () => {
    const s = await site((host, url) => (url === "/" ? { status: 302, headers: { location: `http://clinic.selftest.example.com:${s.port}/` } } : null));
    try {
      const r = await go(s, "a.selftest.example.com", { exclude: new Map([["clinic.selftest.example.com", "health"]]) });
      expect(r).toMatchObject({ status: "excluded", reason: "exclusion_redirect" });
      expect(s.hits.filter((h) => h.startsWith("clinic"))).toEqual([]);
    } finally { await s.close(); }
  });
  it("sends no app page under the strict rules, even when asked", async () => {
    const s = await site((_h, url) => (url === "/" ? { status: 200, body: '<a href="/login">Log in</a>' } : null));
    try {
      const r = await go(s, "www.selftest.example.com", { appPage: true });
      expect(r.app).toBeUndefined();
      expect(s.hits).not.toContain("www.selftest.example.com/login");
    } finally { await s.close(); }
  });
});

describe("E20-R DNS, read apart from HTTP", () => {
  const answers = (txt) => ({ ...stubDns, resolveTxt: async (n) => { if (txt[n]) return txt[n].map((t) => [t]); throw Object.assign(new Error("x"), { code: "ENODATA" }); }, resolveCaa: async () => [{ issue: "letsencrypt.org" }], ns: async () => ["a.ns.cloudflare.com."], mx: async () => [{ exchange: "aspmx.l.google.com." }] });

  it("reads p, sp and pct", () => {
    expect(dmarcTags("v=DMARC1; p=Reject; sp=none; pct=50; rua=mailto:a@b.c")).toEqual({ p: "reject", sp: "none", pct: "50" });
    expect(dmarcTags("v=DMARC1;p=none")).toEqual({ p: "none", sp: null, pct: null });
  });
  it("keeps the registered reading, adds the frozen one, and redacts report addresses", async () => {
    const d = await readDomain("www.example.com", answers({ "example.com": ["v=spf1 include:_spf.example.net -all"], "_dmarc.example.com": ["v=DMARC1; p=reject; pct=25; rua=mailto:dmarc-reports@example.com"] }));
    expect(d).toMatchObject({ domain: "example.com", mx: "google", ns: "cloudflare", exists: true, spf: true, dmarc: true, caa: true, "spf+dmarc": true, spfRecordPresent: true, "spf-record+dmarc-enforcing": true, "spf-record+dmarc-reject": true });
    expect(d.spfRecord).toBe("v=spf1 include:_spf.example.net -all");
    expect(d.dmarcReading).toMatchObject({ valid: true, partial: true, pct: 25, inherited: false });
    expect(d.dmarcTags.pct).toBe("25");
    expect(d.dmarcRecord).toContain("<redacted>@example.com");
    expect(d.dmarcRecord).not.toContain("dmarc-reports");
  });
  it("gives null, not a failure, when DNS does not answer", async () => {
    const down = () => Promise.reject(Object.assign(new Error("x"), { code: "ETIMEOUT" }));
    const d = await readDomain("example.com", { resolveTxt: down, resolveCaa: down, mx: down, ns: down });
    expect(d).toMatchObject({ spf: null, dmarc: null, caa: null, "spf+dmarc": null, spfRecordPresent: null, "spf-record+dmarc-enforcing": null, ns: "unknown", exists: null, caaTree: { found: null } });
    expect(d.outcomes).toEqual({ txt: "resolver-failure:ETIMEOUT", dmarc: "resolver-failure:ETIMEOUT", caa: "resolver-failure:ETIMEOUT", mx: "resolver-failure:ETIMEOUT", ns: "resolver-failure:ETIMEOUT" });
  });
  it("names each DNS outcome: NXDOMAIN, NODATA or a resolver failure", async () => {
    expect(dnsOutcome({ code: "ENOTFOUND" })).toBe("nxdomain");
    expect(dnsOutcome({ code: "ENODATA" })).toBe("nodata");
    expect(dnsOutcome({ code: "ESERVFAIL" })).toBe("resolver-failure:ESERVFAIL");
    const gone = () => Promise.reject(Object.assign(new Error("x"), { code: "ENOTFOUND" }));
    const d = await readDomain("gone.example.com", { resolveTxt: gone, resolveCaa: gone, mx: gone, ns: gone });
    expect(d).toMatchObject({ exists: false, outcomes: { txt: "nxdomain", dmarc: "nxdomain", ns: "nxdomain" } });
    const empty = await readDomain("empty.example.com", stubDns);
    expect(empty).toMatchObject({ exists: true, outcomes: { ns: "nodata", mx: "nodata" } });
    const mixed = await readDomain("a.b.example.com", answers({ "example.com": ["v=spf1 -all"] }));
    expect(mixed.outcomes).toMatchObject({ txt: "answer", dmarc: "nodata", caa: "answer", ns: "answer" });
  });
  it("reads the final domain too when a redirect ended on another organization", async () => {
    const a = answers({});
    expect((await siteDns("www.example.com", "www.example.com", a)).final).toBeUndefined();
    expect((await siteDns("www.example.com", "shop.other.com", a)).final.domain).toBe("other.com");
    expect((await siteDns("example.com", "www.example.com", a))).toMatchObject({ final: { caaTree: { found: true, at: "www.example.com" } }, finalOtherOrg: false });
    expect((await siteDns("www.example.com", "[2606:4700::1]", a)).final).toBeUndefined();
  });
  it("reads DNS for a site whose homepage failed, and not for one that opted out", async () => {
    const server = createServer((req, res) => { res.writeHead(req.url === "/robots.txt" ? 200 : 500); res.end(req.headers.host.startsWith("out.") ? "User-agent: Penthera-Research\nDisallow: /\n" : ""); });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    try {
      const rows = mergeCohorts({ T1k: [{ host: "out.selftest.example.com", rank: 1, group: "com" }] });
      const { records } = await runPass(rows, { pass: 2, out: tmp(), loopbackPort: server.address().port, delayMs: 0, dns: stubDns });
      expect(records[0].status).toBe("opted_out");
      expect(records[0].dns).toBeUndefined();
      const dead = await runPass(mergeCohorts({ T1k: [{ host: "dead.selftest.example.com", rank: 1, group: "com" }] }), { pass: 2, out: tmp(), loopbackPort: 9, delayMs: 0, dns: stubDns });
      expect(dead.records[0].status).not.toBe("ok");
      expect(dead.records[0].dns.listed.domain).toBe("example.com");
    } finally { await new Promise((r) => server.close(r)); }
  });
});

describe("E20-R run records", () => {
  it("writes a manifest at the start and the end, with what ran", async () => {
    const out = tmp();
    await runPass(mergeCohorts({ T1k: [{ host: "a.selftest.example.com", rank: 1, group: "com" }] }), { pass: 2, out, loopbackPort: 9, delayMs: 0, dns: stubDns, manifest: { removals: { used: true, count: 0 } } });
    const m = JSON.parse(readFileSync(join(out, "manifest.json"), "utf8"));
    expect(m).toMatchObject({ study: "E20-R2", kind: "pass", pass: 2, seed: PASS_SEED[2], sites: 1, records: 1, removals: { used: true, count: 0 } });
    expect(m.startedAt && m.finishedAt).toBeTruthy();
    expect(m.lockfileSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(m.classifierSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(m.psl).toMatchObject({ commit: PSL_VERSION.commit, sha256: pslSha256() });
    expect(m.gitAtStart).toHaveProperty("remoteTip");
    expect(m.gitAtFinish).toHaveProperty("commit");
    for (const k of ["protocolSha256", "amendmentSha256", "studyPageSha256", "codeSha256", "runtimeSha256", "rawSha256", "aggregateSha256"]) expect(m[k], k).toMatch(/^[0-9a-f]{64}$/);
    expect(m.immutableAtFinish).toEqual({ ok: true, changed: [] });
    expect(m.totals).toHaveProperty("requests");
    expect(m.config.appPage).toBe(false);
  });
  it("records the commit and a dirty tree", () => {
    const calls = [];
    const run = (_c, args, opts) => { calls.push([args, opts]); return ({ "rev-parse": "abc\n", status: " M x\n", "ls-files": "H a\nH b\n", "ls-remote": "def\trefs/heads/main\n" })[args[0]]; };
    expect(gitState("/x", run)).toEqual({ commit: "abc", dirty: true, hidden: false, remoteUrl: REMOTE_URL, remoteTip: "def" });
    expect(calls.find(([a]) => a[0] === "ls-remote")[0]).toEqual(["ls-remote", REMOTE_URL, "refs/heads/main"]);
    expect(calls.find(([a]) => a[0] === "status")[0]).toContain("--untracked-files=all");
    expect(calls.every(([, o]) => o.timeout > 0)).toBe(true);
    // S5: nothing goes to the network unless asked.
    calls.length = 0;
    expect(gitState("/x", run, { remote: false }).remoteTip).toBeNull();
    expect(calls.some(([a]) => a[0] === "ls-remote")).toBe(false);
    expect(gitState("/x", (c, a) => (a[0] === "ls-files" ? "h a\n" : run(c, a))).hidden).toBe(true);
    expect(gitState("/x", (c, a) => (a[0] === "ls-files" ? "S a\n" : run(c, a))).hidden).toBe(true);
    const offline = (c, a) => { if (a[0] === "ls-remote") throw new Error("no network"); return run(c, a); };
    expect(gitState("/x", offline).remoteTip).toBeNull();
    expect(gitState("/x", () => { throw new Error("no git"); })).toEqual({ commit: null, dirty: null, hidden: null, remoteUrl: REMOTE_URL, remoteTip: null });
    expect(runManifest({ kind: "x" }).kind).toBe("x");
  });
  it("counts public IPv4 addresses only", () => {
    expect(sourceAddressCount({ lo: [{ family: "IPv4", internal: true, address: "127.0.0.1" }], eth0: [{ family: "IPv4", internal: false, address: "8.8.8.8" }, { family: "IPv6", internal: false, address: "2a01::1" }, { family: "IPv4", internal: false, address: "10.0.0.2" }] })).toBe(1);
  });
  it("never overwrites a run", async () => {
    const out = tmp();
    writeFileSync(join(out, "raw.jsonl"), "{}\n");
    await expect(runPass([], { pass: 2, out, loopbackPort: 9, delayMs: 0 })).rejects.toThrow(/already holds a run/);
    expect(existsSync(join(out, "manifest.json"))).toBe(false);
    // S7: a run that crashed before its first record still blocks a second start.
    const started = tmp();
    await runPass([], { pass: 2, out: started, loopbackPort: 9, delayMs: 0 });
    await expect(runPass([], { pass: 2, out: started, loopbackPort: 9, delayMs: 0 })).rejects.toThrow(/already holds a run/);
  });
  it("skips a site that opted out earlier, as its own category", async () => {
    const earlier = readRemovals("old.selftest.example.com\n", "opted-out-earlier");
    const { records } = await runPass(mergeCohorts({ T1k: [{ host: "old.selftest.example.com", rank: 1, group: "com" }] }), { pass: 2, out: tmp(), loopbackPort: 9, delayMs: 0, exclude: earlier, dns: stubDns });
    expect(records[0]).toMatchObject({ status: "excluded", reason: "exclusion_list", category: "opted-out-earlier" });
    expect(records[0].dns).toBeUndefined();
  });
});

describe("E20-R pilot", () => {
  const lists = Object.fromEntries(Object.keys(R_COHORTS).map((c) => [c, Array.from({ length: 30 }, (_, i) => ({ host: `s${i}.${c.toLowerCase()}.example.com`, rank: i + 1, group: "x" }))]));
  it("draws a fixed sample from every claim list only, and leaves out excluded sites", () => {
    const rows = mergeCohorts(lists);
    const a = pilotSample(rows, 50);
    expect(a).toHaveLength(50);
    expect(pilotSample([...rows].reverse(), 50).map((r) => r.host)).toEqual(a.map((r) => r.host));
    for (const c of CLAIM_COHORTS) expect(a.some((r) => r.cohorts[c])).toBe(true);
    expect(a.every((r) => CLAIM_COHORTS.some((c) => r.cohorts[c]))).toBe(true);
    const ban = new Map([[a[0].host, "health"]]);
    expect(pilotSample(rows, 50, { exclude: ban }).map((r) => r.host)).not.toContain(a[0].host);
  });
  it("is smaller than the list when the list is small", () => {
    expect(pilotSample(mergeCohorts({ T1k: lists.T1k.slice(0, 3) }), 50)).toHaveLength(3);
  });
  it("drops pilot sites from pass 2, counted, and a rerun draws other sites", async () => {
    const rows = mergeCohorts(lists);
    const first = pilotSample(rows, 10);
    const dropped = readRemovals(first.map((r) => r.host).join("\n"), "pilot");
    expect(pilotSample(rows, 10, { exclude: dropped }).some((r) => first.includes(r))).toBe(false);
    const { records, aggregate: agg } = await runPass(mergeCohorts({ T1k: [{ host: first[0].host, rank: 1, group: "com" }] }), { pass: 2, out: tmp(), loopbackPort: 9, delayMs: 0, exclude: dropped, dns: stubDns });
    expect(records[0]).toMatchObject({ status: "excluded", category: "pilot" });
    expect(records[0].dns).toBeUndefined();
    expect(agg.cohorts.T1k.exclusionCategories.pilot).toBe(1);
  });
  it("labels the run as a pilot", async () => {
    const out = tmp();
    await runPass(mergeCohorts({ T1k: [{ host: "a.selftest.example.com", rank: 1, group: "com" }] }), { pass: "pilot", out, loopbackPort: 9, delayMs: 0, dns: stubDns });
    expect(JSON.parse(readFileSync(join(out, "manifest.json"), "utf8"))).toMatchObject({ kind: "pilot", seed: PASS_SEED.pilot });
    expect(JSON.parse(readFileSync(join(out, "raw.jsonl"), "utf8").split("\n")[0]).pass).toBe("pilot");
    expect(readFileSync(join(out, "pilot-sites.txt"), "utf8")).toBe("a.selftest.example.com\n");
  });
  it("reports counts, names no site, and catches a scrub miss", () => {
    const ok = { host: "secret-site.example.com", status: "ok", httpStatus: 200, checks: [{ evidence: "fine" }], robots: [{ status: 200, access: "allow", error: null }], evidence: { class: { label: "page", rule: "status" }, classRegistered: { label: "challenge" }, bodySha256: "x", others: [], pageExcerpt: { title: "t", text: "hello" }, values: {} }, dns: { listed: { spf: true, dmarc: null, caa: true, exists: true, dmarcRecord: "" } } };
    const r = pilotReport([ok, { host: "other.example.com", status: "error", error: "timeout" }]);
    expect(r).toMatchObject({ sites: 2, labels: { page: 1 }, labelChanges: { "challenge to page": 1 }, evidence: { twoxxWithExcerpt: 1 }, dns: { read: 1, answered: { spf: 1, dmarc: 0 } }, robots: { outcomes: { "2xx": 1 } } });
    expect(r.outcomes["error:timeout"]).toBe(1);
    expect(JSON.stringify(r)).not.toContain("example.com");
    expect(Object.values(r.scrubMisses).every((v) => v === 0)).toBe(true);
    const leak = { ...ok, evidence: { ...ok.evidence, excerpt: "you are 203.0.113.7" } };
    expect(pilotReport([leak]).scrubMisses.ipv4).toBe(1);
  });
});

describe("E20-R analysis", () => {
  it("fixes the family at eleven claims", () => {
    expect(CLAIMS_R).toBe(11);
    expect(LEVEL).toBeCloseTo(1 - 0.05 / 11, 6);
  });
  it("computes Cohen's kappa", () => {
    expect(kappa([1, 1, 0, 0], [1, 1, 0, 0])).toBe(1);
    expect(kappa([1, 0, 1, 0], [1, 1, 0, 0])).toBeCloseTo(0);
    expect(kappa(["a", "a"], ["a", "a"])).toBe(1);
  });
  it("decides on the interval and the predicted sign", () => {
    expect(decide([0.02, 0.2], +1)).toBe("supported");
    expect(decide([-0.2, -0.02], +1)).toBe("refuted");
    expect(decide([-0.05, 0.05], +1)).toBe("no meaningful difference");
    expect(decide([-0.05, 0.3], +1)).toBe("inconclusive");
  });
  it("calls a disagreement between S and R view-dependent", () => {
    expect(combine("supported", "supported")).toBe("supported");
    expect(combine("supported", "inconclusive")).toBe("view-dependent");
    expect(combine("refuted", "supported")).toBe("view-dependent");
    expect(combine("inconclusive", "inconclusive")).toBe("inconclusive");
  });
  const site = (host, csp, extra = {}) => ({ host, finalHost: host, status: "ok", checks: [{ id: "csp", passed: csp, weight: 14 }], evidence: { class: { label: "page" } }, ...extra });
  it("reads derived checks and treats weight 0 as unknown", () => {
    const r = { checks: [{ id: "https", passed: true, weight: 22 }, { id: "hsts", passed: false, weight: 12 }, { id: "spf", passed: true, weight: 3 }, { id: "dmarc", passed: false, weight: 0 }] };
    expect(pass(r, "https+hsts")).toBe(false);
    expect(pass(r, "spf+dmarc")).toBeUndefined();
  });
  it("widens the interval when one organization owns many sites", () => {
    const opts = { resamples: 800, level: 0.95 };
    const a = Array.from({ length: 200 }, (_, i) => site(`a${i}.org`, i % 2 === 0));
    const groupsOf10 = Array.from({ length: 200 }, (_, i) => site(`s${i}.o${Math.floor(i / 10)}.org`, Math.floor(i / 10) % 2 === 0));
    const b = Array.from({ length: 200 }, (_, i) => site(`b${i}.net`, i % 2 === 0));
    const free = clusterDiff(a, b, "csp", opts), tied = clusterDiff(groupsOf10, b, "csp", opts);
    expect(tied.ci[1] - tied.ci[0]).toBeGreaterThan(free.ci[1] - free.ci[0]);
  });
  it("is deterministic for a seed", () => {
    const a = Array.from({ length: 50 }, (_, i) => site(`a${i}.org`, i % 3 === 0)), b = Array.from({ length: 50 }, (_, i) => site(`b${i}.org`, i % 2 === 0));
    expect(clusterDiff(a, b, "csp", { resamples: 200 })).toEqual(clusterDiff(a, b, "csp", { resamples: 200 }));
  });
  it("reports industries only for groups of at least twenty", () => {
    const rows = Array.from({ length: 25 }, (_, i) => ({ host: `www.s${i}.org`, score: 50, checks: [{ id: "csp", passed: true, weight: 14 }] }));
    const map = new Map(rows.map((r, i) => [r.host.slice(4), i < 22 ? "Healthcare" : "Fintech"]));
    const t = industryTable(rows, map, ["csp"]);
    expect(t.Healthcare.sites).toBe(22);
    expect(t.Fintech).toBeUndefined();
    expect(t.suppressedGroups).toBe(1);
  });
  it("repeats C1 to C4 without the hosts E20 excluded", () => {
    const mk = (cohort, n) => Array.from({ length: n }, (_, i) => site(`${cohort.toLowerCase()}${i}.org`, i % 2 === 0, { cohorts: { [cohort]: { rank: i, group: "x" } }, platform: { edge: "vercel" } }));
    const p1 = [...mk("T1k", 40), ...mk("YC-new", 40), ...mk("T100k", 20), ...mk("YC-old", 20)];
    const out = replicationAsE20(p1, new Set(["yc-new0.org"]), { resamples: 50 });
    expect(out.map((c) => c.id)).toEqual(["C1", "C2", "C3", "C4"]);
    expect(out[0].S.nB).toBe(39);
  });
  const rec = (host, label, status, cohort = "T1k") => ({ host, finalHost: host, status: "ok", httpStatus: status, score: 50, cohorts: { [cohort]: { rank: 1, group: "x" } }, checks: [], evidence: { class: { label, rule: "status" } } });
  it("gives C12 an interval and no decision", () => {
    const rows = Array.from({ length: 40 }, (_, i) => rec(`s${i}.example.com`, "page", 200));
    const e20 = { T1k: new Map(rows.map((r) => [r.host, { httpStatus: 403 }])) };
    const c12 = claims(rows, null, e20, { resamples: 200 }).find((c) => c.id === "C12");
    expect(c12.decision).toBe("descriptive");
    expect(c12.ci).toHaveLength(2);
    expect(c12.diff).toBe(-1);
  });
  it("counts agreement over every cohort, with one label definition", () => {
    const one = Array.from({ length: 40 }, (_, i) => ({ ...rec(`s${i}.example.com`, i % 2 ? "page" : "block", 200, "T100k") }));
    const two = one.map((r) => ({ ...r, evidence: { class: { label: "page", rule: "status" }, classRegistered: r.evidence.class } }));
    const c15 = claims(two, one, {}, { resamples: 200 }).find((c) => c.id === "C15");
    expect(c15.n).toBe(40);
    expect(c15.kappa).toBe(1);
  });
  it("decides the mail claims on DNS for every site with a domain, graded or not", () => {
    const site = (i, cohort, passed, status = "ok") => ({ host: `s${i}.${cohort.toLowerCase()}.example${i}.com`, listedOrg: `example${i}-${cohort}.com`, finalHost: "same.example.net", status, cohorts: { [cohort]: { rank: i, group: "x" } }, dns: { listed: { exists: i !== 0, spf: passed, dmarc: passed, spfRecordPresent: true, dmarcReading: { enforcing: passed, declared: true, reject: false } } } });
    const rows = [...Array.from({ length: 60 }, (_, i) => site(i, "T1k", true)), ...Array.from({ length: 60 }, (_, i) => site(i, "YC-new", false, "error"))];
    const c2 = dnsClaims(rows, { resamples: 200 }).find((c) => c.id === "C2");
    expect(c2.S.nA).toBe(59);
    // Clustered on the listed organization: one shared final host doesn't collapse them.
    expect(c2.decision).toBe("supported");
    expect(dnsClaims(rows, { measure: "declared", resamples: 200 }).find((c) => c.id === "C2").decision).not.toBe("supported");
    expect(dnsClaims(rows, { measure: "reject", resamples: 200 }).find((c) => c.id === "C2").S.diff).toBe(0);
  });
  it("gives the refusal share with and without bare 403s", () => {
    const r = (label, rule, registered = "page") => ({ host: `${label}${rule}.example.com`, evidence: { class: { label, rule }, classRegistered: { label: registered } } });
    const rows = [r("candidate-page", "status"), r("block", "unrecognized-403"), r("block", "body", "block"), r("challenge", "body", "challenge")];
    expect(refusalShares(rows)).toEqual({ n: 4, all: 0.75, signatureBacked: 0.5, registered: 0.5 });
    expect(primaryRefusal(rows, { resamples: 200 })).toMatchObject({ n: 4, share: 0.5 });
  });
  it("reports C14 and C15 as not run with one pass", () => {
    const rows = ["T1k", "YC-new", "YC-25", "YC-old", "T100k"].flatMap((c) => Array.from({ length: 30 }, (_, i) => site(`${c.toLowerCase()}${i}.org`, i % 2 === 0, { cohorts: { [c]: { rank: i, group: "x" } }, platform: { edge: "vercel" } })));
    const out = claims(rows, null, new Map(), { resamples: 50 });
    expect(out).toHaveLength(15);
    expect(out.slice(-2).map((c) => c.decision)).toEqual(["not run", "not run"]);
  });
  it("returns the fifteen claims on synthetic records and names no site", () => {
    const mk = (cohort, n, rate, offset = 0) => Array.from({ length: n }, (_, i) => site(`${cohort.toLowerCase()}${i}.org`, i % rate === 0, { cohorts: { [cohort]: { rank: i + offset, group: "x" } }, platform: { edge: i % 2 ? "cloudflare" : "vercel" } }));
    const p1 = [...mk("T1k", 60, 2), ...mk("YC-new", 60, 5), ...mk("YC-25", 30, 5), ...mk("YC-old", 40, 3), ...mk("T100k", 60, 4)];
    const out = claims(p1, p1, new Map(p1.map((r) => [r.host, { httpStatus: 200 }])), { resamples: 100 });
    expect(out.map((c) => c.id)).toEqual(Array.from({ length: 15 }, (_, i) => `C${i + 1}`));
    expect(out.find((c) => c.id === "C14").kappa).toBe(1);
    expect(JSON.stringify(out)).not.toContain(".org");
  });
});
