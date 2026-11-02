/**
 * Runtime advisories: version evidence (banners, Docker images, version files)
 * matched against `runtime-advisory` and `runtime-eol` rules.
 *
 * The rules here are fixtures compiled through the real pack validator, so the
 * tests also pin the schema. Versions are made up; the bundled pack's real
 * data is checked in the "bundled pack" block at the end.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { KINDS, rulesOf } from "../lib/rules/index.js";
import { parseVersion, compareVersions } from "../lib/advisories/versions.js";
import { evidenceFromResponse, evidenceFromRepo, parseImageRef } from "../lib/advisories/evidence.js";
import { matchRuntimeAdvisories, runtimeAdvisoriesForResponse, runtimeAdvisoriesForRepo } from "../lib/advisories/index.js";

const base = { source: "https://www.php.net/ChangeLog-8.php", date: "2026-10-21", confidence: "confirmed" };
const adv = (r) => KINDS["runtime-advisory"]({ ...base, ...r }, "test");
const eolRule = (r) => KINDS["runtime-eol"]({ ...base, id: "eol", ...r }, "test");

const PHP_RCE = adv({
  id: "php-test-rce",
  product: "php",
  title: "Test RCE in PHP",
  cves: ["CVE-2026-11111"],
  cvss: { version: "4.0", score: 9.2 },
  fixed: [{ branch: "8.2", version: "8.2.30" }, { branch: "8.3", version: "8.3.27" }, { branch: "8.4", version: "8.4.14" }],
});
const PHP_EOL = eolRule({ product: "php", source: "https://www.php.net/eol.php", branches: [{ branch: "7.4", eol: "2022-11-28" }, { branch: "8.0", eol: "2023-11-26" }, { branch: "8.2", eol: "2026-12-31" }] });
const rules = { advisories: [PHP_RCE], eol: [PHP_EOL] };

const verdicts = (findings) => findings.map((f) => `${f.severity}/${f.confidence}: ${f.title}`);
const scanHeaders = (headers, extra = {}) => runtimeAdvisoriesForResponse({ headers, ...extra }, rules);

describe("versions", () => {
  it("parses upstream versions, partial versions and suffixes", () => {
    expect(parseVersion("8.3.12")).toMatchObject({ major: 8, minor: 3, patch: 12, suffix: "", upstream: "8.3.12" });
    expect(parseVersion("8.1.2-1ubuntu2.19")).toMatchObject({ upstream: "8.1.2", suffix: "-1ubuntu2.19" });
    expect(parseVersion("1.1.1w")).toMatchObject({ patch: 1, letters: "w", upstream: "1.1.1w" });
    expect(parseVersion("v20")).toMatchObject({ major: 20, minor: null, patch: null });
    expect(parseVersion("8.3")).toMatchObject({ minor: 3, patch: null });
    expect(parseVersion("latest")).toBeNull();
    expect(parseVersion("8x")).toBeNull();
    expect(parseVersion("8.4.27-dev")).toMatchObject({ upstream: "8.4.27", pre: "dev", suffix: "" });
    expect(parseVersion("8.5.0RC1")).toMatchObject({ upstream: "8.5.0", pre: "rc1", suffix: "" });
    expect(parseVersion("3.16.0a1")).toMatchObject({ upstream: "3.16.0", pre: "a1", letters: "" });
    expect(parseVersion("4.1.0-beta2")).toMatchObject({ upstream: "4.1.0", pre: "beta2" });
    expect(parseVersion("1.1.1a")).toMatchObject({ letters: "a", pre: "" });
  });

  it("sorts a pre-release below its release", () => {
    expect(compareVersions("8.4.27-dev", "8.4.27")).toBe(-1);
    expect(compareVersions("8.4.27-dev", "8.4.27RC1")).toBe(-1);
    expect(compareVersions("8.4.27RC1", "8.4.27RC2")).toBe(-1);
    expect(compareVersions("3.15.0b2", "3.15.0rc1")).toBe(-1);
    expect(compareVersions("8.4.28-dev", "8.4.27")).toBe(1);
  });

  it("compares numerically, not as strings, and orders OpenSSL letters", () => {
    expect(compareVersions("8.3.9", "8.3.10")).toBe(-1);
    expect(compareVersions("8.10.0", "8.9.99")).toBe(1);
    expect(compareVersions("1.1.1", "1.1.1a")).toBe(-1);
    expect(compareVersions("1.1.1z", "1.1.1za")).toBe(-1);
    expect(compareVersions("2.4.62", "2.4.62")).toBe(0);
  });
});

describe("rule schema", () => {
  it("refuses a fixed version on the wrong release line, a duplicate line and an unknown product", () => {
    expect(() => adv({ id: "x", product: "php", title: "t", fixed: [{ branch: "8.3", version: "8.4.1" }] })).toThrow(/not on release line 8.3/);
    expect(() => adv({ id: "x", product: "php", title: "t", fixed: [{ branch: "8.3", version: "8.3.1" }, { branch: "8.3", version: "8.3.2" }] })).toThrow(/listed twice/);
    expect(() => adv({ id: "x", product: "cobol", title: "t", fixed: [{ branch: "8.3", version: "8.3.1" }] })).toThrow(/one of php/);
    expect(() => adv({ id: "x", product: "php", title: "t", fixed: [{ branch: "8.3", version: "8.3.1-1ubuntu1" }] })).toThrow(/exact upstream/);
    expect(() => adv({ id: "x", product: "php", title: "t", fixed: [{ branch: "8.3", version: "8.3.1RC1" }] })).toThrow(/exact upstream/);
    expect(() => adv({ id: "x", product: "php", title: "t", cves: ["CVE-26-1"], fixed: [{ branch: "8.3", version: "8.3.1" }] })).toThrow(/CVE-YYYY/);
    expect(() => adv({ id: "x", product: "php", title: "t", fixed: [{ branch: "8.3", version: "8.3.5", introduced: "8.3.9" }] })).toThrow(/below the fixed/);
  });

  it("names release lines the way each product does", () => {
    expect(() => adv({ id: "n", product: "nodejs", title: "t", fixed: [{ branch: "22", version: "22.12.0" }] })).not.toThrow();
    expect(() => adv({ id: "n", product: "nodejs", title: "t", fixed: [{ branch: "22.12", version: "22.12.0" }] })).toThrow(/release line/);
    expect(() => adv({ id: "o", product: "openssl", title: "t", fixed: [{ branch: "1.1.1", version: "1.1.1w" }, { branch: "3.0", version: "3.0.15" }] })).not.toThrow();
  });
});

describe("black-box verdicts", () => {
  it("affected: an exact upstream version below the fix", () => {
    const f = scanHeaders({ "x-powered-by": "PHP/8.3.12" });
    expect(verdicts(f)).toEqual(["critical/potential: PHP 8.3.12 is affected by Test RCE in PHP"]);
    expect(f[0]).toMatchObject({ category: "runtime-advisory", source: "runtime-advisory", url: "x-powered-by header", cves: ["CVE-2026-11111"], rule: "php-test-rce" });
    expect(f[0].description).toMatch(/below 8\.3\.27/);
    expect(f[0].remediation).toMatch(/8\.3\.27 or later/);
  });

  it("patched: at or above the fix gives one info finding", () => {
    expect(verdicts(scanHeaders({ "x-powered-by": "PHP/8.3.27" }))).toEqual(["info/likely: PHP 8.3.27 has the fix for Test RCE in PHP (as advertised)"]);
  });

  it("never 'affected' for a distro build: a suffix, or a Server header naming a distribution", () => {
    for (const headers of [{ "x-powered-by": "PHP/8.3.6-1ubuntu1.4" }, { server: "Apache/2.4.62 (Debian)", "x-powered-by": "PHP/8.3.12" }, { server: "Apache/2.4.37 (Red Hat Enterprise Linux)", "x-powered-by": "PHP/8.2.13" }]) {
      const f = scanHeaders(headers);
      expect(f.map((x) => [x.severity, x.confidence]), JSON.stringify(headers)).toEqual([["medium", "needs-human-review"]]);
      expect(f[0].description).toMatch(/distribution build/);
      expect(f[0].remediation).toMatch(/security tracker/);
    }
  });

  it("a banner with no distribution token is at most potential, with a check-on-server note", () => {
    // Ubuntu 24.04's patched php8.3 prints plain PHP/8.3.6, the same as upstream
    // 8.3.6 (bench/runtime-strings, L1). Severity stays; confidence drops.
    const f = scanHeaders({ "x-powered-by": "PHP/8.3.6" });
    expect(verdicts(f)).toEqual(["critical/potential: PHP 8.3.6 is affected by Test RCE in PHP"]);
    expect(f[0].description).toMatch(/Check on server: your distribution may have patched this under the same version number/);
    expect(f[0].description).toContain("`php -v`");
    const old = scanHeaders({ server: "nginx/1.20.1", "x-powered-by": "PHP/7.4.33" });
    expect(verdicts(old)).toEqual(["high/potential: PHP 7.4.33 is end of life: no more security fixes"]);
    expect(old[0].description).toMatch(/won't get a fix for this advisory, which may apply to it:\n- critical: .*Test RCE in PHP/);
    for (const x of old) expect(x.description).toMatch(/may have patched this under the same version number/);
    const nginxEol = eolRule({ product: "nginx", source: "https://nginx.org/", branches: [{ branch: "1.22", eol: "2023-04-11" }] });
    const deb = runtimeAdvisoriesForResponse({ headers: { server: "nginx/1.22.1" } }, { advisories: [], eol: [nginxEol] });
    expect(verdicts(deb)).toEqual(["high/potential: nginx 1.22.1 is end of life: no more security fixes"]);
    expect(deb[0].description).toContain("`nginx -v`");
    // A distribution token still means check on server, with no affected claim.
    expect(verdicts(scanHeaders({ server: "Apache/2.4.58 (Ubuntu)", "x-powered-by": "PHP/8.3.6" }))[0]).toMatch(/^medium\/needs-human-review/);
  });

  it("an official image or a version file is an upstream build and stays likely", () => {
    const dir = mkdtempSync(join(tmpdir(), "penthera-upstream-"));
    try {
      writeFileSync(join(dir, "Dockerfile"), "FROM php:8.3.12-fpm\n");
      writeFileSync(join(dir, ".php-version"), "7.4.33\n");
      const f = runtimeAdvisoriesForRepo(dir, rules);
      expect(verdicts(f).sort()).toEqual([
        "critical/likely: PHP 8.3.12 is affected by Test RCE in PHP",
        // The end-of-life line's unfixed advisory is listed in its row, with its own severity.
        "high/likely: PHP 7.4.33 is end of life: no more security fixes",
      ]);
      expect(f.every((x) => !/may have patched this/.test(x.description))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a distro build whose upstream number already has the fix is patched", () => {
    expect(verdicts(scanHeaders({ "x-powered-by": "PHP/8.3.28-1+deb13u1" }))[0]).toMatch(/^info/);
  });

  it("pre-releases: below the fix is affected, the fixed version or the next is never 'has the fix'", () => {
    // Strings from bench/runtime-strings (docs/research/runtime-strings.md, B2).
    // PHP-8.3's branch reports the next patch with -dev; RCs have no separator.
    expect(verdicts(scanHeaders({ "x-powered-by": "PHP/8.3.27-dev" }))).toEqual(["critical/potential: PHP 8.3.27-dev is affected by Test RCE in PHP"]);
    expect(verdicts(scanHeaders({ "x-powered-by": "PHP/8.3.27RC1" }))).toEqual(["critical/potential: PHP 8.3.27RC1 is affected by Test RCE in PHP"]);
    for (const v of ["8.3.28-dev", "8.4.15RC1"]) {
      const f = scanHeaders({ "x-powered-by": `PHP/${v}` });
      expect(verdicts(f), v).toEqual([`medium/needs-human-review: PHP ${v} in use: check whether it is affected by Test RCE in PHP`]);
      expect(f[0].description).toMatch(/pre-release build/);
    }
    // Two patches past the fix, a branch build has it.
    expect(verdicts(scanHeaders({ "x-powered-by": "PHP/8.3.29-dev" }))[0]).toMatch(/^info\/potential: PHP 8.3.29-dev has the fix/);
    // A line newer than any the advisory lists stays out of scope.
    expect(scanHeaders({ "x-powered-by": "PHP/8.6.0RC4" })).toEqual([]);
    expect(evidenceFromResponse({ headers: { "x-powered-by": "PHP/8.4.27-dev" } })).toMatchObject([{ kind: "exact", version: { upstream: "8.4.27", pre: "dev" } }]);
    expect(evidenceFromResponse({ headers: { server: "Werkzeug/3.1.3 Python/3.15.0rc1" } })).toMatchObject([{ product: "python", kind: "exact", version: { pre: "rc1" } }]);
    expect(evidenceFromResponse({ headers: { server: "Apache/2.4.69 (Unix) OpenSSL/4.1.0-beta2" } }).find((e) => e.product === "openssl")).toMatchObject({ kind: "exact", version: { pre: "beta2" } });
    expect(parseImageRef("php:8.3.27RC1-fpm")).toMatchObject({ product: "php", kind: "exact", version: { upstream: "8.3.27", pre: "rc1" } });
    expect(parseImageRef("python:3.15.0rc1-slim")).toMatchObject({ product: "python", kind: "exact", version: { pre: "rc1" } });
  });

  it("check on server: PHP present but the version hidden (banner, PHPSESSID, .php links, discovered .php paths)", () => {
    for (const fp of [{ headers: { "x-powered-by": "PHP" } }, { headers: {}, cookieNames: ["PHPSESSID"] }, { headers: {}, phpLink: "/index.php?page=1" }]) {
      const f = runtimeAdvisoriesForResponse(fp, rules);
      expect(verdicts(f), JSON.stringify(fp)).toEqual(["medium/needs-human-review: PHP in use: check whether it is affected by Test RCE in PHP"]);
      expect(f[0].description).toMatch(/not a sign it is safe/);
      expect(f[0].remediation).toMatch(/php -v/);
    }
    expect(runtimeAdvisoriesForResponse({ headers: {} }, { ...rules, phpPaths: ["/wp-login.php"] })).toHaveLength(1);
  });

  it("no evidence, no finding: absence of a banner is never reported as safe", () => {
    expect(scanHeaders({ server: "cloudflare" })).toEqual([]);
    expect(scanHeaders({})).toEqual([]);
  });

  it("end-of-life line: one end-of-life finding that lists the advisory it will never get a fix for", () => {
    const f = scanHeaders({ "x-powered-by": "PHP/7.4.33" });
    expect(verdicts(f)).toEqual(["high/potential: PHP 7.4.33 is end of life: no more security fixes"]);
    expect(f[0].advisories).toHaveLength(1);
    expect(f[0].description).toMatch(/2022-11-28/);
    expect(f[0].description).toMatch(/Test RCE in PHP/);
  });

  it("end of life is judged by the pack's date, not the scan's clock", () => {
    // 8.2's end of life (2026-12-31) is after the rule's date, so 8.2 is still supported.
    expect(verdicts(scanHeaders({ "x-powered-by": "PHP/8.2.29" }))).toEqual(["critical/potential: PHP 8.2.29 is affected by Test RCE in PHP"]);
  });

  it("a newer release line than any the advisory lists is not matched", () => {
    expect(scanHeaders({ "x-powered-by": "PHP/8.5.0" })).toEqual([]);
  });

  it("a line between listed ones, with no fix and not end of life, is 'check'", () => {
    const gap = adv({ id: "gap", product: "php", title: "Gap", fixed: [{ branch: "8.1", version: "8.1.30" }, { branch: "8.3", version: "8.3.27" }] });
    const f = runtimeAdvisoriesForResponse({ headers: { "x-powered-by": "PHP/8.2.1" } }, { advisories: [gap], eol: [] });
    expect(f[0].description).toMatch(/lists no fix for release line 8\.2/);
  });

  it("an advisory with a condition (OS, SAPI) is at most potential", () => {
    const cgi = adv({ id: "cgi", product: "php", title: "CGI argument injection", condition: "Windows with PHP-CGI", fixed: [{ branch: "8.3", version: "8.3.8" }] });
    const f = runtimeAdvisoriesForResponse({ headers: { "x-powered-by": "PHP/8.3.4" } }, { advisories: [cgi], eol: [] });
    expect(f[0]).toMatchObject({ severity: "critical", confidence: "potential" });
    expect(f[0].description).toMatch(/only applies when: Windows with PHP-CGI/);
  });

  it("respects `introduced`: versions before the bug are not affected", () => {
    const trav = adv({ id: "trav", product: "apache-httpd", title: "Path traversal", fixed: [{ branch: "2.4", version: "2.4.51", introduced: "2.4.49" }] });
    const one = (server) => runtimeAdvisoriesForResponse({ headers: { server } }, { advisories: [trav], eol: [] });
    expect(verdicts(one("Apache/2.4.49 (Unix)"))[0]).toMatch(/^critical\/potential: Apache HTTP Server 2.4.49 is affected/);
    expect(verdicts(one("Apache/2.4.50"))[0]).toMatch(/affected/);
    expect(one("Apache/2.4.48")).toEqual([]);
    expect(verdicts(one("Apache/2.4.62"))[0]).toMatch(/^info/);
  });

  it("reads aiohttp's major.minor Python banner as the release line", () => {
    // Strings from bench/runtime-strings (docs/research/runtime-strings.md, B3); aiohttp/http.py.
    const pyEol = eolRule({ product: "python", source: "https://devguide.python.org/versions/", branches: [{ branch: "3.9", eol: "2025-10-31" }] });
    expect(evidenceFromResponse({ headers: { server: "Python/3.11 aiohttp/3.9.5" } })).toMatchObject([{ product: "python", kind: "branch", version: { major: 3, minor: 11, patch: null } }]);
    expect(verdicts(runtimeAdvisoriesForResponse({ headers: { server: "Python/3.9 aiohttp/3.8.6" } }, { advisories: [], eol: [pyEol] }))).toEqual([
      "high/likely: Python 3.9 is end of life: no more security fixes",
    ]);
    // Not CPython's own name inside another word, and not a bare major.
    expect(evidenceFromResponse({ headers: { server: "CPython/3.11" } })).toEqual([]);
    expect(evidenceFromResponse({ headers: { server: "Python/3" } })).toEqual([]);
  });

  it("respects `introduced` on older release lines: a line older than the flaw never had it", () => {
    // Strings from bench/runtime-strings (docs/research/runtime-strings.md, B1).
    const trav = adv({ id: "trav", product: "apache-httpd", title: "Path traversal", fixed: [{ branch: "2.4", version: "2.4.51", introduced: "2.4.49" }] });
    const httpdEol = eolRule({ product: "apache-httpd", source: "https://httpd.apache.org/", branches: [{ branch: "2.2", eol: "2017-07-11" }, { branch: "2.0", eol: "2013-07-10" }] });
    const opts = { advisories: [trav], eol: [httpdEol] };
    for (const server of ["Apache/2.2.34 (Unix)", "Apache/2.0.65 (Unix)"]) {
      expect(verdicts(runtimeAdvisoriesForResponse({ headers: { server } }, opts)), server).toEqual([
        `high/potential: Apache HTTP Server ${server.split(/[/ ]/)[1]} is end of life: no more security fixes`,
      ]);
    }
    expect(verdicts(runtimeAdvisoriesForResponse({ headers: { server: "Apache/2.2.15 (CentOS)" } }, opts))).toEqual([
      "medium/needs-human-review: Apache HTTP Server 2.2.15 is a distribution build of an end-of-life Apache HTTP Server line",
    ]);
    const dir = mkdtempSync(join(tmpdir(), "penthera-introduced-"));
    try {
      writeFileSync(join(dir, "Dockerfile"), "FROM httpd:2.2\n");
      expect(verdicts(runtimeAdvisoriesForRepo(dir, opts))).toEqual(["high/likely: Apache HTTP Server 2.2 is end of life: no more security fixes"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    // Without `introduced`, an unlisted end-of-life line is still treated as affected.
    const noIntro = adv({ id: "x", product: "apache-httpd", title: "Other flaw", fixed: [{ branch: "2.4", version: "2.4.51" }] });
    const unlisted = runtimeAdvisoriesForResponse({ headers: { server: "Apache/2.2.34" } }, { advisories: [noIntro], eol: [httpdEol] });
    expect(unlisted).toHaveLength(1);
    expect(unlisted[0].advisories).toEqual(["x"]);
    expect(unlisted[0].description).toMatch(/Other flaw/);
  });

  it("reads nginx, OpenSSL and Python from Server banners, and not Tomcat as Apache", () => {
    const ev = evidenceFromResponse({ headers: { server: "Apache/2.4.58 (Unix) OpenSSL/3.0.13", "x-powered-by": "PHP/8.3.12" } });
    expect(ev.map((e) => `${e.product} ${e.version?.raw} ${e.kind}`)).toEqual(["php 8.3.12 exact", "apache-httpd 2.4.58 exact", "openssl 3.0.13 exact"]);
    expect(evidenceFromResponse({ headers: { server: "nginx/1.18.0 (Ubuntu)" } })).toMatchObject([{ product: "nginx", kind: "distro" }]);
    expect(evidenceFromResponse({ headers: { server: "Werkzeug/3.0.1 Python/3.12.1" } })).toMatchObject([{ product: "python", kind: "exact" }]);
    expect(evidenceFromResponse({ headers: { server: "Apache-Coyote/1.1" } })).toEqual([]);
  });
});

describe("white-box evidence and verdicts", () => {
  function repo(files) {
    const dir = mkdtempSync(join(tmpdir(), "penthera-runtime-"));
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(join(dir, rel, ".."), { recursive: true });
      writeFileSync(join(dir, rel), text);
    }
    return dir;
  }

  it("parses Docker image references", () => {
    expect(parseImageRef("php:8.3.12-fpm-alpine")).toMatchObject({ product: "php", kind: "exact" });
    expect(parseImageRef("docker.io/library/php:8.3-apache")).toMatchObject({ product: "php", kind: "branch" });
    expect(parseImageRef("node:20-alpine")).toMatchObject({ product: "nodejs", kind: "branch" });
    expect(parseImageRef("php:8")).toMatchObject({ product: "php", kind: "present" });
    expect(parseImageRef("php")).toMatchObject({ product: "php", kind: "present", tag: "latest" });
    expect(parseImageRef("python@sha256:abc")).toMatchObject({ product: "python", kind: "present" });
    expect(parseImageRef("bitnami/php-fpm:8.3")).toBeNull();
    expect(parseImageRef("ghcr.io/acme/php:8.3.1")).toBeNull();
  });

  it("reads Dockerfiles, compose files, version files and composer.json", () => {
    const dir = repo({
      Dockerfile: "FROM --platform=linux/amd64 php:8.3.12-fpm AS app\nFROM node:${NODE_VERSION}\n",
      "docker/web.Dockerfile": "FROM nginx:1.27.2-alpine\n",
      "compose.yaml": "services:\n  db:\n    image: \"python:3.12.1-slim\"\n",
      ".tool-versions": "nodejs 20.11.1\n# php 7.4\n",
      ".php-version": "8.3\n",
      "composer.json": JSON.stringify({ require: { php: "^8.1" } }),
      "node_modules/x/Dockerfile": "FROM php:5.6\n",
    });
    try {
      const ev = evidenceFromRepo(dir).map((e) => `${e.where}: ${e.product} ${e.version?.raw ?? "-"} ${e.kind}`).sort();
      expect(ev).toEqual([
        ".php-version: php 8.3 branch",
        ".tool-versions: nodejs 20.11.1 exact",
        "Dockerfile: php 8.3.12 exact",
        "compose.yaml: python 3.12.1 exact",
        "composer.json: php - present",
        "docker/web.Dockerfile: nginx 1.27.2 exact",
      ]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("resolves Node.js LTS codenames in .nvmrc and image tags to their line", () => {
    // Strings from bench/runtime-strings (docs/research/runtime-strings.md, B4).
    expect(parseImageRef("node:iron")).toMatchObject({ product: "nodejs", kind: "branch", version: { major: 20 } });
    expect(parseImageRef("node:jod-alpine")).toMatchObject({ product: "nodejs", kind: "branch", version: { major: 22 } });
    expect(parseImageRef("node:lts")).toMatchObject({ product: "nodejs", kind: "present" });
    expect(parseImageRef("node:constructor")).toMatchObject({ product: "nodejs", kind: "present" });
    const nodeEol = eolRule({ product: "nodejs", source: "https://nodejs.org/en/about/previous-releases", branches: [{ branch: "18", eol: "2025-04-30" }, { branch: "20", eol: "2026-04-30" }] });
    const dir = mkdtempSync(join(tmpdir(), "penthera-codenames-"));
    try {
      writeFileSync(join(dir, ".nvmrc"), "lts/iron\n");
      mkdirSync(join(dir, "api"));
      writeFileSync(join(dir, "api", "Dockerfile"), "FROM node:hydrogen-alpine\n");
      expect(verdicts(runtimeAdvisoriesForRepo(dir, { advisories: [], eol: [nodeEol] })).sort()).toEqual([
        "high/likely: Node.js 18 is end of life: no more security fixes",
        "high/likely: Node.js 20 is end of life: no more security fixes",
      ]);
      writeFileSync(join(dir, ".nvmrc"), "lts/*\n");
      expect(evidenceFromRepo(dir).find((e) => e.where === ".nvmrc")).toMatchObject({ kind: "present" });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a pinned image below the fix is affected; a floating tag is 'check'", () => {
    const dir = repo({ Dockerfile: "FROM php:8.3.12-apache\n", "worker/Dockerfile": "FROM php:8.4-cli\n" });
    try {
      const f = runtimeAdvisoriesForRepo(dir, rules);
      expect(verdicts(f)).toEqual([
        "critical/likely: PHP 8.3.12 is affected by Test RCE in PHP",
        "medium/needs-human-review: PHP 8.4 in use: check whether it is affected by Test RCE in PHP",
      ]);
      expect(f[0].url).toBe("Dockerfile");
      expect(f[1].description).toMatch(/only the release line \(8\.4\) is pinned/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("the same version in several files is one finding that lists every place", () => {
    const dir = repo({ Dockerfile: "FROM php:8.3.12\n", "compose.yaml": "services:\n  a:\n    image: php:8.3.12\n" });
    try {
      const f = matchRuntimeAdvisories(evidenceFromRepo(dir), rules);
      expect(f).toHaveLength(1);
      expect(f[0].description).toMatch(/Dockerfile, compose\.yaml|compose\.yaml, Dockerfile/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("bundled pack", () => {
  it("every runtime rule cites an https source and the advisories pack is active", () => {
    const all = [...rulesOf("runtime-advisory"), ...rulesOf("runtime-eol")];
    expect(all.length).toBeGreaterThan(0);
    for (const r of all) expect(r.source).toMatch(/^https:\/\//);
  });

  it("the October 2026 PHP release: below the fix is affected, at the fix patched, 8.1 end of life", () => {
    const rules = (v) => runtimeAdvisoriesForResponse({ headers: { "x-powered-by": `PHP/${v}` } }).filter((f) => /^php-cve-2026-10961[89]/.test(f.rule || ""));
    for (const v of ["8.2.34", "8.3.35", "8.4.26", "8.5.11"]) {
      expect(rules(v).map((f) => [f.rule, f.severity, f.confidence]), v).toEqual([
        ["php-cve-2026-109618", "critical", "potential"],
        ["php-cve-2026-109619", "critical", "potential"],
      ]);
    }
    for (const v of ["8.2.35", "8.3.36", "8.4.27", "8.5.12"]) expect(rules(v), v).toEqual([]);
    const old = runtimeAdvisoriesForResponse({ headers: { "x-powered-by": "PHP/8.1.34" } });
    expect(old.some((f) => f.rule === "php-eol" && f.advisories?.includes("php-cve-2026-109618"))).toBe(true);
    // A distro build stays "check on server".
    const deb = runtimeAdvisoriesForResponse({ headers: { "x-powered-by": "PHP/8.3.6-1ubuntu1.4" } });
    expect(deb.every((f) => f.severity !== "critical")).toBe(true);
  });

  it("agrees with OpenAI's php2shell-checker on every branch it lists", () => {
    // An independent implementation of the same check, published 2026-10-21:
    // https://github.com/openai/php2shell-checker/blob/40a4746ec4925d4d7510b99f9e134277918b1ac3/skills/phpcheck-url/scripts/phpcheck.js
    // Its VULNERABLE_THROUGH table, "as of 2026-10-20": the last vulnerable patch per branch.
    const VULNERABLE_THROUGH = {
      "5.4": 45, "5.5": 38, "5.6": 40,
      "7.0": 33, "7.1": 33, "7.2": 34, "7.3": 33, "7.4": 33,
      "8.0": 30, "8.1": 34, "8.2": 34, "8.3": 35, "8.4": 26, "8.5": 11,
    };
    // An end-of-life line's unfixed advisories are listed in its one finding.
    const cves = (v) => runtimeAdvisoriesForResponse({ headers: { "x-powered-by": `PHP/${v}` } })
      .flatMap((f) => [f.rule, ...(f.advisories || [])]).filter((r) => /^php-cve-2026-10961[89]$/.test(r || "")).sort();
    for (const [branch, last] of Object.entries(VULNERABLE_THROUGH)) {
      // Their "vulnerable" is our "affected", or "on an end-of-life line with no fix".
      expect(cves(`${branch}.${last}`), `${branch}.${last}`).toEqual(["php-cve-2026-109618", "php-cve-2026-109619"]);
    }
    // Where PHP shipped a fix, the next patch is clean in both tools.
    for (const branch of ["8.2", "8.3", "8.4", "8.5"]) {
      const next = `${branch}.${VULNERABLE_THROUGH[branch] + 1}`;
      expect(cves(next), next).toEqual([]);
    }
  });

  it("the October 2026 Node.js release: below the fix is affected, at the fix patched, 20 and 25 end of life", () => {
    // https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
    const NODE_2026_10 = ["nodejs-cve-2026-111497", "nodejs-tls-hostname-2026-10"];
    const dir = mkdtempSync(join(tmpdir(), "penthera-node-adv-"));
    const scan = (v) => {
      writeFileSync(join(dir, ".nvmrc"), `${v}\n`);
      return runtimeAdvisoriesForRepo(dir).filter((f) => NODE_2026_10.includes(f.rule));
    };
    try {
      for (const v of ["22.23.3", "24.22.0", "26.12.0"]) {
        expect(scan(v).map((f) => [f.rule, f.severity, f.confidence]), v).toEqual([
          ["nodejs-cve-2026-111497", "high", "likely"],
          ["nodejs-tls-hostname-2026-10", "high", "likely"],
        ]);
      }
      for (const v of ["22.23.4", "24.22.1", "26.12.1", "26.13.0"]) expect(scan(v), v).toEqual([]);
      for (const v of ["20.20.2", "25.9.0"]) {
        // One end-of-life finding that lists both advisories, not one row each.
        writeFileSync(join(dir, ".nvmrc"), `${v}\n`);
        const all = runtimeAdvisoriesForRepo(dir);
        expect(all.filter((f) => f.rule === "nodejs-eol").map((f) => [...f.advisories].sort()), v).toEqual([NODE_2026_10]);
        expect(scan(v), v).toEqual([]);
      }
      // Only the release line pinned: check, not affected.
      writeFileSync(join(dir, ".nvmrc"), "24\n");
      expect(runtimeAdvisoriesForRepo(dir).filter((f) => NODE_2026_10.includes(f.rule)).every((f) => f.confidence === "needs-human-review")).toBe(true);
      const rce = rulesOf("runtime-advisory").find((r) => r.id === "nodejs-cve-2026-111497");
      expect(rce.fixed).toEqual([{ branch: "22", version: "22.23.4" }, { branch: "24", version: "24.22.1" }, { branch: "26", version: "26.12.1" }]);
      expect(rce.source).toBe("https://nodejs.org/en/blog/vulnerability/october-2026-security-releases");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("the worked examples behave as documented", () => {
    const one = (headers) => verdicts(runtimeAdvisoriesForResponse({ headers }));
    // CVE-2021-41773 / CVE-2021-42013: Apache 2.4.49 and 2.4.50 only, and only
    // with a non-default access config, so at most potential.
    expect(one({ server: "Apache/2.4.49 (Unix)" }).some((v) => /^critical\/potential: .*2\.4\.49 is affected by Path traversal/.test(v))).toBe(true);
    expect(one({ server: "Apache/2.4.50 (Unix)" }).some((v) => /2\.4\.50 is affected by Path traversal/.test(v))).toBe(true);
    expect(one({ server: "Apache/2.4.48 (Unix)" }).some((v) => /affected by Path traversal/.test(v))).toBe(false);
    // CVE-2024-4577 needs Windows and PHP-CGI, so it is at most potential; php-src rates it High.
    const cgi = runtimeAdvisoriesForResponse({ headers: { "x-powered-by": "PHP/8.3.7" } }).find((f) => f.rule === "php-cve-2024-4577");
    expect(cgi).toMatchObject({ severity: "high", confidence: "potential" });
    expect(cgi.description).toMatch(/Known Exploited Vulnerabilities catalog, added 2024-06-12/);
  });
});
