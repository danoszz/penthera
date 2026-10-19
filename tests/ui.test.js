/**
 * `penthera ui` (src/ui): the local dashboard is an attack surface, so most of
 * these tests are about the gate: Host (DNS rebinding), the one-time token and
 * session cookie, Origin on state changes, CSP and other headers, no CORS, and
 * path traversal on the static route. Then the data confinement and the run
 * manager's approval flow.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { request as httpRequest } from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, symlinkSync, rmSync, realpathSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { startUiServer, loadStatic, STATIC_DIR } from "../src/ui/server.js";
import { CSP, hostAllowed, originAllowed, createSession, readCookie, COOKIE_NAME } from "../src/ui/security.js";
import { createDataSource, confineDir, isInside, writeNewFile, assertNoSymlinks } from "../src/ui/api/data.js";
import { validateRunRequest, createRunManager, RunError, cleanLine } from "../src/ui/api/runs.js";
import { classify, buildOverview, buildFindings } from "../src/ui/api/summarize.js";
import { writeEvidenceBundle } from "../src/report/evidence.js";
import { scanUrl } from "../src/scan-url.js";
import { resolveScanOptions } from "../src/cli/profiles.js";

const temps = [];
const tempDir = (p = "penthera-ui-") => { const d = mkdtempSync(join(tmpdir(), p)); temps.push(d); return d; };
afterAll(() => temps.forEach((d) => rmSync(d, { recursive: true, force: true })));

/** Raw HTTP so paths like /../x reach the server unnormalised and headers are exact. */
function raw(port, { method = "GET", path = "/", headers = {}, body = null } = {}) {
  return new Promise((resolveReq, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, method, path, headers: { Host: `127.0.0.1:${port}`, ...headers } }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolveReq({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf-8") }));
    });
    req.on("error", reject);
    if (body != null) req.write(body);
    req.end();
  });
}

async function signIn(ui) {
  const bootstrap = new URL(ui.url).searchParams.get("token");
  const r = await raw(ui.port, { path: `/?token=${bootstrap}` });
  const cookie = String(r.headers["set-cookie"]?.[0] || "").split(";")[0];
  return { r, cookie };
}

describe("ui server: binding, token and session", () => {
  let ui;
  let cookie;
  beforeAll(async () => {
    ui = await startUiServer({ demo: true, version: "test" });
    ({ cookie } = await signIn(ui));
  });
  afterAll(() => ui?.close());

  it("listens on 127.0.0.1 only, on a random port", () => {
    expect(ui.server.address().address).toBe("127.0.0.1");
    expect(ui.port).toBeGreaterThan(0);
    expect(ui.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/\?token=[A-Za-z0-9_-]{43}$/);
  });

  it("refuses every route without the session cookie", async () => {
    const fresh = await startUiServer({ demo: true });
    try {
      for (const path of ["/", "/index.html", "/js/app.js", "/api/meta", "/api/findings"]) {
        expect((await raw(fresh.port, { path })).status).toBe(401);
      }
    } finally { await fresh.close(); }
  });

  it("swaps the one-time token for an HttpOnly, SameSite=Strict cookie and redirects off the token URL", async () => {
    const fresh = await startUiServer({ demo: true });
    try {
      const { r, cookie: c } = await signIn(fresh);
      expect(r.status).toBe(303);
      expect(r.headers.location).toBe("/");
      const set = r.headers["set-cookie"][0];
      expect(set).toMatch(/HttpOnly/);
      expect(set).toMatch(/SameSite=Strict/);
      expect(set).toMatch(/Path=\//);
      expect(c).toMatch(new RegExp(`^${COOKIE_NAME}=`));
      // The cookie value is not the URL token.
      expect(c.split("=")[1]).not.toBe(new URL(fresh.url).searchParams.get("token"));
      expect((await raw(fresh.port, { path: "/api/meta", headers: { Cookie: c } })).status).toBe(200);
    } finally { await fresh.close(); }
  });

  it("the URL token works once; a wrong token or a forged cookie is refused", async () => {
    const fresh = await startUiServer({ demo: true });
    try {
      const token = new URL(fresh.url).searchParams.get("token");
      expect((await raw(fresh.port, { path: `/?token=${token}x` })).status).toBe(403);
      expect((await raw(fresh.port, { path: `/?token=${token}` })).status).toBe(303);
      expect((await raw(fresh.port, { path: `/?token=${token}` })).status).toBe(403);
      expect((await raw(fresh.port, { path: "/api/meta", headers: { Cookie: `${COOKIE_NAME}=${token}` } })).status).toBe(401);
      expect((await raw(fresh.port, { path: "/api/meta", headers: { Cookie: `${COOKIE_NAME}=` } })).status).toBe(401);
    } finally { await fresh.close(); }
  });

  it("session helpers compare in constant time and parse cookies exactly", () => {
    const s = createSession({ bootstrap: "boot", mint: () => "sec" });
    expect(s.check(`${COOKIE_NAME}=sec`)).toBe(false); // nothing is valid before the link is redeemed
    expect(s.redeem("boo")).toBeNull();
    expect(s.redeem("boot")).toBe("sec");
    expect(s.redeem("boot")).toBeNull();
    expect(s.check(`a=b; ${COOKIE_NAME}=sec`)).toBe(true);
    expect(s.check(`${COOKIE_NAME}=sec2`)).toBe(false);
    expect(s.check(`x${COOKIE_NAME}=sec`)).toBe(false);
    expect(s.cookie("sec")).toBe(`${COOKIE_NAME}=sec; HttpOnly; SameSite=Strict; Path=/`);
    expect(readCookie("a=1; b=2", "b")).toBe("2");
  });

  it("rate-limits requests without a session (429 + Retry-After), never the signed-in browser", async () => {
    const fresh = await startUiServer({ demo: true, limits: { maxReads: 3, maxWrites: 2 } });
    try {
      const { cookie: c } = await signIn(fresh);
      const post = () => raw(fresh.port, { method: "POST", path: "/api/login", body: "{}", headers: { "Content-Type": "application/json" } });
      expect((await post()).status).toBe(401);
      expect((await post()).status).toBe(401);
      const limited = await post();
      expect(limited.status).toBe(429);
      expect(Number(limited.headers["retry-after"])).toBeGreaterThan(0);
      for (let i = 0; i < 4; i++) await raw(fresh.port, { path: "/api/meta" });
      expect((await raw(fresh.port, { path: "/api/meta" })).status).toBe(429);
      expect((await raw(fresh.port, { path: "/api/meta", headers: { Cookie: c } })).status).toBe(200);
    } finally { await fresh.close(); }
  });

  describe("Host header (DNS rebinding)", () => {
    it("accepts 127.0.0.1:<port> and localhost:<port>", async () => {
      expect((await raw(ui.port, { path: "/api/meta", headers: { Cookie: cookie } })).status).toBe(200);
      expect((await raw(ui.port, { path: "/api/meta", headers: { Cookie: cookie, Host: `localhost:${ui.port}` } })).status).toBe(200);
    });

    it("refuses any other Host, even with a valid session", async () => {
      for (const host of ["evil.example", `evil.example:${ui.port}`, "127.0.0.1", `127.0.0.1:${ui.port + 1}`, `127.0.0.1:${ui.port}.evil.example`, `[::1]:${ui.port}`, `0.0.0.0:${ui.port}`, `localhost.evil.example:${ui.port}`]) {
        const r = await raw(ui.port, { path: "/api/meta", headers: { Cookie: cookie, Host: host } });
        expect(r.status, host).toBe(421);
        expect(r.body).not.toMatch(/"version"/);
      }
    });

    it("checks Host before the token, so a rebinding page cannot redeem it", async () => {
      const fresh = await startUiServer({ demo: true });
      try {
        const token = new URL(fresh.url).searchParams.get("token");
        expect((await raw(fresh.port, { path: `/?token=${token}`, headers: { Host: `attacker.example:${fresh.port}` } })).status).toBe(421);
        expect((await raw(fresh.port, { path: `/?token=${token}` })).status).toBe(303); // still unused
      } finally { await fresh.close(); }
    });

    it("hostAllowed is an exact match", () => {
      expect(hostAllowed("127.0.0.1:5000", 5000)).toBe(true);
      expect(hostAllowed("LOCALHOST:5000", 5000)).toBe(true);
      expect(hostAllowed("127.0.0.1:50000", 5000)).toBe(false);
      expect(hostAllowed(undefined, 5000)).toBe(false);
    });
  });

  describe("Origin on state-changing requests", () => {
    const post = (headers, body = '{"offline":true}') => raw(ui.port, {
      method: "POST", path: "/api/settings", body,
      headers: { Cookie: cookie, "Content-Type": "application/json", ...headers },
    });

    it("accepts this server's own origin", async () => {
      expect((await post({ Origin: `http://127.0.0.1:${ui.port}` })).status).toBe(200);
      expect((await post({ Origin: `http://localhost:${ui.port}`, "Sec-Fetch-Site": "same-origin" })).status).toBe(200);
    });

    it("refuses a missing, foreign or null Origin, and cross-site fetch metadata", async () => {
      for (const h of [{}, { Origin: "https://evil.example" }, { Origin: "null" }, { Origin: `http://127.0.0.1:${ui.port + 1}` }, { Origin: `https://127.0.0.1:${ui.port}` },
        { Origin: `http://127.0.0.1:${ui.port}`, "Sec-Fetch-Site": "cross-site" }]) {
        const r = await post(h);
        expect(r.status, JSON.stringify(h)).toBe(403);
      }
    });

    it("refuses non-JSON bodies (no simple cross-site form posts)", async () => {
      const r = await post({ Origin: `http://127.0.0.1:${ui.port}`, "Content-Type": "text/plain" });
      expect(r.status).toBe(415);
      const f = await post({ Origin: `http://127.0.0.1:${ui.port}`, "Content-Type": "application/x-www-form-urlencoded" }, "offline=false");
      expect(f.status).toBe(415);
    });

    it("originAllowed lets GETs through and checks every unsafe method", () => {
      expect(originAllowed({ method: "GET", headers: {} }, 1)).toBe(true);
      for (const method of ["POST", "PUT", "PATCH", "DELETE"]) expect(originAllowed({ method, headers: {} }, 1)).toBe(false);
    });
  });

  describe("headers: CSP, framing, no CORS", () => {
    it("sends the strict CSP and friends on every kind of response", async () => {
      const responses = [
        await raw(ui.port, { path: "/", headers: { Cookie: cookie } }),
        await raw(ui.port, { path: "/js/app.js", headers: { Cookie: cookie } }),
        await raw(ui.port, { path: "/api/overview", headers: { Cookie: cookie } }),
        await raw(ui.port, { path: "/nope", headers: { Cookie: cookie } }),
        await raw(ui.port, { path: "/api/meta" }),
        await raw(ui.port, { path: "/", headers: { Host: "evil.example" } }),
      ];
      for (const r of responses) {
        const csp = r.headers["content-security-policy"];
        expect(csp).toBe(CSP);
        expect(csp).toMatch(/default-src 'self'/);
        expect(csp).toMatch(/script-src 'self'(;|$)/);
        expect(csp).toMatch(/frame-ancestors 'none'/);
        expect(csp).not.toMatch(/unsafe-inline|unsafe-eval|\*/);
        expect(r.headers["x-frame-options"]).toBe("DENY");
        expect(r.headers["x-content-type-options"]).toBe("nosniff");
        expect(r.headers["referrer-policy"]).toBe("no-referrer");
        expect(r.headers["cache-control"]).toBe("no-store");
        expect(r.headers["access-control-allow-origin"]).toBeUndefined();
        expect(r.headers["access-control-allow-credentials"]).toBeUndefined();
      }
    });

    it("answers CORS preflights with 405 and no CORS headers", async () => {
      const r = await raw(ui.port, { method: "OPTIONS", path: "/api/runs", headers: { Origin: "https://evil.example", "Access-Control-Request-Method": "POST" } });
      expect(r.status).toBe(405);
      expect(Object.keys(r.headers).some((k) => k.startsWith("access-control-"))).toBe(false);
    });

    it("the page has no inline script, inline handlers, inline styles or innerHTML", () => {
      const html = readFileSync(join(STATIC_DIR, "index.html"), "utf-8");
      const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\b[^>]*>/gi)];
      expect(html.match(/<script\b/gi).length).toBe(scripts.length); // every opening tag is matched above
      expect(scripts.length).toBe(2); // theme.js (classic, before paint) and the app module
      for (const [, attrs, body] of scripts) {
        expect(attrs).toMatch(/\bsrc="\/[^"]+"/);
        expect(body.trim()).toBe("");
      }
      expect(html).not.toMatch(/\son[a-z]+\s*=/i);
      expect(html).not.toMatch(/\sstyle\s*=/i);
      expect(html).not.toMatch(/<style/i);
      expect(html).not.toMatch(/https?:\/\/(?!www\.w3\.org)/); // nothing external
      const js = readdirSync(join(STATIC_DIR, "js"), { recursive: true }).filter((f) => f.endsWith(".js"));
      for (const f of js) {
        const src = readFileSync(join(STATIC_DIR, "js", f), "utf-8");
        expect(src, f).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function/);
        expect(src, f).not.toMatch(/https?:\/\/(?!www\.w3\.org|localhost|127\.0\.0\.1|\$\{)/); // no external hosts
      }
      const css = readFileSync(join(STATIC_DIR, "app.css"), "utf-8");
      expect(css).not.toMatch(/@import|url\(\s*["']?https?:/);
    });
  });

  describe("static route: path traversal", () => {
    const attempts = [
      "/../package.json", "/..%2fpackage.json", "/%2e%2e/package.json", "/%2e%2e%2fpackage.json",
      "/js/../../server.js", "/js/..%2f..%2fserver.js", "/js/%2e%2e/%2e%2e/server.js", "/..\\server.js",
      "//etc/passwd", "/%2f%2fetc%2fpasswd", "/js/app.js%00.png", "/js/app.js/..", "/../../../../etc/passwd",
      "/server.js", "/api/../server.js", "/static/index.html", "/.%2e/.%2e/package.json", "/js/./app.js",
    ];

    it("serves only allowlisted files and 404s every traversal attempt", async () => {
      for (const path of attempts) {
        const r = await raw(ui.port, { path, headers: { Cookie: cookie } });
        expect([400, 404], path).toContain(r.status);
        expect(r.body, path).not.toMatch(/"name": "penthera"|root:|startUiServer|import /);
      }
    });

    it("the allowlist holds exactly the files under src/ui/static", () => {
      const files = loadStatic();
      for (const p of files.keys()) expect(p.startsWith("/") && !p.includes("..")).toBe(true);
      expect(files.has("/index.html")).toBe(true);
      expect(files.has("/js/app.js")).toBe(true);
      expect([...files.keys()].some((p) => /server|api\//.test(p))).toBe(false);
    });

    it("serves real files with the right type", async () => {
      const r = await raw(ui.port, { path: "/js/app.js", headers: { Cookie: cookie } });
      expect(r.status).toBe(200);
      expect(r.headers["content-type"]).toMatch(/^text\/javascript/);
    });
  });

  describe("API (demo data)", () => {
    const get = (path) => raw(ui.port, { path, headers: { Cookie: cookie } }).then((r) => ({ ...r, json: JSON.parse(r.body) }));

    it("every screen's endpoint answers", async () => {
      for (const path of ["/api/meta", "/api/overview", "/api/findings", "/api/deps", "/api/ai", "/api/memory", "/api/evidence", "/api/settings", "/api/runs"]) {
        const r = await get(path);
        expect(r.status, path).toBe(200);
      }
      const o = (await get("/api/overview")).json;
      expect(o.projects.length).toBe(4);
      expect(o.mix.critical).toBeGreaterThan(0);
    });

    it("finding detail includes sources and a fix diff; unknown ids 404", async () => {
      const { findings } = (await get("/api/findings")).json;
      const csp = findings.find((f) => /Content-Security-Policy/.test(f.title));
      const d = (await get(`/api/findings/${csp.id}?project=${encodeURIComponent(csp.project)}`)).json;
      expect(d.fix.diff).toMatch(/Content-Security-Policy/);
      expect((await get("/api/findings/0000000000000000")).status).toBe(404);
      expect([400, 404]).toContain((await raw(ui.port, { path: "/api/findings/../meta", headers: { Cookie: cookie } })).status);
    });

    it("history compares two scans: new, fixed, still open", async () => {
      const r = await get(`/api/history?project=${encodeURIComponent("http://localhost:3000")}`);
      expect(r.status).toBe(200);
      expect(r.json.scans.length).toBeGreaterThan(1);
      expect(r.json.b.i).toBe(r.json.scans.length - 1);
      expect(r.json.fixed.length + r.json.new.length + r.json.still.length).toBeGreaterThan(0);
      const first = await get(`/api/history?project=${encodeURIComponent("http://localhost:3000")}&a=0&b=${r.json.b.i}`);
      expect(first.json.fixed.length).toBeGreaterThan(r.json.fixed.length);
      expect((await get("/api/history?project=nope")).status).toBe(404);
      // The timeline: one lifetime per finding, open ones reach the latest scan.
      const life = r.json.lifetimes;
      expect(life.length).toBeGreaterThan(0);
      for (const l of life) {
        expect(l.from).toBeLessThanOrEqual(l.to);
        expect(l.open).toBe(l.to === r.json.scans.length - 1);
      }
      expect(life.some((l) => !l.open)).toBe(true);
    });

    it("overview has the This week columns: fix first, new, fixed", async () => {
      const { columns } = (await get("/api/overview")).json;
      expect(columns.fixFirst.every((f) => f.severity === "critical" || f.severity === "high")).toBe(true);
      expect(columns.fixFirst.length).toBeGreaterThan(0);
      expect(columns.newest.map((f) => f.title)).toContain("Open redirect via ?next=");
      expect(columns.fixed.length).toBeGreaterThan(0);
    });

    it("downloads the auditor report as a Markdown attachment", async () => {
      const r = await raw(ui.port, { path: `/api/report?project=${encodeURIComponent("http://localhost:3000")}&audience=auditor`, headers: { Cookie: cookie } });
      expect(r.status).toBe(200);
      expect(r.headers["content-type"]).toMatch(/^text\/markdown/);
      expect(r.headers["content-disposition"]).toMatch(/^attachment; filename="penthera-auditor-[a-z0-9-]+\.md"$/);
      expect(r.headers["content-security-policy"]).toBe(CSP);
      expect(r.body.length).toBeGreaterThan(200);
      expect((await raw(ui.port, { path: "/api/report?project=x&audience=auditor", headers: { Cookie: cookie } })).status).toBe(404);
      expect((await raw(ui.port, { path: `/api/report?project=${encodeURIComponent("http://localhost:3000")}&audience=root`, headers: { Cookie: cookie } })).status).toBe(404);
    });

    it("finding detail explains the finding in plain words", async () => {
      const { findings } = (await get("/api/findings")).json;
      const f = findings.find((x) => x.severity === "critical");
      const d = (await get(`/api/findings/${f.id}?project=${encodeURIComponent(f.project)}`)).json;
      expect(d.explain.plainSeverity).toBe("serious");
      expect(d.explain.confidenceMeaning).toMatch(/\w/);
    });

    it("unknown API routes 404 and wrong methods 405", async () => {
      expect((await get("/api/nope")).status).toBe(404);
      const r = await raw(ui.port, { method: "DELETE", path: "/api/settings", headers: { Cookie: cookie, Origin: `http://127.0.0.1:${ui.port}` } });
      expect(r.status).toBe(405);
    });
  });
});

describe("ui self-scan: penthera scans its own dashboard clean", () => {
  it("--profile standard finds nothing, with and without the session cookie", async () => {
    const ui = await startUiServer({ demo: true });
    try {
      const { cookie } = await signIn(ui);
      const profile = resolveScanOptions({ profile: "standard" });
      for (const authCookie of [null, cookie]) {
        const r = await scanUrl(ui.origin, { ...profile, offline: true, timeout: 5000, concurrency: 8, authCookie, onPhase: () => {} });
        expect(r.reachable).toBe(true);
        expect(r.findings.filter((f) => f.severity !== "info").map((f) => f.title), authCookie ? "signed in" : "anonymous").toEqual([]);
      }
    } finally { await ui.close(); }
  });
});

describe("ui data source: only the chosen folders", () => {
  it("confineDir accepts folders inside a root and refuses the rest, symlinks included", () => {
    const root = tempDir();
    const outside = tempDir();
    mkdirSync(join(root, "app"));
    symlinkSync(outside, join(root, "escape"));
    expect(confineDir("app", [realpathSync(root)])).toBe(realpathSync(join(root, "app")));
    const realRoot = realpathSync(root);
    expect(() => confineDir(outside, [realRoot])).toThrow(/outside the project folders/);
    expect(() => confineDir(join(realRoot, "escape"), [realRoot])).toThrow(/outside the project folders/);
    expect(() => confineDir(join(realRoot, ".."), [realRoot])).toThrow(/outside the project folders/);
    expect(() => confineDir(join(realRoot, "nope"), [realRoot])).toThrow(/not found/);
    expect(() => confineDir("a\0b", [realRoot])).toThrow();
  });

  it("isInside does not confuse sibling prefixes", () => {
    expect(isInside("/a/b", "/a/b/c")).toBe(true);
    expect(isInside("/a/b", "/a/bc")).toBe(false);
    expect(isInside("/a/b", "/a")).toBe(false);
  });

  it("reads reports from the reports folder, skips symlinks and non-reports, and verifies evidence bundles", async () => {
    const project = tempDir();
    const reports = join(project, "reports");
    mkdirSync(reports);
    const secret = join(tempDir(), "secret.json");
    writeFileSync(secret, JSON.stringify({ target: "http://leak.example", findings: [{ severity: "critical", title: "LEAKED" }] }));
    symlinkSync(secret, join(reports, "linked.json"));
    writeFileSync(join(reports, "package.json"), JSON.stringify({ name: "x" }));
    writeFileSync(join(reports, "a.json"), JSON.stringify({ target: "http://localhost:3000", mode: "url", timestamp: "2026-10-01T00:00:00Z", findings: [{ severity: "high", title: "Missing CSP", category: "headers" }, { severity: "low", title: "X-Powered-By" }] }));
    writeFileSync(join(reports, "b.json"), JSON.stringify({ target: "http://localhost:3000", mode: "url", timestamp: "2026-10-05T00:00:00Z", findings: [{ severity: "low", title: "X-Powered-By" }] }));
    const bundle = join(reports, "evidence", "one");
    writeEvidenceBundle(bundle, [{ path: "report.json", content: "{}\n" }], { target: "http://localhost:3000", version: "test", argv: [], generatedAt: "2026-10-05T00:00:00Z" });

    const src = createDataSource({ projects: [project], reportsDir: reports, home: tempDir(), memoryRoot: join(tempDir(), "memory"), settings: { get: () => ({}) } });
    const o = src.overview();
    expect(o.projects.map((p) => p.key)).toEqual(["http://localhost:3000"]);
    expect(o.open).toBe(1);
    expect(o.fixed).toBe(1);
    expect(JSON.stringify(src.findings())).not.toMatch(/LEAKED/);

    const [b] = src.evidence();
    expect(b.readable).toBe(true);

    // "Export evidence for an auditor": a new bundle from the latest report, inside the reports folder.
    const made = src.createEvidence("http://localhost:3000");
    expect(made.path).toMatch(/^evidence\/localhost-3000-/);
    expect(src.verifyEvidence(made.id).ok).toBe(true);
    expect(src.verifyEvidence(made.id).files.map((f) => f.path)).toEqual(expect.arrayContaining(["report.json", "report-auditor.md", "report.sarif"]));
    expect(src.createEvidence("http://nope")).toBeNull();
    expect(src.audienceReport("http://localhost:3000", "auditor")).toMatch(/\w/);
    expect(src.audienceReport("http://localhost:3000", "../../etc")).toBeNull();
    expect(src.history("http://localhost:3000").fixed.map((f) => f.title)).toEqual(["Missing CSP"]);
    expect(src.verifyEvidence(b.id).ok).toBe(true);
    writeFileSync(join(bundle, "report.json"), "{\"tampered\":true}\n");
    expect(src.verifyEvidence(b.id).ok).toBe(false);
    expect(src.verifyEvidence("ffffffffffffffff")).toBeNull();
  });

  it("writes into the reports folder only as new files, never through a symlink (same rule as lib/fix/apply.js)", () => {
    const project = realpathSync(tempDir());
    const reports = join(project, "reports");
    mkdirSync(reports);
    const outside = realpathSync(tempDir());

    expect(readFileSync(writeNewFile(reports, reports, "a.json", "{}\n"), "utf-8")).toBe("{}\n");
    expect(() => writeNewFile(reports, reports, "a.json", "x")).toThrow(/EEXIST/); // never overwrites
    for (const bad of ["../x.json", "a/b.json", "", "..", "a\0b"]) expect(() => writeNewFile(reports, reports, bad, "x")).toThrow();

    symlinkSync(join(outside, "target.json"), join(reports, "link.json"));
    expect(() => writeNewFile(reports, reports, "link.json", "x")).toThrow(/symlink/);
    expect(existsSync(join(outside, "target.json"))).toBe(false);

    // A planted reports/evidence -> elsewhere must not receive a bundle.
    symlinkSync(outside, join(reports, "evidence"));
    expect(() => assertNoSymlinks(reports, join(reports, "evidence", "x"))).toThrow(/symlink/);
    writeFileSync(join(reports, "s.json"), JSON.stringify({ target: "http://localhost:3000", mode: "url", timestamp: "2026-10-01T00:00:00Z", findings: [{ severity: "high", title: "x" }] }));
    const src = createDataSource({ projects: [project], reportsDir: reports, home: tempDir(), memoryRoot: join(tempDir(), "memory"), settings: { get: () => ({}) } });
    expect(() => src.createEvidence("http://localhost:3000")).toThrow(/symlink/);
    expect(readdirSync(outside)).toEqual([]);

    // Run reports and loop runs go through the same writer.
    expect(src.writeReport("deps_1.json", { mode: "deps" })).toBe("deps_1.json");
    expect(() => src.writeReport("../escape.json", {})).toThrow();
    expect(src.saveLoopRun({ startedAt: "2026-10-19T10:00:00.000Z" })).toMatch(/^loop-/);
  });

  it("classify recognises each report kind", () => {
    expect(classify({ loopRun: {} })).toBe("loop");
    expect(classify({ mode: "deps", deps: {} })).toBe("deps");
    expect(classify({ mode: "agents", agents: {} })).toBe("agents");
    expect(classify({ changes: [], specs: [], npm: {} })).toBe("install");
    expect(classify({ target: "x", findings: [] })).toBe("scan");
    expect(classify({ name: "pkg" })).toBeNull();
    expect(classify([])).toBeNull();
  });

  it("summaries keep finding text as data", () => {
    const scans = [{ name: "a.json", mtime: 1, data: { target: "http://x", timestamp: "2026-10-01T00:00:00Z", findings: [{ severity: "high", title: "<img src=x onerror=alert(1)>" }] } }];
    expect(buildFindings(scans)[0].title).toBe("<img src=x onerror=alert(1)>");
    expect(buildOverview({ scans }).open).toBe(1);
  });
});

describe("ui runs: authorization and the approval flow", () => {
  const root = tempDir();
  mkdirSync(join(root, "repo"));
  const roots = [realpathSync(root)];

  it("needs a repo inside the project folders for the loop", () => {
    expect(() => validateRunRequest({ kind: "loop" }, roots)).toThrow(/project folder/);
    expect(() => validateRunRequest({ kind: "loop", repo: tmpdir() }, roots)).toThrow(/outside the project folders/);
    expect(validateRunRequest({ kind: "loop", repo: join(root, "repo") }, roots).repo).toMatch(/repo$/);
    expect(() => validateRunRequest({ kind: "nope" }, roots)).toThrow(RunError);
    expect(() => validateRunRequest({ kind: "deps" }, roots)).toThrow(/package-lock/);
    expect(() => validateRunRequest({ kind: "agents", repo: join(root, "repo"), url: "http://localhost:3000" }, roots)).toThrow(/reads files only/);
    expect(validateRunRequest({ kind: "agents", repo: join(root, "repo") }, roots).kind).toBe("agents");
  });

  it("needs the hostname typed back for a URL that is not on this machine", () => {
    const base = { kind: "scan" };
    expect(validateRunRequest({ ...base, url: "http://localhost:3000" }, roots).url).toBe("http://localhost:3000");
    expect(validateRunRequest({ ...base, url: "127.0.0.1:8080" }, roots).url).toBe("http://127.0.0.1:8080");
    expect(validateRunRequest({ ...base, url: "http://app.localhost" }, roots).url).toBe("http://app.localhost");
    let err;
    try { validateRunRequest({ ...base, url: "https://staging.example.com" }, roots); } catch (e) { err = e; }
    expect(err.status).toBe(428);
    expect(() => validateRunRequest({ ...base, url: "https://staging.example.com", confirm: "example.com" }, roots)).toThrow(/Type the hostname/);
    expect(validateRunRequest({ ...base, url: "https://staging.example.com", confirm: " Staging.Example.com " }, roots).url).toBe("https://staging.example.com");
    expect(() => validateRunRequest({ ...base, url: "file:///etc/passwd" }, roots)).toThrow(/http and https/);
    expect(() => validateRunRequest({ ...base, url: "http://u:p@localhost" }, roots)).toThrow(/credentials/);
    expect(() => validateRunRequest({ kind: "loop", repo: join(root, "repo"), maxIterations: 99 }, roots)).toThrow(/1 to 50/);
  });

  it("streams loop output, waits for each decision, and stops cleanly", async () => {
    const asked = [];
    const runLoop = async ({ ask, log, signal }) => {
      log("  iteration 1/2");
      log("  scan: 3 findings (0 suppressed), 2 fixable");
      const a1 = await ask({ plan: { title: "Add headers \u001b[31m", recipe: "security-headers", files: ["a.js"], diff: "+x", findings: [] }, iteration: 1, index: 1, total: 2 });
      asked.push(a1);
      if (a1 === "y") log("    verified and committed abc1234567");
      const a2 = await ask({ plan: { title: "Cookies", recipe: "cookie-flags", files: ["b.js"], diff: "+y", findings: [] }, iteration: 1, index: 2, total: 2 });
      asked.push(a2);
      return { stopReason: signal.aborted ? "interrupted" : "user-quit", error: null, totals: { iterations: 1, verified: 1 }, findings: {}, branch: { fix: "penthera/fix-x" }, durationMs: 5, iterations: [] };
    };
    const saved = [];
    const mgr = createRunManager({ runLoop, saveLoopRun: (l) => { saved.push(l); return "loop.json"; }, settings: () => ({ offline: true }), projectRoots: roots });
    const run = mgr.start({ kind: "loop", repo: join(root, "repo") });
    expect(() => mgr.start({ kind: "loop", repo: join(root, "repo") })).toThrow(/already in progress/);

    const events = [];
    await new Promise((done) => mgr.subscribe(run.id, 0, (ev) => { if (ev) events.push(ev); if (ev?.type === "approval") done(); }));
    const first = events.find((e) => e.type === "approval").data;
    expect(first.plan.title).toBe("Add headers "); // terminal escapes stripped
    expect(() => mgr.decide(run.id, { approvalId: "wrong", answer: "approve" })).toThrow(/Nothing is waiting/);
    expect(() => mgr.decide(run.id, { approvalId: first.approvalId, answer: "rm -rf" })).toThrow(/approve, skip or stop/);
    mgr.decide(run.id, { approvalId: first.approvalId, answer: "approve" });

    const ended = new Promise((done) => mgr.subscribe(run.id, events.length, (ev) => { if (!ev) done(); else events.push(ev); }));
    await new Promise((r) => setTimeout(r, 10));
    mgr.stop(run.id);
    await ended;
    expect(asked).toEqual(["y", "quit"]);
    expect(events.some((e) => e.type === "iteration" && e.data.n === 1)).toBe(true);
    expect(events.some((e) => e.type === "fix" && e.data.status === "verified")).toBe(true);
    expect(mgr.get(run.id).status).toBe("stopped");
    expect(saved).toHaveLength(1);
  });

  it("cleanLine strips terminal escapes and control characters", () => {
    expect(cleanLine("\u001b[2Jhi\u0007 there\u009b")).toBe("hi there");
  });
});
