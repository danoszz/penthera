/**
 * `penthera ui` (src/ui): the local dashboard is an attack surface, so most of
 * these tests are about the gate: Host (DNS rebinding), the one-time token and
 * bearer session (no cookie), Origin on state changes, CSP and other headers, no CORS, and
 * path traversal on the static route. Then the data confinement and the run
 * manager's approval flow.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { request as httpRequest } from "node:http";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, symlinkSync, rmSync, realpathSync, existsSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { startUiServer, loadStatic, STATIC_DIR } from "../src/ui/server.js";
import { CSP, hostAllowed, originAllowed, createSession } from "../src/ui/security.js";
import { createDataSource, confineDir, isInside, writeNewFile, assertNoSymlinks } from "../src/ui/api/data.js";
import { validateRunRequest, createRunManager, RunError, cleanLine } from "../src/ui/api/runs.js";
import { classify, buildOverview, buildFindings } from "../src/ui/api/summarize.js";
import { writeEvidenceBundle } from "../src/report/evidence.js";
import { scanUrl } from "../src/scan-url.js";
import { resolveScanOptions } from "../src/cli/profiles.js";

/** What the page sends with an approval: the hex SHA-256 of the diff text it showed. */
const diffSha256 = (s) => createHash("sha256").update(s, "utf-8").digest("hex");

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

const bootstrapOf = (ui) => new URL(ui.url).hash.replace(/^#t=/, "");
const redeem = (ui, token, headers = {}) => raw(ui.port, {
  method: "POST", path: "/api/session", body: JSON.stringify({ token }),
  headers: { "Content-Type": "application/json", Origin: `http://127.0.0.1:${ui.port}`, ...headers },
});

/** Sign in the way the page does; returns the Authorization header value. */
async function signIn(ui) {
  const r = await redeem(ui, bootstrapOf(ui));
  const sid = r.status === 200 ? JSON.parse(r.body).session : "";
  return { r, sid, auth: `Bearer ${sid}` };
}

describe("ui server: binding, token and session", () => {
  let ui;
  let auth;
  beforeAll(async () => {
    ui = await startUiServer({ demo: true, version: "test" });
    ({ auth } = await signIn(ui));
  });
  afterAll(() => ui?.close());

  it("listens on 127.0.0.1 only, on a random port, with the token in the URL fragment", () => {
    expect(ui.server.address().address).toBe("127.0.0.1");
    expect(ui.port).toBeGreaterThan(0);
    expect(ui.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/#t=[A-Za-z0-9_-]{43}$/);
  });

  it("serves the page without a session, but refuses every API route without one", async () => {
    const fresh = await startUiServer({ demo: true });
    try {
      for (const path of ["/", "/index.html", "/js/app.js"]) expect((await raw(fresh.port, { path })).status, path).toBe(200);
      for (const path of ["/api/meta", "/api/findings", "/api/runs", "/api/nope"]) expect((await raw(fresh.port, { path })).status, path).toBe(401);
    } finally { await fresh.close(); }
  });

  it("swaps the one-time token for a bearer session id, and never sets a cookie", async () => {
    const fresh = await startUiServer({ demo: true });
    try {
      const { r, sid, auth: a } = await signIn(fresh);
      expect(r.status).toBe(200);
      expect(r.headers["set-cookie"]).toBeUndefined();
      expect(sid).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(sid).not.toBe(bootstrapOf(fresh)); // the session id is not the URL token
      expect((await raw(fresh.port, { path: "/api/meta", headers: { Authorization: a } })).status).toBe(200);
    } finally { await fresh.close(); }
  });

  it("a valid session in a cookie is refused: only the Authorization header counts", async () => {
    const fresh = await startUiServer({ demo: true });
    try {
      const { sid } = await signIn(fresh);
      // Cookies are not bound to a port, so another 127.0.0.1 server could replay one.
      for (const name of ["penthera_ui", "session", "sid"]) {
        const r = await raw(fresh.port, { path: "/api/meta", headers: { Cookie: `${name}=${sid}` } });
        expect(r.status, name).toBe(401);
        expect(r.body).not.toMatch(/"version"/);
      }
      const post = await raw(fresh.port, {
        method: "POST", path: "/api/settings", body: '{"offline":false}',
        headers: { Cookie: `penthera_ui=${sid}`, Origin: `http://127.0.0.1:${fresh.port}`, "Content-Type": "application/json" },
      });
      expect(post.status).toBe(401);
      expect((await raw(fresh.port, { path: "/api/meta", headers: { Authorization: `Bearer ${sid}` } })).status).toBe(200);
      expect((await raw(fresh.port, { path: "/api/meta", headers: { Authorization: sid } })).status).toBe(401);
    } finally { await fresh.close(); }
  });

  it("the URL token works once; a wrong token or a forged session is refused", async () => {
    const fresh = await startUiServer({ demo: true });
    try {
      const token = bootstrapOf(fresh);
      expect((await redeem(fresh, `${token}x`)).status).toBe(403);
      expect((await redeem(fresh, token, { Origin: "https://evil.example" })).status).toBe(403); // sign-in is Origin-checked too
      expect((await redeem(fresh, token)).status).toBe(200);
      expect((await redeem(fresh, token)).status).toBe(403);
      expect((await raw(fresh.port, { path: "/api/meta", headers: { Authorization: `Bearer ${token}` } })).status).toBe(401);
      expect((await raw(fresh.port, { path: "/api/meta", headers: { Authorization: "Bearer " } })).status).toBe(401);
      // The old query-string link redeems nothing.
      expect((await raw(fresh.port, { path: `/?token=${token}` })).headers["set-cookie"]).toBeUndefined();
    } finally { await fresh.close(); }
  });

  it("session helpers compare in constant time and parse the header exactly", () => {
    const s = createSession({ bootstrap: "boot", mint: () => "sec-0123456789abcdef" });
    expect(s.check("Bearer sec-0123456789abcdef")).toBe(false); // nothing is valid before the link is redeemed
    expect(s.redeem("boo")).toBeNull();
    expect(s.redeem("boot")).toBe("sec-0123456789abcdef");
    expect(s.redeem("boot")).toBeNull();
    expect(s.check("Bearer sec-0123456789abcdef")).toBe(true);
    expect(s.check("Bearer sec-0123456789abcdeg")).toBe(false);
    expect(s.check("bearer sec-0123456789abcdef")).toBe(false);
    expect(s.check("Basic sec-0123456789abcdef")).toBe(false);
    expect(s.check(undefined)).toBe(false);
    expect(s.check("Bearer sec-0123456789abcdef x")).toBe(false);
  });

  it("rate-limits requests without a session (429 + Retry-After), never the signed-in browser", async () => {
    const fresh = await startUiServer({ demo: true, limits: { maxReads: 3, maxWrites: 2 } });
    try {
      const { auth: a } = await signIn(fresh);
      const post = () => raw(fresh.port, { method: "POST", path: "/api/login", body: "{}", headers: { "Content-Type": "application/json", Origin: fresh.origin } });
      expect((await post()).status).toBe(401);
      expect((await post()).status).toBe(401);
      const limited = await post();
      expect(limited.status).toBe(429);
      expect(Number(limited.headers["retry-after"])).toBeGreaterThan(0);
      for (let i = 0; i < 4; i++) await raw(fresh.port, { path: "/api/meta" });
      expect((await raw(fresh.port, { path: "/api/meta" })).status).toBe(429);
      expect((await raw(fresh.port, { path: "/api/meta", headers: { Authorization: a } })).status).toBe(200);
    } finally { await fresh.close(); }
  });

  it("guessing the sign-in token is rate-limited", async () => {
    const fresh = await startUiServer({ demo: true, limits: { maxReads: 3, maxWrites: 2 } });
    try {
      expect((await redeem(fresh, "x".repeat(43))).status).toBe(403);
      expect((await redeem(fresh, "y".repeat(43))).status).toBe(403);
      expect((await redeem(fresh, "z".repeat(43))).status).toBe(429);
    } finally { await fresh.close(); }
  });

  describe("Host header (DNS rebinding)", () => {
    it("accepts 127.0.0.1:<port> and localhost:<port>", async () => {
      expect((await raw(ui.port, { path: "/api/meta", headers: { Authorization: auth } })).status).toBe(200);
      expect((await raw(ui.port, { path: "/api/meta", headers: { Authorization: auth, Host: `localhost:${ui.port}` } })).status).toBe(200);
    });

    it("refuses any other Host, even with a valid session", async () => {
      for (const host of ["evil.example", `evil.example:${ui.port}`, "127.0.0.1", `127.0.0.1:${ui.port + 1}`, `127.0.0.1:${ui.port}.evil.example`, `[::1]:${ui.port}`, `0.0.0.0:${ui.port}`, `localhost.evil.example:${ui.port}`]) {
        const r = await raw(ui.port, { path: "/api/meta", headers: { Authorization: auth, Host: host } });
        expect(r.status, host).toBe(421);
        expect(r.body).not.toMatch(/"version"/);
      }
    });

    it("checks Host before the token, so a rebinding page cannot redeem it", async () => {
      const fresh = await startUiServer({ demo: true });
      try {
        const token = bootstrapOf(fresh);
        expect((await redeem(fresh, token, { Host: `attacker.example:${fresh.port}` })).status).toBe(421);
        expect((await redeem(fresh, token)).status).toBe(200); // still unused
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
      headers: { Authorization: auth, "Content-Type": "application/json", ...headers },
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
        await raw(ui.port, { path: "/", headers: { Authorization: auth } }),
        await raw(ui.port, { path: "/js/app.js", headers: { Authorization: auth } }),
        await raw(ui.port, { path: "/api/overview", headers: { Authorization: auth } }),
        await raw(ui.port, { path: "/nope", headers: { Authorization: auth } }),
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
        const r = await raw(ui.port, { path, headers: { Authorization: auth } });
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
      const r = await raw(ui.port, { path: "/js/app.js", headers: { Authorization: auth } });
      expect(r.status).toBe(200);
      expect(r.headers["content-type"]).toMatch(/^text\/javascript/);
    });

    it("serves the self-hosted font and the logo as static files, with no active content", async () => {
      const files = loadStatic();
      for (const p of ["/fonts/DepartureMono-Regular.woff2", "/logo.svg", "/mark.svg", "/favicon.svg"]) expect(files.has(p), p).toBe(true);
      // Static files hold no data and need no session; the API is where the session is checked.
      const font = await raw(ui.port, { path: "/fonts/DepartureMono-Regular.woff2" });
      expect(font.status).toBe(200);
      expect(font.headers["content-type"]).toBe("font/woff2");
      const logo = await raw(ui.port, { path: "/logo.svg" });
      expect(logo.headers["content-type"]).toMatch(/^image\/svg\+xml/);
      expect(logo.body).not.toMatch(/<script|on[a-z]+=|href=/i);
    });

    it("the stylesheet loads fonts and masks from this server only", () => {
      const css = readFileSync(join(STATIC_DIR, "app.css"), "utf-8");
      for (const [, u] of css.matchAll(/url\(\s*["']?([^"')]+)/g)) expect(u, u).toMatch(/^(\/|#)/);
    });
  });

  describe("API (demo data)", () => {
    const get = (path) => raw(ui.port, { path, headers: { Authorization: auth } }).then((r) => ({ ...r, json: JSON.parse(r.body) }));

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
      expect([400, 404]).toContain((await raw(ui.port, { path: "/api/findings/../meta", headers: { Authorization: auth } })).status);
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

    it("env reports the folder, branch and hosts for a project", async () => {
      const repo = (await get(`/api/env?project=${encodeURIComponent("/Users/demo/code/acme-shop")}`)).json;
      expect(repo.branch).toBe("main");
      expect(repo.fixBranches.every((b) => b.startsWith("penthera/fix-"))).toBe(true);
      const url = (await get(`/api/env?project=${encodeURIComponent("https://staging.acme.test")}`)).json;
      expect(url.folder).toBeNull();
      expect(url.hosts.some((x) => x.thirdParty)).toBe(true);
    });

    it("overview has the This week columns: fix first, new, fixed", async () => {
      const { columns } = (await get("/api/overview")).json;
      expect(columns.fixFirst.every((f) => f.severity === "critical" || f.severity === "high")).toBe(true);
      expect(columns.fixFirst.length).toBeGreaterThan(0);
      expect(columns.newest.map((f) => f.title)).toContain("Open redirect via ?next=");
      expect(columns.fixed.length).toBeGreaterThan(0);
    });

    it("downloads the auditor report as a Markdown attachment", async () => {
      const r = await raw(ui.port, { path: `/api/report?project=${encodeURIComponent("http://localhost:3000")}&audience=auditor`, headers: { Authorization: auth } });
      expect(r.status).toBe(200);
      expect(r.headers["content-type"]).toMatch(/^text\/markdown/);
      expect(r.headers["content-disposition"]).toMatch(/^attachment; filename="penthera-auditor-[a-z0-9-]+\.md"$/);
      expect(r.headers["content-security-policy"]).toBe(CSP);
      expect(r.body.length).toBeGreaterThan(200);
      expect((await raw(ui.port, { path: "/api/report?project=x&audience=auditor", headers: { Authorization: auth } })).status).toBe(404);
      expect((await raw(ui.port, { path: `/api/report?project=${encodeURIComponent("http://localhost:3000")}&audience=root`, headers: { Authorization: auth } })).status).toBe(404);
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
      const r = await raw(ui.port, { method: "DELETE", path: "/api/settings", headers: { Authorization: auth, Origin: `http://127.0.0.1:${ui.port}` } });
      expect(r.status).toBe(405);
    });
  });
});

describe("ui self-scan: penthera scans its own dashboard clean", () => {
  it("--profile standard finds nothing, with and without the session", async () => {
    const ui = await startUiServer({ demo: true });
    try {
      const { sid } = await signIn(ui);
      const profile = resolveScanOptions({ profile: "standard" });
      for (const authBearer of [null, sid]) {
        const r = await scanUrl(ui.origin, { ...profile, offline: true, timeout: 5000, concurrency: 8, authBearer, onPhase: () => {} });
        expect(r.reachable).toBe(true);
        // The session id is an opaque random token, not a JWT; the JWT probe's
        // note about that is about the scan's configuration, not the dashboard.
        const real = r.findings.filter((f) => f.severity !== "info" && f.source !== "jwt-probe");
        expect(real.map((f) => f.title), authBearer ? "signed in" : "anonymous").toEqual([]);
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

  it("env reads git through the safe runner, only for folders inside the project roots", () => {
    const project = realpathSync(tempDir());
    const g = (...a) => execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", ...a], { cwd: project, stdio: "ignore" });
    g("init", "-q", "-b", "main");
    writeFileSync(join(project, "a.txt"), "x");
    g("add", "-A");
    g("commit", "-qm", "init");
    g("branch", "penthera/fix-20261019-1200");
    const src = createDataSource({ projects: [project], reportsDir: join(project, "reports"), home: tempDir(), memoryRoot: join(tempDir(), "memory"), settings: { get: () => ({}) } });
    const env = src.env(project);
    expect(env.folder).toBe(project);
    expect(env.branch).toBe("main");
    expect(env.head).toMatch(/^[0-9a-f]{7,}$/);
    expect(env.fixBranches).toEqual(["penthera/fix-20261019-1200"]);
    expect(src.env(realpathSync(tmpdir())).folder).toBeNull(); // outside the roots: no git, no folder
    expect(src.env("http://localhost:3000").folder).toBeNull();
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
    mgr.decide(run.id, { approvalId: first.approvalId, answer: "approve", diffSha256: diffSha256(first.plan.diff) });

    // Stop while the second approval is pending: wait for it, not for a fixed delay.
    let secondAsked;
    const second = new Promise((r) => { secondAsked = r; });
    const ended = new Promise((done) => mgr.subscribe(run.id, events.length, (ev) => {
      if (!ev) return done();
      events.push(ev);
      if (ev.type === "approval" && ev.data.approvalId !== first.approvalId) secondAsked();
    }));
    await second;
    mgr.stop(run.id);
    await ended;
    expect(asked).toEqual(["y", "quit"]);
    expect(events.some((e) => e.type === "iteration" && e.data.n === 1)).toBe(true);
    expect(events.some((e) => e.type === "fix" && e.data.status === "verified")).toBe(true);
    expect(mgr.get(run.id).status).toBe("stopped");
    expect(saved).toHaveLength(1);
  });

  it("scans again after a loop that fixed something, and carries the verdict", async () => {
    const loopRun = { stopReason: "no-fixable-findings", error: null, totals: { iterations: 1, verified: 2 }, findings: {}, branch: { fix: "penthera/fix-x" }, durationMs: 5, iterations: [] };
    const reports = [];
    const mgr = createRunManager({
      runLoop: async () => loopRun, loopVerdict: () => ({ clean: false, headline: "2 fixed, 1 critical left." }),
      executeScan: async () => ({ merged: { findings: [] } }), writeReport: (merged, name) => { reports.push(name); return name; },
      saveLoopRun: () => "loop.json", settings: () => ({ offline: true }), projectRoots: roots,
    });
    const run = mgr.start({ kind: "loop", repo: join(root, "repo") });
    await new Promise((done) => mgr.subscribe(run.id, 0, (ev) => { if (!ev) done(); }));
    expect(reports).toHaveLength(1);
    expect(mgr.get(run.id).summary.verdict.headline).toBe("2 fixed, 1 critical left.");
  });

  it("forgets a waiting diff when a run ends or the view leaves it, so a replay opens no approval", () => {
    const center = readFileSync(resolve("src/ui/static/js/center.js"), "utf-8");
    expect(center.match(/export function stopStream\(\) \{[^}]*\}/)[0]).toMatch(/pending = null;/);
    expect(center.slice(center.indexOf('case "status": {'), center.indexOf("closeApproval();", center.indexOf('case "status": {')))).toMatch(/pending = null;/);
  });

  it("cleanLine strips terminal escapes and control characters", () => {
    expect(cleanLine("\u001b[2Jhi\u0007 there\u009b")).toBe("hi there");
  });
});

describe("ui stream: a run that already finished", () => {
  it("ends the event stream cleanly instead of throwing", async () => {
    const { stream } = await import("../src/ui/api/routes.js");
    const { EventEmitter } = await import("node:events");
    const req = new EventEmitter();
    req.headers = {};
    const written = [];
    const res = { writableEnded: false, writeHead() {}, write(s) { written.push(s); }, end() { this.writableEnded = true; } };
    let unsubscribed = 0;
    // Like the real manager for a finished run: replay, then fn(null), synchronously.
    const runs = { subscribe(_id, _after, fn) { fn({ seq: 1, type: "log", data: "done" }); fn(null); return () => { unsubscribed++; }; } };
    expect(() => stream(req, res, runs, "0123456789abcdef")).not.toThrow();
    expect(res.writableEnded).toBe(true);
    expect(written.join("")).toContain("event: end");
    expect(unsubscribed).toBe(1);
    req.emit("close"); // a late close must not unsubscribe or end twice
    expect(unsubscribed).toBe(1);
  });
});

describe("ui reports folder: symlinks at startup and swapped in later", () => {
  it("refuses a default reports folder that is a symlink, unless --reports names it", async () => {
    const project = realpathSync(tempDir());
    const elsewhere = realpathSync(tempDir());
    symlinkSync(elsewhere, join(project, "reports"));
    await expect(startUiServer({ projects: [project], memoryRoot: join(tempDir(), "memory") })).rejects.toThrow(/symlink.*--reports/);
    const ui = await startUiServer({ projects: [project], reportsDir: join(project, "reports"), memoryRoot: join(tempDir(), "memory") });
    await ui.close();
  });

  it("refuses every write once reports/ (or reports/evidence) no longer resolves to the folder checked at startup", () => {
    const project = realpathSync(tempDir());
    const reports = join(project, "reports");
    mkdirSync(reports);
    writeFileSync(join(reports, "s.json"), JSON.stringify({ target: "http://localhost:3000", mode: "url", timestamp: "2026-10-01T00:00:00Z", findings: [{ severity: "high", title: "x" }] }));
    const src = createDataSource({ projects: [project], reportsDir: reports, home: tempDir(), memoryRoot: join(tempDir(), "memory"), settings: { get: () => ({}) } });
    expect(src.writeReport("before.json", {})).toBe("before.json");
    const made = src.createEvidence("http://localhost:3000");
    expect(made.path).toMatch(/^evidence\//);

    // reports/evidence swapped for a symlink after startup.
    const outEv = realpathSync(tempDir());
    rmSync(join(reports, "evidence"), { recursive: true });
    symlinkSync(outEv, join(reports, "evidence"));
    expect(() => src.createEvidence("http://localhost:3000")).toThrow(/symlink|resolves/);
    expect(readdirSync(outEv)).toEqual([]);

    // reports/ itself swapped for a symlink after startup.
    const out = realpathSync(tempDir());
    writeFileSync(join(out, "s.json"), readFileSync(join(reports, "s.json")));
    rmSync(reports, { recursive: true });
    symlinkSync(out, reports);
    expect(() => src.writeReport("after.json", {})).toThrow(/resolves to/);
    expect(src.saveLoopRun({ startedAt: "2026-10-19T10:00:00.000Z" })).toBeNull();
    expect(() => src.createEvidence("http://localhost:3000")).toThrow();
    expect(readdirSync(out)).toEqual(["s.json"]);
  });
});

describe("ui runs: approval is bound to the diff shown", () => {
  const root = tempDir();
  const roots = [realpathSync(root)];
  mkdirSync(join(root, "repo"));

  /** A run manager whose loop asks once with `diff` and reports the answer. */
  async function asking(diff, logs = 0) {
    let answered;
    const answer = new Promise((r) => { answered = r; });
    const runLoop = async ({ ask, log }) => {
      for (let i = 0; i < logs; i++) log(`line ${i}`);
      answered(await ask({ plan: { title: "t", recipe: "r", files: ["a.js"], diff, findings: [] }, iteration: 1, index: 1, total: 1 }));
      return { stopReason: "done", error: null, totals: {}, findings: {}, branch: null, durationMs: 1, iterations: [] };
    };
    const mgr = createRunManager({ runLoop, settings: () => ({ offline: true }), projectRoots: roots });
    const run = mgr.start({ kind: "loop", repo: join(root, "repo") });
    const ap = await new Promise((done) => mgr.subscribe(run.id, 0, (ev) => { if (ev?.type === "approval") done(ev.data); }));
    return { mgr, run, ap, answer };
  }

  it("a 70,000-character diff says it is cut, and cannot be approved without the matching hash and an acknowledgement", async () => {
    const diff = `${"+a\n".repeat(20000)}+HIDDEN_TAIL_LINE\n${"+b\n".repeat(3330)}`.slice(0, 70000);
    expect(diff.length).toBe(70000);
    const { mgr, run, ap, answer } = await asking(diff);
    expect(ap.plan.truncated).toBe(true);
    expect(ap.plan.fullLength).toBe(70000);
    expect(ap.plan.diff.length).toBe(60000);
    expect(ap.plan.diff).not.toContain("HIDDEN_TAIL_LINE");
    const shown = diffSha256(ap.plan.diff);
    const base = { approvalId: ap.approvalId, answer: "approve" };
    expect(() => mgr.decide(run.id, base)).toThrow(/does not match/);
    expect(() => mgr.decide(run.id, { ...base, diffSha256: diffSha256(diff) })).toThrow(/does not match/);
    expect(() => mgr.decide(run.id, { ...base, diffSha256: shown })).toThrow(/Acknowledge/);
    expect(() => mgr.decide(run.id, { ...base, diffSha256: shown, acknowledgeTruncated: "yes" })).toThrow(/Acknowledge/);
    expect(mgr.get(run.id).pending).not.toBeNull(); // still waiting
    mgr.decide(run.id, { ...base, diffSha256: shown, acknowledgeTruncated: true });
    expect(await answer).toBe("y");
  });

  it("a whole diff still needs its hash to be approved; skip and stop need none", async () => {
    const a = await asking("+x\n");
    expect(a.ap.plan.truncated).toBe(false);
    expect(a.ap.plan.fullLength).toBe(3);
    expect(() => a.mgr.decide(a.run.id, { approvalId: a.ap.approvalId, answer: "approve" })).toThrow(/does not match/);
    a.mgr.decide(a.run.id, { approvalId: a.ap.approvalId, answer: "approve", diffSha256: diffSha256("+x\n") });
    expect(await a.answer).toBe("y");
    const b = await asking("+y\n".repeat(30000));
    b.mgr.decide(b.run.id, { approvalId: b.ap.approvalId, answer: "skip" });
    expect(await b.answer).toBe("n");
  });

  it("prototype keys are not answers", async () => {
    const { mgr, run, ap, answer } = await asking("+x\n");
    for (const bad of ["__proto__", "constructor", "toString", "hasOwnProperty"]) {
      expect(() => mgr.decide(run.id, { approvalId: ap.approvalId, answer: bad }), bad).toThrow(/approve, skip or stop/);
    }
    mgr.decide(run.id, { approvalId: ap.approvalId, answer: "stop" });
    expect(await answer).toBe("quit");
  });

  it("event ids keep counting past the 5,000-event buffer, so a reconnect replays exactly what it missed", async () => {
    const { mgr, run, ap } = await asking("+x\n", 6000);
    const seqs = [];
    mgr.subscribe(run.id, 0, (ev) => { if (ev) seqs.push(ev.seq); })?.();
    expect(seqs.length).toBe(5000);
    expect(new Set(seqs).size).toBe(seqs.length);
    for (let i = 1; i < seqs.length; i++) expect(seqs[i]).toBe(seqs[i - 1] + 1);
    const last = seqs.at(-1);
    expect(last).toBeGreaterThan(6000);
    const missed = [];
    mgr.subscribe(run.id, last - 3, (ev) => { if (ev) missed.push(ev.seq); })?.();
    expect(missed).toEqual([last - 2, last - 1, last]);
    mgr.decide(run.id, { approvalId: ap.approvalId, answer: "stop" });
  });

  it("keeps a bounded number of finished runs", async () => {
    const executeScan = async () => ({ merged: { findings: [] } });
    const mgr = createRunManager({ executeScan, writeReport: () => null, settings: () => ({ offline: true }), projectRoots: roots });
    for (let i = 0; i < 30; i++) {
      const run = mgr.start({ kind: "scan", url: "http://localhost:3000" });
      await new Promise((done) => mgr.subscribe(run.id, 0, (ev) => { if (!ev) done(); }));
    }
    expect(mgr.list().length).toBeLessThanOrEqual(20);
  });
});

describe("ui server: limits", () => {
  /** POST that resolves with the status as soon as the response starts; write errors after that are expected. */
  function postBig(port, auth, body, headers = {}) {
    return new Promise((resolveReq, reject) => {
      const req = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/api/settings", headers: {
        Host: `127.0.0.1:${port}`, Origin: `http://127.0.0.1:${port}`, "Content-Type": "application/json", Authorization: auth, ...headers,
      } }, (res) => { res.resume(); resolveReq({ status: res.statusCode, headers: res.headers }); });
      req.on("error", (e) => reject(e));
      req.end(body);
    });
  }

  it("answers 413 to an oversized body instead of dropping the connection", async () => {
    const ui = await startUiServer({ demo: true });
    try {
      const { auth } = await signIn(ui);
      const big = JSON.stringify({ offline: true, pad: "x".repeat(200 * 1024) });
      const chunked = await postBig(ui.port, auth, big);
      expect(chunked.status).toBe(413);
      const declared = await postBig(ui.port, auth, big, { "Content-Length": Buffer.byteLength(big) });
      expect(declared.status).toBe(413);
      expect(declared.headers.connection).toBe("close");
      expect((await raw(ui.port, { path: "/api/meta", headers: { Authorization: auth } })).status).toBe(200);
    } finally { await ui.close(); }
  });

  it("bounds request time and idle sockets, but not the run event stream", async () => {
    let finish;
    const executeScan = () => new Promise((r) => { finish = () => r({ merged: { findings: [] } }); });
    const ui = await startUiServer({ demo: true, runDeps: { executeScan, writeReport: () => null }, timeouts: { idle: 300 } });
    try {
      expect(ui.server.requestTimeout).toBeGreaterThan(0);
      const { auth } = await signIn(ui);
      const started = await raw(ui.port, { method: "POST", path: "/api/runs", body: JSON.stringify({ kind: "scan", url: "http://localhost:3000" }), headers: { Authorization: auth, Origin: ui.origin, "Content-Type": "application/json" } });
      expect(started.status).toBe(200);
      const { id } = JSON.parse(started.body);
      // The stream opens first, then a socket that sends half a request and goes quiet.
      const streamRes = await new Promise((resolveRes, reject) => {
        const req = httpRequest({ host: "127.0.0.1", port: ui.port, path: `/api/runs/${id}/stream`, headers: { Host: `127.0.0.1:${ui.port}`, Authorization: auth } }, resolveRes);
        req.on("error", reject);
        req.end();
      });
      expect(streamRes.statusCode).toBe(200);
      streamRes.resume();
      const { connect } = await import("node:net");
      const slow = connect(ui.port, "127.0.0.1");
      slow.on("error", () => {});
      // Signed in, so the server is waiting on the body rather than answering at once.
      slow.write(`POST /api/settings HTTP/1.1\r\nHost: 127.0.0.1:${ui.port}\r\nOrigin: ${ui.origin}\r\nAuthorization: ${auth}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{`);
      await new Promise((r) => slow.once("close", r)); // the idle socket is closed by the server
      expect(streamRes.socket.destroyed).toBe(false); // the stream, idle for longer, is not
      streamRes.destroy();
    } finally { finish?.(); await ui.close(); }
  });

  it("caps open run streams", async () => {
    const { createApi } = await import("../src/ui/api/routes.js");
    const { EventEmitter } = await import("node:events");
    const runs = { get: () => ({}), subscribe: () => () => {} };
    const handle = createApi({ source: {}, runs, version: "t", settings: { get: () => ({}) }, maxStreams: 2 });
    const open = () => {
      const req = new EventEmitter();
      req.headers = {};
      req.method = "GET";
      const res = { status: 0, writableEnded: false, setHeader() {}, writeHead(s) { this.status = s; }, write() {}, end() { this.writableEnded = true; } };
      return { req, res };
    };
    const a = open();
    const b = open();
    const c = open();
    for (const x of [a, b, c]) await handle(x.req, x.res, "/api/runs/0123456789abcdef/stream", new URLSearchParams());
    expect([a.res.status, b.res.status, c.res.status]).toEqual([200, 200, 429]);
    a.req.emit("close"); // a closed stream frees its slot
    const d = open();
    await handle(d.req, d.res, "/api/runs/0123456789abcdef/stream", new URLSearchParams());
    expect(d.res.status).toBe(200);
    for (const x of [b, d]) x.req.emit("close");
  });
});

describe("ui --open: the token stays off the command line", () => {
  it("writes a launcher page only this user can read, which forwards to the one-time URL", async () => {
    const { writeLauncher } = await import("../src/cli/ui.js");
    const dir = tempDir();
    const url = "http://127.0.0.1:4321/#t=abcdefghijklmnopqrstuvwxyz0123456789_-ABCDE";
    const { file } = writeLauncher(url, dir);
    const html = readFileSync(file, "utf-8");
    expect(html).toContain(`content="0;url=${url}"`);
    if (process.platform !== "win32") expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(() => writeLauncher(url, dir)).toThrow(/EEXIST/); // never over an existing file
  });
});

describe("ui: stopping on a signal", () => {
  // Under `npx penthera ui`, npm forwards SIGINT/SIGTERM to penthera right after
  // the terminal (or a group kill) delivered the same signal. The repeat must not
  // kill the process before it reports that it stopped.
  it.skipIf(process.platform === "win32")("prints Stopped. and exits 0 when the signal arrives twice", { timeout: 60_000 }, async () => {
    const child = spawn(process.execPath, [join(import.meta.dirname, "..", "bin", "penthera.js"), "ui", "--demo"], {
      env: { ...process.env, NO_COLOR: "1" }, stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => { out += d; });
    child.stderr.on("data", (d) => { err += d; });
    const exited = new Promise((r) => child.once("exit", (code, signal) => r({ code, signal })));
    // Resolves once `text` is in stdout (including text already there); fails
    // with what the child printed if it exits first or takes too long, so a
    // regression shows up as a message instead of a hung test.
    const seen = (text, ms = 20_000) => new Promise((resolve, reject) => {
      const done = (fn) => { clearTimeout(timer); clearInterval(poll); fn(); };
      const why = (what) => new Error(`${what} before "${text}"\nstdout: ${out}\nstderr: ${err}`);
      const timer = setTimeout(() => done(() => reject(why(`no output in ${ms} ms`))), ms);
      const poll = setInterval(() => { if (out.includes(text)) done(resolve); }, 10);
      exited.then((e) => setImmediate(() => { if (!out.includes(text)) done(() => reject(why(`exited ${JSON.stringify(e)}`))); }));
    });
    await seen("Ctrl-C to stop");
    child.kill("SIGTERM");
    await seen("Stopped.");
    try { child.kill("SIGTERM"); } catch { /* already gone */ }
    expect(await exited).toEqual({ code: 0, signal: null });
  });
});
