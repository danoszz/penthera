/**
 * penthera.org for agents: the homepage as Markdown (/index.md, linked from
 * "/"), Markdown and JSON 404s, JSON-LD, the live check's OpenAPI spec, the MCP
 * manifest, /contact and the "When to use" section of llms.txt. The preview
 * server (site/serve.mjs) applies the same rewrites as vercel.json, so the 404s
 * are tested here.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync, readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildSite, siteVersion } from "../site/build.mjs";
import { apiErrorCodes, undescribedCodes, jsonLd } from "../site/agent-ready.mjs";
import { serve } from "../site/serve.mjs";

const ROOT = join(import.meta.dirname, "..");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
// The version the site tells people to install (the latest stable while main is a release candidate).
const SITE_V = siteVersion(pkg.version);
const ORIGIN = pkg.homepage.replace(/\/+$/, "");
const vercel = JSON.parse(readFileSync(join(ROOT, "vercel.json"), "utf8"));

let dir, out, values, server, base;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "penthera-agent-ready-"));
  out = join(dir, "dist");
  const prev = process.env.PENTHERA_SITE_STARS;
  process.env.PENTHERA_SITE_STARS = "off";
  try {
    ({ values } = await buildSite({ out }));
  } finally {
    if (prev === undefined) delete process.env.PENTHERA_SITE_STARS;
    else process.env.PENTHERA_SITE_STARS = prev;
  }
  server = await serve({ dir: out, port: 0 });
  base = `http://127.0.0.1:${server.address().port}`;
}, 180_000);

afterAll(() => {
  server?.close();
  rmSync(dir, { recursive: true, force: true });
});

const read = (f) => readFileSync(join(out, f), "utf8");

/** Every CheckError the API throws, with its status, straight from api/**.mjs. */
function sourceCodes() {
  const codes = {};
  const walk = (d) => {
    for (const f of readdirSync(d)) {
      const p = join(d, f);
      if (statSync(p).isDirectory()) walk(p);
      else if (f.endsWith(".mjs")) {
        const src = readFileSync(p, "utf8");
        for (const m of src.matchAll(/new CheckError\(\s*"(\w+)",\s*(?:"(?:[^"\\]|\\.)*"|`[^`]*`),\s*(\d+)\s*,/g)) if (Number(m[2]) >= 400) codes[m[1]] ??= Number(m[2]);
        // Every construction is matched: none is skipped for an odd message.
        expect(src.match(/new CheckError\(/g)?.length ?? 0, p).toBe([...src.matchAll(/new CheckError\(\s*"(\w+)",\s*(?:"(?:[^"\\]|\\.)*"|`[^`]*`),\s*(\d+)\s*,/g)].length);
      }
    }
  };
  walk(join(ROOT, "api"));
  return codes;
}

describe("homepage as Markdown", () => {
  it("builds index.md from the page's values, with pinned commands and the links", () => {
    const md = read("index.md");
    expect(md).toMatch(/^# Penthera: your open-source cyber security agent\n/);
    expect(md).not.toMatch(/\{\{|undefined|—/);
    for (const cmd of [`npx penthera@${SITE_V}`, "npx skills add danoszz/penthera", `claude mcp add penthera -- npx -y penthera@${SITE_V} mcp`]) expect(md).toContain(cmd);
    const pins = [...md.matchAll(/penthera@(\d[\w.-]*)/g)].map((m) => m[1]);
    expect(new Set(pins)).toEqual(new Set([SITE_V]));
    for (const n of [values.N_URL, values.N_SECRETS, values.N_AGENTS, values.RULES_ALL]) expect(md).toContain(n);
    expect(md).toContain("## Limits");
    expect(md).toContain(`${ORIGIN}/api/check`);
    expect(md).toContain(`"consent":true`);
    expect(md).toContain(`${ORIGIN}/terms`);
    // "deep" as a word or flag; the tool name deepsecrets (public benchmarks) is fine.
    expect(md).not.toMatch(/\baction\b|token|\bdeep\b/);
    for (const link of ["/llms.txt", "/docs/index.md", "/openapi.json"]) expect(md).toContain(`${ORIGIN}${link}`);
    expect(md).toContain("https://github.com/danoszz/penthera");
    expect(md).toContain("https://www.npmjs.com/package/penthera");
  });

  it("is served as Markdown and linked from / with rel=alternate", async () => {
    const md = await fetch(`${base}/index.md`);
    expect(md.status).toBe(200);
    expect(md.headers.get("content-type")).toBe("text/markdown; charset=utf-8");
    expect(await md.text()).toBe(read("index.md"));
    const html = await fetch(`${base}/`);
    expect(html.status).toBe(200);
    expect(html.headers.get("content-type")).toMatch(/^text\/html/);
    expect(html.headers.get("link")).toContain('</index.md>; rel="alternate"; type="text/markdown"');
    await html.text();
  });

  it("vercel.json has no Routing Middleware, so / stays a static file with no Vary", async () => {
    expect(vercel.proxy).toBeUndefined();
    for (const f of ["proxy.js", "middleware.js", "middleware.ts"]) expect(existsSync(join(ROOT, f)), f).toBe(false);
    const res = await fetch(`${base}/`, { headers: { accept: "text/markdown" } });
    expect(res.headers.get("content-type")).toMatch(/^text\/html/);
    expect(res.headers.get("vary")).toBeNull();
    await res.text();
  });
});

describe("404 for agents", () => {
  it("answers an unknown path asked for as Markdown with a 404 in Markdown", async () => {
    const res = await fetch(`${base}/no-such-page`, { headers: { accept: "text/markdown" } });
    expect(res.status).toBe(404);
    expect(res.headers.get("content-type")).toBe("text/markdown; charset=utf-8");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
    const body = await res.text();
    expect(body.length).toBeGreaterThanOrEqual(20);
    for (const link of ["/llms.txt", "/sitemap.xml", "/docs/index.md"]) expect(body).toContain(`${ORIGIN}${link}`);
  });

  it("keeps the plain 404 for everyone else, and files still win over the rewrite", async () => {
    const res = await fetch(`${base}/no-such-page`, { headers: { accept: "text/html" } });
    expect(res.status).toBe(404);
    expect(res.headers.get("content-type") || "").not.toMatch(/markdown/);
    await res.text();
    const llms = await fetch(`${base}/llms.txt`, { headers: { accept: "text/markdown" } });
    expect(llms.status).toBe(200);
    expect(llms.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    await llms.text();
  });

  it("the function's origin is the package homepage", async () => {
    const { NOT_FOUND_MD } = await import("../api/not-found.mjs");
    expect(NOT_FOUND_MD).toContain(`${ORIGIN}/llms.txt`);
  });
});

describe("JSON errors on the API", () => {
  it("answers an unknown API path with a JSON 404, whatever the Accept header", async () => {
    for (const [path, init] of [["/api", {}], ["/api/", {}], ["/api/nope", {}], ["/api/check/extra", {}], ["/api/nope", { method: "POST" }], ["/api/nope", { headers: { accept: "text/markdown" } }]]) {
      const res = await fetch(`${base}${path}`, init);
      expect(res.status, path).toBe(404);
      expect(res.headers.get("content-type"), path).toBe("application/json; charset=utf-8");
      expect(res.headers.get("content-security-policy"), path).toContain("default-src 'none'");
      const { error } = await res.json();
      expect(error.code, path).toBe("unknown_endpoint");
      expect(error.message.length, path).toBeGreaterThan(10);
      expect(error.hint, path).toContain(`${ORIGIN}/openapi.json`);
    }
  });

  it("leaves the real route alone", async () => {
    const res = await fetch(`${base}/api/check`);
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("POST");
    expect(res.headers.get("content-type")).toBe("application/json; charset=utf-8");
    const { error } = await res.json();
    expect(error).toMatchObject({ code: "method_not_allowed" });
    expect(error.hint).toContain("/openapi.json");
  });

  it("the function's origin is the package homepage", async () => {
    const { NO_ROUTE } = await import("../api/no-route.mjs");
    expect(NO_ROUTE.error.hint).toContain(`${ORIGIN}/api/check`);
  });
});

describe("JSON-LD", () => {
  it("is one ld+json data block with an Organization and the SoftwareApplication, and no address", () => {
    const tag = values.JSONLD;
    expect(tag).toMatch(/^<script type="application\/ld\+json">[^<]*<\/script>$/);
    const ld = JSON.parse(tag.replace(/^<script[^>]*>|<\/script>$/g, ""));
    expect(ld["@context"]).toBe("https://schema.org");
    expect(ld["@graph"].map((n) => n["@type"])).toEqual(["Organization", "SoftwareApplication"]);
    const [org, data] = ld["@graph"];
    expect(org).toMatchObject({
      "@id": `${ORIGIN}/#organization`, name: "Penthera", url: ORIGIN,
      contactPoint: { "@type": "ContactPoint", email: "daan@penthera.org", url: `${ORIGIN}/contact` },
    });
    expect(org.description).toBe(data.description);
    expect(org.sameAs).toContain("https://github.com/danoszz/penthera");
    expect(data.publisher).toEqual({ "@id": org["@id"] });
    expect(data).toMatchObject({
      name: "Penthera", url: ORIGIN, applicationCategory: "SecurityApplication",
      softwareVersion: pkg.version, downloadUrl: "https://www.npmjs.com/package/penthera",
      offers: { "@type": "Offer", price: "0" },
      author: { "@type": "Person", name: "Daan van der Zwaag", url: "https://daanvanderzwaag.com" },
    });
    expect(data.license).toMatch(/MIT/);
    expect(data.sameAs).toContain("https://github.com/danoszz/penthera");
    expect(data.operatingSystem).toBeTruthy();
    // The approved short line from site/BRIEF.md.
    expect(readFileSync(join(ROOT, "site", "BRIEF.md"), "utf8").replace(/\s+/g, " ")).toContain(data.description);
    // Privacy: the public address is the one contact detail. No street address, no phone.
    expect(tag).not.toMatch(/address|telephone|faxNumber|geo"|@gaia|@gmail/i);
    expect([...tag.matchAll(/[\w.+-]+@[\w-]+\.[\w.-]+/g)].map((m) => m[0])).toEqual(["daan@penthera.org"]);
  });

  it("escapes < so a value cannot close the script element", () => {
    expect(jsonLd({ version: "</script><x>", origin: ORIGIN })).not.toMatch(/<\/script><x>/);
  });

  it("lands in the page when index.html has the placeholder", () => {
    const html = read("index.html");
    if (!readFileSync(join(ROOT, "site", "index.html"), "utf8").includes("{{JSONLD}}")) return;
    expect(html).toContain(values.JSONLD);
  });
});

describe("OpenAPI for the live check", () => {
  let spec;
  beforeAll(() => { spec = JSON.parse(read("openapi.json")); });

  it("is OpenAPI 3.1 for POST /api/check, with a unique operationId", () => {
    expect(spec.openapi).toBe("3.1.0");
    expect(spec.info.version).toBe(SITE_V);
    expect(spec.servers[0].url).toBe(ORIGIN);
    expect(spec.info.termsOfService).toBe(`${ORIGIN}/terms`);
    expect(Object.keys(spec.paths)).toEqual(["/api/check"]);
    const ops = Object.values(spec.paths).flatMap((p) => Object.values(p));
    const ids = ops.map((o) => o.operationId);
    expect(new Set(ids).size).toBe(ids.length);
    for (const o of ops) expect(o.description.length).toBeGreaterThan(40);
    const op = spec.paths["/api/check"].post;
    const req = spec.components.schemas.CheckRequest;
    expect(op.requestBody.content["application/json"].schema.$ref).toBe("#/components/schemas/CheckRequest");
    expect(req.required).toEqual(["url", "consent"]);
    expect(req.properties.consent.const).toBe(true);
    expect(req.properties.action).toBeUndefined();
    expect(spec.components.schemas.Report.properties.tier.const).toBe("passive");
    expect(spec.components.schemas.OwnershipToken).toBeUndefined();
    expect(JSON.stringify(spec)).not.toMatch(/"deep"|ownership token/i);
  });

  it("fits LLM function-calling formats: a short id and description, typed fields", () => {
    const op = spec.paths["/api/check"].post;
    expect(op.operationId).toMatch(/^[a-zA-Z0-9_-]{1,64}$/);
    expect(op.description.length).toBeLessThanOrEqual(1024);
    const typed = (schema, where) => {
      if (schema.$ref) return;
      expect(schema.type, where).toBeTruthy();
      for (const [k, v] of Object.entries(schema.properties || {})) typed(v, `${where}.${k}`);
      if (schema.items) typed(schema.items, `${where}[]`);
    };
    for (const [name, schema] of Object.entries(spec.components.schemas)) typed(schema, name);
  });

  it("states the limits api/check.mjs enforces, Retry-After and the versioning policy", async () => {
    const { LIMITS } = await import("../api/check.mjs");
    expect(LIMITS.map((l) => [l.key, l.window, l.max])).toEqual([["ip", 60_000, 6], ["ip", 86_400_000, 40], ["host", 3_600_000, 30]]);
    expect(spec.info.description).toContain("6 checks a minute and 40 a day per client address, and 30 an hour per target site");
    expect(spec.info.description).toContain("Breaking changes and deprecations are listed in the changelog");
    expect(spec.info.description).toContain("in memory, for up to a day");
    expect(spec.info.description).toContain("A rate_limited 429 carries Retry-After");
    expect(spec.info.description).toContain("unknown_endpoint");
    expect(spec.info.description).toContain("/robots.txt");
    const res429 = spec.paths["/api/check"].post.responses[429];
    expect(res429.headers["Retry-After"].schema.type).toBe("integer");
    expect(res429.headers["Retry-After"].description).toContain("not with `budget`");
    expect(res429.description).toContain("`budget`");
  });

  it("says what the handler does with a large body and with extra fields", () => {
    const req = spec.components.schemas.CheckRequest;
    expect(req.additionalProperties).toBeUndefined();
    expect(req.description).toContain("ignores any other field");
    expect(spec.paths["/api/check"].post.responses[413].description).toContain("may not fire");
  });

  it("describes the report fields api/check.mjs documents", () => {
    // The contract in api/check.mjs's header comment.
    const contract = readFileSync(join(ROOT, "api", "check.mjs"), "utf8").match(/^\/\*\*[\s\S]*?\*\//)[0];
    const report = spec.components.schemas.Report;
    for (const f of ["url", "tier", "score", "verdict", "redirects", "scope", "categories", "checks"]) {
      expect(contract, f).toMatch(new RegExp(`\\b${f}\\b`));
      expect(report.properties, f).toHaveProperty(f);
    }
    for (const f of ["id", "label", "passed", "total"]) expect(spec.components.schemas.Category.properties).toHaveProperty(f);
    for (const f of ["id", "category", "passed", "severity", "title", "evidence", "fix", "verify", "weight"]) expect(spec.components.schemas.Check.properties).toHaveProperty(f);
  });

  it("lists exactly the error codes api/ throws, each under its status and described", () => {
    const codes = sourceCodes();
    expect(Object.keys(codes).length).toBeGreaterThan(5);
    expect(apiErrorCodes(ROOT)).toEqual(codes);
    expect(spec.components.schemas.Error.properties.error.properties.code.enum).toEqual(Object.keys(codes).sort());
    expect(spec.components.schemas.Error.properties.error.required).toEqual(["code", "message", "hint"]);
    const responses = spec.paths["/api/check"].post.responses;
    for (const [code, status] of Object.entries(codes)) expect(responses[status]?.description, `${code} (${status})`).toContain(`\`${code}\``);
    // A new code needs a line in site/agent-ready.mjs (ERROR_HINTS).
    expect(undescribedCodes(codes)).toEqual([]);
  });

  it("is served as JSON, linked from llms.txt and listed in the sitemap", async () => {
    const res = await fetch(`${base}/openapi.json`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/^application\/json/);
    await res.json();
    const terms = await fetch(`${base}/terms`);
    if (existsSync(join(ROOT, "docs", "live-check-terms.md"))) expect(terms.status).toBe(200);
    await terms.text();
    expect(read("llms.txt")).toContain(`(${ORIGIN}/openapi.json)`);
    for (const u of ["openapi.json", "server.json", "index.md", "contact"]) expect(read("sitemap.xml")).toContain(`<loc>${ORIGIN}/${u}</loc>`);
    const termsPage = existsSync(join(ROOT, "docs", "live-check-terms.md"));
    expect(read("sitemap.xml").includes(`<loc>${ORIGIN}/terms</loc>`)).toBe(termsPage);
  });
});

describe("MCP manifest", () => {
  it("publishes the repo's server.json, a local stdio package with no hosted endpoint", async () => {
    const res = await fetch(`${base}/server.json`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/^application\/json/);
    expect(await res.text()).toBe(readFileSync(join(ROOT, "server.json"), "utf8"));
    const manifest = JSON.parse(read("server.json"));
    expect(manifest.packages.map((p) => p.transport.type)).toEqual(["stdio"]);
    expect(manifest.remotes).toBeUndefined();
  });

  it("claims no hosted server: no card, no HTTP transport in what the site says", () => {
    for (const f of [".well-known/mcp/server-card.json", ".well-known/mcp.json"]) expect(existsSync(join(out, f)), f).toBe(false);
    for (const f of ["llms.txt", "index.md"]) expect(read(f), f).not.toMatch(/streamable[- ]http/i);
    expect(read("llms.txt")).toContain(`(${ORIGIN}/server.json)`);
    expect(read("llms.txt")).toContain("There is no hosted MCP endpoint.");
  });
});

describe("/contact", () => {
  it("is a page in the site's frame with at least 500 characters of public contact", async () => {
    const res = await fetch(`${base}/contact`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('<main class="terms land"');
    expect(html).toContain('class="rail"');
    expect(html).toContain("mailto:daan@penthera.org");
    expect(html).toContain("/security/advisories/new");
    const main = html.slice(html.indexOf("<main"), html.indexOf("</main>")).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
    expect(main.length).toBeGreaterThanOrEqual(500);
    expect(read("contact.md")).toContain("# Contact Penthera");
    // Public contact only.
    expect(html.slice(html.indexOf("<main"), html.indexOf("</main>"))).not.toMatch(/telephone|\+\d{2}[ \d]{6,}|straat|street|@gaia|@gmail/i);
  });

  it("is in the footer under Trust and in llms.txt, not among the check's questions", () => {
    expect(read("trust.html")).toContain('href="/contact"');
    const llms = read("llms.txt");
    expect(llms).toContain(`(${ORIGIN}/contact.md)`);
    const q = llms.indexOf("## Questions the live check answers");
    expect(llms.slice(q, llms.indexOf("## Trust"))).not.toContain("/contact");
  });
});

describe("llms.txt", () => {
  it("says when to use Penthera, before the docs, with pinned commands and the API call", () => {
    const llms = read("llms.txt");
    const section = llms.slice(llms.indexOf("## When to use Penthera"), llms.indexOf("## Docs"));
    expect(llms.indexOf("## When to use Penthera")).toBeGreaterThan(0);
    expect(section.length).toBeGreaterThan(200);
    for (const cmd of ["--repo .", " deps", " agents", " mcp"]) expect(section).toContain(cmd);
    expect(section).toContain(`POST ${ORIGIN}/api/check`);
    expect(section).toContain('{"url": "example.com", "consent": true}');
    expect(section).toContain(`${ORIGIN}/terms`);
    expect(section).not.toMatch(/"action"|token|deep/);
    expect(section).not.toContain("—");
    expect(section).toContain("What it does not do:");
    expect(section).toContain("IDOR/BOLA results are heuristics a human must confirm.");
    expect(section).not.toContain("authorization flaws");
    expect(read("index.md")).not.toContain("authorization flaws");
    expect(section).toContain("npx skills add danoszz/penthera");
    expect(section).toContain("over stdio");
    const pins = [...llms.matchAll(/penthera@(\d[\w.-]*)/g)].map((m) => m[1]);
    expect(new Set(pins)).toEqual(new Set([SITE_V]));
  });
});
