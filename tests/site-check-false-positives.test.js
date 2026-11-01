/**
 * Three detection bugs found while copying the URL scan templates into
 * penthera.org's live check: the .env.local template's inline (?m) flag never
 * compiled, so it never matched; the phase 6 "body names a secret" rule fired
 * on a single-page app's index.html served at every path; and a Map lookup of
 * "/robots.txt" plus a RegExp#exec call read as a route with a shell exec.
 * Servers run on 127.0.0.1 port 0; repos are temp dirs.
 */
import { describe, it, expect, afterEach, beforeAll, afterAll } from "vitest";
import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { BUILT_IN_TEMPLATES, executeTemplate } from "../lib/templates.js";
import { checkRegex } from "../lib/rules/regex-guard.js";
import { discoverFrameworkRoutes, SHELL_EXEC_RE } from "../lib/whitebox/frameworks.js";
import { scanUrl } from "../src/scan-url.js";
import { scanRepo } from "../src/scan-repo.js";

let server;
afterEach(() => new Promise((r) => (server ? server.close(r) : r())));

function serve(handler) {
  server = createServer(handler);
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${server.address().port}`)));
}

describe("built-in template regexes", () => {
  it("all compile and pass the regex guard, so none is silently skipped", () => {
    for (const t of BUILT_IN_TEMPLATES) {
      for (const m of (t.http || []).flatMap((h) => h.matchers || [])) {
        if (!/regex/.test(m.type)) continue;
        for (const p of m.regex) {
          expect(() => new RegExp(p, m.flags), `${t.id}: ${p}`).not.toThrow();
          expect(checkRegex(p, m.flags).ok, `${t.id}: ${p}`).toBe(true);
        }
      }
    }
  });
});

describe("env-local-exposure template", () => {
  const template = BUILT_IN_TEMPLATES.find((t) => t.id === "env-local-exposure");
  const at = (status, type, body) => serve((req, res) => {
    const hit = req.url === "/.env.local";
    res.writeHead(hit ? status : 404, { "Content-Type": type });
    res.end(hit ? body : "");
  });

  it("reports a served .env.local", async () => {
    const base = await at(200, "text/plain", "# local overrides\nNEXT_PUBLIC_URL=http://localhost:3000\nDATABASE_URL=postgres://u:p@db/app\n");
    const findings = await executeTemplate(base, template);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ templateId: "env-local-exposure", severity: "critical", status: 200 });
  });

  it("ignores an SPA index page and a body with no dotenv line", async () => {
    let base = await at(200, "text/html", "<!DOCTYPE html><html><body>\nAPI_KEY=shown-in-docs\n</body></html>");
    expect(await executeTemplate(base, template)).toHaveLength(0);
    await new Promise((r) => server.close(r));
    base = await at(200, "text/plain", "not a dotenv file, a=b\n");
    expect(await executeTemplate(base, template)).toHaveLength(0);
  });
});

describe("phase 6 sensitive-file checks", () => {
  const sensitive = (result) => result.findings.filter((f) => f.source === "sensitive-file-check" && f.severity !== "info");

  it("does not report an SPA that serves its index.html for every path", async () => {
    const index = '<!doctype html><html><head><title>App</title></head><body><div id="root"></div>'
      + '<script>window.__CONFIG__ = { keyName: "API_KEY", project: "FIREBASE_PROJECT" }</script></body></html>';
    const base = await serve((req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(index);
    });
    const result = await scanUrl(base, { offline: true, timeout: 3000, concurrency: 2 });
    expect(sensitive(result)).toEqual([]);
  });

  it("reads an index page behind leading comments as HTML, quickly on a comment run", async () => {
    const index = "<!-- build 42 -->\n<!-- cdn -->" + "<!---->".repeat(20_000) + "<html><body><script>const k = 'API_KEY'</script></body></html>";
    const base = await serve((req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(index);
    });
    const result = await scanUrl(base, { offline: true, timeout: 3000, concurrency: 2 });
    expect(sensitive(result)).toEqual([]);
  });

  it("still reports a non-HTML file that names a secret, and phpinfo and server-status by their page text", async () => {
    const pages = {
      "/actuator/env": ['application/json', '{"propertySources":[{"properties":{"DATABASE_URL":{"value":"******"}}}]}'],
      "/phpinfo.php": ["text/html", "<!DOCTYPE html><html><head><title>PHP 8.3.1 - phpinfo()</title></head><body>PHP Version</body></html>"],
      "/server-status": ["text/html", "<!DOCTYPE html><html><body><h1>Apache Server Status for localhost</h1>Server uptime: 3 days</body></html>"],
    };
    const base = await serve((req, res) => {
      const page = pages[req.url];
      res.writeHead(page ? 200 : 404, { "Content-Type": page ? page[0] : "text/plain" });
      res.end(page ? page[1] : "");
    });
    const result = await scanUrl(base, { offline: true, timeout: 3000, concurrency: 2 });
    const paths = sensitive(result).map((f) => new URL(f.url).pathname).sort();
    expect(paths).toEqual(["/actuator/env", "/phpinfo.php", "/server-status"]);
  });
});

describe("whitebox routes and shell execs", () => {
  let tmp;
  beforeAll(() => { tmp = mkdtempSync(join(tmpdir(), "penthera-fp-")); });
  afterAll(() => rmSync(tmp, { recursive: true, force: true }));

  function repo(name, files) {
    const dir = join(tmp, name);
    for (const [file, body] of Object.entries(files)) {
      mkdirSync(join(dir, file, ".."), { recursive: true });
      writeFileSync(join(dir, file), body);
    }
    return dir;
  }

  it("does not read a Map lookup as a route or RegExp#exec as a shell", async () => {
    const dir = repo("map-regex", {
      "api/deep.mjs": [
        "import express from 'express';",
        "export function summarize(results, header) {",
        '  const robots = results.get("/robots.txt");',
        "  const age = /max-age=(\\d+)/i.exec(header)?.[1];",
        "  const re = new RegExp('Disallow: (.*)');",
        "  return { robots, age, rule: re.exec(robots.body) };",
        "}",
        "",
      ].join("\n"),
    });
    expect(discoverFrameworkRoutes(dir)).toEqual([]);
    const result = await scanRepo(dir);
    expect(result.findings.filter((f) => f.pattern === "command-injection")).toEqual([]);
  });

  it("still reports a route that runs child_process exec on request input", async () => {
    const dir = repo("real-exec", {
      "api/run.js": [
        "const express = require('express');",
        "const { exec } = require('child_process');",
        "const app = express();",
        "app.get('/run', (req, res) => {",
        "  exec(`ping -c 1 ${req.query.host}`, (err, out) => res.send(out));",
        "});",
        "",
      ].join("\n"),
    });
    const routes = discoverFrameworkRoutes(dir);
    expect(routes.map((r) => r.url)).toEqual(["/run"]);
    expect(routes[0].securityPatterns).toContain("RISK:command-injection");
    const result = await scanRepo(dir);
    expect(result.findings.filter((f) => f.pattern === "command-injection").map((f) => f.description)).toEqual([expect.stringContaining("This file serves 1 route: /run.")]);
  });

  it("reports a whole-file pattern once and lists its routes", async () => {
    const dir = repo("whole-file", {
      "routes/tools.js": [
        "import { exec } from 'node:child_process';",
        "app.get('/a', (req, res) => res.send('a'));",
        "app.get('/b', (req, res) => res.send('b'));",
        "app.get('/run', (req, res) => { exec(`ping ${req.query.host}`); });",
        "app.get('/size', (req, res) => { eval(req.query.x); });",
        "",
      ].join("\n"),
    });
    const code = (await scanRepo(dir)).findings.filter((f) => f.category === "code-pattern");
    expect(code.filter((f) => f.pattern === "command-injection")).toHaveLength(1);
    expect(code.filter((f) => f.pattern === "eval")).toHaveLength(1);
    expect(code.find((f) => f.pattern === "eval").description).toContain("This file serves 4 routes: /a, /b, /run, /size.");
  });

  it("does not let a weaker sink finding lower a route's severity", async () => {
    const dir = repo("weak-sink", {
      "package.json": JSON.stringify({ name: "pinger", version: "1.0.0", main: "index.js", peerDependencies: { express: "^4" } }),
      "index.js": "const { exec } = require('child_process');\nfunction run(cmd, cb) { exec(cmd, cb); }\napp.get('/ping', (req, res) => run('ping ' + req.query.host, () => res.end()));\nmodule.exports = { run };\n",
    });
    const severities = (await scanRepo(dir)).findings.filter((f) => f.pattern === "command-injection").map((f) => f.severity);
    expect(severities).toContain("critical");
  });

  it("reports a pattern the sink scan does not cover once, with the routes", async () => {
    const dir = repo("innerhtml", {
      "routes/page.js": "app.get('/a', (q, r) => r.send(el.innerHTML));\napp.get('/b', (q, r) => r.send('b'));\n",
    });
    const code = (await scanRepo(dir)).findings.filter((f) => f.pattern === "innerHTML");
    expect(code).toHaveLength(1);
    expect(code[0].description).toContain("serves 2 routes: /a, /b");
  });

  it("reads a file of unclosed imports in linear time", () => {
    const dir = repo("planted-imports", { "server.js": `const express = require('express');\n${"import { ".repeat(300_000)}` });
    const start = Date.now();
    discoverFrameworkRoutes(dir);
    expect(Date.now() - start).toBeLessThan(3_000);
  }, 60_000);

  it("keeps the mount prefix on a router's routes", () => {
    const dir = repo("mounted", {
      "server.js": [
        "import express from 'express';",
        "import tools from './routes/tools.js';",
        "import { admin as boss } from './routes/admin.js';",
        "const users = require('./routes/users');",
        "const app = express();",
        "app.use('/api/tools', tools);",
        "app.use('/api/', users);",
        "app.use('/api/admin', boss);",
        "app.use('/v2', require('./routes/nested/index.js'));",
        "app.get('/health', (req, res) => res.send('ok'));",
        "",
      ].join("\n"),
      "routes/tools.js": "import { Router } from 'express';\nconst router = Router();\nrouter.get('/calc', (q, r) => r.end());\nrouter.get('/', (q, r) => r.end());\nexport default router;\n",
      "routes/admin.js": "import { Router } from 'express';\nexport const admin = Router();\nadmin.get('/all', (q, r) => r.end());\n",
      "routes/users.js": "const router = require('express').Router();\nrouter.post('/users/:id', (q, r) => r.end());\nmodule.exports = router;\n",
      "routes/nested/index.js": "const router = require('express').Router();\nrouter.use('/deep', require('./leaf.js'));\nmodule.exports = router;\n",
      "routes/nested/leaf.js": "const router = require('express').Router();\nrouter.get('/x', (q, r) => r.end());\nmodule.exports = router;\n",
    });
    expect(discoverFrameworkRoutes(dir).map((r) => r.url).sort()).toEqual([
      "/api/admin/all", "/api/tools", "/api/tools/calc", "/api/users/:id", "/health", "/v2/deep/x",
    ]);
  });

  it("tells a shell exec from a regex exec", () => {
    for (const shell of ["exec(cmd)", "execSync(cmd)", "child_process.exec(cmd)", "cp.execFile(cmd)",
      "require('node:child_process').exec(cmd)", "shell.exec(cmd)", "spawn('sh', args)"]) {
      expect(SHELL_EXEC_RE.test(shell), shell).toBe(true);
    }
    for (const regex of ["/a(b)/.exec(s)", "re.exec(s)", "new RegExp(p).exec(s)", "PATTERN.exec(s)", "this.re.exec(s)"]) {
      expect(SHELL_EXEC_RE.test(regex), regex).toBe(false);
    }
  });
});
