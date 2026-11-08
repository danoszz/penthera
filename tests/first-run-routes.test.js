// Route discovery on the shapes starter apps use, found in the first-run study
// (5 starter apps, 2 Nov 2026). Each fixture is a minimal reproduction, written
// here, not a copy of a template's code.
import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { scanRepo } from "../src/scan-repo.js";
import { reachLines } from "../src/report/reach.js";

const temps = [];
afterAll(() => temps.forEach((d) => rmSync(d, { recursive: true, force: true })));
function app(files) {
  const dir = mkdtempSync(join(tmpdir(), "penthera-first-run-"));
  temps.push(dir);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
}
const routes = (r) => r.attackSurface.map((s) => `${[...s.methods].sort().join(",")} ${s.url}`).sort();
const statusRows = (r) => r.findings.filter((f) => ["repo-scan", "framework-scan"].includes(f.source) && /API routes/.test(f.title));

describe("Next.js route handlers", () => {
  it("are found anywhere under app/, not only under app/api", async () => {
    const r = await scanRepo(app({
      "app/auth/confirm/route.ts": "export async function GET(request) { return Response.redirect(new URL(request.url).searchParams.get('next')); }\n",
      "app/(marketing)/feed/route.ts": "export function GET() { return Response.json([]); }\n",
      "app/page.tsx": "export default function Page() { return null; }\n",
    }));
    expect(routes(r)).toEqual(["GET /auth/confirm", "GET /feed"]);
    expect(r.attackSurface.find((s) => s.url === "/auth/confirm").filePath).toBe("app/auth/confirm/route.ts");
    expect(statusRows(r)).toEqual([]);
  });

  it("keep their /api URLs and api root when all of them sit under app/api", async () => {
    const dir = app({ "src/app/api/items/[id]/route.ts": "export async function DELETE() {}\n" });
    const r = await scanRepo(dir);
    expect(routes(r)).toEqual(["DELETE /api/items/:id"]);
    expect(r.apiRoot).toBe(join(dir, "src", "app", "api"));
  });

  it("name the methods of `export const` and `export { … as … }` handlers", async () => {
    const r = await scanRepo(app({
      "app/api/counter/route.ts": "export const PUT = async (request) => new Response('ok');\nexport const GET = () => new Response('ok');\n",
      "app/api/items/route.ts": "async function handler() {}\nexport { handler as POST, handler as PATCH };\n",
    }));
    expect(routes(r)).toEqual(["GET,PUT /api/counter", "PATCH,POST /api/items"]);
  });
});

describe("A Worker's fetch handler", () => {
  it("is a route, so route analysis runs on it", async () => {
    const r = await scanRepo(app({
      "wrangler.jsonc": '{ "name": "demo", "main": "src/index.ts" }\n',
      "src/index.ts": "export default {\n  fetch(request, env, ctx) {\n    return new Response('ok');\n  },\n};\n",
    }));
    expect(routes(r)).toEqual(["ALL /*"]);
    expect(r.attackSurface[0].filePath).toBe("src/index.ts");
    expect(statusRows(r)).toEqual([]);
  });
});

describe("Route discovery's status lines", () => {
  it("are not findings: an app with no server routes says so in coverage, not as 'not run'", async () => {
    const r = await scanRepo(app({ "src/main.tsx": "import React from 'react';\n", "index.html": "<div id=root></div>\n" }));
    expect(statusRows(r)).toEqual([]);
    const lines = reachLines([r]).join("\n");
    expect(lines).toMatch(/no server routes found/i);
    expect(lines).not.toMatch(/not run/);
  });

  it("put the Express route count in coverage, not in the findings", async () => {
    const r = await scanRepo(app({
      "server.js": "const express = require('express');\nconst app = express();\napp.get('/health', (req, res) => res.send('ok'));\napp.listen(3000);\n",
    }));
    expect(routes(r)).toEqual(["GET /health"]);
    expect(statusRows(r)).toEqual([]);
  });
});

describe("the next step's wording", () => {
  it("says the plan changes nothing on its own, and no longer claims checks the scan lacks", async () => {
    const { buildBrief } = await import("../src/report/brief.js");
    // The scan runs the fix planner's checks itself now (src/report/counts.js), so "also checks" would be false.
    const b = buildBrief({ mode: "repo", findings: [] }, { fixes: { command: "penthera fix --plan --repo ." } });
    // No recipe matched: a short first sentence, so the first screen's line stays under 100 columns.
    expect(b.next[0].why).toMatch(/^Plans a fix for each problem it can\. It shows each diff and changes nothing until you approve one/);
    expect(b.next[0].why).not.toMatch(/also checks/);
    const one = buildBrief({ mode: "repo", findings: [{ title: "Cookie \"sid\" missing Secure", severity: "medium", category: "cookie", file: "a.js" }] }, { fixes: { count: 1, command: "penthera fix --plan --repo ." } });
    expect(one.next[0].why).toMatch(/^A fix recipe matches 1 of the 1 problem\. It shows each diff/);
  });
});
