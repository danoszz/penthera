#!/usr/bin/env node
/**
 * The Vercel integration on your own machine, to click through by hand.
 *
 *   node integrations/vercel/scripts/local-journey.mjs            # a free port
 *   node integrations/vercel/scripts/local-journey.mjs --port 4319  # a fixed one
 *
 * It runs the real server (createApp) against the strict fake Vercel and the fake GitHub OIDC
 * issuer from test/journey-harness.mjs, seeded with one team, a GitHub project, a GitLab project
 * and a production deployment. /__fake, served only by this script, does what Vercel and GitHub
 * would do: make a production deployment, send the workflow's pass or fail, send the uninstall
 * webhook, and show the fake's state. Nothing leaves the machine: a request to anywhere but the
 * fakes is refused and listed on /__fake.
 */
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { harness, listingInstallUrl, removedWebhook, reportRequest } from "../test/journey-harness.mjs";

const PUBLIC = new URL("../public/", import.meta.url);
const ROUTES = { "/": "home", "/start": "start", "/install": "install", "/setup": "setup", "/configure": "configure", "/webhook": "webhook", "/report": "report", "/health": "health", "/api/sweep": "sweep" };
const esc = (v) => String(v).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

let h = null;
let base = "";
let deploys = 1;
let runs = 700;
const events = [];

function seed() {
  h = harness({ base, now: () => Date.now() });
  deploys = 1;
  events.length = 0;
  events.push("Seeded: team team_JourneyTeam1, projects gaia-web (GitHub daan/gaia-web) and notes (GitLab), deployments dpl_prod1 (production) and dpl_preview1 (preview).");
}

async function fakePage(request) {
  const url = new URL(request.url);
  if (request.method === "POST") {
    const form = new URLSearchParams(await request.text());
    const act = form.get("act");
    if (act === "deploy") {
      const id = `dpl_prod${++deploys}`;
      h.world.deployments[id] = { projectId: "prj_gaiaweb", target: "production", url: `gaia-web-${deploys}.vercel.app` };
      // Vercel queues a run of each check on the project when the deployment is ready.
      await h.vercel.fetch(new URL(`https://api.vercel.com/v2/deployments/${id}/check-runs?teamId=${h.world.teamId}`), { headers: { Authorization: `Bearer ${h.vercel.token}` } });
      events.push(`Vercel made production deployment ${id}.`);
    } else if (act === "report") {
      const id = form.get("deployment");
      const conclusion = form.get("conclusion") === "failed" ? "failed" : "succeeded";
      const res = await h.app.report(reportRequest(id, conclusion, { base, t: Date.now(), runId: String(++runs), host: h.world.deployments[id].url }));
      events.push(`The workflow reported ${conclusion} for ${id}: POST /report answered ${res.status} ${await res.text()}`);
    } else if (act === "uninstall") {
      const res = await h.app.webhook(removedWebhook({ base, at: Date.now() }));
      events.push(`Vercel sent integration-configuration.removed: /webhook answered ${res.status}.`);
    } else if (act === "reset") {
      seed();
    }
    return new Response(null, { status: 303, headers: { location: "/__fake" } });
  }
  if (url.pathname === "/__fake/state") {
    return new Response(JSON.stringify(state(), null, 2), { headers: { "content-type": "application/json" } });
  }
  const production = Object.entries(h.world.deployments).filter(([, d]) => d.target === "production").map(([id]) => id);
  const options = production.map((id) => `<option${id === production.at(-1) ? " selected" : ""}>${esc(id)}</option>`).join("");
  const st = state();
  const body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Fake Vercel and GitHub</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:2rem auto;padding:0 16px;background:#fff;color:#111}code,pre{font:13px ui-monospace,monospace}pre{background:#f4f4f5;padding:12px;overflow:auto;border-radius:8px}form{display:inline-block;margin:0 8px 8px 0}button{font:inherit;padding:6px 12px;border-radius:8px;border:1px solid #bbb;background:#f8f8f8;cursor:pointer}ol li{margin:4px 0}.bad{color:#b00020}</style></head><body>
<h1>Fake Vercel and GitHub</h1>
<p>Local only. The server is the real one; Vercel and GitHub are fakes. Nothing leaves this machine.</p>
<h2>Steps</h2>
<ol>
<li><a href="${esc(listingInstallUrl(base))}">Install from the listing</a>: the redirect Vercel sends after <code>vercel.com/integrations/penthera/new</code> (<code>source=external</code>, no state).</li>
<li>Pick <strong>gaia-web</strong>, then <strong>Next: add the workflow</strong>, then <strong>Turn on the check</strong>. Done sends you to Vercel's <code>next</code> URL; come back here.</li>
<li>Make a production deployment, then send a pass. Make another and send a fail. The runs below show the conclusions.</li>
<li>Open <a href="/configure?configurationId=${esc(h.world.configurationId)}">Configure</a>, then uninstall. The store and our check are then empty.</li>
</ol>
<h2>Act as Vercel and GitHub</h2>
<form method="post"><input type="hidden" name="act" value="deploy"><button>Make a production deployment</button></form>
<form method="post"><input type="hidden" name="act" value="report"><select name="deployment">${options}</select> <select name="conclusion"><option>succeeded</option><option>failed</option></select> <button>Workflow reports</button></form>
<form method="post"><input type="hidden" name="act" value="uninstall"><button>Uninstall (webhook)</button></form>
<form method="post"><input type="hidden" name="act" value="reset"><button>Reset everything</button></form>
<h2>What happened</h2><ol>${events.map((e) => `<li>${esc(e)}</li>`).join("")}</ol>
${st.violations.length ? `<p class="bad"><strong>Requests Vercel would refuse:</strong></p><pre class="bad">${esc(st.violations.join("\n"))}</pre>` : "<p>Every request to the fake Vercel fit its spec and the table of what Vercel accepts.</p>"}
${st.outside.length ? `<p class="bad"><strong>Requests to anywhere else (refused):</strong></p><pre class="bad">${esc(st.outside.join("\n"))}</pre>` : ""}
<h2>State</h2><pre>${esc(JSON.stringify({ store: st.store, links: st.links, checks: st.checks, runs: st.runs }, null, 2))}</pre>
<p><a href="/__fake/state">As JSON</a></p></body></html>`;
  return new Response(body, { headers: { "content-type": "text/html; charset=utf-8" } });
}

function state() {
  const runsView = Object.fromEntries(Object.entries(h.vercel.runs).map(([d, list]) => [d, list.map(({ id, checkId, status, conclusion, conclusionText, externalUrl }) => ({ id, checkId, status, conclusion, conclusionText, externalUrl }))]));
  return {
    store: h.store.dump().map(({ configurationId, ownerId, createdAt }) => ({ configurationId, ownerId, createdAt, token: "(sealed)" })),
    links: h.store.dumpLinks(),
    checks: h.vercel.checks,
    runs: runsView,
    violations: h.vercel.violations,
    outside: h.outside,
  };
}

async function handle(req, res) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const url = new URL(req.url, base);
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) if (v !== undefined) headers.set(k, Array.isArray(v) ? v.join(", ") : v);
  headers.set("x-real-ip", "127.0.0.1");
  const request = new Request(url, { method: req.method, headers, body: ["GET", "HEAD"].includes(req.method) ? undefined : Buffer.concat(chunks) });

  let response;
  if (url.pathname === "/__fake" || url.pathname === "/__fake/state") response = await fakePage(request);
  else if (ROUTES[url.pathname]) response = await h.app[ROUTES[url.pathname]](request);
  else if (/^\/(fonts\/[A-Za-z0-9.-]+|favicon\.svg)$/.test(url.pathname)) {
    try {
      const file = readFileSync(new URL(url.pathname.slice(1), PUBLIC));
      response = new Response(file, { headers: { "content-type": url.pathname.endsWith(".svg") ? "image/svg+xml" : url.pathname.endsWith(".woff2") ? "font/woff2" : "text/plain" } });
    } catch {
      response = new Response("not found", { status: 404 });
    }
  } else response = new Response("not found", { status: 404 });

  const out = {};
  response.headers.forEach((v, k) => { if (k !== "set-cookie") out[k] = v; });
  // The server sends the browser to vercel.com at the end (Vercel's `next`) and on /start. Here the
  // browser comes back to /__fake instead, which says where the real flow would have gone.
  if (out.location && new URL(out.location, base).origin !== new URL(base).origin) {
    events.push(`The server sent the browser to ${out.location} (${url.pathname}). On real Vercel that page ${url.pathname === "/start" ? "asks which team to install on" : "closes the install window"}; here you are back on this page.`);
    out.location = "/__fake";
  }
  const cookies = response.headers.getSetCookie();
  if (cookies.length) out["set-cookie"] = cookies;
  res.writeHead(response.status, out);
  res.end(Buffer.from(await response.arrayBuffer()));
}

const server = createServer((req, res) => handle(req, res).catch((e) => {
  res.writeHead(500, { "content-type": "text/plain" });
  res.end(`local-journey: ${e.stack}`);
}));
const at = process.argv.indexOf("--port");
server.listen(at > 0 ? Number(process.argv[at + 1]) : 0, "127.0.0.1", () => {
  base = `http://localhost:${server.address().port}`;
  seed();
  process.stdout.write(`Penthera on Vercel, local: ${base}
  Start here: ${base}/__fake
  1. Install from the listing (link on /__fake): source=external, no state.
  2. Pick gaia-web, add the workflow, Turn on the check.
  3. On /__fake: make a production deployment, send a pass; make another, send a fail.
  4. Configure, then Uninstall on /__fake: the store and our check are empty.
Stop with Ctrl-C.
`);
});
