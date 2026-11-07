/**
 * The integration's routes as plain Web handlers: (Request) -> Response.
 * api/*.mjs wraps each one for Vercel; tests call them directly with an
 * in-memory store and a mocked fetch.
 *
 *   GET  /start      external install: sets the CSRF state cookie, then sends you to Vercel
 *   GET  /install    Redirect URL: checks state, exchanges the code, stores the sealed token
 *   GET  /setup      pick projects (needs the 30-minute session cookie from /install)
 *   POST /setup      action=workflow | enable | remove
 *   GET  /configure  Configuration URL
 *   POST /webhook    Webhook URL: signed integration-configuration events only
 *   POST /report     the workflow's pass or fail, with a GitHub OIDC token: sets our check run's conclusion
 *   GET  /sweep      weekly cron: deletes records whose token no longer works
 *   GET  /health
 */
import { createHash } from "node:crypto";
import {
  ConfigError, cookieKey, mac, openToken, parseKeys, randomToken, safeEqual, sealToken, signValue, unsignValue,
  verifyWebhookSignature,
} from "./crypto.mjs";
import { clearCookie, esc, html, json, message, readBody, readCookie, readForm, redirect, safeNext, setCookie } from "./http.mjs";
import { logError, logInfo } from "./log.mjs";
import { OidcError, jwksCache, verifyGithubToken } from "./oidc.mjs";
import { STAT_FIELDS } from "./store.mjs";
import { VercelError, exchangeCode, vercelClient } from "./vercel.mjs";
import { WORKFLOW_PATH, WORKFLOW_YAML, checkBody, githubNewFileUrl, isIntegrationCheck, isOurCheck, isOurIntegrationsCheck } from "./workflow.mjs";

const SESSION = "pv_session";
const STATE = "pv_state";
const SESSION_MS = 30 * 60_000;
/** The /start state cookie lasts as long as Vercel's install code: 30 minutes. */
const STATE_SECONDS = 30 * 60;
const MAX_PROJECTS_PER_POST = 20;
const CONFIG_ID = /^icfg_[A-Za-z0-9]{1,64}$/;
const TEAM_ID = /^team_[A-Za-z0-9]{1,64}$/;
const PROJECT_ID = /^prj_[A-Za-z0-9]{1,64}$/;
const DEPLOYMENT_ID = /^dpl_[A-Za-z0-9]{1,64}$/;
const INTEGRATION_ID = /^oac_[A-Za-z0-9]{1,64}$/;
const GITHUB_REPO = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;
/** The only body POST /report accepts, and the only conclusions. */
const REPORT_FIELDS = ["conclusion", "deploymentId", "projectId"];
// Sent by the workflow since 8 Nov: a SHA-256 of the host it scanned (never the host: no deployment
// URL reaches us), and why it could not read the site. A workflow from before sends neither; its
// "succeeded" then counts as failed, with no host to bind.
const REPORT_OPTIONAL = ["hostSha256", "reason"];
const CONCLUSIONS = new Set(["succeeded", "failed"]);
const sha256 = (s) => createHash("sha256").update(s).digest("hex");
/** The workflow's reasons a scan did not read the site, in the words the check shows. */
const NOT_READ = {
  unreachable: "nothing answered at the deployment",
  challenge: "a firewall served a bot challenge instead of the site",
  denied: "the deployment answered 401 or 403 (Deployment Protection?)",
  redirected: "the deployment redirected the scanner elsewhere instead of serving the site",
  status: "the deployment's home page did not answer 2xx",
  rate_limited: "requests were rate limited during the scan",
  blocked: "a firewall's block page answered instead of the site",
  incomplete: "the scan did not finish reading the site",
  unreadable: "the scan left no report to check",
};
const TEXT = {
  succeeded: "Penthera found no high or critical issue. Details in the GitHub job summary.",
  failed: "Penthera found a high or critical issue, or could not finish the scan. Details in the GitHub job summary.",
  unbound: "Scanned URL is not this deployment, so it was not checked. Update the workflow from Penthera's setup page.",
};
/** Reports per runner address per minute, per function instance. The firewall rule in README.md is the real limit. */
const REPORTS_PER_MINUTE = 30;
/** Unverified refusals are written to the counters at most this often, per instance. */
const STATS_FLUSH_MS = 60_000;

/** The OIDC audience the workflow asks GitHub for: this server's /report for one deployment. */
export const reportAudience = (origin, deploymentId) => `${origin}/report/${deploymentId}`;
/** Best-effort check cleanup on uninstall stays well inside the webhook's maxDuration (25 s). */
const CLEANUP_MS = 15_000;
/** How far Vercel's event clock may run ahead of ours before a stored time counts as tampered. */
const CLOCK_SKEW_MS = 10 * 60_000;
/** Vercel's dashboard links that pick the team (and project) for the user. */
const VERCEL_INTEGRATIONS = "https://vercel.com/d?to=%2F%5Bteam%5D%2F%7E%2Fintegrations&title=Open+Integrations";
const VERCEL_CHECKS = "https://vercel.com/d?to=%2F%5Bteam%5D%2F%5Bproject%5D%2Fsettings%2Fbuild-and-deployment%23deployment-checks&title=Open+Deployment+Checks";
const ISSUES_URL = "https://github.com/danoszz/penthera/issues/new?title=Vercel+integration%3A+Turn+on+failed";

/** Our own store failed while turning a check on (not Vercel). */
class StoreProblem extends Error {}

/** Install exchanges per visitor per minute, per function instance. The firewall rule in README.md is the real limit. */
const INSTALLS_PER_MINUTE = 10;

/** Reads and checks the env once per call. Throws ConfigError without echoing values. */

// The page anyone sees who opens the bare domain. Static, no script, no data.
const HOME = `<div>
<p class="shrug" role="img" aria-label="Shrug">¯\\_(ツ)_/¯</p>
<p class="line">Not much to find here. Found something anyway?</p>
<a class="btn go" href="https://github.com/danoszz/penthera" rel="noopener noreferrer">Open a pull request</a>
</div>`;

// What the integration asks for, and why. Each line is checked against lib/ and workflow/penthera-vercel.yml.
const SOURCE_URL = "https://github.com/danoszz/penthera/tree/main/integrations/vercel";
const asks = ({ open = false } = {}) => `<details class="faq"${open ? " open" : ""}><summary>What Penthera asks for, and why</summary>
<dl>
<dt>Access to Vercel</dt>
<dd>Deployment Checks, read and write, to add and remove the check and to set its result for each production deploy. Projects, read, to list your projects and their repos. Deployments, read, to confirm a result is for a production deploy of that project. Nothing else.</dd>
<dt>What this server keeps</dt>
<dd>One encrypted install token, with the installation id, your team or user id, the install date and a random value that ends old setup sessions. For each project with the check on, the project id and which installation turned it on. We delete all of it when you uninstall. Apart from that, anonymous daily totals with no ids, deleted after 90 days. No code, no deployment URLs, no results.</dd>
<dt>What the workflow does</dt>
<dd>It runs Penthera's passive scan on your deployment, in your own GitHub Actions. The file holds no secrets; behind Vercel Authentication it reads one from your repo's secrets, the bypass secret, and sends it only to your deployment. For a production deploy it then sends us the deployment id, the project id, pass or fail, a fingerprint (SHA-256) of the host it scanned and, if it couldn't read the site, a reason code, with a token GitHub signs for your repo. We check the token, pass only a scan of that deployment's own host, set the check's result in Vercel, and keep nothing about it, only anonymous daily totals to keep the service working. The findings stay in GitHub: the job summary and a run artifact.</dd>
<dt>What it never does</dt>
<dd>It never reads your code, never writes to your repo beyond one commit status, and never sends findings or code to us. It doesn't attack your site: it reads your pages and sends one login with obviously fake credentials, to check a wrong password is refused.</dd>
<dt>Why you commit the workflow yourself</dt>
<dd>We don't ask for write access to your repos, on purpose. One commit by you is the price.</dd>
</dl>
<ul class="links"><li><a href="https://docs.penthera.org/vercel/terms" target="_blank" rel="noopener noreferrer">Terms</a></li><li><a href="https://docs.penthera.org/vercel/privacy" target="_blank" rel="noopener noreferrer">Privacy</a></li><li><a href="${SOURCE_URL}" target="_blank" rel="noopener noreferrer">Source on GitHub</a></li></ul>
</details>`;

// What a production deploy does once the check is on: shown before Turn on, and on Done.
const NEXT_STEPS = `<h2>What happens on your next deploy</h2>
<ol class="steps">
<li><span class="n" aria-hidden="true">1</span><span><strong>Vercel builds it</strong> and asks your repo's workflow to scan it.</span></li>
<li><span class="n" aria-hidden="true">2</span><span><strong>Penthera scans the live deployment</strong> in your GitHub Actions. That usually takes under a minute, and the deploy waits for it.</span></li>
<li><span class="n" aria-hidden="true">3</span><span><strong>A pass goes live.</strong> A fail stays out of production, and the check in Vercel links to the findings in the GitHub job summary.</span></li>
</ol>
<p class="small" data-reason="auto_alias"><strong>One Vercel setting matters:</strong> automatic production aliasing, which is on unless you turned it off (Project Settings, Environments, Production). The check holds a deploy only while it's on. With it off, Vercel never moves your domain by itself, so there's nothing to hold back, and the scan still runs.</p>`;

// Changing an install happens in Vercel; this says where. `confirmed` is true on the status view.
const UNINSTALL = "<strong>Uninstall.</strong> Vercel, Settings, Integrations, Penthera, Manage, Uninstall. We delete the token and project links then. Remove <code>penthera-vercel.yml</code> from your repo too.";
const manage = (confirmed) => `<h2>${confirmed ? "Change your install" : "What you can do"}</h2>
<ul class="steps">
${confirmed ? "" : '<li><span><strong>Turn the check on or off.</strong> Show my projects, then one button per project. Or in Vercel: Project Settings, Deployment Checks.</span></li>\n'}<li><span><strong>Add projects.</strong> Give Penthera access to them in Vercel (Settings, Integrations, Penthera, Manage), then ${confirmed ? '<a href="/setup">reload this page</a>' : "Show my projects"}.</span></li>
<li><span>${UNINSTALL}</span></li>
</ul>`;

// The workflow, for anyone who needs it again: closed by default.
const copyWorkflow = () => `<details class="faq copy"><summary>Copy the workflow again</summary>
<div class="in"><p class="small">Commit it as <code>${WORKFLOW_PATH}</code> on your default branch. The workflow only runs from there.</p>
<textarea readonly spellcheck="false" wrap="off" aria-label="Workflow file">${esc(WORKFLOW_YAML)}</textarea></div>
</details>`;

// What a refused install leaves behind. Vercel makes the installation before it sends the browser to
// /install, so it probably still lists Penthera; we stopped before the code exchange (README, "A refused install").
const LEFT_REFUSED = {
  penthera: "We stored nothing and added nothing to your projects. Nothing to undo here.",
  vercel: "Penthera may still be listed under Settings, Integrations, with no access to any project. If Vercel says it's already installed when you restart, remove it there first. If it ends up listed twice, remove the one with no projects.",
};

export function readConfig(env) {
  const need = (name) => {
    if (!env[name]) throw new ConfigError(`${name} is not set`);
    return env[name];
  };
  const baseUrl = new URL(need("PUBLIC_BASE_URL"));
  if (baseUrl.protocol !== "https:" && baseUrl.hostname !== "localhost") throw new ConfigError("PUBLIC_BASE_URL must be https");
  return {
    clientId: need("INTEGRATION_CLIENT_ID"),
    clientSecret: need("INTEGRATION_CLIENT_SECRET"),
    keys: parseKeys(env.PENTHERA_TOKEN_KEYS),
    origin: baseUrl.origin,
    redirectUri: `${baseUrl.origin}/install`,
    slug: /^[a-z0-9-]{1,32}$/.test(env.INTEGRATION_SLUG ?? "") ? env.INTEGRATION_SLUG : "penthera",
    // An override for the check's `source.integrationId`. Without it, the id is read from Vercel's
    // record of the installation on each "Turn on the check" (README, "The check").
    integrationId: INTEGRATION_ID.test(env.INTEGRATION_ID ?? "") ? env.INTEGRATION_ID : null,
    cronSecret: env.CRON_SECRET || null,
  };
}

/**
 * @param {{ env: object, store: object, fetch?: typeof fetch, now?: () => number }} deps
 */
export function createApp({ env = process.env, store, fetch: fetchImpl = globalThis.fetch, now = Date.now }) {
  const cfg = () => readConfig(env);
  // GitHub's OIDC signing keys, cached for 10 minutes in this instance (lib/oidc.mjs).
  const jwks = jwksCache({ fetch: fetchImpl, now });

  /**
   * A record from the store, only if it is the record for `id`: the id we looked up, which came
   * from a signed cookie, a signed webhook or the store's own key. A record whose configurationId
   * says otherwise was moved or edited in the store and is never used.
   */
  async function load(id) {
    const record = await store.get(id);
    if (!record) return null;
    if (record.configurationId !== id) {
      logError("record_mismatch");
      return null;
    }
    return record;
  }

  /**
   * A Vercel client for the record under the trusted `id`. The id is the AAD, never the record's own
   * field, so a ciphertext moved from another installation fails to decrypt and no call is made.
   */
  const client = (record, id, keys) =>
    vercelClient({
      token: openToken(record, id, keys),
      teamId: TEAM_ID.test(record.ownerId) ? record.ownerId : null,
      fetch: fetchImpl,
    });

  /** The client, or null when the token does not decrypt under `id`. */
  function tryClient(record, id, keys) {
    try {
      return client(record, id, keys);
    } catch (e) {
      logError("token_unreadable", { code: e instanceof ConfigError ? "config" : "decrypt" });
      return null;
    }
  }

  /**
   * The install session from the cookie, with its record, or null. The cookie is bound to the
   * record's session nonce when it was issued: 192 random bits, made fresh on every install and
   * every verified transfer, whether or not the owner changed. So a transfer (also A to B to A, or
   * one that names no new owner), a reinstall, or an uninstall and reinstall of the same id ends
   * every older session: a deleted record never comes back with a matching nonce. The new owner
   * needs a fresh install to get a session. The owner is checked too, as a second guard.
   */
  async function session(request, c) {
    const raw = readCookie(request, SESSION);
    const data = raw && unsignValue(raw, cookieKey(c.keys), now());
    if (!data || !CONFIG_ID.test(data.c) || typeof data.o !== "string" || typeof data.s !== "string") return null;
    const record = await load(data.c);
    if (!record || !safeEqual(record.ownerId, data.o) || !safeEqual(record.sessionNonce, data.s)) return null;
    const api = tryClient(record, data.c, c.keys);
    return api ? { raw, configurationId: data.c, next: data.n ?? null, record, api } : null;
  }

  // Each /install makes one outbound exchange and each /report a few, so a visitor gets a few a
  // minute. Per instance only; the firewall rule is the real limit.
  function limiter(max) {
    const hits = new Map();
    return (request) => {
      const who = (request.headers.get("x-real-ip") ?? request.headers.get("x-forwarded-for")?.split(",")[0] ?? "unknown").trim();
      const t = now();
      // A clock that moved backwards keeps no future-dated hit around (BYPASS-CHECKLIST row 11).
      const recent = (hits.get(who) ?? []).filter((x) => x > t - 60_000 && x <= t);
      recent.push(t);
      if (hits.size > 10_000) hits.clear();
      hits.set(who, recent);
      return recent.length > max;
    };
  }
  const installLimited = limiter(INSTALLS_PER_MINUTE);
  const reportLimited = limiter(REPORTS_PER_MINUTE);

  const formToken = (s, c) => mac(cookieKey(c.keys), `form:${s.raw}`);

  // A form post must come from our own pages: same origin when the browser says, and the session's form token.
  function formAllowed(request, form, s, c) {
    const origin = request.headers.get("origin");
    if (origin && origin !== "null" && origin !== c.origin) return false;
    return safeEqual(form.get("csrf"), formToken(s, c));
  }

  async function start() {
    const c = cfg();
    const state = randomToken();
    const target = new URL(`https://vercel.com/integrations/${c.slug}/new`);
    target.searchParams.set("state", state);
    return redirect(target.toString(), { status: 302, cookies: [setCookie(STATE, state, STATE_SECONDS)] });
  }

  async function install(request) {
    const c = cfg();
    const q = new URL(request.url).searchParams;
    const code = q.get("code");
    const configurationId = q.get("configurationId");
    const teamId = q.get("teamId");
    const state = q.get("state");
    const source = q.get("source");
    const next = q.get("next") ? safeNext(q.get("next")) : null;
    if (!code || !/^[A-Za-z0-9]{8,128}$/.test(code)) return message(400, "Part of your install link is missing", "Vercel's link was cut short, often by copying it. Restarting from Vercel gives you a complete one.", { left: LEFT_REFUSED, action: { href: "/start", label: "Restart on Vercel" }, why: "We go on only when Vercel's link is complete." });
    if (!CONFIG_ID.test(configurationId ?? "")) return message(400, "Part of your install link is missing", "Vercel's link was cut short, often by copying it. Restarting from Vercel gives you a complete one.", { left: LEFT_REFUSED, action: { href: "/start", label: "Restart on Vercel" }, why: "We go on only when Vercel's link is complete." });
    if (teamId && !TEAM_ID.test(teamId)) return message(400, "Part of your install link is missing", "Vercel's link was cut short, often by copying it. Restarting from Vercel gives you a complete one.", { left: LEFT_REFUSED, action: { href: "/start", label: "Restart on Vercel" }, why: "We go on only when Vercel's link is complete." });
    if (q.get("next") && !next) return message(400, "Your install link points away from Vercel", "Its return address isn't on vercel.com, so we stopped before sending you anywhere.", { left: LEFT_REFUSED, action: { href: "/start", label: "Restart on Vercel" }, why: "We only ever send you back to vercel.com, so a link can't take you to another site." });

    // CSRF: an install that comes back with a state (one we started on /start) must match the state
    // cookie this browser still holds. Installs started on vercel.com carry no state: the
    // Marketplace, the deploy button, and the listing link vercel.com/integrations/<slug>/new, which
    // Vercel sends back as source=external (live, 7 Nov 2026; Vercel documents `state` only as
    // passed back when the starter set one). They must name a Vercel source, and the session is
    // bound only after the exchange proves the configuration and its owner (README, "Security").
    // A leftover state cookie from an earlier /start does not block them: such a browser takes the
    // same path as one without the cookie, and the cookie is cleared.
    const cookies = [];
    const stateCookie = readCookie(request, STATE);
    const fromVercel = source === "marketplace" || source === "deploy-button" || source === "external";
    if (state) {
      const reason = !stateCookie ? "state_cookie_missing" : !safeEqual(state, stateCookie) ? "state_mismatch" : null;
      if (reason) {
        logError("install_refused", { code: reason });
        return installRefused(reason);
      }
      cookies.push(clearCookie(STATE));
    } else if (fromVercel) {
      if (stateCookie) cookies.push(clearCookie(STATE));
    } else {
      return message(403, "Install Penthera from Vercel", "This link didn't come from Penthera's page on Vercel, where installs start.", { cookies: stateCookie ? [clearCookie(STATE)] : [], left: LEFT_REFUSED, action: { href: "/start", label: "Open Penthera on Vercel" }, why: "Installs start on Vercel, so a link someone sends you can't connect Penthera to your account.", reason: "no_source" });
    }
    if (installLimited(request)) return message(429, "Too many install tries from your network", "We'll take you back to Vercel in a minute. You don't need to do anything.", { cookies, left: LEFT_REFUSED, action: { href: "/start", label: "Restart now" }, refresh: { seconds: 60, url: "/start" }, why: "A short limit keeps the install page from being flooded." });

    let token;
    try {
      token = await exchangeCode({ code, clientId: c.clientId, clientSecret: c.clientSecret, redirectUri: c.redirectUri, fetch: fetchImpl });
    } catch (e) {
      logError("exchange_failed", { status: e.status ?? 0, code: e.code ?? "network" });
      return message(502, "Vercel's one-time code had already run out", "Each code lasts 30 minutes and works once. Restarting gets you a fresh one.", { cookies, left: LEFT_REFUSED, action: { href: "/start", label: "Restart on Vercel" }, why: "Vercel's code proves the install is yours, and we can't go on without it." });
    }
    // The exchange must name the configuration this redirect claims, and the team, or we store nothing.
    if (token.configurationId !== configurationId || (teamId && token.teamId !== teamId)) {
      logError("configuration_mismatch");
      return message(400, "Vercel named a different install", "The link and Vercel disagree about which install this is, so we stopped and stored nothing.", { cookies, left: LEFT_REFUSED, action: { href: "/start", label: "Restart on Vercel" }, why: "We store an install only once Vercel confirms whose it is." });
    }
    const ownerId = token.teamId ?? token.userId ?? teamId;
    if (!ownerId) return message(502, "Vercel didn't say which team this is for", "We keep each team's install separate, so we need that before going on.", { cookies, left: LEFT_REFUSED, action: { href: "/start", label: "Restart on Vercel" }, why: "We store an install only once Vercel confirms whose it is." });

    // One record per configuration. A deploy-button install may reuse an existing id: we overwrite it,
    // never duplicate, and never hand a record to another owner.
    const previous = await load(configurationId);
    if (previous && previous.ownerId !== ownerId) {
      logError("owner_mismatch");
      return message(409, "This install belongs to another Vercel team", "Restart, and Vercel asks which team to install on. Pick the one you want Penthera on.", { cookies, left: { penthera: "Nothing changed, here or in the other team's setup.", vercel: "The install stays with the team that made it." }, action: { href: "/start", label: "Choose a team on Vercel" }, why: "One team can never take over another team's install, or see its projects." });
    }
    // createdAt is the latest install, so a replayed older uninstall event cannot delete it.
    const createdAt = new Date(now()).toISOString();
    const sessionNonce = randomToken(24);
    await store.put({ configurationId, ownerId, ...sealToken(token.accessToken, configurationId, c.keys), createdAt, sessionNonce });
    const value = signValue({ c: configurationId, o: ownerId, s: sessionNonce, n: next, e: now() + SESSION_MS }, cookieKey(c.keys));
    cookies.push(setCookie(SESSION, value, SESSION_MS / 1000));
    logInfo("install_ok", { source });
    return redirect("/setup", { cookies });
  }

  /**
   * The two ways an install from our own link can fail its state check, each with its own page.
   * Each is refused before the code is exchanged, so nothing is stored and no check is added.
   * Vercel has already made the installation by then; README, "A refused install", says what that
   * leaves behind. Placeholder copy: the Designer owns these pages.
   */
  function installRefused(reason) {
    const why = "An install link works only in the browser that started it, for 30 minutes, so nobody else can finish an install in your name.";
    const pages = {
      state_cookie_missing: ["Your install link has run out", "This browser no longer holds the install it started: more than 30 minutes passed, or the link opened in another browser or on another device."],
      state_mismatch: ["This install didn't start in this browser", "If you clicked Install on Vercel just now, restart it here and it goes through. If you didn't, close this page: nothing happened."],
    };
    const [title, text] = pages[reason];
    return message(403, title, text, { cookies: [clearCookie(STATE)], left: LEFT_REFUSED, action: { href: "/start", label: "Restart on Vercel" }, why, reason });
  }


  async function setupPage(request) {
    const c = cfg();
    const s = await session(request, c);
    if (!s) return expired();
    const from = new URL(request.url).searchParams.get("from");
    const api = s.api;
    let page;
    try {
      page = await api.listProjects({ from: /^\d{1,16}$/.test(from ?? "") ? from : undefined });
    } catch (e) {
      return apiFailure(e, s.configurationId, "projects_failed");
    }
    const eligible = page.projects.filter((p) => p.repo);
    const status = new Map(
      await Promise.all(eligible.map(async (p) => [p.id, await api.listChecks(p.id).then((list) => list.some((k) => isOurCheck(k, p.name, s.configurationId)), () => null)])),
    );
    const single = page.projects.length === 1 && !page.next && !from;
    const anyOn = [...status.values()].some(Boolean);
    const token = formToken(s, c);
    if (anyOn) return statusPage(page, status, token, from);
    const rows = page.projects.map((p, i) => {
      if (!p.repo) return `<li class="row off"><label class="pick"><input type="checkbox" disabled aria-label="Not available"><span class="grow"><span class="name" title="${esc(p.name)}">${esc(p.name)}</span><span class="meta">Needs a GitHub-connected project</span></span></label></li>`;
      const on = status.get(p.id);
      const checked = single || (!anyOn && i === page.projects.indexOf(eligible[0]));
      const box = single
        ? `<input type="checkbox" checked disabled aria-label="Selected"><input type="hidden" name="p" value="${esc(p.id)}">`
        : `<input type="checkbox" name="p" value="${esc(p.id)}"${checked ? " checked" : ""} aria-label="Select ${esc(p.name)}">`;
      const state = on === true ? '<span class="on">Check on</span>' : on === false ? "Check off" : "Check status unknown";
      const remove = on ? `<button class="btn quiet" name="remove" value="${esc(p.id)}" formaction="/setup" type="submit">Remove check</button>` : "";
      return `<li class="row"><label class="pick">${box}<span class="grow"><span class="name" title="${esc(p.name)}">${esc(p.name)}</span><span class="meta">${esc(p.repo)} · ${state}</span></span></label>${remove}</li>`;
    });
    const more = page.next ? `<p class="more"><a href="/setup?from=${esc(page.next)}">More projects</a></p>` : "";
    return html(200, "Penthera: pick your projects", `
<h1>Pick your projects</h1>
<p class="lede">Penthera adds a Deployment Check to each project you pick. Your next production deploy then waits for Penthera's scan, which runs in your own GitHub Actions.</p>
<form method="post" action="/setup">
<input type="hidden" name="csrf" value="${token}">
<input type="hidden" name="action" value="workflow">
<ul class="list">${rows.join("") || '<li class="empty">No projects are shared with this integration. Change the project access in Vercel and open Configure.</li>'}</ul>
${more}
<div class="act"><button class="btn go" type="submit">Next: add the workflow</button></div>
</form>
<p class="small">When Penthera finds a high or critical issue, the check keeps your production domain on the last good deployment. Previews are scanned too and never blocked.</p>
${asks()}`, { step: "Step 1 of 2: pick" });
  }

  // Once a check is on, /setup reports in instead of starting the wizard again. Each row says what
  // Vercel says about its check now; results stay in GitHub, so the row links there.
  function statusPage(page, status, token, from) {
    const total = page.projects.length;
    const onCount = [...status.values()].filter((v) => v === true).length;
    const title = page.next || from
      ? "Your projects"
      : onCount === total
        ? total === 1 ? "Penthera checks your project" : `Penthera checks all ${total} projects`
        : `Penthera checks ${onCount} of ${total} projects`;
    const rows = page.projects.map((p) => {
      const name = `<span class="name" title="${esc(p.name)}">${esc(p.name)}</span>`;
      if (!p.repo) return `<li class="row off"><span class="grow">${name}<span class="meta">Needs a GitHub-connected project</span></span></li>`;
      const on = status.get(p.id);
      const state = on === true ? '<span class="on">Check on</span>' : on === false ? "Check off" : "Check status unknown";
      const link = `<a class="sub" href="https://github.com/${esc(p.repo)}/actions/workflows/penthera-vercel.yml" target="_blank" rel="noopener noreferrer">Workflow and results <span aria-hidden="true">↗</span></a>`;
      const button = on === true
        ? `<button class="btn quiet" name="remove" value="${esc(p.id)}" type="submit" aria-label="Turn off for ${esc(p.name)}">Turn off</button>`
        : on === false ? `<button class="btn quiet" name="p" value="${esc(p.id)}" type="submit" aria-label="Turn on for ${esc(p.name)}">Turn on</button>` : "";
      return `<li class="row"><span class="grow">${name}<span class="meta">${esc(p.repo)} · ${state}</span>${link}</span>${button}</li>`;
    });
    const more = page.next ? `<p class="more"><a href="/setup?from=${esc(page.next)}">More projects</a></p>` : "";
    return html(200, "Penthera: your projects", `
<h1>${title}</h1>
<p class="lede">Each production deploy of a checked project waits for Penthera's scan. Previews are scanned too and never blocked.</p>
<form method="post" action="/setup">
<input type="hidden" name="csrf" value="${token}">
<input type="hidden" name="action" value="workflow">
<ul class="list">${rows.join("")}</ul>
</form>
${more}
${manage(true)}
${copyWorkflow()}
${asks()}`);
  }

  async function setupPost(request) {
    const c = cfg();
    const s = await session(request, c);
    if (!s) return expired();
    const form = await readForm(request);
    if (!form || !formAllowed(request, form, s, c)) return message(403, "This page was out of date", "Nothing changed. Reload to pick up where you were.", { action: { href: "/setup", label: "Reload setup" }, why: "Each setup page carries a one-time check, so another site can't submit it for you." });
    const api = s.api;

    const removeId = form.get("remove");
    if (removeId) {
      if (!PROJECT_ID.test(removeId)) return message(400, "That project isn't in your list", "Nothing changed. Reload and pick again.", { action: { href: "/setup", label: "Reload setup" } });
      try {
        const project = await api.getProject(removeId);
        for (const check of await api.listChecks(removeId)) {
          if (isOurCheck(check, project.name, s.configurationId)) await api.deleteCheck(removeId, check.id);
        }
        // The relay stops for this project. A link that another installation set is left alone.
        const link = await store.getLink(removeId);
        if (link?.configurationId === s.configurationId) await store.deleteLink(removeId);
      } catch (e) {
        return apiFailure(e, s.configurationId, "remove_failed");
      }
      logInfo("check_off", { projects: 1 });
      return redirect("/setup");
    }

    const ids = [...new Set(form.getAll("p"))].filter((id) => PROJECT_ID.test(id)).slice(0, MAX_PROJECTS_PER_POST);
    if (!ids.length) return message(400, "Pick a project first", "Tick at least one project, then go on.", { action: { href: "/setup", label: "Back to your projects" } });
    // Names and repos come from Vercel, never from the form.
    let projects;
    try {
      projects = (await Promise.all(ids.map((id) => api.getProject(id)))).filter((p) => p.repo);
    } catch (e) {
      return apiFailure(e, s.configurationId, "project_failed");
    }
    if (!projects.length) return message(400, "This project doesn't deploy from GitHub", "Penthera runs in GitHub Actions, so the project needs a GitHub repo. In Vercel: Project Settings, Git.", { action: { href: "/setup", label: "Back to your projects" } });

    if (form.get("action") === "enable") {
      const failed = [];
      const taken = [];
      const lookalikes = [];
      const integrationId = await integrationIdFor(api, s.configurationId, c);
      for (const p of projects) {
        try {
          // A project's link belongs to the installation that owns a live Penthera check on it. If
          // another installation's link is there and that installation's own token still sees its
          // check, the link stays theirs and this one adds no second check (README, "Links").
          const current = await store.getLink(p.id);
          if (current && current.configurationId !== s.configurationId && (await ownsCheck(current.configurationId, p.id, c))) {
            taken.push(p);
            continue;
          }
          // The link first: a link with no check changes nothing, while a check with no link would
          // hold production until Vercel times the run out.
          try {
            await store.putLink({ projectId: p.id, configurationId: s.configurationId });
          } catch {
            throw new StoreProblem();
          }
          const existing = await api.listChecks(p.id);
          if (!existing.some((k) => isIntegrationCheck(k, s.configurationId))) {
            // A check our own integration made under an earlier installation that this server no
            // longer holds (an uninstall and reinstall) would keep holding production with nobody to
            // finish its runs. It is ours by source, so it is removed first. A live installation's
            // check is left alone, and nothing that is not ours by source is ever deleted.
            const leftovers = existing.filter((k) => isOurIntegrationsCheck(k, integrationId) && k.source.integrationConfigurationId !== s.configurationId);
            let skip = false;
            for (const k of leftovers) {
              if (await ownsCheck(k.source.integrationConfigurationId, p.id, c)) {
                taken.push(p);
                skip = true;
                break;
              }
              try {
                await api.deleteCheck(p.id, k.id);
              } catch (e) {
                throw Object.assign(e, { leftover: true });
              }
            }
            if (skip) continue;
            await createOurCheck(api, p.id, s.configurationId, integrationId);
          }
          // A check named like ours that this installation cannot vouch for: say so, delete nothing.
          const others = existing.filter((k) => /^penthera\b/i.test(String(k?.name ?? "")) && !isIntegrationCheck(k, s.configurationId) && !isOurIntegrationsCheck(k, integrationId));
          if (others.length) lookalikes.push(p);
        } catch (e) {
          const problem = turnOnProblem(e);
          logError("check_failed", { status: e.status ?? 0, code: e.code ?? problem.kind, message: e.detail ?? "", route: problem.kind });
          failed.push({ ...p, problem });
        }
      }
      const turnedOn = projects.filter((p) => !failed.some((f) => f.id === p.id) && !taken.includes(p)).length;
      if (turnedOn) logInfo("check_on", { projects: turnedOn });
      // Vercel's install ends on its `next` address, which closes the popup; Turn on already said what comes next.
      if (!failed.length && !taken.length && !lookalikes.length && s.next) return redirect(s.next, { cookies: [clearCookie(SESSION)] });
      const failedIds = new Set(failed.map((p) => p.id));
      return donePage(projects.filter((p) => !failedIds.has(p.id) && !taken.includes(p)), failed, taken, s, lookalikes);
    }

    const token = formToken(s, c);
    const items = projects.map((p) => {
      const link = githubNewFileUrl(p.repo, p.branch);
      const button = link ? `<a class="btn" href="${esc(link)}" target="_blank" rel="noopener noreferrer">Commit it on GitHub <span aria-hidden="true">↗</span></a>` : '<span class="meta">Copy the file below by hand.</span>';
      return `<li class="row stack"><span class="grow"><span class="name" title="${esc(p.name)}">${esc(p.name)}</span><span class="meta">${esc(p.repo)}, branch ${esc(p.branch)}</span></span>${button}<input type="hidden" name="p" value="${esc(p.id)}" form="enable"></li>`;
    });
    return html(200, "Penthera: add the workflow", `
<h1>Add the workflow <span class="aside">(one commit)</span></h1>
<p class="lede">Commit <code>${WORKFLOW_PATH}</code> on each repo's default branch. The button opens GitHub in a new tab with the file filled in. It holds no secrets.</p>
<ul class="list">${items.join("")}</ul>
<label class="cap" for="yaml">Or copy it:</label>
<textarea id="yaml" readonly spellcheck="false" wrap="off">${esc(WORKFLOW_YAML)}</textarea>
<p class="small" data-reason="deployment_protection">Behind Vercel Authentication? Create Vercel's Protection Bypass for Automation secret (Project Settings, Deployment Protection) and add it to the repo as the Actions secret <code>VERCEL_AUTOMATION_BYPASS_SECRET</code>. The workflow sends it to your deployment only. It never reaches us. <a href="https://docs.penthera.org/vercel#deployment-protection" target="_blank" rel="noopener noreferrer">How</a></p>
<form id="enable" method="post" action="/setup">
<input type="hidden" name="csrf" value="${token}">
<input type="hidden" name="action" value="enable">
<h2>Then turn on the check</h2>
<p class="lede">Back from GitHub? Turn it on here. From then on, each production deploy waits for Penthera's scan.</p>
${NEXT_STEPS}
<div class="act"><button class="btn go" type="submit">${s.next ? "Turn on the check and finish" : "Turn on the check"}</button></div>
${s.next ? '<p class="small">This takes you back to Vercel, and the install is done.</p>' : ""}
</form>
<p class="small">Your next production deploy will wait for Penthera's check. Findings stay in the GitHub job summary. Only pass or fail reaches us, to pass on to Vercel.</p>
${asks()}`, { step: "Step 2 of 2: commit, turn on" });
  }

  /**
   * After "Turn on the check": what is on, what happens on the next deploy and where the result
   * shows. Also when Vercel gave a `next` address: its one blue button finishes the install there.
   */
  function donePage(on, failed, taken, s, lookalikes = []) {
    const names = (list) => list.map((p) => esc(p.name)).join(", ");
    const notes = [
      ...failed.map((p) => problemNote(p, p.problem)),
      taken.length ? `<p class="note">Another Penthera installation already runs the check for ${names(taken)}. Nothing changed there. Remove that check first to move it here.</p>` : "",
      lookalikes.length ? `<div class="note" data-reason="lookalike_check"><p>${names(lookalikes)} also has a check named Penthera that this installation did not add. If it is from an earlier install, remove it, or production deploys keep waiting for it.</p><p><a href="${VERCEL_CHECKS}" target="_blank" rel="noopener noreferrer">Open Deployment Checks in Vercel <span aria-hidden="true">↗</span></a></p></div>` : "",
    ].join("");
    const status = failed.length ? 502 : taken.length ? 409 : 200;
    const next = on.length ? `
${NEXT_STEPS}
<ul class="links col">${on.map((p) => `<li><a href="https://github.com/${esc(p.repo)}/actions/workflows/penthera-vercel.yml" target="_blank" rel="noopener noreferrer">${esc(p.name)} on GitHub Actions <span aria-hidden="true">↗</span></a></li>`).join("")}<li><a href="${SOURCE_URL}#readme" target="_blank" rel="noopener noreferrer">How it works <span aria-hidden="true">↗</span></a></li></ul>` : "";
    // Try again only when trying again can help: Vercel or our store was busy, not a refusal.
    const retry = failed.some((p) => p.problem.transient) ? '<a class="btn" href="/setup">Try again</a>' : "";
    const finish = s.next || retry ? `<div class="act">${s.next ? `<a class="btn go" href="${esc(s.next)}">Back to Vercel</a>` : ""}${retry}</div>` : "";
    const title = status === 200 ? "The check is on" : on.length ? "Some checks were not turned on" : "The check was not turned on";
    const lede = on.length ? `<p class="lede">Penthera now checks each production deploy of ${names(on)} before it goes live.</p>` : "";
    return html(status, "Penthera: done", `<h1>${title}</h1>${notes}${lede}${finish}${next}`, { main: "one" });
  }

  async function configure(request) {
    const c = cfg();
    const id = new URL(request.url).searchParams.get("configurationId");
    const s = await session(request, c);
    if (s && s.configurationId === id) return redirect("/setup");
    // Vercel's Configure button proves nothing about who clicks it, so without the install
    // session this page shows only what is the same for everyone.
    return html(200, "Penthera: your install", `
<h1>Your Penthera install</h1>
<p class="lede">To show your projects and their checks here, Vercel first confirms it's you. That's one click on Vercel.</p>
<div class="act"><a class="btn go" href="/start">Show my projects</a></div>
<dl class="left">
<div><dt>Penthera</dt><dd>An encrypted install token and the ids of projects with the check on. No code, no results.</dd></div>
<div><dt>Vercel</dt><dd>The check on each project, under Project Settings, Deployment Checks.</dd></div>
<div><dt>GitHub</dt><dd>The workflow and every scan result, in your repo's Actions tab.</dd></div>
</dl>
${manage(false)}
${copyWorkflow()}
${asks()}`);
  }

  async function webhook(request) {
    const c = cfg();
    const raw = await readBody(request, 64 * 1024);
    if (raw === null) return json(413, { error: "too_large" });
    if (!verifyWebhookSignature(raw, request.headers.get("x-vercel-signature"), c.clientSecret)) return json(403, { error: "invalid_signature" });
    let event;
    try {
      event = JSON.parse(raw.toString("utf8"));
    } catch {
      return json(400, { error: "bad_json" });
    }
    const id = event?.payload?.configuration?.id;
    const type = event?.type;
    if ((type !== "integration-configuration.removed" && type !== "integration-configuration.transferred") || !CONFIG_ID.test(id ?? "")) {
      return json(200, { ok: true, ignored: true });
    }
    // A store error answers 500, so Vercel retries for up to 24 hours.
    let record;
    try {
      record = await store.get(id);
    } catch {
      logError("store_failed", { route: "webhook" });
      return json(500, { error: "store_unavailable" });
    }
    // A record whose own id is not the one Vercel signed for was tampered with: for `removed` the key
    // is still deleted, with no call to Vercel; a transfer leaves it alone.
    const trusted = record && record.configurationId === id ? record : null;
    if (record && !trusted) logError("record_mismatch");
    if (!trusted) {
      if (type === "integration-configuration.removed") {
        // Also when the record is already gone: a retry after a failed link cleanup lands here.
        try {
          if (record) await store.delete(id);
          await dropLinks(id);
        } catch {
          logError("store_failed", { route: "webhook" });
          return json(500, { error: "store_unavailable" });
        }
      }
      return json(200, { ok: true, deleted: type === "integration-configuration.removed" });
    }
    record = trusted;
    // A signed event replayed after a newer install of the same id changes nothing.
    // createdAt comes from the store. A time beyond our own clock plus a little skew is treated as
    // unreadable and the replay check is skipped: capping it would still make every real uninstall,
    // dated about now, look stale and keep the record forever.
    const latest = now() + CLOCK_SKEW_MS;
    const parsedAt = Date.parse(record.createdAt);
    const installedAt = parsedAt <= latest ? parsedAt : NaN;
    if (eventTime(event) !== null && Number.isFinite(installedAt) && eventTime(event) <= installedAt) return json(200, { ok: true, ignored: "stale" });

    if (type === "integration-configuration.transferred") {
      // Every verified transfer ends older setup sessions, even when it names no new owner. Its time
      // becomes the record's createdAt, so a replay of this or an older transfer changes nothing.
      const t = eventTime(event);
      await store.put({
        ...record,
        ownerId: newOwner(event.payload) ?? record.ownerId,
        createdAt: new Date(t !== null && !(t <= installedAt) ? Math.min(t, latest) : Number.isFinite(installedAt) ? installedAt : now()).toISOString(),
        sessionNonce: randomToken(24),
      });
      return json(200, { ok: true });
    }

    // Removed: open the token into memory, delete the record first, then its project links, then
    // tidy up best effort. A failed link cleanup answers 500; Vercel's retry finds no record and
    // runs the link cleanup again.
    const api = tryClient(record, id, c.keys);
    try {
      await store.delete(id);
      await dropLinks(id);
    } catch {
      logError("store_failed", { route: "webhook" });
      return json(500, { error: "store_unavailable" });
    }
    if (api) await removeOurChecks(api, event.payload.configuration.projects, id);
    logInfo("uninstall_ok");
    return json(200, { ok: true, deleted: true });
  }

  /**
   * The integration id for the check's source: INTEGRATION_ID when set, else Vercel's own record of
   * this installation. When the lookup fails, null: the source then names the configuration only,
   * and the failure is logged with Vercel's code and message.
   */
  async function integrationIdFor(api, configurationId, c) {
    if (c.integrationId) return c.integrationId;
    try {
      const id = await api.getIntegrationId(configurationId);
      if (!id) logError("integration_lookup_failed", { code: "no_integration_id" });
      return id;
    } catch (e) {
      logError("integration_lookup_failed", { status: e.status ?? 0, code: e.code ?? "network", message: e.detail ?? "" });
      return null;
    }
  }

  /**
   * What Vercel's answer to "Turn on" means, in plain words: what happened, what to do, where, and
   * the code to send us. `transient` is true only when trying again can help (429, 5xx, network,
   * our store). Vercel's own message goes in the small print, escaped.
   */
  function turnOnProblem(e) {
    const vercel = e instanceof VercelError;
    const code = vercel ? `Vercel ${e.status} ${e.code}${e.detail ? `: ${e.detail}` : ""}` : e instanceof StoreProblem ? "penthera store_unavailable" : "network";
    const base = { code, link: null, linkLabel: null, transient: false };
    if (e instanceof StoreProblem) return { ...base, kind: "store", what: "Our server could not save this setting. Nothing changed in Vercel.", todo: "Try again in a minute. If it keeps failing, send us the code below.", transient: true };
    if (!vercel) return { ...base, kind: "network", what: "Vercel did not answer in time.", todo: "Try again in a minute.", transient: true };
    if (e.leftover) return { ...base, kind: "leftover", what: "This project still has a Penthera check from an earlier install, and Vercel did not let this installation remove it.", todo: "Remove the old Penthera check in the project's Deployment Checks, then turn the check on again.", link: VERCEL_CHECKS, linkLabel: "Open Deployment Checks in Vercel" };
    if (e.status === 429) return { ...base, kind: "rate_limited", what: "Vercel is limiting requests right now.", todo: "Wait a minute, then try again.", transient: true };
    if (e.status >= 500) return { ...base, kind: "vercel_down", what: "Vercel had a problem on its side.", todo: "Try again in a minute.", transient: true };
    if (e.status === 401) return { ...base, kind: "revoked", what: "Vercel no longer accepts this installation's access. It was uninstalled, or its access was taken back.", todo: "Install Penthera again from Vercel.", link: "/start", linkLabel: "Install again" };
    if (e.status === 403 && e.code === "integration_configuration_disabled") return { ...base, kind: "disabled", what: "Vercel has disabled this installation, usually because the person who installed it left the team.", todo: "A team owner can transfer it in Vercel, Settings, Integrations, or install Penthera again.", link: VERCEL_INTEGRATIONS, linkLabel: "Open Integrations in Vercel" };
    if (e.status === 403) return { ...base, kind: "forbidden", what: "Vercel says this installation may not add Deployment Checks to this project.", todo: "In Vercel, open Settings, Integrations, Penthera, and accept any pending permission update. If there is none, check that the project is shared with Penthera under Manage.", link: VERCEL_INTEGRATIONS, linkLabel: "Open Integrations in Vercel" };
    if (e.status === 404) return { ...base, kind: "not_found", what: "Vercel cannot find this project for this installation. Penthera may no longer have access to it.", todo: "Give Penthera access to the project in Vercel, Settings, Integrations, Penthera, Manage. Then turn the check on again.", link: VERCEL_INTEGRATIONS, linkLabel: "Open Integrations in Vercel" };
    if (e.status === 409 || /\b(exist|duplicate|already|unique)/i.test(e.detail ?? "")) return { ...base, kind: "conflict", what: "Vercel says this project already has a check like this one.", todo: "Open the project's Deployment Checks. Remove an old Penthera check if there is one, then turn the check on again.", link: VERCEL_CHECKS, linkLabel: "Open Deployment Checks in Vercel" };
    return { ...base, kind: "rejected", what: "Vercel did not accept the check's settings. That is on our side, not yours.", todo: "Send us the code below and we will fix it. Your project is unchanged.", link: ISSUES_URL, linkLabel: "Tell us on GitHub" };
  }

  /** One project's failure on the Done page. */
  function problemNote(p, problem) {
    const local = problem.link?.startsWith("/");
    const link = problem.link ? `<p><a href="${esc(problem.link)}"${local ? "" : ' target="_blank" rel="noopener noreferrer"'}>${esc(problem.linkLabel)}${local ? "" : ' <span aria-hidden="true">↗</span>'}</a></p>` : "";
    return `<div class="note" data-reason="${esc(problem.kind)}"><p><strong>${esc(p.name)}</strong>: ${esc(problem.what)}</p><p>${esc(problem.todo)}</p>${link}<p class="small">Code: <code>${esc(problem.code)}</code></p></div>`;
  }

  /**
   * POST the check. The docs give `timeout` a default of 300 and no maximum; if Vercel refuses the
   * body with a 400 whose message names `timeout`, the create is tried once more without it (the
   * default applies). Any other error is thrown as it came.
   */
  async function createOurCheck(api, projectId, configurationId, integrationId) {
    const body = checkBody(configurationId, integrationId);
    try {
      return await api.createCheck(projectId, body);
    } catch (e) {
      if (!(e instanceof VercelError && e.status === 400 && /timeout/i.test(e.detail ?? ""))) throw e;
      logError("check_timeout_refused", { status: e.status, code: e.code, message: e.detail });
      const { timeout: _dropped, ...rest } = body;
      return api.createCheck(projectId, rest);
    }
  }

  /**
   * True when installation `configurationId` still owns a Penthera check on the project, read with
   * its own token. It fails closed: only a missing record, or Vercel saying 401 or 404 for that
   * token, means it does not. A record whose token does not decrypt (a key rotation, a config
   * error) and a 403 (a disabled installation can come back, as in the sweep) count as owned, like
   * any other error: a check is never deleted and a link never taken over on a guess.
   */
  async function ownsCheck(configurationId, projectId, c) {
    if (!CONFIG_ID.test(configurationId ?? "")) return false;
    const record = await load(configurationId);
    if (!record) return false;
    const api = tryClient(record, configurationId, c.keys);
    if (!api) return true;
    try {
      return (await api.listChecks(projectId)).some((k) => isIntegrationCheck(k, configurationId));
    } catch (e) {
      return !(e instanceof VercelError && [401, 404].includes(e.status));
    }
  }

  /** Deletes every project link that names this installation, whatever key it sits under. */
  async function dropLinks(configurationId) {
    for (const { key, link } of await store.links()) {
      if (link?.configurationId === configurationId) await store.deleteLink(key);
    }
  }

  /** The event's creation time in ms, or null when it has none. */
  function eventTime(event) {
    const t = typeof event?.createdAt === "number" ? event.createdAt : Date.parse(event?.createdAt ?? "");
    return Number.isFinite(t) ? t : null;
  }

  /**
   * The owner after a transfer: the new team, or for a personal account the new account id.
   * Any id that is not a team id makes the client call without teamId.
   */
  function newOwner(payload) {
    if (TEAM_ID.test(payload?.newTeamId ?? "")) return payload.newTeamId;
    if (/^[A-Za-z0-9_]{1,64}$/.test(payload?.newAccountId ?? "")) return payload.newAccountId;
    return payload?.newTeamId === null ? "personal" : null;
  }

  /**
   * Best effort, inside the webhook's 30 seconds: Vercel probably revokes the token before it
   * sends `removed`, and then every call fails and we only delete the record.
   */
  async function removeOurChecks(api, projectIds, configurationId) {
    const ids = (Array.isArray(projectIds) ? projectIds : []).filter((p) => PROJECT_ID.test(p)).slice(0, 50);
    const signal = AbortSignal.timeout(CLEANUP_MS);
    const deadline = now() + CLEANUP_MS;
    for (const pid of ids) {
      if (signal.aborted || now() > deadline) break;
      try {
        const project = await api.getProject(pid, { signal });
        for (const check of await api.listChecks(pid, { signal })) {
          if (signal.aborted || now() > deadline) return;
          if (isOurCheck(check, project.name, configurationId)) await api.deleteCheck(pid, check.id, { signal });
        }
      } catch (e) {
        if (e instanceof VercelError && (e.status === 401 || e.status === 403)) return;
      }
    }
  }

  /**
   * POST /report, counted in anonymous daily totals (no id, no IP, nothing from the request).
   *
   * Only a relay that reached Vercel (200: succeeded or failed) is written at once, as received
   * plus its result. Every refusal, also one with a valid GitHub token (anyone can mint one from
   * their own repo), is added up in this instance's memory and written at most once a minute, so
   * junk requests cannot spend the store's quota. Rate-limited requests are not counted at all.
   * A store error while counting never changes the answer.
   */
  async function report(request) {
    if (reportLimited(request)) return json(429, { error: "rate_limited" });
    const res = await relay(request);
    let field = null;
    try {
      const out = await res.clone().json();
      field = res.status === 200 && (out?.conclusion === "succeeded" || out?.conclusion === "failed") ? out.conclusion : `rejected_${out?.error}`;
    } catch {}
    const day = today();
    if (day && field && STAT_FIELDS.has(field)) {
      if (res.status === 200) await writeStats(day, { received: 1, [field]: 1 });
      else {
        if (!pendingStats.has(day) && pendingStats.size >= 3) pendingStats.delete(pendingStats.keys().next().value);
        const counts = pendingStats.get(day) ?? pendingStats.set(day, {}).get(day);
        for (const f of ["received", field]) counts[f] = Math.min((counts[f] ?? 0) + 1, 1_000_000);
      }
    }
    await flushStats();
    return res;
  }

  // Unverified refusals, by day, waiting for the next flush. At most a few days and 15 names.
  const pendingStats = new Map();
  let flushedAt = -Infinity;

  /** Writes the waiting counts if a minute has passed since the last flush (or the clock moved back). */
  async function flushStats() {
    const t = now();
    if (!pendingStats.size || !(t - flushedAt >= STATS_FLUSH_MS || t < flushedAt)) return;
    flushedAt = t;
    const batch = [...pendingStats.entries()];
    pendingStats.clear();
    for (const [day, counts] of batch) await writeStats(day, counts);
  }

  /** Today's date in UTC, or null for a clock out of range. */
  function today() {
    try {
      return new Date(now()).toISOString().slice(0, 10);
    } catch {
      return null;
    }
  }

  async function writeStats(day, counts) {
    try {
      await store.countStats(day, counts);
    } catch {
      logError("stats_failed", { route: "report" });
    }
  }

  /**
   * POST /report: the workflow's pass or fail for one production deployment, relayed to our check.
   *
   * Body: { deploymentId, projectId, conclusion: "succeeded" | "failed" }, and since 8 Nov hostSha256
   * (a SHA-256 of the host the workflow scanned) and reason (why the scan did not read the site), and
   * nothing else. Authorization: a
   * GitHub Actions OIDC token for this server's origin (lib/oidc.mjs). Every id that decides
   * anything is checked against Vercel with the token of the installation that turned the check on:
   *
   *   1. the token is GitHub's, for us and this one deployment (aud <origin>/report/<deploymentId>),
   *      current, from the Penthera workflow file, run by a repository_dispatch, in some repo R;
   *   2. the project's link names an installation, whose record and token we hold;
   *   3. that installation's token reads the project live from Vercel, and the project is
   *      connected to R (name and GitHub's repository id, both required; owner id when given),
   *      and the deployment, read before any write, is a production deployment of the project;
   *   4. the project has this installation's own check, and the deployment has a run of exactly
   *      that check, which Vercel says belongs to this project and this deployment;
   *   5. the run is not completed yet, so a result is never overwritten.
   *
   * A "succeeded" counts only when hostSha256 is the hash of the deployment's own host in Vercel's
   * record (3): the dispatch URL the workflow scanned is signed by nobody. Otherwise it is "failed".
   * Only then is the run's conclusion set. Nothing about the scan or the request is stored.
   */
  async function relay(request) {
    const c = cfg();
    const auth = /^Bearer ([A-Za-z0-9_.-]{1,8192})$/.exec(request.headers.get("authorization") ?? "");
    if (!auth) return json(401, { error: "unauthorized" });
    const raw = await readBody(request, 1024);
    if (raw === null) return json(413, { error: "too_large" });
    let body;
    try {
      body = JSON.parse(raw.toString("utf8"));
    } catch {
      return json(400, { error: "bad_json" });
    }
    const keys = body && typeof body === "object" && !Array.isArray(body) ? Object.keys(body) : [];
    if (!REPORT_FIELDS.every((k) => keys.includes(k)) || !keys.every((k) => REPORT_FIELDS.includes(k) || REPORT_OPTIONAL.includes(k))) return json(400, { error: "bad_body" });
    const { deploymentId, projectId, conclusion } = body;
    // Untrusted, like the rest of the body: the host's hash is only ever compared with Vercel's own
    // record, and the reason only picks one of our sentences.
    const hostSha256 = typeof body.hostSha256 === "string" && /^[0-9a-f]{64}$/.test(body.hostSha256) ? body.hostSha256 : null;
    const reason = typeof body.reason === "string" && Object.hasOwn(NOT_READ, body.reason) ? body.reason : null;
    if (typeof deploymentId !== "string" || !DEPLOYMENT_ID.test(deploymentId)) return json(400, { error: "bad_deployment" });
    if (typeof projectId !== "string" || !PROJECT_ID.test(projectId)) return json(400, { error: "bad_project" });
    if (typeof conclusion !== "string" || !CONCLUSIONS.has(conclusion)) return json(400, { error: "bad_conclusion" });

    // 1. GitHub's token, for us, from our workflow file.
    let claims;
    try {
      // The audience names the deployment, so a token works for exactly one deployment.
      claims = await verifyGithubToken(auth[1], { audience: reportAudience(c.origin, deploymentId), jwks, now });
    } catch (e) {
      const code = e instanceof OidcError ? e.code : "malformed";
      if (code === "jwks_unavailable") {
        logError("report_jwks_failed", { code });
        return json(503, { error: "try_again" });
      }
      return json(401, { error: "bad_token" });
    }
    const repo = typeof claims.repository === "string" && GITHUB_REPO.test(claims.repository) ? claims.repository : null;
    const repoId = typeof claims.repository_id === "string" && /^\d{1,20}$/.test(claims.repository_id) ? claims.repository_id : null;
    const ownerId = typeof claims.repository_owner_id === "string" && /^\d{1,20}$/.test(claims.repository_owner_id) ? claims.repository_owner_id : null;
    if (!repo || !repoId || !ownerId) return json(401, { error: "bad_token" });
    if (claims.event_name !== "repository_dispatch" || typeof claims.workflow_ref !== "string" || !claims.workflow_ref.startsWith(`${repo}/${WORKFLOW_PATH}@`)) {
      return json(403, { error: "workflow_not_allowed" });
    }

    // 2. The installation that turned the check on for this project.
    let link, record;
    try {
      link = await store.getLink(projectId);
      record = link && link.projectId === projectId && CONFIG_ID.test(link.configurationId ?? "") ? await load(link.configurationId) : null;
    } catch {
      logError("store_failed", { route: "report" });
      return json(503, { error: "try_again" });
    }
    if (!record) return json(404, { error: "not_enabled" });
    const configurationId = link.configurationId;
    const api = tryClient(record, configurationId, c.keys);
    if (!api) return json(404, { error: "not_enabled" });

    try {
      // 3. The project, read live with that installation's token, is connected to the token's repo:
      //    the name, and GitHub's repository id, which must be there (a name can change hands). The
      //    owner id is compared too when Vercel gives it.
      const project = await api.getProject(projectId);
      if (
        project.id !== projectId || !project.repo || project.repo.toLowerCase() !== repo.toLowerCase() ||
        !project.repoId || project.repoId !== repoId || (project.repoOwnerId && project.repoOwnerId !== ownerId)
      ) {
        return json(403, { error: "repository_mismatch" });
      }
      // 3b. The deployment belongs to this project and is a production deployment, before any write.
      const deployment = await api.getDeployment(deploymentId);
      if (deployment.id !== deploymentId || deployment.projectId !== projectId || deployment.target !== "production") {
        return json(403, { error: "deployment_mismatch" });
      }
      // 3c. A pass counts only for a scan of this deployment's own host. The dispatch URL the
      //     workflow scanned is not signed by anyone, so it is bound here, to Vercel's record.
      //     A missing or other host turns a pass into a fail; a fail stays a fail.
      const bound = hostSha256 !== null && deployment.url !== "" && hostSha256 === sha256(deployment.url);
      const result = conclusion === "succeeded" && !bound ? "failed" : conclusion;
      const text = conclusion === "succeeded" && !bound ? TEXT.unbound
        : result === "failed" && reason ? `Site not read: ${NOT_READ[reason]}. Details in the GitHub job summary.`
          : TEXT[result];
      // 4. This installation's check on the project, and its run on this deployment.
      const check = (await api.listChecks(projectId)).find((k) => isIntegrationCheck(k, configurationId) && typeof k.id === "string" && k.id);
      if (!check) return json(404, { error: "not_enabled" });
      let run = (await api.listCheckRuns(deploymentId)).find((r) => r?.checkId === check.id);
      run ??= await api.createCheckRun(deploymentId, check.id);
      if (!run || typeof run.id !== "string" || !run.id || run.checkId !== check.id || run.projectId !== projectId || run.deploymentId !== deploymentId) {
        return json(403, { error: "deployment_mismatch" });
      }
      // 5. A result is set once.
      if (run.status === "completed") return json(409, { error: "already_completed" });
      const runUrl = /^\d{1,20}$/.test(String(claims.run_id ?? "")) ? `https://github.com/${repo}/actions/runs/${claims.run_id}` : undefined;
      await api.updateCheckRun(deploymentId, run.id, {
        status: "completed",
        conclusion: result,
        conclusionText: text,
        ...(runUrl ? { externalUrl: runUrl } : {}),
      });
      logInfo("report_ok", { conclusion: result });
      return json(200, { ok: true, conclusion: result, ...(result !== conclusion ? { note: "scanned_url_not_this_deployment" } : {}) });
    } catch (e) {
      // Every Vercel error is a 502, also a 403 or 404: the workflow then fails loudly instead of
      // reading it as "the check is not on", and the run stays as it was.
      logError("report_failed", { status: e.status ?? 0, code: e.code ?? "network" });
      return json(502, { error: "vercel_unavailable" });
    }
  }

  async function sweep(request) {
    const c = cfg();
    const auth = request.headers.get("authorization") ?? "";
    if (!c.cronSecret || !safeEqual(auth, `Bearer ${c.cronSecret}`)) return json(401, { error: "unauthorized" });
    let checked = 0, removed = 0, unlinked = 0;
    const deadline = now() + 50_000;
    const ids = await store.ids();
    for (const id of ids) {
      if (now() > deadline) break;
      const record = await load(id);
      if (!record) continue;
      checked++;
      const api = tryClient(record, id, c.keys);
      if (!api) continue;
      try {
        await api.listProjects({ limit: 1 });
      } catch (e) {
        // 401 and 404 mean the install is gone. A 403 is kept: it can be a disabled configuration that
        // comes back, or a transfer whose webhook we missed. Vercel sends `removed` when either ends.
        if (e instanceof VercelError && (e.status === 401 || e.status === 404)) {
          await store.delete(id);
          removed++;
        } else if (!(e instanceof VercelError)) {
          logError("sweep_failed", { code: e instanceof ConfigError ? "config" : "network" });
        }
      }
    }
    // Links whose installation is gone, or that do not match the key they sit under, are deleted.
    const live = new Set(await store.ids());
    for (const { key, link } of await store.links()) {
      if (now() > deadline) break;
      if (link?.projectId === key && live.has(link.configurationId) && Object.keys(link).length === 2) continue;
      await store.deleteLink(key);
      unlinked++;
    }
    return json(200, { ok: true, checked, removed, unlinked });
  }

  // Every way a setup session ends lands here: no cookie (a later Configure click, another browser),
  // 30 minutes passed, an uninstall, a reinstall or a transfer. The copy must be true for all of them.
  function expired() {
    return message(401, "This setup page has closed", "Setup stays open for 30 minutes after an install, in the browser you installed from. It also closes when Penthera is uninstalled or installed again. To change projects, restart from Vercel.", { left: { penthera: "Nothing changed. If Penthera is still installed, your checks run as you left them. If you uninstalled it, we already deleted its token and project links.", vercel: "Nothing changed. Settings, Integrations shows whether Penthera is installed." }, action: { href: "/start", label: "Restart on Vercel" }, why: "Setup can change which deploys Penthera holds, so only the browser that just installed can use it, and only for 30 minutes." });
  }

  function apiFailure(e, configurationId, event) {
    logError(event, { status: e.status ?? 0, code: e.code ?? "network" });
    return message(502, "Vercel didn't answer just now", "Your projects are as they were. Vercel is usually back within a minute, and this page tries again by itself.", { left: { penthera: "Nothing changed.", vercel: "Nothing changed." }, action: { href: "/setup", label: "Try again" }, refresh: { seconds: 30, url: "/setup" } });
  }

  /** Wraps a route: config errors become a 500 with a code, never a stack or a value. */
  const guard = (fn) => async (request) => {
    try {
      return await fn(request);
    } catch (e) {
      logError(e instanceof ConfigError ? "config_error" : "unhandled_error", { code: e instanceof ConfigError ? "config" : "internal" });
      return json(500, { error: e instanceof ConfigError ? "not_configured" : "internal_error" });
    }
  };

  const method = (map) => async (request) => {
    const fn = map[request.method] ?? (request.method === "HEAD" ? map.GET : null);
    return fn ? fn(request) : json(405, { error: "method_not_allowed" });
  };

  return {
    start: guard(method({ GET: start })),
    install: guard(method({ GET: install })),
    setup: guard(method({ GET: setupPage, POST: setupPost })),
    configure: guard(method({ GET: configure })),
    webhook: guard(method({ POST: webhook })),
    report: guard(method({ POST: report })),
    sweep: guard(method({ GET: sweep })),
    home: method({ GET: async () => html(200, "Penthera", HOME, { footer: false, main: "home" }) }),
    health: method({ GET: async () => json(200, { ok: true }) }),
  };
}
