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
 *   GET  /sweep      weekly cron: deletes records whose token no longer works
 *   GET  /health
 */
import {
  ConfigError, cookieKey, mac, openToken, parseKeys, randomToken, safeEqual, sealToken, signValue, unsignValue,
  verifyWebhookSignature,
} from "./crypto.mjs";
import { FOOTER, clearCookie, esc, html, json, message, readBody, readCookie, readForm, redirect, safeNext, setCookie } from "./http.mjs";
import { logError } from "./log.mjs";
import { VercelError, exchangeCode, vercelClient } from "./vercel.mjs";
import { WORKFLOW_PATH, WORKFLOW_YAML, checkBody, checkName, githubNewFileUrl, isOurCheck } from "./workflow.mjs";

const SESSION = "pv_session";
const STATE = "pv_state";
const SESSION_MS = 30 * 60_000;
const STATE_SECONDS = 15 * 60;
const MAX_PROJECTS_PER_POST = 20;
const CONFIG_ID = /^icfg_[A-Za-z0-9]{1,64}$/;
const TEAM_ID = /^team_[A-Za-z0-9]{1,64}$/;
const PROJECT_ID = /^prj_[A-Za-z0-9]{1,64}$/;
/** Best-effort check cleanup on uninstall stays well inside the webhook's maxDuration (25 s). */
const CLEANUP_MS = 15_000;
/** Install exchanges per visitor per minute, per function instance. The firewall rule in README.md is the real limit. */
const INSTALLS_PER_MINUTE = 10;

/** Reads and checks the env once per call. Throws ConfigError without echoing values. */
export function readConfig(env) {
  const need = (name) => {
    if (!env[name]) throw new ConfigError(`${name} is not set`);
    return env[name];
  };
  const baseUrl = new URL(need("PUBLIC_BASE_URL"));
  if (baseUrl.protocol !== "https:" && baseUrl.hostname !== "localhost") throw new ConfigError("PUBLIC_BASE_URL must be https");
  return {
    clientId: need("VERCEL_CLIENT_ID"),
    clientSecret: need("VERCEL_CLIENT_SECRET"),
    keys: parseKeys(env.PENTHERA_TOKEN_KEYS),
    origin: baseUrl.origin,
    redirectUri: `${baseUrl.origin}/install`,
    slug: /^[a-z0-9-]{1,32}$/.test(env.INTEGRATION_SLUG ?? "") ? env.INTEGRATION_SLUG : "penthera",
    cronSecret: env.CRON_SECRET || null,
  };
}

/**
 * @param {{ env: object, store: object, fetch?: typeof fetch, now?: () => number }} deps
 */
export function createApp({ env = process.env, store, fetch: fetchImpl = globalThis.fetch, now = Date.now }) {
  const cfg = () => readConfig(env);

  const client = (record, keys) =>
    vercelClient({
      token: openToken(record, record.configurationId, keys),
      teamId: TEAM_ID.test(record.ownerId) ? record.ownerId : null,
      fetch: fetchImpl,
    });

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
    const record = await store.get(data.c);
    if (!record || !safeEqual(record.ownerId, data.o) || !safeEqual(record.sessionNonce, data.s)) return null;
    return { raw, configurationId: data.c, next: data.n ?? null, record };
  }

  // Each /install makes one outbound exchange, so a visitor gets a few a minute. Per instance only.
  const installHits = new Map();
  function installLimited(request) {
    const who = (request.headers.get("x-real-ip") ?? request.headers.get("x-forwarded-for")?.split(",")[0] ?? "unknown").trim();
    const t = now();
    const recent = (installHits.get(who) ?? []).filter((x) => x > t - 60_000);
    recent.push(t);
    if (installHits.size > 10_000) installHits.clear();
    installHits.set(who, recent);
    return recent.length > INSTALLS_PER_MINUTE;
  }

  const formToken = (s, c) => mac(cookieKey(c.keys), `form:${s.raw}`);

  // A form post must come from our own pages: same origin when the browser says, and the session's form token.
  function formAllowed(request, form, s, c) {
    const origin = request.headers.get("origin");
    if (origin && origin !== c.origin) return false;
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
    if (!code || !/^[A-Za-z0-9]{8,128}$/.test(code)) return message(400, "Missing install code", "Start the install from Vercel.");
    if (!CONFIG_ID.test(configurationId ?? "")) return message(400, "Missing configuration", "Start the install from Vercel.");
    if (teamId && !TEAM_ID.test(teamId)) return message(400, "Bad team id", "Start the install from Vercel.");
    if (q.get("next") && !next) return message(400, "Bad return address", "The return address does not point at vercel.com.");

    // CSRF: an install we started (/start) must come back with the state we set in the cookie, and
    // a browser that holds that cookie must send the matching state. Installs started on vercel.com
    // (marketplace, deploy button) carry no state; they must say so in `source`, and the session is
    // bound only after the exchange proves the configuration and its owner (README, "Security").
    const cookies = [];
    const stateCookie = readCookie(request, STATE);
    if (state || stateCookie || source === "external") {
      if (!safeEqual(state, stateCookie)) return message(403, "Install check failed", "This install did not start here, or took longer than 15 minutes. Start it again from Vercel.", { cookies: [clearCookie(STATE)] });
      cookies.push(clearCookie(STATE));
    } else if (source !== "marketplace" && source !== "deploy-button") {
      return message(403, "Install check failed", "Start the install from Vercel.");
    }
    if (installLimited(request)) return message(429, "Too many installs", "Wait a minute and start the install again from Vercel.", { cookies });

    let token;
    try {
      token = await exchangeCode({ code, clientId: c.clientId, clientSecret: c.clientSecret, redirectUri: c.redirectUri, fetch: fetchImpl });
    } catch (e) {
      logError("exchange_failed", { status: e.status ?? 0, code: e.code ?? "network", configurationId });
      return message(502, "Vercel did not accept the install", "The code may have expired (it lasts 30 minutes) or been used already. Start the install again from Vercel.", { cookies });
    }
    // The exchange must name the configuration this redirect claims, and the team, or we store nothing.
    if (token.configurationId !== configurationId || (teamId && token.teamId !== teamId)) {
      logError("configuration_mismatch", { configurationId });
      return message(400, "Install mismatch", "Start the install again from Vercel.", { cookies });
    }
    const ownerId = token.teamId ?? token.userId ?? teamId;
    if (!ownerId) return message(502, "Vercel sent no owner", "Start the install again from Vercel.", { cookies });

    // One record per configuration. A deploy-button install may reuse an existing id: we overwrite it,
    // never duplicate, and never hand a record to another owner.
    const previous = await store.get(configurationId);
    if (previous && previous.ownerId !== ownerId) {
      logError("owner_mismatch", { configurationId });
      return message(409, "Install mismatch", "This installation belongs to another account. Install again from Vercel.", { cookies });
    }
    // createdAt is the latest install, so a replayed older uninstall event cannot delete it.
    const createdAt = new Date(now()).toISOString();
    const sessionNonce = randomToken(24);
    await store.put({ configurationId, ownerId, ...sealToken(token.accessToken, configurationId, c.keys), createdAt, sessionNonce });
    const value = signValue({ c: configurationId, o: ownerId, s: sessionNonce, n: next, e: now() + SESSION_MS }, cookieKey(c.keys));
    cookies.push(setCookie(SESSION, value, SESSION_MS / 1000));
    return redirect("/setup", { cookies });
  }

  async function setupPage(request) {
    const c = cfg();
    const s = await session(request, c);
    if (!s) return expired();
    const from = new URL(request.url).searchParams.get("from");
    const api = client(s.record, c.keys);
    let page;
    try {
      page = await api.listProjects({ from: /^\d{1,16}$/.test(from ?? "") ? from : undefined });
    } catch (e) {
      return apiFailure(e, s.configurationId, "projects_failed");
    }
    const eligible = page.projects.filter((p) => p.repo);
    const status = new Map(
      await Promise.all(eligible.map(async (p) => [p.id, await api.listChecks(p.id).then((list) => list.some((k) => isOurCheck(k, p.name)), () => null)])),
    );
    const single = page.projects.length === 1 && !page.next && !from;
    const anyOn = [...status.values()].some(Boolean);
    const token = formToken(s, c);
    const rows = page.projects.map((p, i) => {
      if (!p.repo) return `<li class="off"><input type="checkbox" disabled aria-label="Not available"><span><span class="name" title="${esc(p.name)}">${esc(p.name)}</span><span class="muted">Needs a GitHub-connected project</span></span></li>`;
      const on = status.get(p.id);
      const checked = single || (!anyOn && i === page.projects.indexOf(eligible[0]));
      const box = single
        ? `<input type="checkbox" checked disabled aria-label="Selected"><input type="hidden" name="p" value="${esc(p.id)}">`
        : `<input type="checkbox" name="p" value="${esc(p.id)}"${checked ? " checked" : ""} aria-label="Select ${esc(p.name)}">`;
      const state = on === true ? "Check on" : on === false ? "Check off" : "Check status unknown";
      const remove = on ? `<button class="quiet" name="remove" value="${esc(p.id)}" formaction="/setup" type="submit">Remove check</button>` : "";
      return `<li>${box}<span class="grow"><span class="name" title="${esc(p.name)}">${esc(p.name)}</span><span class="muted">${esc(p.repo)} · ${state}</span></span>${remove}</li>`;
    });
    const more = page.next ? `<p><a href="/setup?from=${esc(page.next)}">More projects</a></p>` : "";
    return html(200, "Penthera: pick your projects", `
<h1>Pick your projects</h1>
<p>Penthera adds a Deployment Check to each project you pick. Your next production deploy then waits for Penthera's scan, which runs in your own GitHub Actions.</p>
<form method="post" action="/setup">
<input type="hidden" name="csrf" value="${token}">
<input type="hidden" name="action" value="workflow">
<ul>${rows.join("") || '<li class="off">No projects are shared with this integration. Change the project access in Vercel and open Configure.</li>'}</ul>
${more}
<p><button type="submit">Next: add the workflow</button></p>
</form>
<p class="muted">The check blocks promotion to production when Penthera finds a high or critical issue. Previews are scanned too and never blocked.</p>
${FOOTER}`);
  }

  async function setupPost(request) {
    const c = cfg();
    const s = await session(request, c);
    if (!s) return expired();
    const form = await readForm(request);
    if (!form || !formAllowed(request, form, s, c)) return message(403, "Form check failed", "Reload the page and try again.");
    const api = client(s.record, c.keys);

    const removeId = form.get("remove");
    if (removeId) {
      if (!PROJECT_ID.test(removeId)) return message(400, "Bad project", "Reload the page and try again.");
      try {
        const project = await api.getProject(removeId);
        for (const check of await api.listChecks(removeId)) {
          if (isOurCheck(check, project.name)) await api.deleteCheck(removeId, check.id);
        }
      } catch (e) {
        return apiFailure(e, s.configurationId, "remove_failed");
      }
      return redirect("/setup");
    }

    const ids = [...new Set(form.getAll("p"))].filter((id) => PROJECT_ID.test(id)).slice(0, MAX_PROJECTS_PER_POST);
    if (!ids.length) return message(400, "No project picked", "Go back and pick at least one project.");
    // Names and repos come from Vercel, never from the form.
    let projects;
    try {
      projects = (await Promise.all(ids.map((id) => api.getProject(id)))).filter((p) => p.repo);
    } catch (e) {
      return apiFailure(e, s.configurationId, "project_failed");
    }
    if (!projects.length) return message(400, "No GitHub project", "Penthera needs a project connected to a GitHub repository.");

    if (form.get("action") === "enable") {
      const failed = [];
      for (const p of projects) {
        try {
          const existing = await api.listChecks(p.id);
          if (!existing.some((k) => isOurCheck(k, p.name))) await api.createCheck(p.id, checkBody(p.name));
        } catch (e) {
          logError("check_failed", { status: e.status ?? 0, code: e.code ?? "network", configurationId: s.configurationId });
          failed.push(p);
        }
      }
      if (!failed.length && s.next) return redirect(s.next, { cookies: [clearCookie(SESSION)] });
      const back = s.next ? `<p><a class="button" href="${esc(s.next)}">Back to Vercel</a></p>` : "";
      const text = failed.length
        ? `<p class="warn">Vercel did not accept the check for: ${failed.map((p) => esc(p.name)).join(", ")}. Try again from Configure, or add it by hand in Project Settings, Deployment Checks.</p>`
        : "<p>The check is on. Your next production deploy waits for Penthera.</p>";
      return html(failed.length ? 502 : 200, "Penthera: done", `<h1>${failed.length ? "Some checks failed" : "Done"}</h1>${text}${back}${FOOTER}`);
    }

    const token = formToken(s, c);
    const items = projects.map((p) => {
      const link = githubNewFileUrl(p.repo, p.branch);
      const button = link ? `<a class="button" href="${esc(link)}" target="_blank" rel="noopener noreferrer">Add penthera-vercel.yml on GitHub</a>` : "<span class=\"muted\">Copy the file below by hand.</span>";
      return `<li><span class="grow"><span class="name" title="${esc(p.name)}">${esc(p.name)}</span><span class="muted">${esc(p.repo)}, branch ${esc(p.branch)}</span><p>${button}</p><p class="muted">Status name: <code>${esc(checkName(p.name))}</code></p></span><input type="hidden" name="p" value="${esc(p.id)}" form="enable"></li>`;
    });
    return html(200, "Penthera: add the workflow", `
<h1>Add the workflow (one commit)</h1>
<p>Commit <code>${WORKFLOW_PATH}</code> on each repo's default branch. The button opens GitHub with the file filled in. It holds no secrets.</p>
<ul>${items.join("")}</ul>
<p><label for="yaml">Or copy it:</label></p>
<textarea id="yaml" readonly>${esc(WORKFLOW_YAML)}</textarea>
<p class="muted">If your deployments sit behind Vercel Authentication, the scan cannot read them yet and the check fails with a clear message. Penthera never sees or stores a bypass secret.</p>
<form id="enable" method="post" action="/setup">
<input type="hidden" name="csrf" value="${token}">
<input type="hidden" name="action" value="enable">
<p class="warn">Commit the workflow first. Once the check is on, a production deploy waits for it.</p>
<p><button type="submit">Turn on the check</button></p>
</form>
<p class="muted">Your next production deploy will wait for Penthera's check. Findings show in the GitHub job summary. Nothing is sent to us.</p>
${FOOTER}`);
  }

  async function configure(request) {
    const c = cfg();
    const id = new URL(request.url).searchParams.get("configurationId");
    const s = await session(request, c);
    if (s && s.configurationId === id) return redirect("/setup");
    // Vercel's Configure button proves nothing about who clicks it, so without the install
    // session this page shows only what is the same for everyone.
    return html(200, "Penthera: configure", `
<h1>Penthera on Vercel</h1>
<p>Penthera's check runs from the workflow in your repo, <code>${WORKFLOW_PATH}</code>. Copy it again here:</p>
<textarea readonly aria-label="Workflow file">${esc(WORKFLOW_YAML)}</textarea>
<p>To turn the check off for one project: Vercel, Project Settings, Deployment Checks, and remove the Penthera check. You can also delete the workflow file.</p>
<p>To add projects: give the integration access to them in Vercel, then install again from <a href="/start" target="_blank" rel="noopener noreferrer">this link</a>. Changing projects from this page works for 30 minutes after an install.</p>
<p>To uninstall: Vercel, Settings, Integrations, Penthera, Manage, Uninstall. We delete the stored token then. Remove the Penthera check from each project too, or production deploys keep waiting for it.</p>
${FOOTER}`);
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
      logError("store_failed", { configurationId: id, route: "webhook" });
      return json(500, { error: "store_unavailable" });
    }
    if (!record) return json(200, { ok: true, deleted: type === "integration-configuration.removed" });
    // A signed event replayed after a newer install of the same id changes nothing.
    if (eventTime(event) !== null && eventTime(event) <= Date.parse(record.createdAt)) return json(200, { ok: true, ignored: "stale" });

    if (type === "integration-configuration.transferred") {
      // Every verified transfer ends older setup sessions, even when it names no new owner. Its time
      // becomes the record's createdAt, so a replay of this or an older transfer changes nothing.
      const t = eventTime(event);
      await store.put({
        ...record,
        ownerId: newOwner(event.payload) ?? record.ownerId,
        createdAt: t !== null && t > Date.parse(record.createdAt) ? new Date(t).toISOString() : record.createdAt,
        sessionNonce: randomToken(24),
      });
      return json(200, { ok: true });
    }

    // Removed: open the token into memory, delete the record first, then tidy up best effort.
    let api = null;
    try {
      api = client(record, c.keys);
    } catch {}
    try {
      await store.delete(id);
    } catch {
      logError("store_failed", { configurationId: id, route: "webhook" });
      return json(500, { error: "store_unavailable" });
    }
    if (api) await removeOurChecks(api, event.payload.configuration.projects);
    return json(200, { ok: true, deleted: true });
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
  async function removeOurChecks(api, projectIds) {
    const ids = (Array.isArray(projectIds) ? projectIds : []).filter((p) => PROJECT_ID.test(p)).slice(0, 50);
    const signal = AbortSignal.timeout(CLEANUP_MS);
    const deadline = now() + CLEANUP_MS;
    for (const pid of ids) {
      if (signal.aborted || now() > deadline) break;
      try {
        const project = await api.getProject(pid, { signal });
        for (const check of await api.listChecks(pid, { signal })) {
          if (signal.aborted || now() > deadline) return;
          if (isOurCheck(check, project.name)) await api.deleteCheck(pid, check.id, { signal });
        }
      } catch (e) {
        if (e instanceof VercelError && (e.status === 401 || e.status === 403)) return;
      }
    }
  }

  async function sweep(request) {
    const c = cfg();
    const auth = request.headers.get("authorization") ?? "";
    if (!c.cronSecret || !safeEqual(auth, `Bearer ${c.cronSecret}`)) return json(401, { error: "unauthorized" });
    let checked = 0, removed = 0;
    const deadline = now() + 50_000;
    for (const id of await store.ids()) {
      if (now() > deadline) break;
      const record = await store.get(id);
      if (!record) continue;
      checked++;
      try {
        await client(record, c.keys).listProjects({ limit: 1 });
      } catch (e) {
        // 401 and 404 mean the install is gone. A 403 is kept: it can be a disabled configuration that
        // comes back, or a transfer whose webhook we missed. Vercel sends `removed` when either ends.
        if (e instanceof VercelError && (e.status === 401 || e.status === 404)) {
          await store.delete(id);
          removed++;
        } else if (!(e instanceof VercelError)) {
          logError("sweep_failed", { configurationId: id, code: e instanceof ConfigError ? "config" : "network" });
        }
      }
    }
    return json(200, { ok: true, checked, removed });
  }

  function expired() {
    return message(401, "This setup page has expired", "It works for 30 minutes after an install. Open Configure from Vercel, or install again.");
  }

  function apiFailure(e, configurationId, event) {
    logError(event, { status: e.status ?? 0, code: e.code ?? "network", configurationId });
    return message(502, "Vercel did not answer", "Try again in a minute. If it keeps failing, reinstall the integration.");
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
    sweep: guard(method({ GET: sweep })),
    health: method({ GET: async () => json(200, { ok: true }) }),
  };
}
