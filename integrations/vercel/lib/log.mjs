/**
 * The integration's only logger, and the only file allowed to use console.
 *
 * Errors: the event, Vercel's status and error code, a route, and Vercel's
 * error text. No ids: an installation, team, project, deployment, integration
 * or user id is never a field, and any id inside a string (Vercel's message)
 * becomes [id]. Request bodies, headers, tokens, codes and secrets never reach
 * it. As a second guard, any string value is redacted if it looks like a
 * credential, and the values of the secret env vars are masked wherever they
 * appear.
 *
 * Good events (logInfo): with the privacy of the daily counters, an event name
 * from a fixed list and only fields with fixed values or a small count. No
 * configuration, project, deployment, team or user id, no repo, no token.
 */
const FIELDS = new Set(["status", "code", "message", "route", "count"]);

/** Vercel's id prefixes, and the check and run ids it hands out. The no-id test uses the same list. */
export const ID_PREFIXES = ["icfg", "team", "prj", "dpl", "oac", "user", "chk", "crun"];
const ID = new RegExp(`\\b(?:${ID_PREFIXES.join("|")})_[A-Za-z0-9]+`, "g");
const SECRET_ENV = ["INTEGRATION_CLIENT_SECRET", "PENTHERA_TOKEN_KEYS", "KV_REST_API_TOKEN", "CRON_SECRET"];

// Long opaque strings (tokens, codes, keys) and anything after a bearer or key= label.
const CREDENTIAL = /\b(?:bearer\s+\S+|(?:access_token|client_secret|code|token|key)=\S+|[A-Za-z0-9_\-+/=]{20,})/gi;

export function redact(text, env = process.env) {
  let out = String(text);
  for (const name of SECRET_ENV) {
    for (const part of String(env[name] ?? "").split(/[,:]/)) {
      if (part.length >= 8) out = out.split(part).join("[redacted]");
    }
  }
  // Ids are never logged: each becomes [id] before anything else.
  out = out.replace(ID, "[id]");
  // snake_case error codes (integration_configuration_disabled) are not secrets.
  const allowed = (m) => /^[a-z]+(?:[_-][a-z]+)+$/.test(m);
  return out.replace(CREDENTIAL, (m) => (allowed(m) ? m : "[redacted]"));
}

let sink = (line, level = "error") => (level === "info" ? console.log(line) : console.error(line));

/** Tests capture output here. */
export function setLogSink(fn) {
  const previous = sink;
  sink = fn;
  return previous;
}

/** Logs one error event: `logError("exchange_failed", { status: 400 })`. */
export function logError(event, fields = {}) {
  const safe = { event: redact(event) };
  for (const [k, v] of Object.entries(fields)) {
    if (FIELDS.has(k) && (typeof v === "string" || typeof v === "number")) safe[k] = typeof v === "string" ? redact(v) : v;
  }
  sink(JSON.stringify(safe));
}

/**
 * The good events and the only fields each may carry: a list of fixed values, or "count" for a
 * whole number from 0 to 1000. Anything else is dropped, so an id cannot reach these lines.
 */
export const INFO_EVENTS = {
  install_ok: { source: ["marketplace", "deploy-button", "external"] },
  check_on: { projects: "count" },
  check_off: { projects: "count" },
  report_ok: { conclusion: ["succeeded", "failed"] },
  uninstall_ok: {},
};

/** Logs one good event: `logInfo("check_on", { projects: 1 })`. An unknown event logs nothing. */
export function logInfo(event, fields = {}) {
  const allowed = Object.hasOwn(INFO_EVENTS, event) ? INFO_EVENTS[event] : null;
  if (!allowed) return;
  const safe = { level: "info", event };
  for (const [k, rule] of Object.entries(allowed)) {
    const v = fields[k];
    if (rule === "count" ? Number.isInteger(v) && v >= 0 && v <= 1000 : rule.includes(v)) safe[k] = v;
  }
  sink(JSON.stringify(safe), "info");
}
