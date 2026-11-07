/**
 * The integration's only logger, and the only file allowed to use console.
 *
 * Errors only: an error code plus a few allow-listed fields. Request bodies,
 * headers, tokens, codes and secrets never reach it. As a second guard, any
 * string value is redacted if it looks like a credential, and the values of
 * the secret env vars are masked wherever they appear.
 */
const FIELDS = new Set(["configurationId", "status", "code", "message", "route", "count"]);
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
  // Ids and snake_case error codes (integration_configuration_disabled) are not secrets.
  const allowed = (m) => /^(icfg|team|prj)_[A-Za-z0-9]{1,40}$/.test(m) || /^[a-z]+(?:[_-][a-z]+)+$/.test(m);
  return out.replace(CREDENTIAL, (m) => (allowed(m) ? m : "[redacted]"));
}

let sink = (line) => console.error(line);

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
