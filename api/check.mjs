/**
 * POST /api/check  {"url": "example.com", "consent": true}
 *
 * penthera.org's live quick check, described in /openapi.json, under the
 * terms at https://penthera.org/terms. Passive only: what a browser loads
 * anyway (api/_lib/tier1.mjs). There is no deeper scan online; that runs with
 * npx penthera on the user's own machine.
 *
 * Abuse guards, all in memory and per instance, so each instance counts on its
 * own. Nothing here is global: that takes a rate-limit rule in the Vercel
 * firewall, set in its dashboard. A consent affirmation in every request, 6
 * checks a minute and 40 a day per visitor (an IPv6 visitor is their /64), 30
 * an hour per target site (its registrable domain, so subdomains share it),
 * and the target's own opt-out (robots.txt, in tier1.mjs). Nothing is stored or logged; the
 * URL travels in the body, so it never appears in request logs. Every
 * request to the target goes through the guard in api/_lib/guard.mjs.
 *
 * The report, which the page renders:
 *   { url, tier: "passive", score, verdict, redirects[], scope,
 *     categories: [{ id, label, passed, total }],
 *     checks: [{ id, category, passed, severity, title, evidence, fix, verify, weight }] }
 */
import { parseTarget, CheckError } from "./_lib/guard.mjs";
import { passiveReport, ungraded } from "./_lib/tier1.mjs";
import { ipv6Groups } from "../lib/net/ip.js";
import { registrableDomain } from "../src/utils/url.js";

const MINUTE = 60_000, HOUR = 60 * MINUTE, DAY = 24 * HOUR;
export const LIMITS = [
  { key: "ip", window: MINUTE, max: 6, hint: "Wait a minute." },
  { key: "ip", window: DAY, max: 40, hint: "Come back tomorrow." },
  { key: "host", window: HOUR, max: 30, hint: "This site was checked often in the last hour; try again later." },
];
/**
 * The limits above, for agents to pace themselves. Policy only: each instance
 * counts on its own, so a remaining count could be false and none is sent.
 */
export const RATE_LIMIT_POLICY = LIMITS.map((l) => `"${l.key}-${l.window / 1000}s";q=${l.max};w=${l.window / 1000}`).join(", ");
const hits = new Map();
/** Keys kept per instance. Past this, the oldest go first, so a full store never lifts every limit at once. */
export const MAX_KEYS = 20_000;

// Hosts where each subdomain is someone else's app. Our registrableDomain() has no
// public-suffix list, so without this every app on one of them would share a limit.
const SHARED_HOSTING = /(?:^|\.)([^.]+\.(?:vercel\.app|netlify\.app|github\.io|pages\.dev|workers\.dev|web\.app|firebaseapp\.com|herokuapp\.com|onrender\.com|fly\.dev|railway\.app|replit\.app|repl\.co|glitch\.me|surge\.sh|azurewebsites\.net|cloudfront\.net|amplifyapp\.com|ngrok\.app|ngrok-free\.app|lovable\.app|bolt\.new|webflow\.io|framer\.website|wixsite\.com|myshopify\.com))$/i;

/** The site a per-site limit counts: the registrable domain, or the app on a shared host. */
export function siteKey(hostname) {
  const host = String(hostname).toLowerCase().replace(/\.$/, "");
  return SHARED_HOSTING.exec(host)?.[1] ?? registrableDomain(host);
}

/** Who is asking: the address, or an IPv6 address's /64, which one person usually holds whole. */
export function visitorKey(address) {
  const g = ipv6Groups(address);
  return g ? `${g.slice(0, 4).map((x) => x.toString(16)).join(":")}::/64` : address;
}

/**
 * The rule one more hit would pass, with the seconds until every rule lets it
 * through: the largest wait when several are full. Records the hit otherwise.
 */
export function limited(entries, now = Date.now()) {
  let worst = null;
  for (const [key, rule] of entries) {
    const list = (hits.get(key) || []).filter((t) => now - t < rule.window);
    if (list.length < rule.max) continue;
    const retryAfter = Math.ceil((list[0] + rule.window - now) / 1000);
    if (!worst || retryAfter > worst.retryAfter) worst = { ...rule, retryAfter };
  }
  if (worst) return worst;
  for (const [key, rule] of entries) {
    const list = (hits.get(key) || []).filter((t) => now - t < rule.window);
    list.push(now);
    hits.delete(key);  // re-inserted last, so the map stays in order of use
    hits.set(key, list);
  }
  for (const key of hits.keys()) {
    if (hits.size <= MAX_KEYS) break;
    hits.delete(key);
  }
  return null;
}

function send(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "RateLimit-Policy": RATE_LIMIT_POLICY,
  });
  res.end(JSON.stringify(body));
}

const fail = (res, e) => send(res, e.status, { error: { code: e.code, message: e.message, hint: e.hint } });

async function readBody(req) {
  // Vercel hands over a parsed body; plain Node (the local preview) a stream.
  if (req.body !== undefined) return typeof req.body === "string" ? JSON.parse(req.body || "{}") : req.body;
  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 4096) throw new CheckError("too_large", "The request body is too large.", 413, "Send only {\"url\": \"…\"}.");
  }
  return JSON.parse(raw || "{}");
}

/** @param {{lookup?: Function, allowPrivate?: boolean, anyPort?: boolean, now?: number}} opts  For tests only. */
export function createHandler(opts = {}) {
  return async function handler(req, res) {
    if (req.method !== "POST") {
      res.setHeader?.("Allow", "POST");
      return fail(res, new CheckError("method_not_allowed", "Use POST with a JSON body.", 405, "POST /api/check with {\"url\": \"example.com\", \"consent\": true}. See /openapi.json."));
    }

    let body;
    try {
      body = await readBody(req);
    } catch (e) {
      return fail(res, e instanceof CheckError ? e : new CheckError("invalid_json", "The body is not JSON.", 400, "Send {\"url\": \"example.com\", \"consent\": true}."));
    }
    if (body?.consent !== true) {
      return fail(res, new CheckError("consent_required", "Confirm that you own this site or are authorized to test it.", 400, "Send \"consent\": true, which means you own the site or have permission to test it and accept https://penthera.org/terms."));
    }

    try {
      const typed = String(body?.url ?? "");
      const target = parseTarget(typed);
      const ip = visitorKey(String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "").split(",")[0].trim());
      const host = siteKey(target.hostname);
      const rule = limited([
        [`ip:m:${ip}`, LIMITS[0]], [`ip:d:${ip}`, LIMITS[1]], [`host:${host}`, LIMITS[2]],
      ], opts.now);
      if (rule) res.setHeader?.("Retry-After", String(rule.retryAfter));
      if (rule) throw new CheckError("rate_limited", "Too many checks.", 429, `${rule.hint} Or run npx penthera <url> on your own machine.`);
      const report = await passiveReport(target, { ...opts, typed });
      return send(res, 200, report.refused ? ungraded(report) : report);
    } catch (e) {
      if (e instanceof CheckError) return fail(res, e);
      return fail(res, new CheckError("internal", "The check failed on our side.", 500, "Try again, or run npx penthera <url> on your own machine."));
    }
  };
}

export default createHandler();
