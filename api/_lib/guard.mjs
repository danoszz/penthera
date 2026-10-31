/**
 * The live check's network guard. penthera.org fetches a URL that anyone can
 * type, so before any byte leaves, the target must be a public web server:
 * http or https on the default port, no credentials, and every address the
 * name resolves to public. The connection is pinned to the address that was
 * checked, so a second DNS answer cannot swap in an internal one, and every
 * redirect is checked again from the start.
 */
import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";
import http from "node:http";
import https from "node:https";

export class CheckError extends Error {
  /** @param {string} code  @param {string} message  @param {number} status  @param {string} hint */
  constructor(code, message, status, hint) {
    super(message);
    this.code = code;
    this.status = status;
    this.hint = hint;
  }
}

const NOT_PUBLIC_NAME = /(^|\.)(localhost|local|internal|intranet|home|lan|corp|test|invalid|example)$/i;

/** The URL to check, from what someone typed: "example.com" means https://example.com/. */
/** @param {{anyPort?: boolean}} opts  anyPort is for tests, whose fixture listens on a random port. */
export function parseTarget(input, { anyPort = false } = {}) {
  const raw = String(input ?? "").trim();
  if (!raw || raw.length > 2048) throw new CheckError("invalid_url", "Enter a web address, such as example.com.", 400, "Send {\"url\": \"https://example.com\"}.");
  let url;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
  } catch {
    throw new CheckError("invalid_url", "That is not a web address.", 400, "Use a domain name or an http(s) URL.");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new CheckError("invalid_url", "Only http and https addresses can be checked.", 400, "Use an http(s) URL.");
  if (url.username || url.password) throw new CheckError("invalid_url", "Addresses with a user name or password are not checked.", 400, "Remove the credentials from the URL.");
  if (url.port && !anyPort && !["80", "443"].includes(url.port)) throw new CheckError("invalid_url", "Only the standard web ports (80 and 443) are checked.", 400, "For other ports, run npx penthera on your own machine.");
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (isIP(host)) {
    if (!isPublicIp(host)) throw notPublic();
  } else if (!host.includes(".") || NOT_PUBLIC_NAME.test(host)) {
    throw notPublic();
  }
  url.hash = "";
  return url;
}

function notPublic() {
  return new CheckError("not_public", "Only public websites can be checked here.", 400, "For localhost or an internal address, run npx penthera on your own machine.");
}

const V4_BLOCKED = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16],
  ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
];

const v4num = (ip) => ip.split(".").reduce((n, p) => n * 256 + Number(p), 0);

/** True only for addresses on the public internet. */
export function isPublicIp(ip) {
  if (isIP(ip) === 4) {
    const n = v4num(ip);
    return !V4_BLOCKED.some(([base, bits]) => Math.floor(n / 2 ** (32 - bits)) === Math.floor(v4num(base) / 2 ** (32 - bits)));
  }
  if (isIP(ip) !== 6) return false;
  const a = ip.toLowerCase();
  const mapped = /^(?:0*:)*:?ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(a) || /^64:ff9b::(\d+\.\d+\.\d+\.\d+)$/.exec(a);
  if (mapped) return isPublicIp(mapped[1]);
  if (a === "::" || a === "::1") return false;
  const first = parseInt(a.split(":")[0] || "0", 16);
  if ((first & 0xfe00) === 0xfc00) return false;  // fc00::/7, unique local
  if ((first & 0xffc0) === 0xfe80) return false;  // fe80::/10, link local
  if ((first & 0xff00) === 0xff00) return false;  // ff00::/8, multicast
  if (a.startsWith("2001:db8:") || a.startsWith("2001:0db8:")) return false;
  return true;
}

/** One public address for a host name, or a CheckError. */
export async function resolvePublic(host, { lookup = dnsLookup, allowPrivate = false } = {}) {
  if (isIP(host)) {
    if (!allowPrivate && !isPublicIp(host)) throw notPublic();
    return { address: host, family: isIP(host) };
  }
  let answers;
  try {
    answers = await lookup(host, { all: true, verbatim: true });
  } catch (e) {
    throw Object.assign(new CheckError("not_found", `${host} does not resolve to an address.`, 422, "Check the spelling of the domain."), { netCode: e?.code });
  }
  if (!answers.length) throw new CheckError("not_found", `${host} does not resolve to an address.`, 422, "Check the spelling of the domain.");
  // Every answer must be public, so a mixed record cannot smuggle in an internal one.
  if (!allowPrivate && answers.some((r) => !isPublicIp(r.address))) throw notPublic();
  return answers[0];
}

export const UA = "Penthera-QuickCheck/1 (+https://penthera.org/terms; passive check run by a visitor; opt out: robots.txt)";

/**
 * GET the page once, as a browser would, and keep only what came before the
 * body: status, headers and the TLS session. Redirects are followed, each
 * one guarded again. Nothing is logged.
 */
export async function fetchHeaders(start, { maxRedirects = 4, timeout = 6000, lookup, allowPrivate = false, anyPort = false } = {}) {
  let url = start;
  const hops = [];
  for (let i = 0; i <= maxRedirects; i++) {
    const host = url.hostname.replace(/^\[|\]$/g, "");
    const { address, family } = await resolvePublic(host, { lookup, allowPrivate });
    const res = await requestOnce(url, address, family, timeout);
    hops.push({ url: url.href, status: res.status });
    const location = res.headers.location;
    if (res.status >= 300 && res.status < 400 && location) {
      let next;
      try { next = new URL(location, url); } catch { break; }
      url = parseTarget(next.href, { anyPort });
      continue;
    }
    return { ...res, url: url.href, hops };
  }
  throw new CheckError("too_many_redirects", "The site redirected too many times.", 422, "Check the address for a redirect loop.");
}

/**
 * GET a URL and read its body, up to maxBytes, as a browser would load it.
 * Same guard as fetchHeaders: every hop resolved, checked and pinned again.
 * `onHop` runs before each request (the caller's request budget); it may
 * be async, and it may throw to stop. The body is decoded as UTF-8; a compressed body (which we
 * never ask for) is left empty. Nothing is logged. `userAgent` replaces the
 * live check's User-Agent (the E20 study names itself, bench/front-door), and
 * `meter` (study only) counts requests, bytes read and redirects.
 */
export async function fetchBody(start, { maxRedirects = 4, timeout = 6000, maxBytes = 1_500_000, accept, onHop, lookup, allowPrivate = false, anyPort = false, userAgent, meter } = {}) {
  let url = start;
  const hops = [];
  for (let i = 0; i <= maxRedirects; i++) {
    await onHop?.(url);
    const host = url.hostname.replace(/^\[|\]$/g, "");
    const { address, family } = await resolvePublic(host, { lookup, allowPrivate });
    if (meter) { meter.requests++; meter.hosts?.push(url.hostname); }
    const res = await requestOnce(url, address, family, timeout, { maxBytes, accept, userAgent, meter });
    meter?.tick?.(true);
    hops.push({ url: url.href, status: res.status });
    const location = res.headers.location;
    if (res.status >= 300 && res.status < 400 && location) {
      let next;
      try { next = new URL(location, url); } catch { break; }
      url = parseTarget(next.href, { anyPort });
      if (meter) meter.redirects++;
      continue;
    }
    return { ...res, url: url.href, hops };
  }
  throw new CheckError("too_many_redirects", "The site redirected too many times.", 422, "Check the address for a redirect loop.");
}

function requestOnce(url, address, family, timeout, body = null) {
  const secure = url.protocol === "https:";
  const lib = secure ? https : http;
  return new Promise((resolve, reject) => {
    const req = lib.request(url, {
      method: "GET",
      headers: { "User-Agent": body?.userAgent || UA, Accept: body?.accept || "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8" },
      // Pinned: connect to the address that passed the guard, nothing else.
      lookup: (_h, opts, cb) => (opts?.all ? cb(null, [{ address, family }]) : cb(null, address, family)),
      servername: secure && !isIP(url.hostname) ? url.hostname : undefined,
      timeout,
      agent: false,
    }, (res) => {
      const tls = secure ? tlsInfo(res.socket) : null;
      const redirect = res.statusCode >= 300 && res.statusCode < 400;
      const encoded = res.headers["content-encoding"] && !/^identity$/i.test(res.headers["content-encoding"]);
      if (!body || redirect || encoded) {
        const answer = { status: res.statusCode, headers: res.headers, tls, ...(body ? { body: "", truncated: false } : {}) };
        if (!body?.meter) {
          resolve(answer);
          return res.destroy();
        }
        // Study only: these bodies are never kept, but the traffic count should hold them.
        // A redirect is followed at its headers, as in pass 1; what follows is counted as it comes.
        if (redirect) resolve(answer);
        let read = 0;
        const stop = () => { clearTimeout(limit); resolve(answer); res.destroy(); };
        const limit = setTimeout(stop, redirect ? Math.min(timeout, 1000) : timeout);
        res.on("data", (c) => { read += c.length; body.meter.bytes += c.length; body.meter.tick?.(); if (read >= body.maxBytes) stop(); });
        res.on("end", stop);
        res.on("error", stop);
        return undefined;
      }
      // Read up to maxBytes, then stop; the whole read must fit the timeout.
      const chunks = [];
      let size = 0;
      let done = false;
      const finish = (truncated) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve({ status: res.statusCode, headers: res.headers, tls, body: Buffer.concat(chunks).toString("utf8"), truncated });
        res.destroy();
      };
      const timer = setTimeout(() => finish(true), timeout);
      res.on("data", (c) => {
        if (body.meter) { body.meter.bytes += c.length; body.meter.tick?.(); }
        const room = body.maxBytes - size;
        chunks.push(c.length > room ? c.subarray(0, room) : c);
        size += Math.min(c.length, room);
        if (size >= body.maxBytes) finish(true);
      });
      res.on("end", () => finish(false));
      res.on("error", () => finish(true));
    });
    req.on("timeout", () => req.destroy(new CheckError("timeout", `${url.hostname} did not answer within ${timeout / 1000} seconds.`, 504, "Try again, or run npx penthera from your own machine.")));
    req.on("error", (e) => {
      if (e instanceof CheckError) return reject(e);
      if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS/i.test(e.code || "")) {
        return reject(Object.assign(new CheckError("tls_invalid", `The certificate for ${url.hostname} is not valid (${e.code}).`, 422, "Renew or reissue the certificate; browsers show a warning for this site."), { tlsReason: e.code }));
      }
      reject(Object.assign(new CheckError("unreachable", `Could not connect to ${url.hostname}.`, 502, "Check that the site is up, or run npx penthera from your own machine."), { netCode: e.code }));
    });
    req.end();
  });
}

function tlsInfo(socket) {
  try {
    const cert = socket.getPeerCertificate?.() || {};
    return {
      protocol: socket.getProtocol?.() || null,
      validTo: cert.valid_to || null,
      issuer: cert.issuer?.O || cert.issuer?.CN || null,
    };
  } catch {
    return null;
  }
}
