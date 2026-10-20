/**
 * Preloaded into every scan process (`node --import`) by run.js: refuses any
 * network connection to a host that is not loopback, and DNS lookups of
 * anything but localhost. Each refusal is appended to the file named by
 * PENTHERA_BENCH_NET_LOG so the runner can require a count of zero.
 *
 * fetch (undici), http, https and tls all connect through net.Socket, so
 * patching Socket.prototype.connect covers them.
 */
import net from "node:net";
import dns from "node:dns";
import { appendFileSync } from "node:fs";

const LOG = process.env.PENTHERA_BENCH_NET_LOG;
const LOOPBACK = /^(?:localhost|127(?:\.\d{1,3}){3}|::1|0:0:0:0:0:0:0:1|::ffff:127(?:\.\d{1,3}){3})$/i;

function refuse(what) {
  if (LOG) {
    try { appendFileSync(LOG, JSON.stringify({ refused: what, at: new Date().toISOString() }) + "\n"); } catch { /* best effort */ }
  }
  const err = new Error(`penthera-bench: network access refused (${what})`);
  err.code = "EPENTHERABENCH";
  return err;
}

const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function connect(...args) {
  const first = Array.isArray(args[0]) ? args[0][0] : args[0];
  let host;
  let path;
  if (first && typeof first === "object") { host = first.host; path = first.path; }
  else if (typeof first === "string" && !/^\d+$/.test(first)) path = first;
  else host = typeof args[1] === "string" ? args[1] : "localhost";
  if (path) return origConnect.apply(this, args); // unix socket or pipe: local by definition
  const h = String(host ?? "localhost").replace(/^\[|\]$/g, "");
  if (!LOOPBACK.test(h)) {
    const err = refuse(`connect ${h}`);
    process.nextTick(() => this.destroy(err));
    return this;
  }
  return origConnect.apply(this, args);
};

const origLookup = dns.lookup;
dns.lookup = function lookup(hostname, ...rest) {
  if (!LOOPBACK.test(String(hostname))) {
    const cb = rest.find((x) => typeof x === "function");
    const err = refuse(`dns ${hostname}`);
    if (cb) process.nextTick(() => cb(err));
    return undefined;
  }
  return origLookup.call(this, hostname, ...rest);
};
for (const fn of ["resolve", "resolve4", "resolve6", "resolveMx", "resolveTxt", "resolveAny", "resolveNs", "resolveCname"]) {
  if (typeof dns[fn] !== "function") continue;
  dns[fn] = (hostname, ...rest) => {
    const cb = rest.find((x) => typeof x === "function");
    const err = refuse(`dns.${fn} ${hostname}`);
    if (cb) process.nextTick(() => cb(err));
  };
}
if (dns.promises) {
  for (const fn of ["lookup", "resolve", "resolve4", "resolve6", "resolveMx", "resolveTxt", "resolveAny", "resolveNs", "resolveCname"]) {
    if (typeof dns.promises[fn] !== "function") continue;
    const orig = dns.promises[fn];
    dns.promises[fn] = (hostname, ...rest) =>
      fn === "lookup" && LOOPBACK.test(String(hostname)) ? orig.call(dns.promises, hostname, ...rest) : Promise.reject(refuse(`dns.promises.${fn} ${hostname}`));
  }
}
