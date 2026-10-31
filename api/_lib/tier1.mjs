/**
 * The passive report: only what a browser loads anyway, for any public site.
 *
 *   1. GET the page (redirects followed, each hop guarded), read up to 1.5 MB.
 *      The first response is graded in grade.mjs: transport, headers, cookies.
 *   2. From the HTML: the scripts and stylesheets the page references (up to
 *      8 same-site and 6 third-party, 2 MB each), mixed content, Subresource
 *      Integrity, a generator tag. Secrets and library versions from the page
 *      and those files; source map references, never the maps (page.mjs).
 *   3. GET /.well-known/security.txt, a file meant to be fetched.
 *   4. Public DNS: SPF, DMARC and CAA (dns.mjs).
 *
 * Before anything else, GET /robots.txt: a group naming Penthera-QuickCheck
 * with Disallow: / stops the check (opted_out, see page.mjs optedOut).
 *
 * At most 20 requests and about 8 seconds in all, every one through the guard
 * and pinned to the vetted address. No other paths, no payloads, no query
 * strings of our own. Nothing is stored or logged.
 */
import { parseTarget, fetchBody, CheckError } from "./guard.mjs";
import { grade } from "./grade.mjs";
import { dnsChecks } from "./dns.mjs";
import { runtimeAdvisoriesForResponse } from "../../lib/advisories/index.js";
import {
  LIMITS, makeBudget, parsePage, loadAssets, secretChecks, libraryChecks,
  generatorCheck, sriCheck, mixedContentCheck, sourceMapCheck, securityTxtCheck, checkOptOut,
} from "./page.mjs";

export const SCOPE = "Only what a browser loads: /robots.txt first (a site can opt out there), then the page, up to 14 of the scripts and stylesheets it references, /.well-known/security.txt and public DNS records. No other paths probed, no payloads sent, nothing stored. For a full scan, run npx penthera on your own machine.";

/**
 * @param {URL} target
 * @param {{typed?: string, now?: number, lookup?: Function, allowPrivate?: boolean, anyPort?: boolean,
 *   timeout?: number, dns?: object, dnsTimeout?: number, budgetMs?: number, retireDb?: object,
 *   assets?: boolean, secrets?: boolean, userAgent?: string, optOutTokens?: string[], optOutAll?: boolean,
 *   onPage?: Function, onResponse?: Function, onRobots?: Function, onHopUrl?: Function, onFallback?: Function, allowFallback?: Function, fallbackError?: Function, robotsHop?: Function, onAnswered?: Function, meter?: object, budget?: object, skipDns?: boolean, robotsRedirects?: number, robotsMaxBytes?: number}} opts
 *   lookup, allowPrivate, anyPort, dns and retireDb are for tests. The E20
 *   study (bench/front-door/run.mjs) sets the rest: assets: false skips the
 *   referenced scripts and stylesheets, secrets: false the secret rules, and
 *   userAgent and optOutTokens name the study instead of the live check, and
 *   optOutAll also honors a robots.txt `*` group with Disallow: /. onPage
 *   (study only) is called once with { html, url, headers, status, body } of
 *   the page that was already fetched, so the study can read a link or the
 *   hosting platform without a second request, and onResponse (study only)
 *   with ("robots" | "security.txt", response). onRobots hears each robots.txt
 *   outcome and may throw. onHopUrl is called with the URL of every hop, before
 *   and after a new origin's robots.txt, and may throw; robotsRedirects sets
 *   how many redirects a robots.txt may take and robotsMaxBytes how much of it
 *   is read; robotsHop checks that file's hops, and onAnswered hears that the
 *   origin replied. allowFallback may refuse the http fallback, onFallback hears
 *   why https failed, and fallbackError picks the error when http fails too.
 *   skipDns leaves DNS out: the study reads it apart, on its own thread and clock.
 *   meter counts requests, bytes and redirects, budget shares one budget across
 *   attempts, and an error at a redirect's origin names it in `redirectedTo`.
 *   The live check sets none of these.
 */
export async function passiveReport(target, opts = {}) {
  const budget = opts.budget ?? makeBudget({ budgetMs: opts.budgetMs ?? LIMITS.budgetMs });
  const guard = { lookup: opts.lookup, allowPrivate: opts.allowPrivate, anyPort: opts.anyPort, userAgent: opts.userAgent, optOutTokens: opts.optOutTokens, optOutAll: opts.optOutAll, optedOut: opts.optedOut, onResponse: opts.onResponse, onRobots: opts.onRobots, robotsHop: opts.robotsHop, onAnswered: opts.onAnswered, meter: opts.meter, robotsRedirects: opts.robotsRedirects, robotsMaxBytes: opts.robotsMaxBytes };
  // Study only: every hop goes past onHopUrl, and a new origin's robots.txt is read first.
  const seen = new Set([target.origin]);
  guard.gate = opts.onHopUrl && (async (u) => {
    opts.onHopUrl(u);
    if (seen.has(u.origin)) return;
    seen.add(u.origin);
    try {
      await checkOptOut(u.origin, budget, guard);
    } catch (e) {
      throw Object.assign(e, { redirectedTo: u.hostname });
    }
    opts.onHopUrl(u);
  });
  let hops = 0;
  const pageOpts = { ...guard, timeout: Math.min(opts.timeout ?? 6000, 6000), maxBytes: LIMITS.pageBytes, onHop: async (u) => { if (hops++) opts.onAnswered?.(); await guard.gate?.(u); budget.hop(); } };

  let result;
  try {
    await checkOptOut(target.origin, budget, guard);
    result = await fetchBody(target, pageOpts);
  } catch (e) {
    // "example.com" with no https at all: look at what http serves instead.
    const bare = !/^https?:\/\//i.test(String(opts.typed ?? "").trim());
    if (!bare || !(e instanceof CheckError) || !["unreachable", "tls_invalid"].includes(e.code)) throw e;
    if (opts.allowFallback && !opts.allowFallback(e)) throw e;
    opts.onFallback?.(e);
    const plain = parseTarget(`http://${target.host}${target.pathname}`, guard);
    seen.add(plain.origin);
    try {
      await checkOptOut(plain.origin, budget, guard);
      result = await fetchBody(plain, pageOpts);
    } catch (e2) {
      throw opts.fallbackError ? opts.fallbackError(e, e2) : e2;
    }
  }

  const pageUrl = result.url;
  const host = new URL(pageUrl).hostname;
  const html = /html/i.test(String(result.headers["content-type"] || "")) && result.status < 400 ? result.body : "";
  const parsed = html ? parsePage(html, pageUrl) : null;
  opts.onPage?.({ html, url: pageUrl, headers: result.headers, status: result.status, body: result.body });

  const [assets, dns, securityTxt] = await Promise.all([
    parsed && opts.assets !== false ? loadAssets(parsed, pageUrl, budget, guard) : { files: [], wanted: 0, skipped: 0 },
    opts.skipDns ? [] : dnsChecks(host, { dns: opts.dns, dnsTimeout: Math.min(opts.dnsTimeout ?? 2500, 2500) }).catch(() => []),
    securityTxtCheck(pageUrl, budget, guard, opts.now ?? Date.now()),
  ]);

  const extra = [];
  if (parsed) {
    extra.push(
      ...(opts.secrets === false ? [] : secretChecks(html, assets.files, pageUrl)),
      ...libraryChecks(html, parsed, assets.files, pageUrl, { db: opts.retireDb }),
      ...mixedContentCheck(parsed, pageUrl, result.headers),
      ...sriCheck(parsed, pageUrl),
      ...sourceMapCheck(assets.files),
      ...generatorCheck(parsed, pageUrl),
    );
    if (assets.skipped) {
      const s = extra.find((c) => c.id === "secrets");
      if (s) s.evidence += ` ${assets.skipped} of ${assets.wanted} referenced files were not read (limit of 14 files, 20 requests, 8 seconds).`;
    }
  }
  extra.push(...runtimeCheck(result.headers, pageUrl), ...dns, ...securityTxt);

  return { tier: "passive", ...grade(result, { now: opts.now, extra, scope: SCOPE }) };
}

/**
 * Software versions the response names (X-Powered-By, Server), against the
 * CLI's signed runtime advisories (lib/advisories): PHP, nginx, Apache, Node
 * and others. A version string alone cannot show a distribution's backported
 * fix, so a match is "may be affected", at most high, never critical.
 */
export function runtimeCheck(headers, pageUrl) {
  const h = Object.fromEntries(Object.entries(headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
  const cookieNames = [].concat(h["set-cookie"] || []).map((c) => String(c).split("=")[0].trim()).filter(Boolean);
  let found;
  try {
    found = runtimeAdvisoriesForResponse({ headers: h, cookieNames }, { url: pageUrl });
  } catch {
    return [];
  }
  const named = [h["x-powered-by"], h.server].filter((v) => v && /\d+\.\d+/.test(String(v)));
  if (!named.length && !found.length) return [];
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const worst = found.map((f) => f.severity).sort((a, b) => rank[a] - rank[b])[0];
  const titles = [...new Set(found.map((f) => f.title))];
  return [{
    id: "runtime", category: "software", weight: 10, passed: found.length === 0,
    severity: worst === "critical" || worst === "high" ? "high" : worst || "info",
    title: found.length ? `Server software may be affected by ${titles.length} known advisor${titles.length === 1 ? "y" : "ies"}` : "No known advisories for the versions it names",
    evidence: found.length ? `${named.join("; ")}: ${titles.slice(0, 3).join("; ")}${titles.length > 3 ? "; …" : ""}. From the version alone; a distribution may have backported the fix.` : `Named: ${named.join("; ")}`,
    fix: found[0]?.remediation || "Keep the server software on a supported, patched release.",
    verify: `curl -sI ${pageUrl} | grep -i -e x-powered-by -e ^server`,
  }];
}
