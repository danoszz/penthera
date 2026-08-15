/**
 * Supplier passive rating (NIS2 measure d — supply-chain security).
 *
 * NIS2 pulls smaller suppliers into scope through supply-chain risk assessment.
 * This lets a company point Penthera's PASSIVE checks at their own suppliers'
 * public domains and get a red/amber/green posture per supplier.
 *
 * STRICTLY PASSIVE and public-data-only — equivalent to visiting the public
 * website and looking up public DNS. It performs exactly three non-intrusive
 * actions per domain:
 *   1. one HTTPS GET of the homepage (security headers),
 *   2. a TLS handshake to read the certificate (protocol/expiry),
 *   3. public DNS lookups for SPF/DMARC/MX (email authentication).
 * No endpoint discovery, no auth probes, no injection, no fuzzing. This is the
 * only third-party-facing feature, and it is deliberately kept passive.
 */
import { checkTls } from "./tls.js";
import { auditSecurityHeaders } from "./blackbox/headers.js";
import { probeEmailDns } from "./blackbox/email-dns.js";
import { safeFetch } from "../src/utils/http.js";

/** Parse a domain from a line/entry: strip scheme, path, and whitespace. */
export function parseDomain(entry) {
  const s = String(entry).trim();
  if (!s || s.startsWith("#")) return null;
  return s.replace(/^https?:\/\//i, "").replace(/\/.*$/, "").replace(/:\d+$/, "").trim() || null;
}

/** Parse a supplier list: newline- or comma-separated domains, # comments ok. */
export function parseSupplierList(text) {
  return [...new Set(
    String(text).split(/[\n,]+/).map(parseDomain).filter(Boolean),
  )];
}

const PENALTY = { critical: 40, high: 25, medium: 12, low: 5, info: 1 };

/** Score and RAG-rate a supplier from its passive findings. */
export function scoreSupplier(result) {
  if (!result.reachable) return { score: null, rating: "unknown" };
  let penalty = 0;
  for (const f of result.findings) penalty += PENALTY[f.severity] || 0;
  const score = Math.max(0, Math.min(100, 100 - penalty));
  const rating = score >= 80 ? "green" : score >= 50 ? "amber" : "red";
  return { score, rating };
}

/**
 * Rate one supplier domain with passive checks only.
 */
export async function rateSupplier(domain, opts = {}) {
  const timeout = opts.timeout || 8000;
  const httpsUrl = `https://${domain}`;
  const result = { domain, reachable: false, tls: null, email: null, findings: [] };

  // 1. Passive homepage GET (follow redirects to reach the real homepage headers)
  let res = null;
  try {
    res = await safeFetch(httpsUrl, { timeout, redirect: "follow" });
  } catch { /* unreachable */ }
  result.reachable = !!res;

  // 2. Security headers from the homepage response
  if (res) {
    const headerMap = Object.fromEntries(res.headers.entries());
    result.findings.push(...auditSecurityHeaders(headerMap, httpsUrl, { local: false }));
  }

  // 3. TLS certificate / protocol (passive handshake)
  try {
    const tls = await checkTls(domain, 443);
    result.tls = { protocol: tls.protocol, valid: tls.valid, daysUntilExpiry: tls.daysUntilExpiry };
    for (const f of tls.findings || []) {
      result.findings.push({ ...f, category: "tls", source: "supplier-tls" });
    }
  } catch { /* no TLS */ }

  // 4. Email authentication (public DNS)
  try {
    const email = await probeEmailDns(domain);
    result.email = { spf: !!email.spf, dmarc: !!email.dmarc, dmarcPolicy: email.dmarcPolicy, mxCount: email.mxCount };
    result.findings.push(...email.findings);
  } catch { /* no DNS */ }

  Object.assign(result, scoreSupplier(result));
  result.keyIssues = result.findings
    .filter((f) => f.severity === "critical" || f.severity === "high" || f.severity === "medium")
    .map((f) => f.title);
  return result;
}

/** Rate a list of supplier domains (small concurrency, passive). */
export async function rateSuppliers(domains, opts = {}) {
  const concurrency = opts.concurrency || 5;
  const results = [];
  for (let i = 0; i < domains.length; i += concurrency) {
    const batch = domains.slice(i, i + concurrency);
    const settled = await Promise.all(batch.map((d) => rateSupplier(d, opts).catch(() => ({
      domain: d, reachable: false, findings: [], score: null, rating: "unknown", keyIssues: [],
    }))));
    results.push(...settled);
  }
  const summary = { green: 0, amber: 0, red: 0, unknown: 0 };
  for (const r of results) summary[r.rating] = (summary[r.rating] || 0) + 1;
  return { generated_at: opts.generatedAt || null, count: results.length, summary, suppliers: results };
}

const RATING_LABEL = { green: "🟢 Green", amber: "🟡 Amber", red: "🔴 Red", unknown: "⚪ Unknown" };

/** Render supplier ratings as Markdown. */
export function formatSuppliersMarkdown(report) {
  if (!report) return "";
  const L = [];
  L.push("# Supplier security ratings");
  L.push("");
  L.push("> **Passive, public-data-only assessment** — equivalent to visiting each supplier's public website and looking up public DNS. No intrusive testing was performed. This is a screening aid for supply-chain risk (NIS2 measure d), **not** an authorised penetration test of the supplier and **not** a certification of them.");
  L.push("");
  const s = report.summary;
  L.push(`**${report.count}** suppliers: ${s.green} green · ${s.amber} amber · ${s.red} red · ${s.unknown} unknown.`);
  L.push("");
  L.push("| Supplier | Rating | Score | Key issues |");
  L.push("|----------|--------|-------|-----------|");
  for (const r of report.suppliers) {
    const issues = r.keyIssues?.length ? r.keyIssues.slice(0, 4).join("; ") : (r.rating === "unknown" ? "unreachable" : "none found (passive)");
    L.push(`| ${r.domain} | ${RATING_LABEL[r.rating] || r.rating} | ${r.score ?? "—"} | ${issues} |`);
  }
  L.push("");
  L.push("Methodology: one HTTPS homepage GET (security headers), a TLS handshake (certificate/protocol), and public DNS lookups (SPF/DMARC/MX). Ratings: green ≥ 80, amber 50–79, red < 50; unknown = unreachable.");
  L.push("");
  return L.join("\n");
}
