/**
 * Email authentication posture, SPF, DMARC, and MX via DNS.
 *
 * Spoofed email is one of the most common attack vectors, and every security
 * questionnaire asks about it, yet most vibecoded apps ship without SPF or
 * DMARC. These are passive DNS lookups against the domain you're scanning, no
 * traffic to the app itself.
 *
 * DKIM needs an organisation-specific selector, which can't be enumerated
 * reliably, so we flag it as a manual follow-up rather than guessing selectors.
 *
 * The resolver is injectable so the evaluation logic is unit-testable without
 * live DNS.
 */
import { resolveTxt as dnsResolveTxt, resolveMx as dnsResolveMx } from "node:dns/promises";
import { currentEgress } from "../../src/utils/http.js";
import { SHARED_HOST_DOMAINS } from "../../src/utils/url.js";

const DEFAULT_RESOLVER = { resolveTxt: dnsResolveTxt, resolveMx: dnsResolveMx };

// Platforms that give each customer a subdomain (SHARED_HOST_DOMAINS, shared with the redirect
// rule). Their SPF and DMARC are the platform's, so they say nothing about the customer's site.
// Not every such platform is listed: a host missing from it still gets the platform's records.

/** The platform domain a customer host sits under, or null. The platform's own apex has no customer. */
export function sharedHostDomain(hostname) {
  const host = String(hostname).toLowerCase();
  return SHARED_HOST_DOMAINS.find((d) => host.endsWith(`.${d}`)) ?? null;
}

async function safeTxt(resolver, name) {
  try {
    const records = await resolver.resolveTxt(name);
    // resolveTxt returns string[][]; each record's chunks must be joined.
    return records.map((chunks) => (Array.isArray(chunks) ? chunks.join("") : String(chunks)));
  } catch {
    return [];
  }
}

async function safeMx(resolver, name) {
  try {
    return await resolver.resolveMx(name);
  } catch {
    return [];
  }
}

/** Evaluate SPF from a domain's root TXT records. */
export function evaluateSpf(txtRecords) {
  const spf = (txtRecords || []).find((r) => /^v=spf1\b/i.test(r.trim()));
  if (!spf) {
    return { present: false, record: null, finding: {
      severity: "medium",
      title: "No SPF record",
      description: "No `v=spf1` TXT record found. Anyone can send email that appears to come from this domain.",
      category: "email-auth",
      source: "email-dns-probe",
    } };
  }
  if (/[+]all\b/i.test(spf)) {
    return { present: true, record: spf, finding: {
      severity: "high",
      title: "SPF allows all senders (+all)",
      description: `SPF record ends in \`+all\`, which authorises any server to send as this domain: \`${spf.slice(0, 140)}\``,
      category: "email-auth",
      source: "email-dns-probe",
    } };
  }
  if (/[-~]all\b/i.test(spf) || /\bredirect=/i.test(spf)) {
    return { present: true, record: spf, finding: null }; // -all / ~all / delegated
  }
  return { present: true, record: spf, finding: {
    severity: "medium",
    title: "SPF does not restrict senders",
    description: `SPF record has no \`-all\` or \`~all\` mechanism, so spoofing is not restricted: \`${spf.slice(0, 140)}\``,
    category: "email-auth",
    source: "email-dns-probe",
  } };
}

/** Evaluate DMARC from the `_dmarc.<domain>` TXT records. */
export function evaluateDmarc(txtRecords) {
  const dmarc = (txtRecords || []).find((r) => /^v=DMARC1\b/i.test(r.trim()));
  if (!dmarc) {
    return { present: false, record: null, policy: null, finding: {
      severity: "medium",
      title: "No DMARC record",
      description: "No `v=DMARC1` record at `_dmarc.<domain>`. Without DMARC, receivers can't act on or report spoofed mail.",
      category: "email-auth",
      source: "email-dns-probe",
    } };
  }
  const policy = (dmarc.match(/\bp=(none|quarantine|reject)\b/i)?.[1] || "none").toLowerCase();
  if (policy === "none") {
    return { present: true, record: dmarc, policy, finding: {
      severity: "low",
      title: "DMARC policy is monitoring-only (p=none)",
      description: "DMARC is published but `p=none` only monitors, it does not block spoofed mail. Move to `quarantine` or `reject` once your legitimate senders are aligned.",
      category: "email-auth",
      source: "email-dns-probe",
    } };
  }
  return { present: true, record: dmarc, policy, finding: null };
}

/**
 * Probe a domain's email authentication posture.
 * @param {string} domain
 * @param {object} opts - { resolver }
 */
export async function probeEmailDns(domain, opts = {}) {
  // DNS queries go to resolvers, not the target: --offline forbids them.
  if (currentEgress()?.offline) {
    return { domain, spf: null, dmarc: null, dmarcPolicy: null, mxCount: 0, findings: [], skipped: "offline" };
  }
  const resolver = opts.resolver || DEFAULT_RESOLVER;
  const findings = [];

  const [rootTxt, dmarcTxt, mx] = await Promise.all([
    safeTxt(resolver, domain),
    safeTxt(resolver, `_dmarc.${domain}`),
    safeMx(resolver, domain),
  ]);

  const spf = evaluateSpf(rootTxt);
  const dmarc = evaluateDmarc(dmarcTxt);
  if (spf.finding) findings.push(spf.finding);
  if (dmarc.finding) findings.push(dmarc.finding);

  // DKIM: selector is provider-specific and can't be enumerated. Only nudge when
  // the domain clearly handles mail (has MX) and email auth is already imperfect.
  if (mx.length > 0 && (spf.finding || dmarc.finding)) {
    findings.push({
      severity: "info",
      title: "Verify DKIM is signing outbound mail",
      description: "This domain has MX records (it handles mail) and its SPF/DMARC is incomplete. Also confirm DKIM signing, the selector is provider-specific, so Penthera does not auto-check it.",
      category: "email-auth",
      source: "email-dns-probe",
    });
  }

  return {
    domain,
    spf: spf.record,
    dmarc: dmarc.record,
    dmarcPolicy: dmarc.policy || null,
    mxCount: mx.length,
    findings,
  };
}
