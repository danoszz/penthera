/**
 * Remediation knowledge base + action-plan builder.
 *
 * Turns raw findings into a prioritised, owner-actionable plan: what to do, why
 * it matters, how to fix it, rough effort, and whether it's a code change or an
 * owner action (rotate a secret, renew a cert, change DNS) that a tool must not
 * do for you. This is the structured data the report renders and that the Agent
 * Skill uses to draft questionnaire answers and remediation documents.
 */

// Each rule matches a finding and yields remediation guidance. First match wins,
// so order specific rules (by title) before broad ones (by category).
const RULES = [
  {
    id: "email-spf",
    match: (f) => f.category === "email-auth" && /SPF/i.test(f.title),
    action: "Publish (or tighten) an SPF record",
    why: "Without a restrictive SPF record, anyone can send email that appears to come from your domain, a common phishing and business-email-compromise vector.",
    fix: "Add a DNS TXT record at the root: `v=spf1 include:<your-mail-provider> -all`. End with `-all` (hard fail), not `~all` or `+all`.",
    effort: "quick",
    ownerAction: true, // DNS change
  },
  {
    id: "email-dmarc",
    match: (f) => f.category === "email-auth" && /DMARC/i.test(f.title),
    action: "Publish and enforce a DMARC policy",
    why: "DMARC tells receivers what to do with mail that fails SPF/DKIM and gives you reporting. `p=none` only monitors, it does not block spoofing.",
    fix: "Add a TXT record at `_dmarc.<domain>`: start with `v=DMARC1; p=none; rua=mailto:you@domain` to gather reports, then move to `p=quarantine` and finally `p=reject` once your legitimate senders are aligned.",
    effort: "moderate",
    ownerAction: true,
  },
  {
    id: "email-dkim",
    match: (f) => f.category === "email-auth" && /DKIM/i.test(f.title),
    action: "Confirm DKIM is signing outbound mail",
    why: "DKIM cryptographically signs your mail so receivers can verify it wasn't forged or altered. It's the third leg of email authentication with SPF and DMARC.",
    fix: "Enable DKIM in your email provider and publish the provider's public key at `<selector>._domainkey.<domain>`. Verify a signed test message passes DKIM.",
    effort: "moderate",
    ownerAction: true,
  },
  {
    id: "header-csp",
    match: (f) => /content-security-policy/i.test(f.title),
    action: "Add a Content-Security-Policy header",
    why: "CSP is the strongest defence-in-depth against cross-site scripting and data injection, it limits what scripts and resources the browser will load.",
    fix: "Start in report-only mode to avoid breakage, then enforce. On Vercel/Next.js set it in `next.config.js` headers or `vercel.json`; on Express use `helmet`'s `contentSecurityPolicy`. Begin with `default-src 'self'` and add sources as needed.",
    effort: "moderate",
    ownerAction: false,
  },
  {
    id: "header-generic",
    match: (f) => f.category === "headers" || /x-frame-options|x-content-type-options|referrer-policy|permissions-policy|strict-transport-security|hsts/i.test(f.title),
    action: "Add the missing security response headers",
    why: "Headers like X-Frame-Options (clickjacking), X-Content-Type-Options (MIME sniffing), Referrer-Policy, Permissions-Policy, and HSTS are low-effort, high-value hardening.",
    fix: "Set them once at the edge/framework layer: `helmet()` on Express, a `headers()` entry in `next.config.js`, or a `headers` block in `vercel.json`. Include `Strict-Transport-Security: max-age=63072000; includeSubDomains`.",
    effort: "quick",
    ownerAction: false,
  },
  {
    id: "tls",
    match: (f) => f.category === "tls" || /TLS|certificate|cipher|expir/i.test(f.title),
    action: "Fix the TLS configuration",
    why: "Weak protocols/ciphers or an expiring certificate undermine transport security and can break trust or enable downgrade attacks.",
    fix: "Renew the certificate before expiry (automate with Let's Encrypt/ACME), disable TLS < 1.2, and prefer AEAD ciphers. Renewal is an operations action, not a code change.",
    effort: "moderate",
    ownerAction: true, // cert renewal
  },
  {
    id: "secrets",
    match: (f) => f.category === "secrets",
    action: "Rotate the exposed secret and move it to a secret store",
    why: "A hardcoded credential in source is compromised the moment the repo is shared or leaked; attackers scan public and private repos for exactly this.",
    fix: "Treat the secret as burned: rotate/revoke it at the provider first, then remove it from source, load it from an environment variable or secret manager, and purge it from git history. Rotation is an owner action a tool must not perform for you.",
    effort: "moderate",
    ownerAction: true,
  },
  {
    id: "injection",
    match: (f) => ["sqli", "ssti", "ssrf", "xss", "cmdi", "injection", "open-redirect"].includes(f.category),
    action: "Fix the injection / input-handling flaw",
    why: "Injection flaws (SQLi, SSTI, SSRF, XSS, command injection, open redirect) let an attacker run code, read data, or redirect users. These are among the highest-impact web vulnerabilities.",
    fix: "Never build queries/commands/markup from raw input: use parameterised queries, context-aware output encoding, an allow-list for redirect targets and outbound URLs (SSRF), and a sandboxed template engine. Validate and canonicalise all user input.",
    effort: "involved",
    ownerAction: false,
  },
  {
    id: "auth",
    match: (f) => f.category === "auth" || f.category === "auth-bypass",
    action: "Harden authentication and access control",
    why: "Broken auth or object-level access control (IDOR/BOLA, weak login, OAuth open redirect) lets attackers reach data or actions that aren't theirs.",
    fix: "Enforce authorization server-side on every request (never trust the client), check that the authenticated user owns the object being accessed, validate OAuth `redirect_uri` against an allow-list, and add rate limiting and lockout on login.",
    effort: "involved",
    ownerAction: false,
  },
  {
    id: "rate-limiting",
    match: (f) => f.category === "rate-limiting" || /rate limit/i.test(f.title),
    action: "Add rate limiting to sensitive endpoints",
    why: "Without rate limiting, login and expensive endpoints are open to brute force, credential stuffing, and abuse/cost attacks.",
    fix: "Apply per-IP and per-account rate limits on auth and costly routes (e.g. `express-rate-limit`, an edge/WAF rule, or your platform's built-in limiter). Return 429 with backoff.",
    effort: "moderate",
    ownerAction: false,
  },
  {
    id: "cve",
    match: (f) => f.category === "cve" || f.category === "js-vulnerability",
    action: "Update the vulnerable dependency",
    why: "A dependency with a known CVE is a documented, exploitable path in, attackers scan for exactly these versions.",
    fix: "Upgrade to a patched version, run `npm audit fix` (or your ecosystem's equivalent), and add dependency scanning to CI so regressions are caught.",
    effort: "quick",
    ownerAction: false,
  },
  {
    id: "cors",
    match: (f) => f.category === "cors",
    action: "Restrict CORS to explicit origins",
    why: "A permissive CORS policy (reflecting arbitrary or `null` origins) can let malicious sites read authenticated responses.",
    fix: "Replace origin reflection with an explicit allow-list of trusted origins, and never combine `Access-Control-Allow-Origin: *` with credentials.",
    effort: "quick",
    ownerAction: false,
  },
  {
    id: "cookie",
    match: (f) => f.category === "cookie",
    action: "Set secure cookie flags",
    why: "Session cookies without HttpOnly, Secure, and SameSite are exposed to theft via XSS and CSRF.",
    fix: "Set `HttpOnly`, `Secure`, and `SameSite=Lax` (or `Strict`) on session/auth cookies. Most frameworks set these via the session middleware config.",
    effort: "quick",
    ownerAction: false,
  },
  {
    id: "exposure",
    match: (f) => f.category === "exposure" || f.category === "disclosure" || f.category === "config",
    action: "Remove the exposed file or interface from production",
    why: "Exposed configs, docs, admin interfaces, or backup files hand attackers a map of your system and sometimes credentials.",
    fix: "Block or remove the path in production (API docs, `.env`, actuator/status endpoints, source maps). Serve them only in non-production or behind authentication.",
    effort: "quick",
    ownerAction: false,
  },
];

const FALLBACK = {
  id: "review",
  action: "Review and remediate this finding",
  why: "This finding needs a manual review to determine impact and the right fix.",
  fix: "Confirm the finding, assess exploitability in your context, apply the appropriate fix, and re-scan to verify.",
  effort: "moderate",
  ownerAction: false,
};

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const EFFORT_ORDER = { quick: 0, moderate: 1, involved: 2 };

function ruleFor(finding) {
  return RULES.find((r) => r.match(finding)) || FALLBACK;
}

/**
 * Build a prioritised action plan from findings. Groups findings by remediation,
 * carries the highest severity in each group, and sorts by severity then effort.
 */
export function buildActionPlan(findings) {
  const groups = new Map();
  for (const f of findings || []) {
    if (f.severity === "info") continue; // info items aren't action items
    const rule = ruleFor(f);
    if (!groups.has(rule.id)) {
      groups.set(rule.id, {
        id: rule.id,
        action: rule.action,
        why: rule.why,
        fix: rule.fix,
        effort: rule.effort,
        ownerAction: rule.ownerAction,
        severity: f.severity,
        findings: [],
      });
    }
    const g = groups.get(rule.id);
    if ((SEV_ORDER[f.severity] ?? 5) < (SEV_ORDER[g.severity] ?? 5)) g.severity = f.severity;
    g.findings.push({ title: f.title, url: f.url || null, severity: f.severity });
  }

  return [...groups.values()].sort((a, b) => {
    const s = (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5);
    if (s !== 0) return s;
    return (EFFORT_ORDER[a.effort] ?? 3) - (EFFORT_ORDER[b.effort] ?? 3);
  });
}

const SEV_TAG = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW", info: "INFO" };

/** Render an action plan as a Markdown section. */
export function formatActionPlanMarkdown(plan) {
  if (!plan || plan.length === 0) return "";
  const findingCount = plan.reduce((n, a) => n + a.findings.length, 0);
  const L = [];
  L.push("## Action plan");
  L.push("");
  L.push(`Prioritised fixes for the owner, **${plan.length}** action${plan.length > 1 ? "s" : ""} covering **${findingCount}** finding${findingCount > 1 ? "s" : ""}, highest severity first.`);
  L.push("");
  plan.forEach((a, i) => {
    const tag = SEV_TAG[a.severity] || "";
    const kind = a.ownerAction ? " · owner action" : "";
    L.push(`### ${i + 1}. ${a.action}`);
    L.push("");
    L.push(`**${tag}** · ${a.effort}${kind} · resolves ${a.findings.length} finding${a.findings.length > 1 ? "s" : ""}`);
    L.push("");
    L.push(`**Why:** ${a.why}`);
    L.push("");
    L.push(`**Fix:** ${a.fix}`);
    L.push("");
    if (a.ownerAction) {
      L.push("> This is an owner action (e.g. rotate a secret, renew a certificate, change DNS). Penthera flags it but will not do it for you.");
      L.push("");
    }
  });
  return L.join("\n");
}
