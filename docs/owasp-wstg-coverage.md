---
title: "OWASP WSTG coverage map"
sidebarTitle: "OWASP WSTG coverage"
description: "Penthera maps its probes to the OWASP Web Security Testing Guide (WSTG) v4.2."
---

> **Pro.** For "which OWASP tests does it cover?"

Penthera maps its probes to the [OWASP Web Security Testing Guide (WSTG) v4.2](https://owasp.org/www-project-web-security-testing-guide/). The mapping lives in `lib/owasp-wstg.js`, and this page follows it. Each scan report includes a coverage table built from the probes that actually ran.

A mapped WSTG ID means a probe touches that test area. It does not mean the probe runs every test case the guide describes for it.

## Coverage by profile

| Profile | Penthera probes | WSTG areas | Destructive payloads |
|---------|-----------------|------------|----------------------|
| **quick** | Reachability, headers, OpenAPI, auth smoke test, repo secrets and routes | INFO, CONF, ATHN, ATHZ | No |
| **standard** | All non-destructive URL and repo probes | INFO, CONF, CRYP, ATHN, ATHZ, SESS, CLNT | No |
| **deep** | Standard, plus recon, injections and fuzzing | All above + INPV, BUSL | Yes |

## Probe to WSTG mapping

| Penthera probe | WSTG IDs | Profiles | Mode |
|----------------|----------|----------|------|
| Reachability & fingerprint | WSTG-INFO-02, WSTG-INFO-04 | quick, standard, deep | URL |
| Endpoint discovery | WSTG-INFO-06, WSTG-INFO-07 | standard, deep | URL |
| TLS / certificate audit | WSTG-CRYP-01 | standard, deep | URL |
| Security headers (missing headers, a CSP that doesn't control scripts, `X-Powered-By`) | WSTG-CONF-12, WSTG-CONF-14, WSTG-INFO-08 | quick, standard, deep | URL |
| OpenAPI / Swagger exposure (an exposed spec is rule `openapi-exposed`) | WSTG-INFO-09, WSTG-CONF-02 | quick, standard, deep | URL |
| Sensitive file templates (also directory listings, `/metrics`, stack traces) | WSTG-CONF-02, WSTG-CONF-04, WSTG-ERRH-01 | standard, deep | URL |
| CORS validation | WSTG-CLNT-07 | standard, deep | URL |
| Cookie security | WSTG-SESS-02 | standard, deep | URL |
| Auth endpoint hardening | WSTG-ATHN-03, WSTG-ATHN-10 | quick, standard, deep | URL |
| Client-side-only auth detection | WSTG-ATHZ-02, WSTG-CLNT-01 | standard, deep | URL |
| JWT probes | WSTG-ATHN-04, WSTG-SESS-10 | standard, deep | URL |
| IDOR / BOLA | WSTG-ATHZ-04, WSTG-ATHZ-05 | standard, deep | URL |
| OAuth open redirect | WSTG-ATHN-11, WSTG-CLNT-04 | standard, deep | URL |
| Adaptive escalation probes | WSTG-ATHZ-02, WSTG-ATHZ-04, WSTG-CLNT-07 | standard, deep | URL |
| Retire.js (JS CVEs) | WSTG-CONF-04, WSTG-CLNT-02 | standard, deep | URL |
| Parameter discovery | WSTG-INFO-06 | standard, deep | URL |
| OSINT recon | WSTG-INFO-01, WSTG-INFO-07 | deep | URL |
| SQL injection | WSTG-INPV-05 | deep | URL |
| SSTI | WSTG-INPV-18 | deep | URL |
| SSRF | WSTG-INPV-19 | deep | URL |
| Reflected XSS | WSTG-INPV-01, WSTG-CLNT-01 | deep | URL |
| Command injection | WSTG-INPV-12 | deep | URL |
| Open redirect (injection suite) | WSTG-CLNT-04 | deep | URL |
| API fuzzing | WSTG-INPV-11, WSTG-BUSL-05 | deep | URL |
| Secret scanning | WSTG-CONF-02, WSTG-CONF-05 | quick, standard, deep | Repo |
| Route / trust-boundary analysis | WSTG-ATHZ-02, WSTG-CONF-02 | quick, standard, deep | Repo |
| Risky code patterns | WSTG-INPV-01, WSTG-INPV-12 | standard, deep | Repo |
| Code-execution sinks (eval, vm, exec) with request data | WSTG-INPV-11, WSTG-INPV-12 | quick, standard, deep | Repo |
| Runtime & server advisories (PHP, nginx, Apache, Node.js, Python, OpenSSL, MongoDB) | WSTG-INFO-02, WSTG-INFO-08, WSTG-CONF-01 | quick, standard, deep | URL, Repo |

## WSTG categories not covered

Penthera does not automate these WSTG areas, or covers them only in part:

| Category | Examples | Status |
|----------|----------|--------|
| WSTG-IDNT | Registration, username policy | Not covered |
| WSTG-ERRH | Verbose stack traces in all contexts | Partial (stack traces on a not-found path only) |
| WSTG-BUSL | Full business-logic workflows | Partial (fuzzing only) |
| WSTG-APIT | GraphQL-specific tests | Partial (an introspection template only) |
| Manual / social | Phishing, physical access | Out of scope |

## Finding category to WSTG

When it reports a finding, Penthera tags it with relevant WSTG IDs in JSON (`finding.wstg[]`), SARIF (`properties.tags`), and Markdown reports.

| Finding category | WSTG IDs |
|------------------|----------|
| `tls` | WSTG-CRYP-01 |
| `exposure` | WSTG-CONF-02, WSTG-CONF-04 |
| `cors` | WSTG-CLNT-07 |
| `cookie` | WSTG-SESS-02 |
| `auth` | WSTG-ATHN-03, WSTG-ATHN-04 |
| `auth-bypass` | WSTG-ATHZ-02, WSTG-ATHN-04 |
| `secrets` | WSTG-CONF-02, WSTG-CONF-05 |
| `sqli` | WSTG-INPV-05 |
| `ssti` | WSTG-INPV-18 |
| `xss` | WSTG-INPV-01, WSTG-CLNT-01 |
| `ssrf` | WSTG-INPV-19 |
| `cmdi` | WSTG-INPV-12 |
| `open-redirect` | WSTG-CLNT-04, WSTG-ATHN-11 |
| `rate-limiting` | WSTG-ATHN-10 |
| `fuzzing` | WSTG-INPV-11 |
| `recon` | WSTG-INFO-01 |
| `cve` | WSTG-CONF-04 |
| `code-pattern` | WSTG-INPV-01, WSTG-INPV-12 |
| `config` | WSTG-CONF-02 |

Penthera also adds tags from the probe that produced a finding and from keywords in its title, so a finding can carry more IDs than its category lists here.

## References

- [OWASP WSTG on GitHub](https://github.com/OWASP/wstg)
- Penthera implementation: `lib/owasp-wstg.js`
- Report integration: `src/report/markdown.js`, `src/reporter.js`
