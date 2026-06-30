# OWASP WSTG coverage map

Penthera maps its probes to the [OWASP Web Security Testing Guide (WSTG) v4.2](https://owasp.org/www-project-web-security-testing-guide/). This document is the canonical reference; scan reports include a summary table generated from `lib/owasp-wstg.js`.

## Coverage by profile

| Profile | Penthera probes | WSTG areas | Destructive payloads |
|---------|-----------------|------------|----------------------|
| **quick** | Headers, OpenAPI, auth smoke | INFO, CONF, ATHN | No |
| **standard** | Full non-destructive black-box + repo | INFO, CONF, CRYP, ATHN, ATHZ, SESS, CLNT | No |
| **deep** | standard + recon + injections + fuzz | All above + INPV, BUSL | Yes |

## Probe → WSTG mapping

| Penthera probe | WSTG IDs | Profiles | Mode |
|----------------|----------|----------|------|
| Reachability & fingerprint | WSTG-INFO-02, WSTG-INFO-04 | quick, standard, deep | URL |
| Endpoint discovery | WSTG-INFO-06, WSTG-INFO-07 | standard, deep | URL |
| TLS / certificate audit | WSTG-CRYP-01, WSTG-CRYP-02 | standard, deep | URL |
| Security headers | WSTG-CONF-12, WSTG-CONF-13, WSTG-CONF-14 | quick, standard, deep | URL |
| OpenAPI / Swagger exposure | WSTG-INFO-09, WSTG-CONF-02 | quick, standard, deep | URL |
| Sensitive file templates | WSTG-CONF-02, WSTG-CONF-04 | standard, deep | URL |
| CORS validation | WSTG-CLNT-07 | standard, deep | URL |
| Cookie security | WSTG-SESS-02 | standard, deep | URL |
| Auth endpoint hardening | WSTG-ATHN-03, WSTG-ATHN-10 | quick, standard, deep | URL |
| Client-side-only auth | WSTG-ATHZ-02, WSTG-CLNT-01 | standard, deep | URL |
| JWT probes | WSTG-ATHN-04, WSTG-SESS-10 | standard, deep | URL |
| IDOR / BOLA | WSTG-ATHZ-04, WSTG-ATHZ-05 | standard, deep | URL |
| OAuth open redirect | WSTG-ATHN-11, WSTG-CLNT-04 | standard, deep | URL |
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

## WSTG categories not covered (yet)

Penthera does **not** currently automate these WSTG areas:

| Category | Examples | Planned |
|----------|----------|---------|
| WSTG-IDNT | Registration, username policy | v0.4 |
| WSTG-ERRH | Verbose stack traces in all contexts | Partial (template scans) |
| WSTG-BUSL | Full business-logic workflows | Partial (fuzz only) |
| WSTG-APIT | GraphQL-specific tests | v0.4 |
| Manual / social | Phishing, physical access | Out of scope |

## Finding category → WSTG

When a finding is reported, Penthera tags it with relevant WSTG IDs in JSON (`finding.wstg[]`), SARIF (`properties.tags`), and Markdown reports.

| Finding category | WSTG IDs |
|------------------|----------|
| `tls` | WSTG-CRYP-01, WSTG-CRYP-02 |
| `exposure` | WSTG-CONF-02, WSTG-CONF-04 |
| `cors` | WSTG-CLNT-07 |
| `cookie` | WSTG-SESS-02 |
| `auth` | WSTG-ATHN-03, WSTG-ATHN-04 |
| `secrets` | WSTG-CONF-02, WSTG-CONF-05 |
| `sqli` | WSTG-INPV-05 |
| `xss` | WSTG-INPV-01, WSTG-CLNT-01 |
| `ssrf` | WSTG-INPV-19 |
| `cmdi` | WSTG-INPV-12 |
| `open-redirect` | WSTG-CLNT-04, WSTG-ATHN-11 |
| `rate-limiting` | WSTG-ATHN-10 |

## References

- [OWASP WSTG on GitHub](https://github.com/OWASP/wstg)
- Penthera implementation: `lib/owasp-wstg.js`
- Report integration: `src/report/markdown.js`, `src/reporter.js`
