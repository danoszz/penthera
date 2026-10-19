# Security evidence report

> https://shop.example + ./shop · scanned 2026-10-19 09:30:00 UTC · Penthera v1.4.0-test

> Automated technical evidence. It is not an audit opinion, a compliance determination or a certification.

## 1. Scope and method

| | |
|---|---|
| **Target** | `https://shop.example + ./shop` |
| **Scan time** | 2026-10-19 09:30:00 UTC |
| **Duration** | 18.4 s |
| **Modes** | url, repo |
| **Profile** | standard |
| **Network** | offline (scan target only) |
| **Tool** | Penthera v1.4.0-test |

Probes that ran: `cookies`, `cors`, `reachability`, `secret-scanning`, `security-headers`, `tls`.

Method, threat model and limits: [docs/METHODOLOGY.md](https://github.com/danoszz/penthera/blob/main/docs/METHODOLOGY.md). A probe that is not listed did not run, and an area it covers is untested.

## 2. Confidence and provenance

Every finding carries a confidence label that says how sure the scanner is that the issue is real, separate from its severity.

| Label | Meaning | This scan |
|-------|---------|-----------|
| `confirmed` | Deterministic evidence: a header is absent, a certificate has expired, a secret is in the file. | 4 |
| `likely` | A strong signal with a small chance of a false positive. | 0 |
| `potential` | A heuristic or timing signal. It needs a second source before anyone acts on it. | 0 |
| `needs-human-review` | A scanner cannot judge exploitability here (access control, IDOR). A person has to look. | 1 |

| # | Id | Finding | Severity | Confidence | Source / method | Collected | Location |
|---|----|---------|----------|------------|-----------------|-----------|----------|
| 1 | `1a2b3c4d5e6f7a8b` | Hardcoded Stripe secret key | critical | confirmed | secret-scan / secret-scan | 2026-10-19 09:30:00 UTC | `src/lib/payments.js:14` |
| 2 | `4d5e6f7a8b9c0d1e` | Possible IDOR on /api/orders/:id | high | needs-human-review | idor-probe / idor-probe | 2026-10-19 09:30:00 UTC | `https://shop.example/api/orders/1001` |
| 3 | `2b3c4d5e6f7a8b9c` | Missing Content-Security-Policy header | medium | confirmed | header-audit / header-audit | 2026-10-19 09:30:00 UTC | `https://shop.example/` |
| 4 | `3c4d5e6f7a8b9c0d` | Session cookie without Secure \| HttpOnly &lt;flags&gt; | medium | confirmed | cookie-audit / cookie-audit | 2026-10-19 09:30:00 UTC | `https://shop.example/login` |
| 5 | `5e6f7a8b9c0d1e2f` | DMARC policy is p=none | low | confirmed | email-dns-probe / email-dns-probe | 2026-10-19 09:30:00 UTC | `https://shop.example` |

## 3. Network egress

- **Mode:** offline (scan target only)
- **User-Agent:** `penthera/1.4.0 (+https://github.com/danoszz/penthera)`
- **Third-party hosts contacted:** none
- **Blocked by --offline:** `crt.sh` (1)

## Inconclusive probes

1 probe could not complete. Their silence is not a clean result.

| Probe | URL | Error | Count |
|-------|-----|-------|-------|
| retirejs | `https://shop.example/_next/static/chunks/main.js` | timeout after 10000 ms | 3 |

## 4. Suppressions

These findings were hidden from the results by a person's decision. Each needs a reason; review them.

| Id | Finding | Severity | Who | Why | Recorded in | Expires |
|----|---------|----------|-----|-----|-------------|---------|
| `6f7a8b9c0d1e2f3a` | X-Powered-By header discloses Express | low | daan | Stripped at the CDN edge; verified 2026-10-01 | local memory | 2027-01-01T00:00:00.000Z |
| `7a8b9c0d1e2f3a4b` | Test fixture key in tests/ | high | ci-bot | Fake key used by unit tests | repo file (penthera.suppress.json) | never |

## 5. Fix timeline

Source: agent loop. 1 verified · 1 failed · 1 open · median time to fix 1 min.

| Finding | Found | Fixed | Verified | Time to fix |
|---------|-------|-------|----------|-------------|
| Hardcoded Stripe secret key (`1a2b3c4d5e6f7a8b`) | iteration 1 | - | - | - |
| Missing Content-Security-Policy header (`2b3c4d5e6f7a8b9c`) | iteration 1 | iteration 1 (`security-headers`) | **failed** iteration 2 | - |
| `8b9c0d1e2f3a4b5c` | iteration 1 | iteration 1 (`cors-allowlist`) | iteration 2 | 1 min |

## 6. NIS2 Article 21(2) mapping

Technical evidence toward each measure, based on the probes that ran. Organisational measures need human process.

| Art. 21(2) | Measure | This scan | Findings |
|-----------|---------|-----------|----------|
| (a) | Risk analysis & information-security policy | Evidence only | - |
| (b) | Incident handling | Planned | - |
| (c) | Business continuity, backup & crisis management | Out of scope | - |
| (d) | Supply-chain security | Tested, gaps found | 1 |
| (e) | Secure acquisition, development & maintenance; vulnerability handling | Tested, gaps found | 5 |
| (f) | Assessing the effectiveness of measures | Evidence only | - |
| (g) | Cyber hygiene & training | Evidence only | - |
| (h) | Cryptography & encryption | Tested, gaps found | 1 |
| (i) | HR security, access control & asset management | Not run this scan | 1 |
| (j) | Multi-factor authentication & secure communications | Planned | - |

## 7. OWASP mapping

| OWASP category | Findings | Ids |
|----------------|----------|-----|
| A01:2021 Broken Access Control | 1 | 4d5e6f7a8b9c0d1e |
| A05:2021 Security Misconfiguration | 2 | 2b3c4d5e6f7a8b9c, 3c4d5e6f7a8b9c0d |
| A07:2021 Identification and Authentication Failures | 1 | 1a2b3c4d5e6f7a8b |

OWASP WSTG test areas with findings: `WSTG-ATHN-04`, `WSTG-ATHZ-02`, `WSTG-ATHZ-04`, `WSTG-ATHZ-05`, `WSTG-CONF-02`, `WSTG-CONF-05`, `WSTG-CONF-12`, `WSTG-CONF-14`, `WSTG-SESS-02`.

## Verifying this report

If this report came in an evidence bundle, check that nothing in it changed since it was produced: `penthera evidence verify <dir> --allowed-signers <file>`. See [docs/evidence.md](https://github.com/danoszz/penthera/blob/main/docs/evidence.md).

---

*Authorized security testing only. See the Penthera README for ethical use guidelines.*

Checked by Penthera, open-source security for the apps and AI systems you ship · https://github.com/danoszz/penthera
