# Security findings for developers

> https://shop.example + ./shop · scanned 2026-10-19 09:30:00 UTC · Penthera v1.4.0-test

5 findings: 1 critical · 1 high · 2 medium · 1 low · 0 info.
2 suppressed (listed at the end).

Findings with a recipe can be fixed locally: `penthera fix --plan` shows the diff, `penthera fix --apply <id>` applies it.

### 1. [CRITICAL] Hardcoded Stripe secret key

- **Where:** `src/lib/payments.js:14`
- **Confidence:** confirmed (secret-scan) · id `1a2b3c4d5e6f7a8b`
- **Fix recipe:** `secret-to-env`
- **How to fix:** Treat the secret as burned: rotate/revoke it at the provider first, then remove it from source, load it from an environment variable or secret manager, and purge it from git history. Rotation is an owner action a tool must not perform for you.
- **Sources:** [Meli et al. 2019](https://doi.org/10.14722/ndss.2019.23418) · [Basak et al. 2023](https://doi.org/10.1109/MSR59073.2023.00053)

A live-format Stripe key is committed to source.

### 2. [HIGH] Possible IDOR on /api/orders/:id

- **Where:** https://shop.example/api/orders/1001
- **Confidence:** needs-human-review (idor-probe) · id `4d5e6f7a8b9c0d1e`
- **How to fix:** Enforce authorization server-side on every request (never trust the client), check that the authenticated user owns the object being accessed, validate OAuth `redirect_uri` against an allow-list, and add rate limiting and lockout on login.
- **Sources:** [OWASP API Top 10:2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) · [OWASP WSTG v4.2](https://wstg.owasp.org/v4.2/)

### 3. [MEDIUM] Missing Content-Security-Policy header

- **Where:** https://shop.example/
- **Confidence:** confirmed (header-audit) · id `2b3c4d5e6f7a8b9c`
- **Fix recipe:** `security-headers`
- **How to fix:** Start in report-only mode to avoid breakage, then enforce. On Vercel/Next.js set it in `next.config.js` headers or `vercel.json`; on Express use `helmet`'s `contentSecurityPolicy`. Begin with `default-src 'self'` and add sources as needed.
- **Sources:** [Weichselbaum et al. 2016](https://doi.org/10.1145/2976749.2978363) · [RFC 6797 (2012)](https://doi.org/10.17487/RFC6797) · [OWASP WSTG v4.2](https://wstg.owasp.org/v4.2/)

### 4. [MEDIUM] Session cookie without Secure \| HttpOnly &lt;flags&gt;

- **Where:** https://shop.example/login
- **Confidence:** confirmed (cookie-audit) · id `3c4d5e6f7a8b9c0d`
- **Fix recipe:** `cookie-flags`
- **How to fix:** Set `HttpOnly`, `Secure`, and `SameSite=Lax` (or `Strict`) on session/auth cookies. Most frameworks set these via the session middleware config.
- **Sources:** [Barth et al. 2008](https://doi.org/10.1145/1455770.1455782) · [OWASP WSTG v4.2](https://wstg.owasp.org/v4.2/)

### 5. [LOW] DMARC policy is p=none

- **Where:** https://shop.example
- **Confidence:** confirmed (email-dns-probe) · id `5e6f7a8b9c0d1e2f`
- **How to fix:** Add a TXT record at `_dmarc.<domain>`: start with `v=DMARC1; p=none; rua=mailto:you@domain` to gather reports, then move to `p=quarantine` and finally `p=reject` once your legitimate senders are aligned.
- **Sources:** [RFC 7208 (2014)](https://doi.org/10.17487/RFC7208) · [RFC 7489 (2015)](https://doi.org/10.17487/RFC7489)

## Inconclusive probes

1 probe could not complete. Their silence is not a clean result.

| Probe | URL | Error | Count |
|-------|-----|-------|-------|
| retirejs | `https://shop.example/_next/static/chunks/main.js` | timeout after 10000 ms | 3 |

## Fix timeline

Source: agent loop. 1 verified · 1 failed · 1 open · median time to fix 1 min.

| Finding | Found | Fixed | Verified | Time to fix |
|---------|-------|-------|----------|-------------|
| Hardcoded Stripe secret key (`1a2b3c4d5e6f7a8b`) | iteration 1 | - | - | - |
| Missing Content-Security-Policy header (`2b3c4d5e6f7a8b9c`) | iteration 1 | iteration 1 (`security-headers`) | **failed** iteration 2 | - |
| `8b9c0d1e2f3a4b5c` | iteration 1 | iteration 1 (`cors-allowlist`) | iteration 2 | 1 min |

## Suppressed

- X-Powered-By header discloses Express (`6f7a8b9c0d1e2f3a`): Stripped at the CDN edge; verified 2026-10-01 (daan, local memory)
- Test fixture key in tests/ (`7a8b9c0d1e2f3a4b`): Fake key used by unit tests (ci-bot, repo file (penthera.suppress.json))

---

*Authorized security testing only. See the Penthera README for ethical use guidelines.*

Checked by Penthera, open-source security for the apps and AI systems you ship · https://github.com/danoszz/penthera
