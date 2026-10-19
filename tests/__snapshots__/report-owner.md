# Security summary

> https://shop.example + ./shop · scanned 2026-10-19 09:30:00 UTC · Penthera v1.4.0-test

## In short

Penthera checked https://shop.example + ./shop and found **2 serious problems** to fix this week, 2 moderate, 1 minor.
The serious ones are things an attacker could use today.
1 check could not finish, so those areas are untested, not clean.
2 known issues were set aside on purpose by someone on the team (the auditor report lists who and why).

## What to do first

1. **Rotate the exposed secret and move it to a secret store** (moderate, needs you). A hardcoded credential in source is compromised the moment the repo is shared or leaked; attackers scan public and private repos for exactly this.
2. **Harden authentication and access control** (involved, a developer can do this). Broken auth or object-level access control (IDOR/BOLA, weak login, OAuth open redirect) lets attackers reach data or actions that aren't theirs.
3. **Set secure cookie flags** (quick, a developer can do this). Session cookies without HttpOnly, Secure, and SameSite are exposed to theft via XSS and CSRF.

## Things only you can do

A tool or a developer cannot do these for you: they need account access, a provider dashboard or a DNS change.

- **Rotate the exposed secret and move it to a secret store**: Treat the secret as burned: rotate/revoke it at the provider first, then remove it from source, load it from an environment variable or secret manager, and purge it from git history. Rotation is an owner action a tool must not perform for you.
- **Publish and enforce a DMARC policy**: Add a TXT record at `_dmarc.<domain>`: start with `v=DMARC1; p=none; rua=mailto:you@domain` to gather reports, then move to `p=quarantine` and finally `p=reject` once your legitimate senders are aligned.

## Trend

Serious problems went from 4 to 2 over the last 3 scans (down).

| Scan | Serious | Moderate | Minor | Total |
|------|---------|----------|-------|-------|
| 2026-09-01 | 4 | 4 | 3 | 11 |
| 2026-09-20 | 3 | 3 | 2 | 8 |
| 2026-10-19 | 2 | 2 | 1 | 5 |

## Fixes

1 fix verified by a re-scan, 1 failed, 1 still open. Typical time to fix: 1 min.

---

*Authorized security testing only. See the Penthera README for ethical use guidelines.*

Checked by Penthera, open-source security for the apps and AI systems you ship · https://github.com/danoszz/penthera
