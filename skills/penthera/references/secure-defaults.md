# Secure defaults

Build it right the first time so Penthera finds nothing. This is the proactive
companion to [remediation.md](remediation.md): apply these while writing code,
then run a scan to verify. For fixing issues that already exist, use the
remediation playbook.

## Checklist for every web app

- [ ] **Security headers** set (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS).
- [ ] **Server-side auth** enforced on every sensitive route. Client-side checks are not security.
- [ ] **Parameterized queries** everywhere. No string-built SQL.
- [ ] **Output encoding** on by default. No raw HTML injection with user input.
- [ ] **Secrets in environment variables**, never in code. `.env` is gitignored.
- [ ] **CORS allowlist** of explicit origins. No `*` with credentials.
- [ ] **Rate limiting** on auth and expensive endpoints.
- [ ] **Secure cookies**: `HttpOnly`, `Secure`, `SameSite`.
- [ ] **API docs disabled** in production (`/docs`, `/openapi.json`).
- [ ] **HTTPS only** with HSTS and a valid TLS certificate.
- [ ] **JWT** with a pinned algorithm (no `alg:none`); verify `exp` and signature.
- [ ] **Redirect targets** validated against an allowlist.

## Per-framework starting points

| Framework | Secure-by-default setup |
|-----------|--------------------------|
| **Next.js** | Security headers in `next.config.js`; auth in `middleware.ts`; cookies via `next/headers` with `httpOnly`/`secure`/`sameSite`. |
| **Express** | `helmet()` + `cors({ origin: [...] })` + `express-rate-limit` + an auth middleware; `app.disable("x-powered-by")`. |
| **Fastify** | `@fastify/helmet` + `@fastify/cors` + `@fastify/rate-limit` + an `onRequest` auth hook. |
| **Hono** | `secureHeaders()` + `cors()` + custom auth middleware. |
| **FastAPI** | header middleware + `CORSMiddleware` allowlist + `slowapi` + `docs_url=None` in production. |

## Verify

Run a scan to confirm the defaults hold:

```bash
penthera https://localhost:3000 --repo .
```

Anything it flags, fix with the [remediation playbook](remediation.md), then re-scan.
