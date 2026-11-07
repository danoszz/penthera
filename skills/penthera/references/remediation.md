# Remediation playbook

Step-by-step, framework-aware fixes for the issues Penthera finds. This is the
"fix" half of the scan -> fix -> verify loop in Workflow 4 of [SKILL.md](../SKILL.md).

## How to use this playbook

1. **Scan** and read the findings (each has a `title`, `category`, and `severity`).
2. **Detect the framework**: check `package.json`/imports for `next`, `express`,
   `fastify`, `hono`; check `requirements.txt`/imports for `fastapi`, `flask`.
3. **For each finding**, find the section below that matches its `category`, then
   apply the snippet for the detected framework as a reviewable diff.
4. **Re-scan** and confirm the finding is gone.

Rules: work highest severity first, **show the diff and get the user's approval
before applying**, never apply against production, and treat a fix as done only
after a clean re-scan.

| Finding category | Section |
|------------------|---------|
| `headers` | [Security headers](#security-headers) |
| `auth`, `auth-bypass` | [Authentication](#authentication) |
| `exposure` | [Exposed API docs](#exposed-api-docs) |
| `cors`, `cors-misconfiguration` | [CORS](#cors) |
| `rate-limiting` | [Rate limiting](#rate-limiting) |
| `secrets` | [Hardcoded secrets](#hardcoded-secrets) |
| `auth-bypass` (JWT) | [JWT](#jwt) |
| `open-redirect` | [Open redirect](#open-redirect) |
| `sqli`/`xss`/`ssti`/`ssrf`/`cmdi`/`injection` | [Injection](#injection) |
| `transport`, `tls` | [HTTPS and TLS](#https-and-tls) |
| `cookie` | [Insecure cookies](#insecure-cookies) |
| `disclosure`, `info-leak` | [Information disclosure](#information-disclosure) |
| `js-vulnerability`, `cve` | [Vulnerable JS libraries](#vulnerable-js-libraries) |

---

## Security headers

**Findings:** Missing Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS.
**Means:** responses lack headers that mitigate clickjacking, MIME sniffing, and content injection.

**Next.js** (`next.config.js`):
```js
const securityHeaders = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  { key: "Content-Security-Policy", value: "default-src 'self'" },
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
];
module.exports = {
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};
```

**Express** (the `helmet` package):
```js
import helmet from "helmet";
app.use(helmet()); // CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy
```

**Fastify:** `await app.register(import("@fastify/helmet"))`
**Hono:** `import { secureHeaders } from "hono/secure-headers"; app.use("*", secureHeaders())`

**FastAPI** (middleware):
```python
@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    return resp
```

**Verify:** re-scan; the "Missing ... header" findings disappear.

---

## Authentication

**Findings:** Unauthenticated endpoint, Client-side-only authentication, Login accepts arbitrary credentials.
**Means:** sensitive routes are reachable without server-side auth, or auth is only enforced in the browser (which is not security).

**Next.js** (`middleware.ts` plus per-route verification):
```ts
import { NextResponse } from "next/server";
export function middleware(req) {
  // verifySession: your auth library's check on the request
  if (!verifySession(req)) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
}
export const config = { matcher: ["/api/:path*"] };
```

**Express:**
```js
function requireAuth(req, res, next) {
  // verifySession: your auth library's check on the request
  if (!verifySession(req)) return res.status(401).json({ error: "Unauthorized" });
  next();
}
app.use("/api/admin", requireAuth);
```

**FastAPI:**
```python
from fastapi import Depends, HTTPException
def require_auth(user = Depends(current_user)):  # your auth library's dependency
    if user is None: raise HTTPException(status_code=401)

@app.get("/api/admin", dependencies=[Depends(require_auth)])
def admin(): ...
```

**Verify:** re-scan; the route returns 401 when not signed in and the "Unauthenticated endpoint" finding clears.

---

## Exposed API docs

**Findings:** FastAPI/Swagger UI exposed, OpenAPI specification exposed.
**Fix:** disable interactive docs and the spec in production.

**FastAPI:** `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)` in production (gate by an env flag).
**Express + swagger-ui:** mount it only outside production (check your app's environment setting).

**Verify:** `/docs` and `/openapi.json` return 404 in production.

---

## CORS

**Finding:** the server reflects an arbitrary `Origin`, or uses `*` together with credentials.
**Fix:** allowlist explicit origins; never reflect a user-supplied origin with credentials.

**Express** (the `cors` package):
```js
import cors from "cors";
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
```

**FastAPI:**
```python
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True)
```

**Next.js / Hono:** set `Access-Control-Allow-Origin` to a fixed allowlist value, not the request `Origin`.

**Verify:** re-scan; the CORS finding clears once only allowlisted origins are reflected.

---

## Rate limiting

**Finding:** No login rate limiting detected.
**Fix:** throttle auth and other expensive endpoints.

**Express** (the `express-rate-limit` package):
```js
import rateLimit from "express-rate-limit";
app.use("/api/login", rateLimit({ windowMs: 15 * 60 * 1000, max: 10 }));
```

**Fastify:** `@fastify/rate-limit`. **Next.js:** an edge limiter such as `@upstash/ratelimit` in `middleware.ts`.
**FastAPI:** the `slowapi` package with `@limiter.limit("10/15minutes")`.

**Verify:** re-scan; rapid repeated requests are throttled (HTTP 429).

---

## Hardcoded secrets

**Finding:** an API key, token, password, or private key is committed in the repo.
**Fix (do all three):**
1. Take the value out of the code and load it from configuration that stays out of the repo, such as an environment variable your host sets. The code then names the setting (say, `STRIPE_KEY`), never the value.
2. **Rotate the secret now**, once committed it is compromised, even after removal.
3. Add the file to `.gitignore`; if it was pushed, scrub history (`git filter-repo`).

**Verify:** re-scan the repo (`penthera --repo .`); the secret finding clears. Confirm the old secret is revoked.

---

## JWT

**Findings:** JWT alg:none bypass accepted, Configured JWT is expired.
**Fix:** pin the signing algorithm and verify expiry on every request.
```js
jwt.verify(token, publicKey, { algorithms: ["RS256"] }); // never accept "none"
```

**Verify:** re-scan; the alg:none and expiry findings clear.

---

## Open redirect

**Finding:** OAuth open redirect, `redirect_uri` (or a `return`/`next` param) reflects an arbitrary URL.
**Fix:** validate against an allowlist of exact registered URIs; never redirect to a raw user-supplied URL.
```js
const ALLOWED = new Set(["https://app.example.com/callback"]);
if (!ALLOWED.has(redirectUri)) return res.status(400).send("Invalid redirect_uri");
```

**Verify:** re-scan; the open-redirect finding clears.

---

## Injection

**Findings:** SQL error leaked, OS command injection, XSS, SSTI, SSRF.

- **SQLi:** use parameterized queries; never concatenate input. `db.query("SELECT * FROM users WHERE id = $1", [id])`.
- **XSS:** rely on framework auto-escaping; set a CSP; avoid `dangerouslySetInnerHTML`/`v-html`/`|safe` with user input.
- **Command injection:** never pass input to a shell. Use `execFile(cmd, [args])` with an allowlist; avoid `exec`/`shell=True`.
- **SSRF:** allowlist outbound hosts; block internal ranges and metadata endpoints (`169.254.169.254`, `127.0.0.0/8`, `10.0.0.0/8`).
- **SSTI:** never render user input as a template; use sandboxed templating with autoescaping.

**Verify:** re-scan with `--deep`; the injection probe no longer triggers.

---

## HTTPS and TLS

**Findings:** No HTTPS (cleartext), TLS certificate expired / expiring / not trusted.
**Fix:** serve over HTTPS, redirect HTTP -> HTTPS, add HSTS, and renew/replace the certificate (e.g. Let's Encrypt). For "not trusted", fix the certificate chain (include intermediates).

**Verify:** re-scan; the transport/TLS findings clear.

---

## Insecure cookies

**Finding:** a session cookie is missing `Secure`, `HttpOnly`, or `SameSite`.
**Fix:**
```js
res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "lax" });
```
**Next.js:** `cookies().set("session", token, { httpOnly: true, secure: true, sameSite: "lax" })`.

**Verify:** re-scan; the cookie finding clears.

---

## Information disclosure

**Findings:** Server version disclosed, stack traces or framework errors leaked.
**Fix:** remove the `Server`/`X-Powered-By` headers (`app.disable("x-powered-by")` in Express) and return generic errors in production (no stack traces, no raw SQL errors).

**Verify:** re-scan; the disclosure finding clears.

---

## Vulnerable JS libraries

**Finding:** a front-end JavaScript library has known CVEs (detected via Retire.js).
**Fix:** upgrade the library to a patched version (bump it in `package.json`, `npm update <pkg>`), or replace it. Re-run `npm audit`.

**Verify:** re-scan; once the patched version is served, the JS CVE finding clears.

---

For building secure-by-default so these never appear, see [secure-defaults.md](secure-defaults.md).
