# Profiles and scan flags

## Profiles

| Profile | Flag | Duration | What runs |
|---------|------|----------|-----------|
| **quick** | `--profile quick` | ~10s | Headers, OpenAPI, auth checks with no login POSTs; skips Retire.js and param discovery |
| **standard** | `--profile standard` | default | Full non-destructive scan: TLS, fingerprint, discovery, templates, CORS, cookies, Retire.js, param discovery, OpenAPI/auth (one `POST /api/login` with invalid credentials; no attack payloads) |
| **deep** | `--profile deep` | longest | recon + injection probes + API fuzzing + a login rate-limit burst and SQL error check (requires authorization confirmation) |

## Individual mode flags

Override or extend profile defaults:

| Flag | Effect |
|------|--------|
| `--recon` | OSINT recon (subdomains, historical URLs) |
| `--deep` | Injection probes (SQLi, SSTI, SSRF, XSS, CMDi), sends attack payloads |
| `--fuzz` | Property-based API fuzzing |
| `--nuclei <path>` | Community Nuclei YAML templates |
| `--adaptive` | Adaptive probes on discovered routes; may send unexpected methods, including `DELETE` |
| `--all` | Enable recon + deep + fuzz |
| `--confirm-target <host>` | Confirms an active scan (`--deep`, `--fuzz`, `--adaptive`, `--all`, `--profile deep`) of this hostname without a prompt. Required when there is no terminal; must match the target |
| `--rate <n>` | Max requests per second (default: no limit; 10 for active scans; `0` removes it) |
| `--machine` | macOS machine audit (keyloggers, trojans, rootkits) |

## Common options

| Flag | Description |
|------|-------------|
| `-r, --repo <path>` | Local repo for white-box analysis |
| `--api-root <path>` | API routes directory (default: auto-detect) |
| `-o, --output <file>` | JSON report (+ companion `.md` if `.json`) |
| `--markdown <file>` | Explicit Markdown report path |
| `--sarif <file>` | SARIF for GitHub Security tab |
| `--baseline <file>` | Compare against previous JSON report |
| `--json` | JSON to stdout |
| `--timeout <ms>` | Request timeout (default: 10000) |
| `--concurrency <n>` | Concurrent requests (default: 15) |
| `-v, --verbose` | Detailed output |
| `-q, --quiet` | Findings only. In a pipe outside CI the brief prints instead; add `PENTHERA_BRIEF=0` |
| `--brief` | The short agent brief, the default with no terminal outside CI |
| `--offline` | No third-party requests and no DNS lookups for email checks |
| `--giants` | Also run the free scanners installed here and merge their findings |
| `--templates <dir>` | Load extra YAML templates |
| `--rules <dir>` | Add a signed rule pack (repeatable) |

## URL scan coverage (black-box)

TLS, fingerprinting, endpoint discovery, built-in templates, CORS, cookies, Retire.js (JS CVEs), param discovery, OpenAPI/FastAPI probes, security headers, auth hardening, JWT probes, provider keys in same-site scripts.

## Repo scan coverage (white-box)

API route discovery (Next.js, Express, Hono, Fastify), trust-boundary mapping, code-execution sinks, hardcoded secrets (keys, tokens, private keys), runtime version pins, library mode for packages. Expanded route discovery in `routes/`, `api/`, `server/routes/`.

## Examples

```bash
# Safe default
penthera https://myapp.com --profile standard

# Fast smoke test
penthera http://localhost:3000 --profile quick -o reports/scan.json

# Maximum coverage (confirm authorization first)
penthera https://staging.myapp.com --profile deep -o reports/scan.json

# Repo secrets only
penthera --repo . -o reports/repo-scan.json

# Combined with Nuclei templates
penthera https://myapp.com --nuclei ~/nuclei-templates/http -o reports/scan.json
```
