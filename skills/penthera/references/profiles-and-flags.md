# Profiles and scan flags

## Profiles

| Profile | Flag | Duration | What runs |
|---------|------|----------|-----------|
| **quick** | `--profile quick` | ~10s | Headers, OpenAPI, auth smoke tests; skips Retire.js and param discovery |
| **standard** | `--profile standard` | default | Full non-destructive scan: TLS, fingerprint, discovery, templates, CORS, cookies, Retire.js, param discovery, OpenAPI/auth |
| **deep** | `--profile deep` | longest | recon + injection probes + API fuzzing (requires authorization confirmation) |

## Individual mode flags

Override or extend profile defaults:

| Flag | Effect |
|------|--------|
| `--recon` | OSINT recon (subdomains, historical URLs) |
| `--deep` | Injection probes (SQLi, SSTI, SSRF, XSS, CMDi) — sends attack payloads |
| `--fuzz` | Property-based API fuzzing |
| `--nuclei <path>` | Community Nuclei YAML templates |
| `--all` | Enable recon + deep + fuzz |
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
| `--auth-cookie <value>` | Cookie header for authenticated scans |
| `--auth-bearer <value>` | Bearer token for authenticated scans |
| `--json` | JSON to stdout |
| `--timeout <ms>` | Request timeout (default: 10000) |
| `--concurrency <n>` | Concurrent requests (default: 15) |
| `-v, --verbose` | Detailed output |
| `-q, --quiet` | Findings only |

## Auth environment variables

| Variable | Maps to |
|----------|---------|
| `PENTHERA_COOKIE` | Cookie header |
| `PENTHERA_BEARER` | Authorization Bearer token |

## URL scan coverage (black-box)

TLS, fingerprinting, endpoint discovery, built-in templates, CORS, cookies, Retire.js (JS CVEs), param discovery, OpenAPI/FastAPI probes, security headers, auth hardening, JWT probes.

## Repo scan coverage (white-box)

Next.js API route discovery, trust-boundary mapping, risky code patterns, hardcoded secrets (keys, tokens, private keys). Expanded route discovery in `routes/`, `api/`, `server/routes/`.

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
