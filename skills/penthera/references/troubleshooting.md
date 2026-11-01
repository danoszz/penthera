# Troubleshooting

## Exit code 2, scan failed

**Symptoms:** CLI exits with code 2, "Target unreachable" or "Scan failed"

**Causes and fixes:**

| Error | Cause | Solution |
|-------|-------|----------|
| Target unreachable | Server down, wrong URL, firewall | Verify URL in browser; check server is running |
| `No target` | Missing URL and `--repo` | Provide a URL, `--repo <path>` or a command |
| `--repo` path not found | The path does not exist | Check the path |
| Unknown profile | Invalid `--profile` value | Use `quick`, `standard`, or `deep` |
| Scan failed (exception) | Network timeout, parse error | Retry with `--verbose`; increase `--timeout` |

```bash
penthera https://myapp.com --verbose --timeout 30000
```

## Node.js not found or wrong version

**Symptoms:** `node: command not found` or engine error

**Solution:** Install Node.js 22+ from [nodejs.org](https://nodejs.org/). Verify:

```bash
node -v   # should be v22.x or higher
```

## Penthera CLI not found

**Symptoms:** `penthera: command not found`

**Solutions:**

```bash
# From repo root (always works)
node bin/penthera.js --version

# Global install
cd /path/to/penthera && npm link
penthera --version
```

## Auth failures / empty authenticated findings

**Symptoms:** Scan completes but misses protected endpoints

**Causes:** Expired token, wrong cookie format, missing Bearer prefix

**Solutions:**

```bash
# Bearer, prefix added automatically if missing
penthera https://myapp.com --auth-bearer "eyJ..."

# Or via env
export PENTHERA_BEARER="eyJ..."
penthera https://myapp.com -o reports/scan.json

# Cookie, full header value
penthera https://myapp.com --auth-cookie "session=abc123; path=/"
```

## Site not read

**Symptoms:** Verdict `Site not read`, no grade, often exit 0

**Expected:** A firewall answered, so nothing about the site was checked. Do not retry to get past it, and do not change the User-Agent to do so. Scan a local or staging copy, or ask the site's owner to allowlist the scanner.

## A package "could not be scanned"

**Symptoms:** `deps` reports a high finding and exits 1

**Expected:** The package has a file Penthera can't read in full. Treat it as unreviewed, not clean. Check it by hand or replace it.

## Active scan refused

**Symptoms:** Exit 2 with `Active modes (...)` or a hostname mismatch

**Expected:** Active modes ask first. In a script or agent, pass `--confirm-target <host>` after the user confirms that exact host.

## Baseline file not found

**Symptoms:** Error reading baseline JSON

**Solution:** Ensure previous scan exists:

```bash
ls reports/previous.json
# Or run initial scan first:
penthera https://myapp.com -o reports/previous.json
```

## SARIF upload fails in CI

**Symptoms:** GitHub Actions SARIF upload error

**Checks:**
- `reports/scan.sarif` was generated (`--sarif` flag used)
- the `github/codeql-action/upload-sarif` step has `if: always()`
- Repository has code scanning enabled

## Preflight script failures

Run manually for diagnostics, from the project folder (the script is in this skill's folder):

```bash
bash <this skill's folder>/scripts/preflight.sh https://myapp.com
```

Fix each reported check before scanning.
