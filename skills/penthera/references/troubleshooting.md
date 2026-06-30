# Troubleshooting

## Exit code 2 — scan failed

**Symptoms:** CLI exits with code 2, "Target unreachable" or "Scan failed"

**Causes and fixes:**

| Error | Cause | Solution |
|-------|-------|----------|
| Target unreachable | Server down, wrong URL, firewall | Verify URL in browser; check server is running |
| No target specified | Missing URL and `--repo` | Provide URL, `--repo <path>`, or `--machine` |
| Unknown profile | Invalid `--profile` value | Use `quick`, `standard`, or `deep` |
| Scan failed (exception) | Network timeout, parse error | Retry with `--verbose`; increase `--timeout` |

```bash
penthera https://myapp.com --verbose --timeout 30000
```

## Node.js not found or wrong version

**Symptoms:** `node: command not found` or engine error

**Solution:** Install Node.js 18+ from [nodejs.org](https://nodejs.org/). Verify:

```bash
node -v   # should be v18.x or higher
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
# Bearer — prefix added automatically if missing
penthera https://myapp.com --auth-bearer "eyJ..."

# Or via env
export PENTHERA_BEARER="eyJ..."
penthera https://myapp.com -o reports/scan.json

# Cookie — full header value
penthera https://myapp.com --auth-cookie "session=abc123; path=/"
```

## Deep/fuzz warnings

**Symptoms:** Yellow WARN about attack payloads

**Expected:** `--deep` always prints a warning. Confirm user authorization before proceeding.

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
- `github/codeql-action/upload-sarif@v3` step has `if: always()`
- Repository has code scanning enabled

## Preflight script failures

Run manually for diagnostics:

```bash
bash skills/penthera/scripts/preflight.sh https://myapp.com
```

Fix each reported check before scanning.
