# Output formats and CI integration

## Output formats

| Format | Flag | Use |
|--------|------|-----|
| Terminal | *(default)* | Colored summary in the shell |
| **Markdown** | `--markdown file.md` or `-o file.json` | Human-readable report with executive summary, findings tables, recommended actions — companion `.md` written automatically when using `-o` with `.json` |
| JSON | `--json` or `-o file.json` | CI pipelines, baseline diffs, custom tooling |
| SARIF | `--sarif file.sarif` | GitHub Security / Code Scanning |

```bash
penthera https://myapp.com -o reports/scan.json
# → reports/scan.json  (machine-readable)
# → reports/scan.md    (human-readable)
```

Reports should go in `reports/` (gitignored). Do not write scan artifacts into `skills/penthera/`.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No critical or high findings |
| `1` | Critical or high findings detected |
| `2` | Scan failed (unreachable target, bad config) |

Use exit codes in CI to fail builds on severe findings:

```yaml
- run: node bin/penthera.js "$PENTEST_URL" --profile standard -o reports/scan.json
# Exit 1 fails the step when critical/high findings exist
```

## Baseline diff

Compare current scan against a previous JSON report:

```bash
penthera https://myapp.com -o reports/scan.json --baseline reports/previous.json
```

Output includes: new findings count, resolved count, unchanged count. Use for weekly regression checks.

## GitHub Actions

**Penthera CI** (`.github/workflows/ci.yml`) runs on every push:

1. Unit + mock server tests
2. Skill preflight check
3. Scan against the local mock API → JSON + SARIF
4. `validate-report.mjs` on the JSON output
5. SARIF upload to GitHub Security tab

For **your staging URL**, copy `.github/workflows/scan.example.yml` to `scan.yml`:

```yaml
name: Security Scan

on:
  workflow_dispatch:
  schedule:
    - cron: "0 6 * * 1"

jobs:
  penthera:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm

      - run: npm ci

      - name: Scan staging URL
        env:
          PENTEST_URL: ${{ secrets.PENTEST_STAGING_URL }}
        run: |
          node bin/penthera.js "$PENTEST_URL" \
            --profile standard \
            -o reports/scan.json \
            --sarif reports/scan.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/scan.sarif

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: penthera-reports
          path: reports/
```

Store `PENTEST_STAGING_URL` as a repository secret.

## Agent reporting workflow

After a scan:

1. Read `reports/scan.md` (or path from `-o` / `--markdown`).
2. Summarize by severity: critical → high → medium → low → info.
3. For each critical/high finding, suggest a concrete fix.
4. Mention exit code and whether CI would fail.
5. If baseline was used, highlight **new** findings only.
