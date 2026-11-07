# Output formats and CI integration

## Output formats

| Format | Flag | Use |
|--------|------|-----|
| Terminal | *(default in a terminal or CI)* | Colored summary in the shell |
| Agent brief | `--brief`, or the default with no terminal outside CI | Short fixed-shape summary for an AI assistant |
| **Markdown** | `--markdown file.md` or `-o file.json` | Human-readable report with executive summary, findings tables, recommended actions, companion `.md` written automatically when using `-o` with `.json` |
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
| `0` | No critical or high rule fired. This run does not prove login, access rules or payments are right |
| `1` | Critical or high findings detected (other tools' too, with `--giants`) |
| `2` | Scan failed (unreachable target, missing path, bad config, a tool the policy requires did not run) |

A firewall's refusal isn't a failed scan: the verdict is `Site not read`, and the exit code follows what Penthera could still read, so it can be 0. In a GitHub Action, the gate step prints a warning for this. Don't treat a green job as a check of that site.

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

**Penthera's own CI** (`.github/workflows/ci.yml`) runs on every push and PR:

1. The full test suite (`npm test`) on Node 22 and 24
2. A scan of the deliberately vulnerable mock API, producing JSON + SARIF
3. `validate-report.mjs` on the JSON output, plus the skill preflight

The mock-server SARIF is kept as a build artifact, not uploaded to code scanning,
because those findings are about the test fixture, not the repo.

**For your own staging URL**, copy
[`docs/examples/github-actions-scan.yml`](https://github.com/danoszz/penthera/blob/main/docs/examples/github-actions-scan.yml)
into your app's repo as `.github/workflows/penthera.yml` and add a
`PENTEST_STAGING_URL` repository setting. It runs `npx penthera@<version>` on a
weekly schedule and uploads SARIF to your Security tab. Pin the version so a
scheduled run never picks up code you have not reviewed.

## Agent reporting workflow

After a scan, reply with the agent brief in its order. Put your own view under **My read**. The full list is in `reports/scan.md` (or the path from `-o` / `--markdown`). Mention the exit code and whether CI would fail. To list new findings only, rerun with `--baseline <file> -q`; that also narrows the exit code.
