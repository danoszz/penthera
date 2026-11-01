---
title: "Evidence bundles and audience reports"
sidebarTitle: "Evidence bundles"
description: "Penthera can write the results of one scan as an evidence bundle: every report, a manifest with the SHA-256 of each file, and an optional SSH signature over the manifest."
---

> **Pro.** For "what do I give my auditor?"

Penthera can write the results of one scan as an **evidence bundle**: every
report, a manifest with the SHA-256 of each file, and an optional SSH
signature over the manifest. An auditor checks the bundle with one command.
No hosted service is involved. The auditor needs only Node (or `shasum` and
`jq`) and OpenSSH 8.0 or later.

## Start here: one run for NIS2 and the CRA

NIS2 puts a duty of care on in-scope organizations, written into national law
(the Cyberbeveiligingswet in the Netherlands, the NIS2-wet in Belgium). The
Cyber Resilience Act adds reporting duties for manufacturers, with deadlines
measured in hours. A small company has to show that it tests, fixes and
records, without a compliance team.

```bash
penthera --assessment-init assessment.json          # once: the organisational measures a scanner cannot test
penthera https://staging.example.com --repo . \
  --framework nis2 --readiness --assessment assessment.json \
  --sbom sbom.cdx.json --evidence evidence/2026-10-19 --sign-key ~/.ssh/id_ed25519
```

That run writes the scan, an Article 21(2) coverage table, a readiness report
with every measure marked met, partial, gap or not applicable, a CycloneDX SBOM,
and a hashed, SSH-signed evidence bundle. Around it:

```bash
penthera --policy-pack ./policies --org "Your Company" --readiness --assessment assessment.json
penthera https://example.com --readiness --assessment assessment.json --questionnaire questions.txt
penthera --cra-init cra.json && penthera --cra cra.json   # CRA Article 14 timeline and drafts
penthera --repo . --aibom aibom.cdx.json                  # CycloneDX 1.6 AI-BOM
```

The questionnaire helper answers each question from your scan and
self-assessment, cites the evidence, and marks anything it cannot map as
`NEEDS HUMAN INPUT` instead of guessing. The details are in the
[NIS2](compliance-nis2.md) and [CRA and AI-BOM](compliance-cra.md) guides.

What it does not do:

- It is readiness tooling, not a certification and not legal advice. Whether you
  are in scope, and what is proportionate for you, is for you and your advisors
  to decide.
- It covers the technical, testable part of the duty of care. Policies,
  training, backups and MFA come from your self-assessment. Penthera records
  what you attest. It cannot check it.
- It does not file anything. Reports to a CSIRT or ENISA are drafts for you to
  review and submit.
- Jurisdiction details ship for the Netherlands only.

## For auditors: verify a bundle

You need the bundle directory and an **allowed signers file** that names the
key you expect the bundle to be signed with. Get that public key from the
organization through a channel other than the bundle itself (their security
page, an email you can authenticate, or in person).

```bash
npx penthera evidence verify ./evidence --allowed-signers allowed_signers --require-signature
```

Exit code `0` means every file matches the manifest and the manifest was signed
by a key in `allowed_signers`. Exit code `1` means something changed, is
missing, was added, or the signature does not check out. The output says which.

An `allowed_signers` file is one line per key:

```text
security@example.com namespaces="penthera-evidence" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
```

### Without Penthera

The bundle does not depend on Penthera to be checked. With standard tools:

```bash
cd evidence
# 1. The manifest was signed by the expected key (namespace penthera-evidence)
ssh-keygen -Y verify -f ../allowed_signers -I security@example.com \
  -n penthera-evidence -s manifest.json.sig < manifest.json
# 2. Every artifact matches its hash in the manifest
jq -r '.artifacts[] | "\(.sha256)  \(.path)"' manifest.json | shasum -a 256 -c -
# 3. Nothing else is in the directory
ls
```

`penthera evidence verify` does the same three checks, and also rejects
manifest paths that would leave the directory (`../`, absolute paths) and
symlinked files.

### What the checks prove, and what they do not

- **Hashes** prove that the files have not changed since the manifest was
  written. Without a signature they prove nothing about who wrote it: anyone
  can rewrite a file and its hash together.
- **The signature** proves that the holder of the signing key produced this
  manifest. It does not prove that the scan was run against the system you
  care about, or with the options you expect. Read the manifest's `command`,
  `target`, `scan` and `git` fields, and the auditor report's scope section.
- A signed bundle verifies only with `--allowed-signers`. Without it,
  `verify` cannot tell whose key made the signature (anyone can re-sign a
  rewritten manifest with their own key), so it fails with status
  `unverified`. A manifest that declares a signature with no `.sig` file
  fails too.
- An unsigned bundle passes with an `UNSIGNED` warning. Pass
  `--require-signature` (with `--allowed-signers`) to make it fail.
- A scan is a snapshot. The bundle is evidence of what Penthera saw at
  `generated_at`, not a statement that the system is secure.

## For the team producing evidence

```bash
penthera https://staging.example.com --repo . --framework nis2 \
  --evidence evidence/2026-10-19 --sign-key ~/.ssh/id_ed25519
```

- `--evidence <dir>` writes the bundle. The directory must be new or empty, so
  a bundle never mixes two runs.
- `--sign-key <key>` signs `manifest.json` with
  `ssh-keygen -Y sign -n penthera-evidence`. Use the private key path, or the
  `.pub` path when the key lives in `ssh-agent` or on a hardware token. A
  passphrase prompt appears in the terminal.
- `--sbom <file>` and `--readiness` add their outputs to the bundle.
- Give auditors the public key out of band, as an `allowed_signers` line.

### What is in a bundle

| File | Contents |
|------|----------|
| `report.json` | The full scan result |
| `report.md` | The default Markdown report |
| `report.sarif` | SARIF 2.1.0 |
| `report-developer.md` | Findings with file:line, fix recipe ids or diffs, and sources |
| `report-owner.md` | Plain-language summary, what to do first, owner actions, trend |
| `report-auditor.md` | Scope and method, confidence and provenance, egress, inconclusive probes, suppressions, fix timeline, NIS2 and OWASP mapping |
| `report-custom.md` | Your `--report-template` output, when given |
| `nis2-readiness.md` | With `--readiness` |
| `sbom.cdx.json` | CycloneDX SBOM, with `--sbom` |
| `report-agent.md` | The agent brief |
| `README.md` | What is in the bundle and how to check it |
| `giants/` | Other tools' raw output, with `--giants` |
| `manifest.json` | Tool version, command line (secrets redacted), timestamp, target, git commit, SHA-256 and size of every file above |
| `manifest.json.sig` | SSH signature over `manifest.json`, with `--sign-key` |

The command line in the manifest has the values of `--auth-cookie`,
`--auth-bearer` and any token, secret or password flag replaced with
`[REDACTED]`, and credentials in URLs masked.

## Audience reports

`--audience developer|owner|auditor|agent` picks who the Markdown report is for. It
applies to `--markdown <file>`. Without `--markdown`, the report goes to stdout.
The default report (no `--audience`) is unchanged.

```bash
penthera https://example.com --repo . --audience owner > for-the-owner.md
penthera https://example.com --repo . --audience auditor --markdown audit.md
```

When a scan used `--memory`, the owner report shows the trend across recent
scans. When the result has an agent loop run (`loopRun`) or memory has fix
events, the developer, owner and auditor reports show a fix timeline
(found, fixed, verified) with the time to fix.

## Your own template

`--report-template file.md` renders your own Markdown from the same data the
audience reports use. The template language is small on purpose:

```markdown
# Security status for {{summary.target}}

{{summary.critical}} critical, {{summary.high}} high ({{summary.total}} total).

{{#each findings}}
- [{{severity}}] {{title}}{{#if location}} at {{location}}{{/if}} ({{confidence}})
{{/each}}

{{#if suppressed}}
Set aside: {{#each suppressed}}{{title}} by {{actor}}: {{reason}}; {{/each}}
{{else}}
Nothing suppressed.
{{/if}}
```

- `{{path.to.value}}` prints a value. Values are HTML- and Markdown-escaped,
  and newlines become spaces, so a finding title cannot add HTML, a heading, a
  list item or a table cell.
- `{{#each list}}…{{/each}}` loops; inside, `{{this}}` is the item and
  `{{@index}}` its 0-based index. Names not found on the item are looked up in
  the enclosing scope.
- `{{#if value}}…{{else}}…{{/if}}` branches. An empty list counts as false.

There are no helpers, no expressions, no raw output, no partials and no file
includes. Paths containing `__proto__`, `constructor` or `prototype` are
rejected, and only own properties are read. A template that uses anything else
fails with a line number before the scan starts.

Top-level fields: `tool`, `target`, `timestamp`, `duration`, `modes`,
`profile`, `offline`, `probes`, `summary` (`critical`, `high`, `medium`,
`low`, `info`, `serious`, `total`, `suppressed`, `inconclusive`), `findings`
(`fid`, `title`, `severity`, `confidence`, `source`, `method`, `collectedAt`,
`category`, `location`, `file`, `line`, `url`, `description`, `recipe`,
`fixText`, `sources`, `owasp`, `wstg`), `suppressed` (`title`, `severity`,
`reason`, `actor`, `by`, `expires`), `inconclusive`, `egress`, `actions`,
`topActions`, `ownerActions`, `nis2`, `owasp`, `trend` and `timeline`. The
model is built in [`src/report/model.js`](https://github.com/danoszz/penthera/blob/main/src/report/model.js).
