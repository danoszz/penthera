---
title: "Penthera and GitHub (Dependabot and code scanning)"
sidebarTitle: "vs GitHub"
description: "What Dependabot and GitHub code scanning cover, what Penthera adds, and when to use both."
---

> **Pro.** For "how does Penthera compare to Dependabot and code scanning, and how do I run both?"

*Last checked: 2026-10-19 against GitHub's docs and security plans page.*

## Use them together

If your code is on GitHub, you probably have Dependabot already. It alerts you
when a dependency has a known, reviewed vulnerability and opens a pull request
to the patched version. Code scanning with CodeQL finds bugs in your own code.
Penthera covers what those do not look at: what a package can do when it has no
advisory yet, the running app, and your AI tooling. Its SARIF output uploads
into the same code scanning tab, so findings sit in one place.

## Side by side

| | Penthera | Dependabot and code scanning |
|---|---|---|
| Dependencies | Capabilities and the upgrade diff, typosquats, licenses; npm and Python | Alerts from GitHub-reviewed advisories in the GitHub Advisory Database ([alerts](https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts)); security and version update PRs |
| Pull requests | Action that comments the capability diff | Dependency review action that can block a vulnerable change ([dependency review](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-dependency-review)) |
| Your code | Routes, trust boundaries, secrets (JS/TS frameworks) | CodeQL queries across many languages |
| Secrets | Repo scan and a pre-commit hook on staged files | Secret scanning and push protection ([features](https://docs.github.com/en/code-security/getting-started/github-security-features)) |
| Running app | URL scan | No |
| AI tooling | `penthera agents` | No dedicated check |
| Where it runs | Your machine or any CI, offline | GitHub; the CodeQL CLI also runs locally ([CodeQL CLI](https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/about-the-codeql-cli)) |
| Cost | Free | Dependabot is free on all plans. Code scanning, dependency review and secret scanning are free on public repos; private repos need GitHub Code Security ($30) or Secret Protection ($19) per active committer a month ([plans](https://github.com/security/plans)) |

## Where GitHub goes further

- **Known-vulnerability coverage** across ecosystems, with update pull requests
  generated for you. Penthera never opens pull requests.
- **CodeQL** is a far deeper code analyzer than Penthera's repo scan.
- **Push protection** stops secrets on the server side, for every contributor,
  without anyone installing a hook.
- **Zero setup** for public repositories.

## Where Penthera adds something

- **Before an advisory exists.** Dependabot needs a reviewed advisory. Penthera's
  capability diff shows a new install script or network call on the day it
  appears.
- **The live app and your agent setup**, which GitHub's tools do not scan.
- **Private repos without a GitHub Advanced Security license**, and code that is
  not on GitHub.

## Run both

Keep Dependabot and code scanning on. Add Penthera's action for the capability
diff ([docs/commands/action.md](../commands/action.md)) and upload its SARIF:

```yaml
- run: npx penthera@2.1.2 "$PREVIEW_URL" --sarif reports/scan.sarif
- uses: github/codeql-action/upload-sarif@6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee # v4.39.0
  with:
    sarif_file: reports/scan.sarif
```

Uploading SARIF to code scanning in a private repository also needs GitHub Code
Security.

[All comparisons](https://github.com/danoszz/penthera/blob/main/docs/compare/README.md) · [Back to the README](https://github.com/danoszz/penthera/blob/main/README.md)
