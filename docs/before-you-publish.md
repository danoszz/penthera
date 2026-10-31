---
title: "Before you publish an app an AI built"
sidebarTitle: "Before you publish"
description: "Your app builder may already scan before publish. Penthera is a second check that runs on your own machine, so your code and secrets stay in your control."
---

> **Starter.** For "an AI tool built my app. What should I check before I
> publish it?"

Many app builders and hosts already scan your app before it goes live. Use
that scan. Penthera does not replace it, and we don't claim it finds more.
It is a second check that runs on your own machine or in your own CI. Your
code and secrets are not sent anywhere to be checked.

That matters more as more of an app is written by tools you can't see inside.
A second, independent check is a safeguard you control.

## What your builder already checks

Each row comes from the builder's own docs, read on 28 October 2026. Builders
change these often; if a link says something else, the link wins.

| Builder | What it checks before publish | Does it stop a publish? |
|---|---|---|
| [Base44](https://docs.base44.com/Setting-up-your-app/running-a-security-scan) | You run the scan yourself: data permissions, exposed secrets, backend functions open without sign-in, vulnerable dependencies, missing security headers. Code vulnerabilities on the Builder plan and up | No. The publish panel warns but does not stop you |
| [Lovable](https://docs.lovable.dev/features/security) | A quick scan runs when you open the publish dialog: database access rules, critical dependency issues, MCP servers open without sign-in. Secrets are in the deep scan, which you start yourself | Only if a workspace admin turns on "Block publishing with critical issues" |
| [Replit](https://docs.replit.com/updates/2025/09/26/changelog) | An optional scan for malicious files and security vulnerabilities before you deploy | Enterprise admins can require it for every deploy |
| [Netlify](https://docs.netlify.com/manage/security/secret-scanning/) | Smart secret detection scans your repository and build output | Yes. A detected secret fails the build |

## What Penthera adds

- **It runs where your code is.** On your laptop or in your GitHub Actions,
  with no account. A repo scan makes no outside connections; we are
  [measuring that claim](https://github.com/danoszz/penthera/blob/main/docs/research/prereg/E17-offline-and-determinism.md).
- **It checks your AI tooling too.** MCP servers, skills, hooks and pre-approved
  shell commands in the project, with `penthera agents`.
- **The same commit gives the same result.** Written rules decide every
  finding, so you can run it again and compare.
- **You can keep the result.** `--evidence <dir>` writes the reports and a
  manifest with SHA-256 hashes, which `penthera evidence verify` checks later.

What it does not do: it does not log in to your live app, and it finds known
classes of problems, not novel ones. See [Privacy](privacy.md) and
[Methodology](METHODOLOGY.md) for the limits.

## Check before you publish

Get the code onto your machine first. Most builders sync to GitHub; see
[App builders](integrations.md#app-builders-lovable-bolt-base44-replit-v0)
for each one.

```bash
npx penthera@2.1.2 --repo .
```

```bash
npx penthera@2.1.2 agents .
```

`npm audit` lists known vulnerabilities in your npm packages. A default
Penthera run can miss those, so run both.

```bash
npm audit
```

Read the Penthera exit code before you publish:

| Code | Meaning | What to do |
|---|---|---|
| `0` | No critical or high rule fired. This run does not prove login, access rules or payments are right | Read any medium or low findings, then test those three yourself |
| `1` | Critical or high findings | Fix them first, or write down why you accept them |
| `2` | The scan did not run | Fix the setup and run it again |

A critical or high finding counts toward exit `1` wherever it is, also in test
fixtures or build output. The agent brief lists those under Likely noise, says
`Review` and tells you why the run fails. A key in a file git ignores is
reported at low, so it does not fail the run.

Penthera tests login and access rules from outside, with rules for known
problems. It does not log in to your app unless you pass a session with
`--auth-cookie` or `--auth-bearer`, and it has no rule for how your payments
work.

## Make it automatic

- **On every commit:** `penthera hook install` adds a pre-commit hook that
  checks staged files for secrets, agent config and lockfile changes. See
  [hook](commands/hook.md).
- **On every pull request:** add the [GitHub Action](commands/action.md). A
  pull request that the check fails can't be merged, if you make the check
  required in your branch settings.
- **After publishing:** paste the live URL into [penthera.org](https://penthera.org)
  for a passive check of the public page.
