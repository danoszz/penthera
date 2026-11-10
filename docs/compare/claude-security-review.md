---
title: "Penthera and Claude Code Security Review"
sidebarTitle: "vs Claude Code Security Review"
description: "How Anthropic's model-based PR review and Penthera's rules fit together, and a workflow that runs both."
---

> **Pro.** For "should I run Penthera, Anthropic's security review action, or both?"

*Last checked: 2026-11-10 against the action's README, prompts and `action.yml` at commit `0c6a49f`.*

## Use them together

[Claude Code Security Review](https://github.com/anthropics/claude-code-security-review)
is a GitHub Action (MIT) from Anthropic. Claude reads a pull request's diff,
reports the problems it is confident about, filters out likely noise in a
second pass, and comments on the changed lines. It needs an API key, and the
model decides what counts as a finding.

Its own audit prompt leaves some ground to other tools on purpose. It tells the
model to skip secrets stored on disk ("these are handled by other processes"),
denial of service, and rate limiting, and its filter skips outdated
third-party libraries. Penthera's rules cover the first and the last, plus the
parts no diff review sees: the lockfile, the agent config and the running app.

A reasonable setup: the Claude review on pull requests from your own team, for
logic and authorization bugs no rule describes. Penthera on every pull request,
forks included, for what a rule can prove.

## Side by side

| | Penthera | Claude Code Security Review |
|---|---|---|
| Who decides | Deterministic rules; a model may only propose | The model, with a confidence score and a model-based noise filter |
| What it reads | The repo, the dependencies, the agent config, and a URL if you give one | The PR diff, with the repository for context |
| Secrets and outdated packages | Yes: the secret scan and `penthera deps` | Left to other tools by its prompt and filter |
| Logic and authorization bugs | Only the patterns its rules describe | Yes: its main strength |
| Untrusted PRs (forks) | Safe: nothing goes to a model, and a PR's text can't steer a rule | Its README: "not hardened against prompt injection", for trusted PRs only |
| Comments on changed lines | One summary comment and SARIF in code scanning | Yes, review comments on the lines |
| Network and cost | None needed; free, MIT | The Anthropic API; you pay per review |

## Where the Claude review goes further

- **Bugs no rule names:** broken authorization logic, a privilege check in the
  wrong place, data that leaks through an API response.
- **Any language,** with the repository as context.
- **Line comments** written for the person who opened the PR.

## Where Penthera adds something

- **What its prompt leaves out:** committed secrets and known-vulnerable or
  risky dependencies.
- **Outside the diff:** install scripts, MCP servers and hooks, and the live app.
- **Fork PRs,** which the Claude review should not see.
- **The same answer every run,** and a rule id for every finding that you can
  read and argue with.

## Run both

The Claude review only on PRs from branches in your own repository, Penthera
on every PR. Pin both actions to a commit SHA, not a branch or tag.

```yaml
name: security
on: pull_request
permissions:
  contents: read
jobs:
  penthera:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: "Penthera: your open-source cyber security agent"
        uses: danoszz/penthera@9b67e8dce0267e587deb5ccebd5ffa7a15235806 # v2.4.0
        with:
          mode: deps
          fail-on: high
  claude-review:
    # Trusted PRs only: the review is not hardened against prompt injection.
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          fetch-depth: 2
      - uses: anthropics/claude-code-security-review@0c6a49f1fa56a1d472575da86a94dbc1edb78eda # main, 11 Feb 2026
        with:
          comment-pr: true
          claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
```

Locally, before you push:

```bash
npx penthera@2.4.0 --repo .
```

Then ask Claude Code for `/security-review` on the same change.

[All comparisons](https://github.com/danoszz/penthera/blob/main/docs/compare/README.md) · [Back to the README](https://github.com/danoszz/penthera/blob/main/README.md)
