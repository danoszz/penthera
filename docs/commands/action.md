---
title: "Penthera in CI: the GitHub Action"
sidebarTitle: "GitHub Action"
description: "There are three places to run Penthera on every change: the GitHub Action on pull requests, a scan step in your own workflow, and the pre-commit hook on each developer's machine."
---

> **Pro.** For "how do I put it in CI?"

There are three places to run Penthera on every change: the GitHub Action on
pull requests, a scan step in your own workflow, and the
[pre-commit hook](hook.md) on each developer's machine.

## The GitHub Action

```yaml
- name: "Penthera: your open-source cyber security agent"
  uses: danoszz/penthera@695d035e16fe4129a9e0731f4fc9037b4375a895 # v2.1.2
  with:
    mode: deps        # deps | agents | scan (scan also needs url:)
    fail-on: none     # none | high | critical
```

Pin the action to a release commit SHA, not a tag: a tag can be moved, a
commit cannot. Find the SHA for a release with
`git ls-remote https://github.com/danoszz/penthera refs/tags/v2.1.2`.

The action's name contains a colon, so a `name:` line that holds it needs
quotes. The snippet on the GitHub Marketplace page may print the name without
quotes. YAML then fails with `mapping values are not allowed here`. Add the
quotes, or leave the `name:` line out.

In 2.0.0, `mode: deps` exits before it scans and still reports success. The
fix is in 2.1.0-rc.1 and later ([known issue](init.md)).

On every pull request it posts one comment with the capability diff against
the PR base and edits that same comment on each push. It also uploads SARIF to
code scanning. Penthera runs from the action's own checkout: no npx and no
install of Penthera from npm. One exception: `mode: agents` runs `npm ci` for
its one dependency, `yaml`, when the checkout does not have it. On fork PRs the
token is read-only, so the diff goes to the job summary instead. Inputs: `mode`, `path`, `base-ref`, `url`,
`fail-on`, `comment`, `sarif`, `penthera-version`. Copy the full workflow, with
permissions and a lockfile paths filter, from
[`docs/examples/pr-dependency-review.yml`](https://github.com/danoszz/penthera/blob/main/docs/examples/pr-dependency-review.yml).

What a reviewer sees:

```
  ▲ net-helper 1.0.0 → 1.1.0  + network, whole environment
      node_modules/net-helper/index.js:3  const https = require('https');
      node_modules/net-helper/index.js:5  const body = JSON.stringify(process.env);
```

A patch release that starts reading the whole environment next to a network
call is the shape of most credential-stealing packages. The diff shows it with
`file:line` evidence, whether or not an advisory exists yet
([`penthera deps`](deps.md)).

## The agent config check in one file

[`docs/examples/github-actions-agents.yml`](https://github.com/danoszz/penthera/blob/main/docs/examples/github-actions-agents.yml)
runs `penthera agents` on every pull request and push to `main`, and uploads
SARIF to code scanning. Copy it into `.github/workflows/`, or let
`penthera init` write it when the repo has agent config. The step it runs:

```yaml
- run: npx --yes penthera@2.1.2 agents "$GITHUB_WORKSPACE" --sarif "$RUNNER_TEMP/penthera-agents.sarif"
```

The rules that [`penthera agents`](agents.md#rules-for-auto-run-registries-and-environment)
lists for auto-run, registries and environment shipped in 2.1.0. A 2.0.0 pin
does not have them; they run once you pin 2.1.0 or later.

It is report-only until you uncomment its last step. The difference from the
action: `npx` fetches Penthera from npm on each run, so pin a version you have
reviewed. The step runs from the runner's temp folder, so a pull request's own
`.npmrc` cannot change what `npx` fetches. Fork PRs skip the SARIF upload,
because their token is read-only.

## A scan step in your own workflow

To scan a preview URL and upload SARIF, see
[scan in CI](scan.md#ci-integration) and the example
[`docs/examples/github-actions-scan.yml`](https://github.com/danoszz/penthera/blob/main/docs/examples/github-actions-scan.yml).
Pin the Penthera version, so every run is checked by the same rules, and use
`--baseline` to show only what is new since the last scan. `penthera --repo .`
and `penthera deps` exit 1 on high or critical findings, so either works as a
gate.

## Before you cut a release

For maintainers, locally:

```bash
npx penthera deps --base origin/main   # what changed in the tree since main
npx penthera --repo .                  # secrets, including AI provider keys
npx penthera agents                    # the agent config you ship (CLAUDE.md, .mcp.json, skills/)
npx penthera hook install              # block secrets and risky config at commit time
```

If your project ships agent skills or MCP configuration, `penthera agents` on
your own repo reads what your users' tools will load.

Penthera's own releases are a pattern you can copy: npm provenance through
trusted publishing, each version staged until a maintainer approves it with
2FA, CI actions pinned by SHA, CodeQL on every push, and a public
[OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/danoszz/penthera).
See [`.github/workflows/publish.yml`](https://github.com/danoszz/penthera/blob/main/.github/workflows/publish.yml).

## The same check on every project

For agencies and teams that ship many similar apps, run the same steps on each
project, in CI or before handover:

```bash
npx penthera https://preview.client.example --repo . --profile standard \
  --sarif reports/scan.sarif -o reports/scan.json
npx penthera deps --license-policy permissive     # dependency capabilities and licenses
npx penthera agents                               # the agent config left in the repo
```

At handover, give the client a plain-language report and an evidence bundle
they can keep. Both are described in [evidence](../evidence.md):

```bash
npx penthera https://client.example --repo . --audience owner > security-summary.md
npx penthera https://client.example --repo . --audience auditor \
  --evidence handover/2026-10-19 --sign-key ~/.ssh/agency_ed25519
```

Only scan what you have the client's written permission to test.

## What it does not do

- Dependency analysis covers npm and Python. The install firewall and the
  `--online` registry checks are npm only for now.
- It does not track CVEs in your dependencies. Keep Dependabot or a similar
  service on for that ([how they fit](../compare/github.md)).
- It does not watch the registry for your package being republished by someone
  else. Enable 2FA and trusted publishing on npm for that.
- A capability is what code *can* do, not proof of intent. Many good packages
  use the network. The diff is there so a person can look.
- It does not replace a penetration test where a contract or a regulator asks
  for one.
- Fix recipes cover common JavaScript and TypeScript frameworks. Other stacks
  get findings and guidance, not diffs.

[Docs index](../index.md) · [All commands](https://github.com/danoszz/penthera/blob/main/docs/commands/README.md)
