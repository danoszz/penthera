---
title: "Trust"
sidebarTitle: "Trust"
description: "How Penthera itself is built, released and run."
---

> **Starter.** For "can I trust the tool I'm about to run on my code?"

How Penthera itself is built, released and run. Every line links to something
you can check yourself. Penthera holds no certification, such as SOC 2 or
ISO 27001. This page shows evidence instead.

## Releases you can verify

- **Published from CI with npm provenance.** Each release is built and staged
  by [the publish workflow](https://github.com/danoszz/penthera/blob/main/.github/workflows/publish.yml)
  on GitHub Actions. npm records a signed statement that links the tarball to
  the commit and the workflow that built it. Check it with
  `npm audit signatures`, or under "Provenance" on the
  [npm page](https://www.npmjs.com/package/penthera).
- **A person approves every release.** CI only stages a version; it goes live
  after the maintainer approves it on npm with two-factor authentication.
- **One runtime dependency.** The package depends on `yaml` and nothing else
  ([package.json](https://github.com/danoszz/penthera/blob/main/package.json)).
  Make your own SBOM with `npx penthera --repo . --sbom sbom.cdx.json`.

## Checked in public

- **OpenSSF Scorecard,** every week:
  [the current score](https://scorecard.dev/viewer/?uri=github.com/danoszz/penthera).
- **CodeQL** on every pull request, and a dependency capability diff that
  Penthera posts on every pull request that changes the lockfile.
- **Benchmarks,** published with their losses:
  [penthera.org/benchmarks](https://penthera.org/benchmarks).
- **The rules are readable.** Every finding comes from a rule in the
  repository. A model may propose, but a rule decides
  ([methodology](METHODOLOGY.md)).

## Tested unplugged

A pre-registered experiment, E17, ran each offline command twice with the
network blocked and once with it allowed, on macOS and Ubuntu
([protocol](https://github.com/danoszz/penthera/blob/main/docs/research/prereg/E17-offline-and-determinism.md),
[results](https://github.com/danoszz/penthera/blob/main/bench/offline/RESULTS.md)).

- **No network at run time.** Repo scans, `agents`, `deps`, `brief`,
  evidence bundles and URL scans with `--offline` made no outside
  connections or DNS lookups.
- **The same result every time.** Two runs gave the same result, and so did
  a run with the network blocked. The one line that changes is the time
  `evidence verify` prints.
- **Limits.** The test watches Node only, so it can't see `git`; Penthera
  calls only local git commands. A URL scan without `--offline` downloads the
  Retire.js database. The targets were small fixtures and this repository.

## What it collects

- **The command-line tool:** nothing. No telemetry and no account. With
  `--offline` it contacts only the target you named
  ([privacy and network use](privacy.md)).
- **penthera.org:** page views and a few named events, counted without
  cookies. The live check stores nothing it fetched
  ([terms](live-check-terms.md)).

## Who runs penthera.org

- **Vercel:** hosting, the live check, cookieless page counts.
- **GitHub:** source code, CI, releases, security advisories.
- **npm:** the package registry.
- **Google Workspace:** email for daan@penthera.org.

## Reporting a vulnerability

Report a problem in Penthera itself through a
[private GitHub security advisory](https://github.com/danoszz/penthera/security/advisories/new).
You get an acknowledgement within 3 working days
([security policy](https://github.com/danoszz/penthera/blob/main/SECURITY.md),
[security.txt](https://penthera.org/.well-known/security.txt)).

## Who builds it

Daan van der Zwaag, part-time, next to a PhD. The code is MIT licensed and
developed in the open: [github.com/danoszz/penthera](https://github.com/danoszz/penthera).
