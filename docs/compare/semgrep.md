---
title: "Penthera and Semgrep"
sidebarTitle: "vs Semgrep"
description: "Where Semgrep and Penthera overlap, where they differ, and how to run both."
---

> **Pro.** For "how does Penthera compare to Semgrep, and how do I run both?"

*Last checked: 2026-10-19 against Semgrep's docs, GitHub and pricing page.*

## Use them together

[Semgrep](https://semgrep.dev) is a static analyzer for your own code. The
Community Edition engine is open source (LGPL-2.1) and runs locally. The
commercial AppSec Platform adds cross-file analysis, supply-chain reachability,
secrets and AI triage ([CE vs platform](https://docs.semgrep.dev/semgrep-pro-vs-oss)).
Penthera's repo scan is narrower than Semgrep's. What Penthera adds is the rest
of the picture: the running app, what your dependencies can do, and your AI
tooling.

A reasonable setup: Semgrep on every pull request for code patterns, with your
own rules if you write them. Penthera for the lockfile, the preview URL and the
agent config.

## Side by side

| | Penthera | Semgrep |
|---|---|---|
| Your code | Route discovery, trust-boundary mapping and secrets for Next.js, Express, Hono, Fastify | Pattern-based analysis in many languages; CE works within a single file, the platform adds cross-file taint analysis ([CE vs platform](https://docs.semgrep.dev/semgrep-pro-vs-oss)) |
| Rules | Built in and readable; add patterns and IOCs with signed rule packs or Nuclei templates; no rule language for code | A rule language plus 2,000+ community rules in the Registry ([repo](https://github.com/semgrep/semgrep)) |
| Dependencies | Capabilities, upgrade diff, typosquats, licenses (npm and Python) | Semgrep Supply Chain with reachability, on the platform |
| Running app | URL scan | No |
| AI tooling | `penthera agents` | No dedicated check |
| Network | None needed | CE with local rules sends no metrics by default; `--metrics=off` turns them off ([metrics](https://docs.semgrep.dev/metrics)) |
| Cost | Free, MIT | CE is free. Platform free for up to 10 contributors; Teams from $30 per contributor a month per product ([pricing](https://semgrep.dev/pricing)) |

## Where Semgrep goes further

- **Code analysis depth and breadth**: many languages, and dataflow across files
  on the platform.
- **Your own rules.** If your team has patterns to ban, Semgrep's rule language
  is the right tool. Penthera has no user rule language for code.
- **Reachability** for dependency vulnerabilities.

## Where Penthera adds something

- **Outside the source**: the running app, what packages do when installed, and
  the agent config on your machine.
- **Fixes that are verified** by a re-scan on a local branch.
- **EU evidence** from the same runs.

## Run both

```bash
semgrep scan --config p/default --sarif -o semgrep.sarif
npx penthera http://localhost:3000 --repo . --sarif penthera.sarif
npx penthera deps --base origin/main
```

[All comparisons](https://github.com/danoszz/penthera/blob/main/docs/compare/README.md) · [Back to the README](https://github.com/danoszz/penthera/blob/main/README.md)
