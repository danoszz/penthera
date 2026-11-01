---
title: "Privacy and network use"
sidebarTitle: "Privacy and network"
description: "Penthera has no telemetry."
---

> **Pro.** For "what does it send over the network?"

Penthera has no telemetry. It does not collect, store or send usage data, analytics or personal information to us or to any third party.

This applies to the CLI, the dashboard and the npm package. The website, [penthera.org](https://penthera.org), is separate: it counts anonymous page views and load times with Vercel Web Analytics and Speed Insights, which set no cookies. The browser check on the site never sends the files you paste; its Content-Security-Policy allows only those two counters.

The site also counts a few named events with Web Analytics, to see how many checks run and how many lead to an install: a check ran (and whether it returned a report or an error), a copy button was used (which one, such as "install", "mcp", or "repo-result" for the code-scan command next to a check result), and a link was followed (which one: GitHub, npm, @penthera_org on X, the Pro waitlist or the report download; "github-star-result" is the Star on GitHub link next to a check result). An event carries its name and that one label, nothing else: never the URL or host you checked, the score, or anything you type or paste. Like page views, events set no cookies. The Pro waitlist is an email you write and send yourself: the form only fills it in, and penthera.org stores nothing from it.

- **Scan traffic goes to the target you name.** Auth tokens passed with `--auth-bearer`, `--auth-cookie`, or `PENTHERA_*` env vars are sent only to that target.
- **Every request identifies itself** as `penthera/<version> (+https://github.com/danoszz/penthera)`, so a target's operator can tell where the traffic comes from. Override it with `--user-agent`.
- **Reports stay local.** Penthera writes them to `reports/` (gitignored) on your machine.
- **Every scan lists the third-party hosts it contacted** besides the target, in the terminal summary and in the report's "Network egress" section.

Without `--offline`, a scan may contact these third parties:

| Host | When | What it learns |
|---|---|---|
| `raw.githubusercontent.com`, `cdn.jsdelivr.net` | Retire.js check (standard and deep profiles) | That someone downloaded the public database. Nothing about your target. |
| `crt.sh`, `web.archive.org`, `otx.alienvault.com` | `--recon` only | The target domain. |
| CDN hosts serving your page's `<script src>` | Retire.js check, when a script's version can only be read from its contents | That someone fetched that public script. |

Other commands stay local unless you opt in. `penthera deps` makes no network requests by default. With `--online` it sends GET requests for public package metadata to the npm registry (`registry.npmjs.org`, or your `npm_config_registry`), and nothing about your project. `--fix-model` talks only to a local Ollama on `127.0.0.1:11434`.

`penthera mcp` talks to your agent over stdin and stdout and opens no port. Of its tools, only `scan_url` uses the network, and it stays on the target and the hosts you listed with `--allow-host`. A redirect may also move within the target's registrable domain. It never contacts the hosts above, and it uses the vendored Retire.js snapshot. Without `--offline` it makes the same DNS lookups as a URL scan. See [docs/commands/mcp.md](commands/mcp.md).

### AI mode: `--ai`

AI mode is off unless you turn it on, and asks every run. Penthera itself talks
only to Ollama on `127.0.0.1:11434`. What reaches the model is parts of your
code with recognised secrets masked. See [ai-mode.md](ai-mode.md).

| Route | What Penthera sends | What you should know |
|---|---|---|
| Rules only (no `--ai`) | Nothing new | No question is asked |
| `--ai` with a local model | Code parts, secrets masked, to Ollama on `127.0.0.1`. Nothing else | The model runs on this computer, and the report lists every host Penthera contacted |
| `--ai` with an Ollama cloud model | Code parts, secrets masked, to Ollama on `127.0.0.1`, which forwards them to ollama.com | Your code leaves this computer, under Ollama's terms. Only after a second screen where you type the host, or `--ai-consent ollama-cloud` |
| `penthera verify` | Nothing. It reads a file and your checkout | Your agent and its model provider handled your code, under their terms |

Penthera checks the address and the model. It cannot see whether something on
this computer forwards port 11434 elsewhere. Each consent is logged to
`~/.penthera/consent.jsonl` on this computer only, and never used to skip a
question.

The dashboard keeps one thing between restarts: the word Simple or Advanced, in
`~/.penthera/ui.json`. It holds no paths and nothing about a project.

### Fully local: `--offline`

```bash
penthera http://localhost:3000 --offline
```

With `--offline`, the HTTP client refuses every host except the scan target. A redirect may only move to a host on the target's registrable domain (`example.com` to `www.example.com`). In practice:

- **Recon is skipped.** No queries go to crt.sh, the Wayback Machine or OTX.
- **The Retire.js database comes from the snapshot vendored in the package** (`lib/data/retire-jsrepository.json.gz`), refreshed by `scripts/refresh-retire-db.mjs`. The source URL, fetch date and SHA-256 sit next to it in `retire-jsrepository.meta.json`, so you can check it against upstream. Online scans fall back to the snapshot too when the live download fails.
- **Third-party scripts are not fetched.** A refused request is listed in the report as an inconclusive probe, not passed over silently.
- **`--suppliers` is refused**, because it rates third-party domains.
- **DNS:** reaching a remote target needs DNS. The SPF, DMARC and MX lookups of the email check are skipped with `--offline`. A `localhost` or IP target needs no DNS at all.

Penthera never fetches rules or code at runtime. Templates, wordlists and the vulnerability database ship in the package.

### Inconclusive probes

When a probe's requests time out, fail or are refused by `--offline`, the scan records `{ probe, url, message }` in `result.errors`. The terminal summary shows "N probes inconclusive", and the Markdown report lists each one. A probe that could not run is not a clean result.

Scan only targets you are authorized to test. See [Ethics and authorization](https://github.com/danoszz/penthera/blob/main/README.md#ethics-and-authorization).
