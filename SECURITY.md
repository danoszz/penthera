# Security Policy

> **Starter and pro.** For "I found a vulnerability in Penthera itself: how do I
> report it?"

## Supported versions

Security fixes land on the latest minor release only. Upgrade to get them.

| Version | Supported |
| ------- | --------- |
| 2.2.x   | Yes (`latest`) |
| < 2.2   | No        |

## Reporting a vulnerability

If you find a security issue in **Penthera itself** (not a finding produced by
scanning a target), please report it privately:

1. Open a [GitHub Security Advisory](https://github.com/danoszz/penthera/security/advisories/new)
   (preferred: it keeps the report private and lets us credit you), or
2. Email the maintainer via the address on the [GitHub profile](https://github.com/danoszz)
   with a clear description and reproduction steps.

Please do **not** open public issues for undisclosed vulnerabilities.

**What to expect.** Penthera is maintained part-time, and security reports come
first:

- Acknowledgement within 3 working days.
- An initial assessment (accepted, needs more info, or out of scope) within 10
  working days.
- A fix or mitigation for accepted issues as fast as severity warrants, followed
  by a release, a GitHub advisory, and credit to you unless you prefer otherwise.

**In scope:** the CLI, the scanner engine (`lib/`, `src/`), the MCP server
(`penthera mcp`), the local dashboard (`penthera ui`), the GitHub Action, the
Agent Skill (`skills/penthera/`), the installer (`install.sh`), and the
published npm package and its build pipeline. Examples: code execution from a malicious scan target or
repo, a skill instruction that bypasses the authorization gate, a supply-chain
weakness in our release workflow.

**Safe harbor.** Good-faith research on Penthera's own code, done on your own
machine, is welcome and we will not pursue action against it. This does not
cover scanning third-party systems: the authorization rules below still apply.

## Responsible use

Penthera sends HTTP requests to targets you specify. Some modes (`--deep`,
`--fuzz`, `--adaptive`, `--all`, `--profile deep`) send **attack payloads** (SQLi, SSTI, SSRF,
XSS, command injection, API fuzzing). They can change data on the target:
[what active modes can change](docs/commands/scan.md#what-active-modes-can-change).

**Only scan systems you own or have explicit written permission to test.**
Unauthorized scanning may be illegal in your jurisdiction. Penthera is built for
defensive research and hardening your own applications. See
[Ethics and authorization](README.md#ethics-and-authorization) in the README.
