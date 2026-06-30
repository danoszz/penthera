# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Reporting a vulnerability

If you find a security issue in **Penthera itself** (not a finding produced by
scanning a target), please report it privately:

1. Open a [GitHub Security Advisory](https://github.com/danoszz/penthera/security/advisories/new), or
2. Email the repository owner with a clear description and reproduction steps.

Please do **not** open public issues for undisclosed vulnerabilities. We aim to
acknowledge reports within a few days.

## Responsible use

Penthera sends HTTP requests to targets you specify. Some modes (`--deep`,
`--fuzz`, `--all`, `--profile deep`) send **attack payloads** (SQLi, SSTI, SSRF,
XSS, command injection, API fuzzing).

**Only scan systems you own or have explicit written permission to test.**
Unauthorized scanning may be illegal in your jurisdiction. Penthera is built for
defensive research and hardening your own applications — see the full
[ethical-use policy](README.md#ethical-use--authorization) and
[disclaimer](README.md#disclaimer) in the README.
