# Authorization and ethical use

Penthera sends HTTP requests to targets you specify. Some modes (`--deep`, `--fuzz`, `--all`) send **attack payloads** designed to find vulnerabilities. This is powerful tooling — treat it like a loaded instrument, not a toy.

## You may use Penthera when

- You **own** the target (your app, your server, your university project).
- You have **written authorization** from the system owner (email, ticket, signed scope document).
- You scan **localhost** or private lab environments you control.
- You use it for **defensive security**: research, coursework, CI hardening, pre-release audits.

## You must not use Penthera to

- Scan systems you do not own or lack explicit permission to test.
- Probe government, healthcare, financial, or third-party production systems without authorization.
- Attempt to exfiltrate data, disrupt services, or bypass access controls for malicious purposes.
- Use findings to attack, extort, or harm individuals or organizations.

## Legal notice

Unauthorized security testing may violate computer misuse laws (e.g. CFAA, UK Computer Misuse Act, EU national equivalents) and can result in **criminal prosecution**, **civil liability**, **IP blocking**, **account termination**, and **academic or professional penalties**.

**Penthera is provided for legitimate security research and defensive testing only.** The authors and contributors assume **no liability** for misuse. By using this tool, you accept full responsibility for ensuring your scans are authorized and lawful in your jurisdiction.

Penthera is a **research and hardening aid**, not a weapon. The goal is to find and fix weaknesses in systems you are responsible for — not to cause harm.

> Before scanning any URL that is not localhost, confirm you have permission. When in doubt, **do not scan**.

## Agent behavior

When acting as an agent with this skill:

1. Always ask for authorization confirmation before scanning non-localhost URLs.
2. Never assume permission from a bare URL in the user's message.
3. Refuse requests to scan well-known third-party domains without explicit ownership claim.
4. Require second confirmation before destructive modes (`--deep`, `--fuzz`, `--all`).
