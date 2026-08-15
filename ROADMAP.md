# Roadmap

What's shipped, what's next, and what's deliberately not being built yet.

Penthera is maintained part-time. New features are gated on evidence that people
actually want them, so the list below is ordered by value per hour rather than
by ambition. Issues and PRs are welcome on anything here.

## Shipped

- URL scanning: TLS, security headers, CORS, cookies, endpoint and OpenAPI
  discovery, auth hardening, JWT, IDOR/BOLA, OAuth redirect, client-side auth
- Repo scanning: API route discovery, trust boundaries, hardcoded secrets
- Email authentication: SPF, DMARC, MX
- Injection probes and property-based API fuzzing (opt-in, payload-based)
- macOS machine audit
- Reports: terminal, Markdown, JSON, SARIF, with provenance and an honest
  confidence label on every finding
- NIS2 readiness: per-measure report, offline self-assessment, policy pack,
  incident-report drafts, questionnaire answerer, CycloneDX SBOM, passive
  supplier rating, remediation and audit-loop tracking
- Agent Skill with an authorization gate, and a CLI

## Next

Ordered by value per hour of maintenance time.

| Feature | Why | Rough size |
|---------|-----|-----------|
| Risk-contextual prioritisation ("fix these three first") | A ranked shortlist beats a long list. Counters the habit of scanners growing a backlog instead of closing it | Small |
| CyFun adapter (Belgium) | Jurisdiction data is already config, so a second country is close to free | Small |
| MFA probe | The last Article 21 measure still marked planned, and a security-questionnaire staple | Medium |
| Evidence bundle | A hashed, timestamped archive an auditor can verify. No other free scanner produces one | Medium |
| Exploit-chain storytelling | Chains are discovered but reported as flat findings. Showing how they combine is the difference between a list and an explanation | Medium |
| Baseline "what changed since you shipped" | Turns the diff into a changelog of your security posture | Small |

## Under consideration

**Local dashboard and live monitor.** A `penthera ui` command that opens a local
web app: a dashboard of current posture, findings and their history, a field to
enter a URL and run a scan, deep-scan and re-scan controls, downloadable
reports, and an interactive view of the agent working rather than a wall of
terminal output. Long-running monitoring with status reporting over time. This
is the largest item on the list and would change what the tool feels like to
use, so it needs real demand before the maintenance cost is worth taking on.

**Other candidates**, roughly in order: SBOM transitive dependencies and
container images, an authorised-versus-unauthorised baseline for the IDOR probe,
broader injection targeting, document export for non-technical owners, and
credential-exposure lookup.

## Not planned

- **Workspace API integrations (Microsoft 365, Google).** They would need OAuth,
  stored tokens, and accounts. Running entirely offline with no accounts is a
  deliberate property of this tool, not a limitation to fix.
- **ISO 27001 Annex A mapping.** Mostly organisational controls, and it would
  dilute the NIS2 focus that makes the compliance output useful.
- **A hosted service.** Penthera is an open-source tool you run yourself. If a
  hosted version ever exists it will not remove anything from this one.

## Principles

- Works offline. Where an API adds value it stays optional with a local fallback.
- Never claims to certify. Output is readiness, evidence, and self-assessment.
- Honest about confidence. A heuristic is labelled as one.
- Proportionate. A small organisation should be able to produce appropriate
  evidence without enterprise overhead.
- Authorized testing only. Anything touching third parties stays passive and
  public-data-only.
