# How Penthera compares

> **Pro.** For "how does Penthera compare to the tool I use, and how do I run both?"

Penthera is a free, offline, MIT-licensed security agent. Most teams that use it also
use at least one of the tools below, and these pages are written for them: what
each tool is for, where it goes further than Penthera, and how to run the two
together.

| Page | In one line |
|---|---|
| [Penthera and Socket](socket.md) | Socket watches the package registries; Penthera checks your app and your AI tooling on your machine |
| [Penthera and Snyk](snyk.md) | Snyk brings curated vulnerability data across many languages; Penthera looks at behavior, the running app and agent config |
| [Penthera and GitHub (Dependabot, code scanning)](github.md) | GitHub alerts on known CVEs and runs CodeQL; Penthera's SARIF lands in the same tab |
| [Penthera and OWASP ZAP](zap.md) | ZAP is the deeper dynamic scanner; Penthera is a quicker first pass with source context |
| [Penthera and Claude Code Security Review](claude-security-review.md) | A model reviews the diff for logic bugs on trusted PRs; Penthera's rules cover secrets, dependencies, agent config and fork PRs |
| [Penthera and Semgrep](semgrep.md) | Semgrep is the deeper static analyzer for your code; Penthera adds dependencies, the live app and AI tooling |
| [Penthera and Cloudflare's security-audit skill](cloudflare-security-audit.md) | The skill has a model audit your code in depth; Penthera runs fast, repeatable checks, looks outside the source and verifies fixes |

## How these pages are written

- Every claim about another product comes from that product's public docs or
  pricing page, linked inline. Anything we could not confirm is left out.
- Each page names where the other tool goes further. Most of them go further
  than Penthera somewhere.
- Prices and plans change. Each page has a last-checked date. Check the vendor's
  page before you rely on a number.
- These pages compare what each tool is for, not how much it finds. Detection
  is compared in one place: the [public benchmarks](https://penthera.org/benchmarks),
  four public datasets on which Penthera and every free tool we could run
  offline were scored the same way, losses included. Penthera does not rank
  first on all four: on leaked secrets, deepsecrets ranks above it.
- Of the tools on these pages, only Semgrep (open source) and CodeQL, which
  GitHub code scanning runs, are in that benchmark, on injection bugs in
  JavaScript libraries. Snyk, Socket and Semgrep Pro publish no results on those
  datasets, and cost and licence terms keep us from measuring them, so no page
  here claims Penthera finds more than they do.
- A public dataset is not your code. Accuracy on real projects is not measured
  yet. That is [experiment E1](../research/prereg/E1-real-world-accuracy.md).

Spotted something wrong or out of date? Please open an issue or a pull request.
