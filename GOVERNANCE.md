# Governance

> **Starter.** For "who decides what goes into Penthera, and what happens if
> the maintainer stops?"

Penthera has one maintainer, [@danoszz](https://github.com/danoszz) (Daan van
der Zwaag), part-time, next to a PhD. This page says how decisions, releases
and security reports work, and what happens if the maintainer steps away.

## Who decides

- **The maintainer decides** what is merged and released, after discussion in
  issues and pull requests.
- **Some rules don't move**, whoever asks, a sponsor included
  ([AGENTS.md](AGENTS.md)):
  - written rules decide every finding, and a model may only propose;
  - no rules, templates or signatures are downloaded at run time;
  - only authorized targets are scanned.
- **Sponsors buy no influence** over findings, rules or the roadmap
  ([sponsor tiers](docs/funding/sponsor-tiers.md)).
- **Measured changes:** a change to detection is measured on the benchmarks
  before it ships, and results are published whether they are good or bad
  ([methodology](docs/METHODOLOGY.md)).

## Money

- **Penthera is free and stays free.** No check moves behind a paywall.
- **Sponsorship pays for maintenance,** and buys no influence over findings,
  rules or the roadmap.
- **Pro is an experiment, not a product for sale.** It measures whether teams
  need anything beyond the free agent, such as a record kept for them and
  checks on a schedule. If there is a need, the income keeps Penthera
  maintained beyond one part-time person: independent reviewers, and outside
  experts who critique the rules and the code. If there isn't, the free tool is
  the whole product.

## How changes land

1. Every change is a pull request against `main`, with tests and a changelog
   fragment ([CONTRIBUTING.md](CONTRIBUTING.md)).
2. Continuous integration must pass: the test suite, lint, CodeQL, the
   dependency check and the commit provenance check.
3. The maintainer reviews and merges. Outside contributions are welcome. A
   contributor who has shipped several reviewed changes can be invited to
   review others.

## How releases happen

1. Only the maintainer starts a release. A minor version goes out as a
   release candidate on npm's `next` tag first.
2. The maintainer tags the merge commit. CI builds the package and stages it
   on npm with provenance, which links the tarball to the commit and the
   workflow.
3. The maintainer approves the staged release on npm with two-factor
   authentication. Nothing is published without that step.

## Security reports

Reports about Penthera itself go through a private GitHub security advisory.
The policy and response times are in [SECURITY.md](SECURITY.md). How Penthera
itself is built and released is on [penthera.org/trust](https://penthera.org/trust).

## If the maintainer stops

- The maintainer will say so in the README and the repository description, and stop
  publishing to npm.
- The maintainer will offer the repository and the npm package to a contributor with a
  record of reviewed changes. Without one, the repository is archived, and
  the last release stays installable.
- The code is MIT licensed. Anyone may fork it and keep it going under
  another name.

## Changing this page

This page changes by pull request, like everything else, with the reason in
the description.
