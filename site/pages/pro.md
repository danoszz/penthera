---
nav: Pro
title: Penthera Pro: rules decide, Pro keeps the record
description: Pro is an experiment, not a sale. Penthera stays free; this asks whether teams need more, such as daily checks of what they shipped and signed reports.
eyebrow: Pro
cta: waitlist
layout: pro
unlisted: true
---
# Penthera Pro

> An experiment, not a sale. Penthera stays free.

Rules decide. Pro keeps the record. The free Penthera agent runs in your CI, and Pro keeps what it found. It watches your dependencies against new advisories every day, checks your sites every week and sends a signed report every month. Your code never leaves your CI.

{{CTA}}

## An open question: is the free tool enough?

Penthera is free and stays free. Pro is an experiment, not a sale: it measures whether teams need anything beyond the free agent. If they do, the income keeps Penthera maintained beyond one part-time person, and pays independent reviewers and outside experts to critique its rules. If they don't, the free tool is the whole product, and that's a fine answer.

## Rules decide. We show our work.

Every finding comes from a written rule: a model can propose a problem, but a rule has to confirm it. Run the same commit twice and you get the same answer. Every result is signed, and anyone can check it with `penthera evidence verify`, free.

## What Pro runs for you

1. **Every day: what you shipped, checked again.** Pro matches the dependency list you shipped against new advisories every day: OSV, the CISA known-exploited list and EPSS. If something you shipped becomes known-bad, you get an email or a GitHub issue.
2. **Every week: your sites, from the outside.** Passive checks on the domains you've verified: certificates, headers, CSP, and keys exposed in your bundles. Nothing is attacked.
3. **Every month: a signed report.** Written from your stored results, for you, your client or your auditor, with evidence for the Cyber Resilience Act. A dashboard with the history in between.

## Your code stays in your CI

- **Opt-in only.** `penthera --publish` sends a signed bundle: findings, the dependency list (SBOM), the evidence manifest and site check results. Never source code.
- **Without `--publish`, nothing leaves your machine.** That is how the free agent works today.
- **Bring your own model.** `penthera verify` keeps what the rules confirm, and the rest stays labelled unverified. We don't resell model access.

## What we'd test

From about $100 a month per team. A person, if you want one: an optional quarterly review with a written note. Assessments of one app or one release are quoted on their own.

Rather run it yourself? `npx penthera@{{VERSION}} init --yes` sets up the same checks in your own CI, free.

**In research:** checks your agents can call and pay for, one at a time, each with a signed verdict.

## What it is not

- **Not for sale.** The hosted parts are planned, and they get built only if the waitlist shows a need. No check ever moves behind a paywall.
- **Not a certification.** It shows what was checked and found, with the evidence.
- **Not a reason to upload your code.** Code checks run on your machine or in your own CI.

## How the waitlist works

Each email counts as one data point in the experiment. The button opens an email to Daan, who builds Penthera, at daan@penthera.org. Say who you are and what you'd want: a daily watch on what you shipped, a dashboard, signed reports, a person to ask, or checks your agents can call. Nothing is stored on penthera.org. Daan replies to every message, and writes again only when there is something to try.
