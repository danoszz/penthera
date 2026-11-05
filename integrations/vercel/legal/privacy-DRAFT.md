# DRAFT: Privacy notice for the Penthera Vercel integration

> **DRAFT, not approved, not published.** For the maintainer's review, and a
> legal reader of his choice. Placeholders are in [brackets]. Every statement
> here must stay true to `../README.md`, "What it keeps".

Last updated: [date]

## Who is responsible

Daan van der Zwaag, [business address], [contact email], is the controller for
the data the integration keeps. Vercel is a separate, independent controller
for the data it handles on its own platform.

## What we keep

For each installation, and nothing else:

- Vercel's configuration id for the installation,
- your team id, or your user or account id for a personal account,
- a Vercel access token, encrypted (AES-256-GCM), and
- the date of the latest install.

## What never reaches us

Your source code, deployment URLs, scan results, findings, GitHub tokens,
Vercel protection bypass secrets, environment variables, names and email
addresses.

To draw the setup pages, the server reads your shared projects' ids, names and
linked GitHub repositories from Vercel. It shows them to you and does not
store them.

## Why, and on what basis

To run the integration you asked for: register the check, and keep it working
until you uninstall. The legal basis is the performance of a contract (GDPR
Art. 6(1)(b)).

## No tracking

No analytics, no tracking, no profiling, no advertising. We do not sell or
share your data. During the install we set two strictly necessary cookies: a
CSRF check (up to 15 minutes) and a setup session (30 minutes). Neither holds
your token.

## Who processes it for us

- Vercel Inc. hosts the server and keeps its request logs. [Region; transfer
  safeguards, such as the EU-US Data Privacy Framework or standard contractual
  clauses.]
- Upstash, through the Vercel Marketplace, stores the records listed above in
  [region]. [Transfer safeguards.]

Separately from the stored record, Vercel's request logs for the server record
each request's path and query string. That includes the one-time install code
(spent within seconds, usable once), the configuration id, your team id and
Vercel's return address. These logs are kept by Vercel for its plan default of
[period]. We do not export or analyze them.

## How long

Until you uninstall: Vercel tells us, and we delete the record. A weekly check
also deletes any record whose token Vercel no longer accepts.

## Your rights

You can ask for access to or deletion of your data at [contact email]. We
answer within 30 days. Uninstalling deletes it without asking. You can complain
to the Autoriteit Persoonsgegevens, the Dutch data protection authority.

## Security incidents

If a breach affects your data, we tell you and the Autoriteit Persoonsgegevens
as the GDPR requires, and Vercel within 48 hours, as our agreement with Vercel
requires.

## The scan itself

The scan runs in your GitHub Actions, not on our server. What it contacts is
described in Penthera's [privacy and network use](https://penthera.org/docs/privacy)
page. [Confirm the URL.]

## Changes

We date every version and give notice of material changes on [where].
