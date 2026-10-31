---
nav: E20 study
title: Penthera-Research/E20: what it requested from your site, and how to opt out
description: E20 and E20-R are low-interaction active measurements of homepages, published as totals. What they request, and how to opt out or be removed.
eyebrow: Research
cta: contact
subject: Penthera-Research/E20
---
# Penthera-Research/E20

> For "why did Penthera-Research/E20 visit my site, and how do I stop it?"

If you saw `Penthera-Research/E20` in your logs, it was a visit to your homepage for a study. E20 asks how the most visited sites on the web, and recent startups, score on the same checks as Penthera's live check. A follow-up, E20-R, repeats and widens it. Results are published as totals and shares only. No site is named.

{{CTA}}

## Who visits

**E20** used two lists, fixed before the run and recorded with their SHA-256 hashes in the [pre-registration](https://github.com/danoszz/penthera/blob/main/docs/research/prereg/E20-front-door.md):

1. the top 1000 sites of the [Tranco list](https://tranco-list.eu/), a research ranking of popular domains;
2. the public websites of companies in the two most recent Y Combinator batches, from YC's public company directory.

**E20-R** ran from 30 October 2026 as a pilot and instrument audit. A second run, E20-R2, repeats it as a prospective corrected remeasurement, over about 7,000 sites: the two lists above, more Tranco sites, older Y Combinator companies, large listed companies in Europe and the US, public Show HN launches, and Dutch organizations in sectors of the Cyberbeveiligingswet. Each run visits a site once, so a site can see two E20-R visits. The second is scheduled for every site, whatever it answered the first time, and isn't a retry of a block. Up to 50 sites are instead visited in a short test before the second run, more if that test has to be repeated on other sites, and aren't visited in the run itself. On 31 October 2026 the second run stopped itself after 188 sites, on a false alarm in our own privacy check. It is reported as a partial run and decides nothing. A new run replaces it and skips those sites and the test sites, so each site is visited once in the run itself. A failed request isn't repeated. Adult, gambling and government sites, and sites of people at risk, are on an exclusion list and are not visited. E20 also excluded health sites. E20-R includes them, so results can show which industries are exposed, but for a health site it requests the homepage only and never follows a link to a login or patient portal. Y Combinator companies stay in whatever their sector, except adult sites.

## What it requests

Per site, in this order, and nothing else, apart from any redirect a site itself sends for these files:

1. `GET /robots.txt`. If you opted out (below), the visit stops here. E20-R2 also stops if the file answers 5xx, can't be reached or can't be read, as [RFC 9309](https://www.rfc-editor.org/rfc/rfc9309) asks. It stops on a 429 too. The RFC doesn't ask for that: it's our own conservative choice.
2. `GET /` over HTTPS, following at most 4 redirects. E20-R2 reads `/robots.txt` at each new origin before it follows a redirect there, and stops at a site on the exclusion list. If the name doesn't resolve, one try at `www.` plus the name. Only if the HTTPS connection is refused or unreachable, or fails its certificate or handshake, `GET /` over HTTP. In E20-R2 both of these run only when nothing from your site has answered yet.
3. `GET /.well-known/security.txt`, the file [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) asks sites to publish.
4. Public DNS records: SPF and DMARC (TXT) and CAA. E20-R also reads MX and NS, and keeps only the provider's name. E20-R2 reads these whether or not your homepage answered, unless you opted out or your site is excluded, and for the host a redirect ended on as well.
5. E20 and the first E20-R run only, never E20-R2: if your homepage links to a login or app page on your own domain (a link named "Log in", "Sign in", "App" or "Dashboard", or a path like `/login`), one `GET` of that page, after checking that page's host's robots.txt. Headers only: no form is filled, nobody logs in, and links to another domain are never followed.

It does not load your scripts, stylesheets or images. It guesses no paths and follows no other links. It adds no query string of its own, and follows a site's redirect as given. It sends no forms, payloads or logins, and reads no keys. At most 4 sites are visited at a time, and each worker waits 1 second between sites.

The request carries this User-Agent:

```
Penthera-Research/E20 (+https://penthera.org/research/e20; opt out: robots.txt User-agent: Penthera-Research)
```

Our byte counts are observed response-body bytes, a lower bound. They exclude request bytes, headers, TLS overhead and DNS.

Every request carries the User-Agent above. It doesn't imitate a browser, solve a challenge, or switch addresses to get past a block: a refusal is a result. E20-R's first run came from `research.penthera.org` (2.31.141.178, a rented server in Germany, since deleted), and E20-R2 comes from 178.104.243.225 under the same name. That name has no web page: reach us through the URL in the User-Agent. For E20 we do not publish the address the visits came from, because it was a personal connection. If you want to know whether a request in your logs was ours, email us the address and time you saw, and we will confirm or deny privately.

## How to opt out

Add this group to `/robots.txt`:

```
User-agent: Penthera-Research
Disallow: /
```

E20 and E20-R also stop for `User-agent: *` with `Disallow: /`. E20-R2 also follows a rule that disallows the path it is about to request. A site that opted out is counted as excluded and nothing else is requested from it, though public DNS may still be read if a redirect led to someone else's opt-out, or your robots.txt couldn't be read. A site that opted out during the first run is skipped in E20-R2.

You can also ask to be removed at any time. Email us from your domain, or from a contact listed for it. We skip your site in every later pass, delete its record from the raw data, recompute the totals, and take it off the published list.

## What we keep and publish

The raw per-site results stay private. They hold check outcomes and short evidence such as header values. E20-R also keeps header names, cookie names (never values), a hash of the page, and, for an error or block page only, its first 4 KB. Stored evidence can contain addresses: error pages can quote the visitor's address back, so the first run's excerpts hold IP addresses, mostly our own server's. E20-R2 removes IP addresses, emails, form fields, query strings, tokens and long numbers by pattern before anything is written, so it catches common forms, not all of them. An address in an image, built by a script, encoded, or split across markup can stay, and so can short numbers and tokens. Every stored string is scanned again after a run. If the scan flags something, a person reviews it on the server, and a real miss means the whole per-site file is deleted. E20-R2 also keeps a hash of robots.txt and security.txt, and the exact DNS query names, types and outcomes for your domain. The exception is your SPF record, which is stored as published, mail server addresses included. For a normal page it also keeps the title and up to 4,096 characters of visible text, so a person can check that it was a real page. Names in that text are not removed. After a sample is drawn for checking, the text of every other normal page is deleted. Error-page excerpts stay until the deletion below. If a run stops early, or for a pilot run, all of this text is deleted, error-page excerpts included. It also keeps your domain's DMARC record with report addresses redacted, because the mail results test it. The evidence stays out of the repository and is never published. The maintainer sees it, and so does a labeler under a written note who checks a sample. An AI agent, a hosted model, also reads that sample, so those rows leave our server for its provider, and the deletion below can't reach what the provider keeps. The first run's labeler saw 150 rows. All the private evidence we hold is deleted 12 months after publication. That can't reach the provider's copies, and it doesn't touch the published aggregates.

What we publish is the share of sites that pass each check, with a descriptive 95% interval, and the score distribution. Claims are decided on 99.55% intervals, which are wider. There is no ranking, and no site is named. For anyone who wants to check the work, the code, the target lists and the aggregates can be downloaded with the results. Health sites and the Dutch sector list are published as a hash and a method only, and appear in the results as industry totals.

## What it is not

It is not a security test of your site. It does not look for your subdomains, staging hosts, app or API, and it does not crawl other pages: only the homepage you put forward. A good or bad result for one site is never published, and it is not a guarantee of anything. We never claim a site is vulnerable, and we do not probe further than the requests above. To check your own site, use the [live check](/#scan).

## Contact

Email daan@penthera.org with "Penthera-Research/E20" in the subject. Daan van der Zwaag runs the study, and maintains Penthera, whose live check is the instrument. For a security issue in Penthera itself, use [GitHub security advisories](https://github.com/danoszz/penthera/security/advisories/new).
