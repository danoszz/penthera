---
title: "Methodology"
sidebarTitle: "Methodology"
description: "Penthera is an open-source, offline security scanner for web applications, their dependencies, and the AI tooling used to build them."
---

> **Pro.** For "how does it decide, and what can't it see?"

## Abstract

Penthera is an open-source, offline security scanner for web applications,
their dependencies, and the AI tooling used to build them. This document
specifies its method. It states the threat model, separates what black-box
(HTTP) and white-box (repository) analysis can and cannot observe, and defines
a four-level confidence model that distinguishes deterministic evidence from
heuristic signals. It describes the false-positive controls built into each
probe (randomized canaries, context-aware payload selection, baseline
comparison, and repeated timing measurement) and the non-destructive defaults
that follow from fail-safe design. Detection rules are distributed only in
reviewed, versioned releases, never through a live feed, which removes an
update channel from the attack surface. Each design choice is tied to prior
research or a published standard. On a bundled benchmark of labeled local
targets, Penthera reaches a precision of 0.88 (95% CI 0.69 to 0.96) and a recall
of 0.91 (95% CI 0.73 to 0.98) on 24 scored findings. Because the same authors
wrote the scanner and the targets, these figures measure
regressions, not accuracy on arbitrary applications.

## How to cite

If you use Penthera or this methodology in research or a report, cite the
software. The metadata are in [CITATION.cff](https://github.com/danoszz/penthera/blob/main/CITATION.cff), which GitHub
renders as "Cite this repository".

```text
van der Zwaag, D. (2026). Penthera: An offline security scanner for web apps and AI-built code (Version 2.1.2) [Computer software]. https://github.com/danoszz/penthera
```

```bibtex
@software{vanderzwaag2026penthera,
  author  = {van der Zwaag, Daan},
  title   = {Penthera: An Offline Security Scanner for Web Apps and {AI}-Built Code},
  year    = {2026},
  version = {2.1.2},
  license = {MIT},
  url     = {https://github.com/danoszz/penthera}
}
```

Citations in this document follow APA 7th edition. Each one resolves to an
entry in [references.md](references.md), generated from
[references.bib](https://github.com/danoszz/penthera/blob/main/docs/references.bib); a test fails if a citation has no entry or an
entry is never cited. Measured accuracy is in
[bench/RESULTS.md](https://github.com/danoszz/penthera/blob/main/bench/RESULTS.md), and the method behind those numbers is
in [bench/README.md](https://github.com/danoszz/penthera/blob/main/bench/README.md).

## Contents

- [Threat model](#threat-model)
- [Black-box and white-box: what each can find](#black-box-and-white-box-what-each-can-find)
- [Runtime advisories](#runtime-advisories)
- [Confidence model](#confidence-model)
- [False-positive controls](#false-positive-controls)
- [Non-destructive by default](#non-destructive-by-default)
- [Offline and no telemetry](#offline-and-no-telemetry)
- [How new attack techniques are adopted](#how-new-attack-techniques-are-adopted)
- [Citations in reports](#citations-in-reports)
- [Known limitations](#known-limitations)

## Threat model

Penthera is built for small teams that ship web apps and APIs, often with AI
coding tools, and need a first line of evidence before a human review or a paid
penetration test. The threat model follows the four questions of Shostack
(2014): what are we building, what can go wrong, what are we going to do about
it, and did we do a good job.

**Assets.** User data behind the API; credentials and API keys, including AI
provider keys; the session and identity layer; and the integrity of the code and
dependencies that get deployed.

**Adversaries in scope.**

1. A remote, unauthenticated attacker on the internet who can send arbitrary
   HTTP requests to the deployed app. The black-box scan models this attacker.
2. An authenticated user who tries to reach another user's data. Broken object
   level authorization is the first item in the OWASP API Security Top 10
   (OWASP Foundation, 2023). Penthera tests for it when given credentials.
3. Anyone who obtains a copy of the source: a leaked repository, a public fork,
   or a compromised CI log. Meli et al. (2019) found secrets leaked in over
   100,000 public GitHub repositories, with thousands of new, unique secrets
   leaked every day. The white-box secret scan models this adversary.
4. A supply-chain attacker who publishes or compromises a dependency (Ladisa et
   al., 2023; Ohm et al., 2020; Zimmermann et al., 2019), including packages
   that code-generating models invent and attackers then register (Spracklen
   et al., 2025).

**Out of scope.** Physical access, insiders with production access, denial of
service, social engineering, and anything that needs exploitation beyond a
single benign probe. Penthera does not try to replace a human tester. It tries
to find the issues a scanner can find reliably, and to say clearly which ones
it cannot judge.

**Penthera itself is in the threat model.** A security tool runs with the
user's credentials and network position, so a compromised scanner is a
compromised machine. Thompson (1984) showed that you cannot fully trust code you
did not build yourself; the argument applies to scanners and their rule feeds.
This is why Penthera fetches no rules at run time
([below](#how-new-attack-techniques-are-adopted)).

STRIDE, the threat taxonomy that Shostack's book builds on, originates at
Microsoft (Kohnfelder & Garg, 1999). Penthera's probes map onto it as follows:

| STRIDE category | Penthera coverage |
|---|---|
| Spoofing | Authentication, JWT, OAuth, email SPF and DMARC |
| Tampering | Injection, CORS |
| Repudiation | Not tested |
| Information disclosure | Exposed files, secrets, verbose errors |
| Denial of service | Not tested; only rate limiting is checked |
| Elevation of privilege | IDOR/BOLA, client-side-only authorization |

## Black-box and white-box: what each can find

Penthera runs two kinds of analysis and reports them together.

### Black-box (URL scan)

The scanner sees only HTTP responses. Its tests are those of the OWASP Web
Security Testing Guide (OWASP Foundation, n.d.-b); each probe's WSTG IDs are
listed in [owasp-wstg-coverage.md](owasp-wstg-coverage.md).

Black-box testing finds three kinds of issue well: properties visible in every
response (missing security headers, TLS configuration, cookie flags, CORS
policy), files and interfaces that should not be public, and injection flaws
whose effect shows in the response or its timing. Protocol checks follow the
relevant specifications: HSTS (Hodges et al., 2012), JWT (Jones et al., 2015;
Sheffer et al., 2020), and OAuth redirect and PKCE handling (Fett et al., 2016;
Lodderstedt et al., 2025; Sakimura et al., 2015).

Two classic evaluations of black-box scanners show what this approach misses.
Bau et al. (2010) tested eight commercial scanners against a custom vulnerable
application and older versions of real ones. As a group the tools did
reasonably well, but many of them missed second-order flaws such as stored XSS
and stored SQL injection. Doupé et al. (2010) tested eleven commercial and
open-source scanners against WackoPicko, a realistic purpose-built app with
sixteen planted flaws. Every scanner missed eight of the sixteen, among them
stored SQL injection, multi-step stored XSS, forceful browsing, and a business
logic flaw. They concluded that crawling matters as much as detection: a
scanner cannot test a page it never reaches, and losing track of state (logins,
multi-step forms) is a main reason it does not reach it.

Penthera's design responds to each point:

- **Crawl coverage.** Endpoint discovery uses a wordlist plus the app's own
  OpenAPI document when one is exposed, and records exactly which probes ran.
  The WSTG coverage table in every report lists each test as run or not run, so
  a missing check is never presented as a pass.
- **State and logic.** Penthera does not claim to find business logic flaws,
  which no scanner in the study by Doupé et al. (2010) found either. IDOR/BOLA
  results are labeled `needs-human-review` because a scanner cannot know
  whether user A is allowed to read object B.
- **Stored and second-order flaws.** Not tested. They need a write followed by
  a read elsewhere, which conflicts with the non-destructive default.

### White-box (repository scan)

The scanner reads source files. It finds hardcoded secrets, route handlers and
their authentication boundaries, and risky code patterns.

Secret detection uses provider-specific prefixes (for example `AKIA` for AWS
and `sk-ant-` for Anthropic) plus a small number of assignment patterns such as
`api_key = "..."` with a placeholder filter. Meli et al. (2019) took the same
conservative route and restricted detection to private keys and API keys with
distinctive formats. The cost is recall: a secret with no recognizable format
is invisible to this approach. SecretBench, a labeled dataset of real secrets
across many formats, is the natural yardstick for that gap (Basak et al.,
2023). The bundled benchmark includes an unprefixed signing key that Penthera
misses for this reason.

The scan reads source, config and notebook files, plus Terraform and other HCL
files (`.tf`, `.tfvars`, `.hcl`), where keys and passwords often sit inline.
One rule is specific to session middleware: a signing secret written into the
options of `session(...)` or `cookieSession(...)`, including the common
`process.env.SESSION_SECRET || '...'` fallback, is reported as a hardcoded
session secret, since anyone with the repository can then sign session
cookies. A secret read only from the environment or from a config object is
not reported.

In a git work tree the scan follows `.gitignore`. Ignored folders are skipped,
like `node_modules` and Python virtualenvs. A key in a single ignored file,
usually a local `.env`, is still reported, but at `low` and marked
`localOnly`, because it is never committed. A committed key keeps its rule's
severity.

Code-execution sinks are looked for in every server code file, not only in
recognized route handlers: `eval` and `new Function` with a non-constant
argument, `node:vm` calls, and `child_process` `exec`/`execSync`. A taint-lite
pass marks request data (`req.body`, `req.query`, `req.params`, headers,
cookies, uploaded files, and those fields destructured from the request) and
every variable assigned from an expression that uses it, within one file. It
has no call graph, scopes or sanitizers, so `likely` means "derived from the
request", not "exploitable". A sink whose arguments carry request data is
`likely`; an `eval` of a value Penthera cannot trace is `potential`. A `vm`
call or a shell command without request data is not reported, since build
scripts and CLIs build commands from their own constants all the time. Tests,
build tooling, browser assets and minified files are skipped.

White-box scanning cannot see runtime configuration (headers added by a CDN, a
WAF in front of the app), secrets injected at deploy time, or anything in
dependencies that is only known from a vulnerability database.

### Combining them

Running both against the same app catches cases neither sees alone: a route
the repository marks as public that the black-box scan confirms is reachable,
or a header the code sets that the edge strips. The report keeps the origin of
each finding (`source`, `method`) so a reader can tell which side produced it.

## Runtime advisories

When a runtime or web server gets a security release, such as the critical PHP
release announced on 20 October 2026 (The PHP Group, 2026), the question is
which systems run an affected version. Penthera answers it from two kinds of
evidence and says what it cannot know. The code is in
[lib/advisories/](https://github.com/danoszz/penthera/tree/main/lib/advisories), and the advisory data is in signed rule
packs ([runtime-advisories.md](runtime-advisories.md)).

### Evidence

**Black-box.** The URL scan reads what the homepage says about itself: the
`Server` and `X-Powered-By` headers, PHP's default `PHPSESSID` cookie name,
and links to `.php` pages or `.php` paths found by endpoint discovery. These
are the signals of WSTG-INFO-02 (fingerprint web server) and WSTG-INFO-08
(fingerprint web application framework) in the OWASP Web Security Testing
Guide (OWASP Foundation, n.d.-b), and the same ones that common fingerprinting
templates use (ProjectDiscovery, n.d.). They are widespread. In a scan of the
top one million websites, over 85% exposed server information in headers,
`X-Powered-By` appeared in 48% of responses and carried the PHP version in two
thirds of those, and `PHPSESSID` was the second most common cookie name
(Lavrenovs & Melon, 2018). PHP adds the version header by default through its
`expose_php` directive (The PHP Group, n.d.-a). Lauinger et al. (2017) took
the same version-based approach for JavaScript libraries on websites.

**White-box.** The repository scan reads what the project pins: base images in
Dockerfiles and compose files, `.tool-versions`, `.php-version`, `.nvmrc`,
`.python-version`, `runtime.txt`, and `composer.json`. An exact image tag
(`php:8.3.12-fpm`) names an upstream build. A floating tag (`php:8.3`) names
only a release line, and `composer.json` only says that PHP is in use.

### Verdicts

Each product and version gets one of four answers:

| Verdict | Evidence | Severity, confidence |
|---|---|---|
| Affected | An exact upstream version below the first fixed version on its line | The vendor's severity; `likely` from a pinned image or version file, `potential` from a banner that names no distribution |
| End of life, no fix | A version on a line the vendor no longer supports | The advisory's severity, `potential`; plus an end-of-life finding |
| Check on server | The product is in use, but the version is hidden, floating, or a distribution build, or the advisory lists no fix for that line | Medium, `needs-human-review` |
| Has the fix (as advertised) | The visible version is at or above every fix | Info |

No evidence gives no answer, and the report never treats that as safe.

Four choices keep the verdicts honest.

**A hidden version is unknown, not safe.** Removing or changing the `Server`
header does not stop identification. Lee et al. (2002) identified web servers
even where the server information was omitted, and Kar et al. (2022)
fingerprinted servers regardless of the mitigation applied. PHP's manual calls
hiding PHP security by obscurity, a weak measure (The PHP Group, n.d.-a). The
NCSC's guidelines for web applications make the same point: removing the
version number "helpt ten dele" [helps partly], because fingerprinting can
often still reveal it. They also note that researchers use a disclosed version
to warn owners, and ask for a deliberate trade-off (Nationaal Cyber Security
Centrum, 2024). On the day of the PHP release, the NCSC was quoted as saying
that every internet-reachable system containing PHP is presumably vulnerable
until it is updated (NOS, 2026). We found no primary NCSC text for that quote;
its own website was offline as a precaution.

**A distribution build is never "affected".** Debian, Ubuntu and Red Hat fix
security issues by backporting patches into the version they shipped, not by
moving to the upstream release that has the fix (Debian Project, n.d.; Red
Hat, n.d.; Ubuntu Security Team, n.d.). Red Hat and Ubuntu both say that
scanners which judge by version number alone produce false positives for this
reason. Nmap's documentation warns that a version number cannot prove a
service vulnerable, because fixes are backported, and that administrators can
spoof it (Lyon, 2009). Zhang and Qian (2018) describe the same divergence for
downstream Linux kernels and test for the patch itself instead of the version.
So a version with a distribution suffix (`8.1.2-1ubuntu2.19`), or any version
behind a `Server` header that names a distribution, gets "check on server",
with the advice to look up the CVE in the distribution's security tracker. We
found no peer-reviewed measurement of how many false positives backports cause
in version-based scanners. The support for this rule is the distributions' own
statements and the Nmap project's.

**A banner that names no distribution may still be one.** Many distribution
builds print a plain upstream number. Debian 11 to 13, Ubuntu 24.04 and later,
and RHEL put no package revision in PHP's version, Debian's and RHEL's nginx
add no OS token, and distribution Pythons print the plain interpreter
version. Apache httpd is the exception: Debian, Ubuntu and RHEL put the
distribution name in its banner. Penthera's labelled test set of 253 real
version strings found 14 such builds
([#97](https://github.com/danoszz/penthera/pull/97)). So for PHP, Apache
httpd, nginx, Python and OpenSSL, an "affected" or "end of life" answer from
a banner without a distribution token is capped at `potential`, with a note to
check on the server. The severity is unchanged, because an upstream build at
that version really is exposed. An official Docker image or a version file
pins an upstream build and stays `likely`. Node.js sends no version banner, so
the cap never applies to it.

**A version match is necessary, not sufficient.** Many advisories need more
than a version. CVE-2024-4577, an argument injection in PHP-CGI, only
affected PHP running as CGI on Windows, and DEVCORE (2024), who found it,
confirmed exploitation under specific Windows code pages. Its 2012
predecessor did not affect mod_php or php-fpm at all (The PHP Group, 2012).
Censys (2024) counted about 458,800 exposed PHP instances by version and called
that count likely an overestimate, because a scan cannot see whether CGI mode
is on. Durumeric et al. (2014) made the same observation for Heartbleed: an
early estimate taken from Apache and nginx market share probably overstated
the vulnerable population, which they measured with an active protocol probe
instead. A rule can therefore carry a `condition`, and a finding from such a
rule never goes above `potential`.

**"Has the fix" is information, not a clean bill of health.** A banner can be
stale, a proxy can rewrite it, and fixes themselves can be incomplete. Li and
Paxson (2017) found that 7% of the security fixes they studied failed to
remediate the issue completely. CVE-2024-4577 is itself a bypass of the fix
for CVE-2012-1823 (The PHP Group, n.d.-b).

### Advisory data

Advisories and end-of-life lines are data, not code, so a new advisory can be
published as a signed pack and used the same day with `--rules`, without a
release (see [How new attack techniques are adopted](#how-new-attack-techniques-are-adopted)).
Speed matters here. Fix commits are often public weeks before the advisory
(Li & Paxson, 2017), deployment of patches lags far behind their release
(Nappa et al., 2015), and a working analysis of CVE-2024-4577 was public a day
after the fix.

Each rule copies its affected and fixed versions from the vendor: the php-src
security advisories (The PHP Group, n.d.-b), the Apache HTTP Server
vulnerability list (The Apache Software Foundation, n.d.), and for later packs
the nginx and OpenSSL advisory pages (nginx, n.d.; OpenSSL Library, n.d.).
Fixed versions are recorded per release line, because vendors patch each
supported line separately and a single range would misclassify versions on
other lines. That is the same per-line shape that the OSV format uses for its
`introduced` and `fixed` events (Chang & Cox, 2026). Severity is the vendor's,
with the CVSS score where the vendor gives one (FIRST, 2023). The CISA Known
Exploited Vulnerabilities catalog, which is CC0-licensed, is a candidate source
for an exploited-in-the-wild flag (Cybersecurity and Infrastructure Security
Agency, n.d.).

End-of-life lines come from each vendor's support page (MongoDB, Inc., n.d.;
OpenJS Foundation and Node.js contributors, n.d.; Python Software Foundation,
n.d.; The PHP Group, n.d.-c), cross-checked against endoflife.date
(endoflife.date contributors, n.d.). MongoDB is the one database in the pack:
it has no HTTP banner, so it is checked only where a repository pins it (the
official `mongo` image in a Dockerfile or compose file, or `.tool-versions`). A line counts as ended only when its end date is on or before the
date of the rule, so the same scan with the same packs gives the same result on
any day.

The NCSC-NL publishes signed advisories in the CSAF 2.0 format (Nationaal
Cyber Security Centrum, n.d.; Rock et al., 2022). We checked whether they could
drive version matching. They cannot: most 2025 and 2026 entries record the
affected version as unknown and refer to the vendor's page, and the feed has
no open license. Penthera uses the vendor pages directly and cites the NCSC
guidance in the methodology instead.

### What this does not claim

Penthera judges known vulnerable versions, not age. Outdated software is not
simply more likely to be compromised: in a case-control study of hacked
webservers, sites running outdated WordPress were less likely to be compromised
than up-to-date ones (Vasek et al., 2016). An end-of-life finding is about the
absence of future fixes, not about current compromise. The scanner also does not
notify third parties. It reports to the owner who runs it, because
notifications sent to site operators mostly do not arrive (Stock et al., 2016).

## Confidence model

Severity says how bad a finding would be if real. Confidence says how likely it
is to be real. Penthera reports both and never lets a heuristic look like a
fact. The labels are defined in [lib/provenance.js](https://github.com/danoszz/penthera/blob/main/lib/provenance.js):

| Label | Meaning | Typical sources |
|---|---|---|
| `confirmed` | Deterministic evidence. The header is absent, the certificate expired, the key matches a provider format. | Header audit, TLS check, cookie audit, secret scan, OpenAPI exposure |
| `likely` | A strong signal with a small false-positive chance. | Injection probes with a verified canary, auth and JWT probes, framework checks |
| `potential` | A heuristic or one-shot signal that needs corroboration. | Fuzzer, adaptive probes |
| `needs-human-review` | Exploitability cannot be judged from outside. | IDOR/BOLA, client-side-only auth |

Every finding also carries `source`, `method`, and `collected_at`. These travel
into SARIF, so the label survives into GitHub code scanning.

The benchmark reports precision per confidence label, which tests whether the
labels mean what they say. On the current run, all `likely` and
`needs-human-review` findings were true positives and the one `potential`
finding was a false positive. The two `confirmed` false positives are cases
where the evidence is real but the judgment is wrong: a health endpoint that
is public by design, and AWS's published example key. See
[bench/RESULTS.md](https://github.com/danoszz/penthera/blob/main/bench/RESULTS.md).

### Findings proposed by a model

`penthera verify` reads findings that a model proposed elsewhere, for example
an AI security audit run with Cloudflare's security-audit skill in a coding
agent (Cloudflare, 2026). Language models find real issues that rules do not
describe, but on realistic benchmarks their vulnerability detection is far
less reliable than headline numbers suggest (Ding et al., 2025). So a model's
finding never gets a confidence label on its own authority. It counts as
`confirmed` or `likely` only through a Penthera rule that flags the same kind
of issue in the same file; the rule's finding is then the record. Everything
else is `needs-human-review`, labelled "model-proposed, unverified", kept apart
from rule findings, and never changes the exit code. A rule that ran and did
not fire does not count against a model's finding, because rules have false
negatives too. How often model findings are confirmed, and how precise each
group is, is not yet measured; a planned experiment (E9) will measure it on
the E1 corpus.

## False-positive controls

A black-box scanner loses trust through false positives faster than through
misses. The probes apply these controls:

- **Randomized canaries.** The SSTI probe multiplies two random four-digit
  numbers and looks for the seven- or eight-digit product, and only when
  neither the raw payload nor the literal expression appears in the response
  ([lib/injections.js](https://github.com/danoszz/penthera/blob/main/lib/injections.js), `buildSstiProbes`). The common
  fixed canary `7*7 = 49` fires on any page that happens to contain "49". XSS
  probes use a random reflection marker per probe (`makeCanary`).
- **Context before payload.** The XSS probe first checks where its marker is
  reflected (HTML body, attribute, or script), sends only payloads that would
  execute in that context, and then checks that they came back unencoded.
  Context-aware tools such as Dalfox take the same approach.
- **Baseline comparison.** Error-based SQL injection is reported only when the
  database error appears in the injected response and not in the baseline.
- **Format, not keyword.** Exposure templates match the format of what they
  look for, not a word that might appear in any page. The Prometheus template
  needs both a `# HELP` and a `# TYPE <name> <kind>` line and no HTML, so a
  single-page app that answers `/metrics` with its index page does not match.
  A directory listing needs the listing in the page title (`Index of /`,
  `listing directory /`, `Directory listing for /`) or IIS's
  `[To Parent Directory]`. A stack trace needs a runtime's frame shape with a
  file and line number (V8, Python, Java, PHP, .NET), not just the word
  "error". The listing check reads the plain folder paths in `robots.txt`
  (no wildcards, at most 20) plus a short list of common upload and backup
  folders; the stack-trace check requests a path that does not exist. Both
  send only `GET`s without payloads.
- **Timing re-sampling.** A single slow response proves nothing: garbage
  collection, cold starts, and network jitter all look like an injected sleep.
  Time-based SQL and command injection candidates are re-sent and reported only
  when the median delay holds (`confirmTimingDelay`). Crosby et al. (2009)
  showed that network jitter dominates single remote timing measurements and
  that filtering over many samples is what makes them usable, building on the
  original timing attacks of Kocher (1996). Penthera's injected delays are
  seconds, not microseconds, so a median of three samples is enough.
- **Host-checked redirects.** An open redirect is reported only when the
  `Location` header resolves to the attacker host, not when the payload merely
  appears in the query string of a same-site redirect.
- **Context-aware suppression.** On localhost and private hosts, findings that
  do not apply there (no HTTPS, missing `Secure` on cookies) are suppressed.

The benchmark's decoy target exercises each control with an endpoint built to
fool a naive scanner. Writing it exposed one real flaw in the decoy itself: a
"safe" redirect that accepted `/\evil.com`, which browsers treat as
`//evil.com`. Penthera reported it correctly.

## Non-destructive by default

The `quick` and `standard` profiles send only requests a normal browser or API
client would send: `GET` and `OPTIONS`, plus, in `standard`, one `POST
/api/login` with invalid credentials and no payload (`quick` sends no login
request). They do not send attack payloads, create or modify data, or exploit
anything they find.

Payload-based testing (`--deep`, `--fuzz`, `--adaptive`, `--all`, or
`--profile deep`) is opt-in, and it does not start without a confirmation
bound to the target's hostname. In a terminal, Penthera asks: a target on this
machine needs a yes, and any other target needs its hostname typed back, the
same rule as the dashboard. A non-interactive run (CI, Docker, piped, `--json`)
must pass `--confirm-target <host>`, and the run stops with exit code 2 when it
is missing or names another host. Active scans are also capped at 10 requests
per second unless `--rate` says otherwise (`src/cli/active-gate.js`). The
login rate-limit burst and the SQL error check on `/api/login` run only under
`--deep`, behind the same gate. Even then, each probe sends a benign marker (a random string, an arithmetic expression, a short sleep, `id`)
rather than a working exploit, and stops at the first confirmation per
endpoint. The adaptive engine may send unexpected HTTP methods, including
`DELETE`, to routes with placeholder IDs, so it is never part of a default run.

This follows the principles of fail-safe defaults and least privilege set out by
Saltzer and Schroeder (1975): the default does the least that is still useful,
and anything riskier needs an explicit decision. NIST SP 800-115 draws the same
line between non-intrusive assessment and penetration testing, and recommends
written rules of engagement before the latter (Scarfone et al., 2008).

## Offline and no telemetry

Penthera does not phone home. It sends no usage data, analytics, or crash
reports, and it has no accounts. Reports are written to local files.

Network traffic goes to the target you name, with the exceptions below. The
full list of hosts is in [privacy.md](privacy.md):

1. `--recon` (and the `deep` profile) queries public OSINT sources (crt.sh, the
   Wayback Machine, AlienVault OTX) with the target domain. It is skipped for
   localhost.
2. The Retire.js check downloads the public Retire.js vulnerability database
   from GitHub and compares JavaScript library versions locally. Outdated
   client-side libraries are common on the web and often carry known
   vulnerabilities (Lauinger et al., 2017). The database is data, not code: it
   is parsed as JSON and never executed. It is the one place a detection input
   arrives at run time. Under `--offline`, and whenever the download fails,
   Penthera uses the snapshot vendored in the release instead. When a script's
   version can only be read from its contents, the check also fetches that
   public script from its CDN (not under `--offline`).

The benchmark enforces offline operation mechanically. It wraps `fetch` so any
request to a non-loopback host is refused and counted, and it fails if the
count is not zero.

These choices follow the principles of economy of mechanism and complete
mediation (Saltzer & Schroeder, 1975): fewer network paths mean fewer things to
audit, and a tool that talks only to its target is easy to reason about in a
regulated environment.

## How new attack techniques are adopted

Attack techniques change quickly. Recent examples include indirect prompt
injection against LLM-integrated applications (Greshake et al., 2023; Liu et
al., 2023; Perez & Ribeiro, 2022), package hallucination and slopsquatting
(Spracklen et al., 2025), and attacks on agent tooling and MCP servers,
catalogued by OWASP (OWASP Foundation, 2024, 2025a, 2025b) and in MITRE ATLAS
(The MITRE Corporation, n.d.-b). A scanner that does not keep up gives a false
sense of security.

Penthera keeps up through reviewed releases, not live updates:

- **Rules ship as code in a release.** New probes, patterns, and templates are
  added by pull request, reviewed, tested against the benchmark, and published
  in a versioned release with a CHANGELOG entry. There is no rule server, no
  background update, and no command that fetches rules from the internet.
- **Detection data ships as signed rule packs.** Patterns and IOC lists that
  are data rather than logic (key formats, malicious package versions, exfil
  hosts) live in versioned packs under `lib/rules/`. Each pack is signed with
  the maintainer's SSH key, which never enters CI. Every file is hash-pinned,
  and every regex must pass a ReDoS guard before it loads. The publish workflow
  refuses to stage a release with an unsigned bundled pack. You can add your
  own packs by path (`--rules <dir>`), never by URL. See
  [rule-packs.md](./rule-packs.md).
- **Every new rule carries a source and a date.** A rule added after v1.2.0
  records where the technique comes from (a paper, an advisory, an OWASP or
  ATLAS entry, an incident write-up) and the date it was added. Finding
  categories are already linked to their sources in
  [lib/references.json](https://github.com/danoszz/penthera/blob/main/lib/references.json); the built-in rules that
  predate this policy are being backfilled.
- **Every new rule comes with a benchmark case.** A detection rule is added
  together with a labeled true positive and, where a false positive is
  plausible, a decoy in [bench/](https://github.com/danoszz/penthera/tree/main/bench). The CI floor in the benchmark
  stops a rule that adds false positives.
- **Your own templates stay local.** `--nuclei <path>` and `--templates <dirs>`
  load YAML templates from directories you choose. Penthera does not download
  them.

Why not update automatically? A rule feed is a code path from someone else's
server into a tool that runs with your network access and often your
credentials. Supply-chain research shows that update channels and package
registries are exactly where attackers insert themselves (Ladisa et al., 2023;
Ohm et al., 2020; Zimmermann et al., 2019), and that securing an update channel
needs signed metadata, key rotation, and explicit trust delegation (Samuel et
al., 2010; Torres-Arias et al., 2019). Shipping rules inside the signed,
versioned package reuses the trust you already place in the release, and gives
a clear audit trail: the rules you ran are the rules in the version you
installed.

## Citations in reports

Each finding category maps to one to three references in
[lib/references.json](https://github.com/danoszz/penthera/blob/main/lib/references.json), chosen to explain why the
finding matters. Besides the sources discussed above, these include the
empirical work behind specific header and policy checks: Content Security
Policy (Weichselbaum et al., 2016), cookie handling and cross-site request
forgery (Barth et al., 2008), and CORS misconfiguration
(Chen et al., 2018). Email authentication findings cite the SPF and DMARC
specifications (Kitterman, 2014; Kucherawy & Zwicky, 2015). Injection,
exposure, and configuration findings cite the OWASP Top 10 (OWASP Foundation,
2021, 2025c), code-pattern findings cite the Common Weakness Enumeration (The
MITRE Corporation, n.d.-a), and license findings use the identifiers of the
SPDX License List (SPDX Workgroup, The Linux Foundation, n.d.).

The references appear in two places:

- in the Markdown report, as a "Why this matters / Sources" line under each
  finding and a "Sources" line under each action-plan item;
- in SARIF (Fanning & Golding, 2023), as the rule's `helpUri` (first source)
  and `help` text (all sources), and as `properties.references` (the BibTeX
  keys).

[references.md](references.md) and the `sources` block of `references.json`
are generated from [references.bib](https://github.com/danoszz/penthera/blob/main/docs/references.bib) by
`node scripts/build-references.mjs`, and a test fails if they drift.

## Known limitations

This section states what Penthera cannot do and how far its evidence reaches.
It is meant to be read before relying on any result. Challenges and additions
are welcome (see [MANIFESTO.md](MANIFESTO.md)).

### What the scanners cannot see

- **URL scanning.**
  - No authenticated crawling beyond the bearer token or cookie you pass, so
    pages behind multi-step flows are not reached (Doupé et al., 2010).
  - No stored or second-order injection testing (Bau et al., 2010).
  - The CVE-2025-29927 check reports when its header steadily changes the
    answer. It misses a login page with a fresh token that turns into another
    HTML page, because that page already differs from itself. It can still
    fire falsely on an unstable site. In stub tests of quick scans, a
    single-page app that answers 503 on 25% of requests fired on about 2% of
    runs, and at 50% on 6.3% of 2,000 runs. Two builds picked at random per
    request fired on 13.3% of 1,000 runs. A steady limiter or round robin that
    passes about one request in three can line up with the request order and
    fire too.
  - The Next.js debug endpoint check takes its proof from the target's site.
    There is no public suffix list, so two sites on a shared host such as
    vercel.app count as one site.
  - No DOM-based XSS analysis, because Penthera does not run JavaScript (Lekies et
    al., 2013; Stock et al., 2014).
- **Logic and authorization.** No business logic testing. IDOR/BOLA findings are
  heuristics that need a human to confirm them.
- **Secrets.** Detection is pattern-based and skips Markdown and other
  documentation files, so unprefixed secrets and secrets in notes are missed.
- **Dependencies (`deps`, `install`).**
  - Analysis is static. Behavior that is only decided at run time (code
    fetched or decrypted on execution, heavily obfuscated or minified bundles,
    logic inside native binaries) can be reported as a capability or as
    "unscanned", but not understood.
  - A package that hides its intent well can look ordinary.
  - The typosquat list and the vendored data are snapshots and age between
    releases.
- **AI tooling (`agents`).**
  - Rules recognize known patterns of hidden content and risky configuration.
  - A new phrasing of a prompt injection, or a malicious skill that behaves
    normally until a later update, can pass.
  - `penthera.lock` detects changes after you pin, not malice present before.
- **Fix loop.**
  - A fix counts as verified when the finding disappears and the project's own
    tests pass. Weak or missing tests mean weak verification.
  - Built-in recipes cover a handful of frameworks and finding types.
- **Runtime advisories.**
  - Only the homepage response is fingerprinted, so a PHP backend behind a CDN
    or reverse proxy that strips headers is invisible from outside.
  - The answers are only as current as the packs. An advisory published after
    the last pack is not checked until a new pack is loaded.
  - Distribution builds always need a check on the server; Penthera does not
    read distribution security trackers.
- **Live AI features.** LLM endpoint checks (rate limits on chat endpoints,
  exposed model servers) are not yet available.

### How far the evidence reaches

- **Small sample.** The bundled benchmark scores 24 findings. Precision 0.88 and
  recall 0.91 come with wide 95% Wilson intervals (0.69 to 0.96 and 0.73 to 0.98), so
  small changes in either are not meaningful.
- **Built by the same team.** The benchmark targets, their labels, and the
  scanner were written by the same people, so the numbers measure regressions
  and the false-positive controls, not accuracy on arbitrary applications.
  Independent benchmarks such as the OWASP Benchmark (OWASP Foundation, n.d.-a)
  and the benchmarking approach of Antunes and Vieira (2010, 2015) are the model
  for a fairer comparison.
- **Possible overfitting.** Probes were tuned while looking at these targets, so
  they may perform better here than elsewhere.
- **Single labeler.** Ground truth was labeled without a second, independent
  labeler, so label errors are not measured.
- **Recall is only partly known.** Recall counts misses of issues we planted. On
  real code, the full set of issues is unknown.
- **No head-to-head comparison** with other tools under the same conditions has
  been run.
- **Confidence labels are not calibrated.** The labels (confirmed, likely,
  potential, needs human review) are expert judgment about each probe's
  method, not measured probabilities. Severity mappings are judgment too.
- **References support the design, not the outcome.** The literature cited here
  explains why each choice was made. It does not show that Penthera's
  implementation achieves what the cited work describes. Some incident
  descriptions in the docs rely on vendor and industry reports that were not
  independently verified.
- Measuring real-world accuracy with an independent, pre-registered study is the
  first goal of the [research plan](vision-2.0.md#research-program) (experiment E1).

### Reproducibility

- Timing-based probes depend on network and machine load. Results can vary
  between runs, and the confirmation rules trade some sensitivity for stability.
- Benchmark runs are seeded, but live scans of real applications are not
  deterministic, because the applications are not.
- The full test suite can be flaky on a heavily loaded machine. CI runs it on
  clean runners.

### How it is built

- Most of the code (107 of 117 non-merge commits up to v1.7.0) was written with
  generative AI under the maintainer's direction ([details](genai.md)).
- Generated code passes the same tests, static analysis, and release gates.
  But it has had less line-by-line human scrutiny than hand-written code would.
  An independent review on 2026-10-19 found and fixed three high-severity bugs,
  and no external security audit has been done yet.

### Compliance output

Compliance output for the NIS2 Directive (European Parliament and Council of the
European Union, 2022) and the Cyber Resilience Act is evidence toward a duty of
care, not a certification and not legal advice.
