# E20-R: Is the front-door gap real, and what do bot challenges hide? (pre-registration)

| | |
|---|---|
| Experiment | E20-R, a follow-up to [E20](E20-front-door.md) |
| Status | **Registered.** By the maintainer, through the commit that merges this version to `main`. The runs start no earlier than 12 hours after the study page is live |
| Date written | 2026-10-30 |
| Authors | Daan van der Zwaag (PI). Drafted with Claude (AI-assisted) |
| Conflict of interest | The PI maintains Penthera, and the instrument is its live check. The study serves Penthera's interest in showing why such checks matter. See § 8 |
| Data collected before registration | The E20 results of 30 Oct 2026 are known, and every prediction below was written after seeing them. The new cohorts are unseen. The new instrument is tested on loopback only |
| Independent review | AI review of the E20 draft (figures, statistics), 30 Oct 2026. No human review |
| Vantage point | Pass 1: rented server: Hetzner Cloud, Falkenstein, `research.penthera.org`, 2.31.141.178, IPv4 only. Pass 2: the Source address row, Amendment 2. The address is published. The maintainer's home connection is not used |
| Runs | Pass 1 no earlier than 12 hours after the updated study page is live, pass 2 seven days later |
| Amendment | **One pass only.** Amendment 1 (30 Oct 2026, before any data) replaces every mention of pass 2 below. See the end of this file |
| Amendment 2 | **Adopted.** 31 Oct 2026, effective through the commit that merges this row to `main`. E20-R2, a prospective corrected remeasurement after the pass 1 data was seen. See the end of this file. The runner refuses a pilot or pass 2 unless this row says Adopted |
| Amendment 3 | **Draft.** Not adopted. E20-R2 after a false stop: a detector fix, withheld text, an audit-quality rule, a stated deviation, pilot round 2, and pass 3. See the end of this file. The runner refuses pilot round 2 and pass 3 until this row says adopted. |
| Source address | `178.104.243.225` |
| Prior opt-outs SHA-256 | `e25d88b24aa1d4122cd78e65af9c8febfd9f7309959ae1ae89446ccc90b07126` (`prior-optouts.txt`, 95 sites) |
| Pass 1 raw SHA-256 | `ef791bee6c9598880af6da7f11db023e96e6d75b219670e45317ee9575e453dd` |
| E20 Tranco raw SHA-256 | `09242bca6880b4a5dd9be57947806fd08105a7afa3499c0a4e21ced38dd60469` |
| E20 YC raw SHA-256 | `b5a98cc266b232e63eee8864198dc961ffe21133fdbf43a51069acf2fcaf0391` |
| Industry map SHA-256 | `78df4910d953379f21d935aeb3ef658d85cbef036539e1a31362c9ad7e26e075` |
| E20 exclusion file SHA-256 | `246127f639968afc906d59f155f6a993982f3a33c0655718234955319ebe4c34` |
| Legacy classifier SHA-256 | `7023106f7bd73c1e4122d80e9479f63a4a04091f1426327be70621951fe71d3b` (`bench/front-door/legacy/classify-7023106f.mjs`, the detector that stopped pass 2) |
| Frozen classifier SHA-256 | `ffd44cf9df79d0de10079cbe9e367420226c5034a0ee4a78461cd474419a8ed7` (`bench/front-door/classify.mjs`) |
| Public Suffix List SHA-256 | `d3e6243b51695327984abb3e2a5aa7077096867f75121e031e6a5a3840ca8bcd` (commit `9dfbe81931367b3f0af21035c36ae7eeb830dd88`, fetched 30 Oct 2026, private suffixes included) |
| Registration commit | The commit that merges this file to `main` |
| T1k list SHA-256 | `d670a3c1910fe7baa4883dcb8320b1ec99d7d29f9d22954b9288ae678540674e` (`tranco-ZJ8PG-top1000.csv`) |
| YC-new list SHA-256 | `13df01eb681993205e89c00322db972e5137d3c4a95ec982d40a2552f415dd7f` (`yc-fall2026-summer2026-2026-10-29.csv`) |
| YC-25 list SHA-256 | `f3fed354eb7bf0e016e682a348c345401d94c27cfa72ad01bab36d935e2ffa5a` (`yc-2025.csv`) |
| YC-old list SHA-256 | `e90c52ba0c09e04613944c34c20329c77eb064cda63de0dc2c413e827a57f761` (`yc-old.csv`) |
| YC-scale list SHA-256 | `654211e16c92e99cad006a5e35b05198f2bb35a7072afa18d19047c40520568c` (`yc-scale.csv`) |
| T10k list SHA-256 | `21c63bd12c68dac11df79bc2f67a09ea8cf8c778640611ad1b170fcae4ecfb3f` (`tranco-ZJ8PG-1k-10k-sample.csv`) |
| T100k list SHA-256 | `bb6d767786a53337ade7e9cb76304d62a4f0adae0518b5aa2c7210f1b3901002` (`tranco-ZJ8PG-10k-100k-sample.csv`) |
| Europe list SHA-256 | `057dcd65db61bdbd246c3910b3be2f40d468c3bff2036e236357935584663234` (`europe-indexes.csv`) |
| SP500 list SHA-256 | `e788b76c67f77fb498951a83833b96b6195138e4f8e6f1cc266ee3a45feb1dc9` (`sp500.csv`) |
| ShowHN list SHA-256 | `050521c6aabc95975320cd1dea143d410e382987ab7377b7c7756925eded1d10` (`showhn-sample.csv`) |
| NL-Cbw list SHA-256 | `0349db735b483b0786bc7a51e687639c8385fee04e467f5ef688bcca3a8dbb1c` (`nl-cbw.csv`) |
| E20-R exclusion list SHA-256 | `b636ab5e761e7266bf6dea56383a1db84610a91884f34d8dcf3e5f978aa712c5` (`exclusions-e20r.txt`, 245 entries) |
| E20-R homepage-only list SHA-256 | `111fde7e8b59af7fe197a10cde7f2954396f76703c2e839d8393741bb2f2f6e4` (`health-homepage-only.txt`, 331 hosts) |
| Dataset | Confirmed by the maintainer, 30 Oct 2026: 7,031 unique sites on eleven lists |
| Cost | About €2 of server time |

## Abstract

**Question.** E20 found that recent startups less often send a CSP and publish
an enforcing mail policy than the most popular sites. It also found that about
a third of homepages answered with HTTP 403, which we could only interpret as
bot challenges. E20-R asks whether those gaps replicate, whether they reflect
company age or popularity, how many responses are really challenges, and how
stable the measurements are.

**Method.** Two passes, seven days apart, from one published server address over
eleven fixed lists: the Tranco top 1,000, the newest YC batches (both as in E20),
the two 2025 YC batches, older YC batches, seeded random samples of 1,000 from
Tranco ranks 1,001 to 10,000 and 10,001 to 100,000, large listed companies from fifteen European stock indexes
and the S&P 500, larger YC companies, a sample of public Show HN launches,
and Dutch organizations in sectors of the Cyberbeveiligingswet (all secondary only).
The grader is unchanged. The instrument now also stores header names and a body
hash, and a fixed rule set classifies each response. Fifteen confirmatory claims
use organization-level bootstrap intervals with a Bonferroni correction.

**Result.** None yet.

**Limits.** A datacenter address may be treated differently from a home
connection, and the comparison with E20 is not concurrent. Older YC batches keep
only companies still listed as active, so they carry survivorship bias. Passive
checks at the front door say nothing about a company's application security.

## 1. Why, and what the E20 review changed

The independent review of the E20 paper found five weaknesses that more data can
address. Each maps to a part of this design.

| Weakness in E20 | Design answer in E20-R |
|---|---|
| "403 means challenge" was assumed | A fixed classifier with stored evidence (§ 4.2) |
| HTTP-layer gaps depended on the edge mix | Two named estimands and stratified claims (§ 6) |
| Cohorts differ in age, popularity and era at once | Older YC batches and a less popular Tranco sample (§ 3) |
| One moment, cohorts run one after the other | Two passes, seven days apart, in one shuffled order (§ 5) |
| One home connection | One published datacenter address, compared with E20 (§ 7) |

More sites alone would not fix the first two, because a narrower interval around
a confounded difference is still confounded.

## 2. Estimands

We name two, and neither is "the site's true configuration".

- **Served (S).** What a declared, non-browser research client receives at the
  listed homepage, for every graded site.
- **Real page (R).** The same, among sites whose response the classifier in § 4.2
  labels `page`. This is a selected subset, because it drops sites that challenge us.

DNS checks do not depend on the response, so they use S alone. An HTTP claim is
**supported** only when both S and R support it. When they disagree, it is reported
as **view-dependent**, a fourth outcome next to refuted and inconclusive.

## 3. Targets

Each list is hashed before any run, and the hashes are in the table above. The new list files stay off the repository until the results, because they hold the health domains that § 8.1 redacts; the redacted versions are published with the results. Each cohort uses the E20 rules:
hostname only, one record per listed domain, and `NOT_A_HOMEPAGE` hosts skipped.

| Cohort | Source | Rule | Listed |
|---|---|---|---|
| **T1k** | E20 list `ZJ8PG` | Same 1,000 rows | 1,000 |
| **YC-new** | E20 list | Same 416 rows | 416 |
| **YC-25** | `yc-oss/api` at the E20 commit `5a217b8` | Summer 2025 and Winter 2025: every company with status `Active` and a website | 159 + 158 = 317 |
| **YC-old** | `yc-oss/api` at the E20 commit `5a217b8` | Summer 2024, 2022, 2020 and 2018: every company with status `Active` and a website | 233 + 180 + 121 + 77 = 611 |
| **Europe** | Public constituent lists of 15 indexes (Germany, France, UK, Netherlands, Spain, Italy, Switzerland, Sweden, Finland, Denmark, Norway, Portugal, Belgium, Austria, Ireland), with each company's main corporate domain | One record per company. **Secondary only**: no claim uses it | 490 |
| **YC-scale** | `yc-oss/api` at the E20 commit | `Active` or `Public`, a website, at least 50 staff, not on another YC list. A stand-in for real revenue: **MRR is not known**. **Secondary only** | 530 |
| **SP500** | Public S&P 500 constituent list, with each company's main corporate domain | One record per company. **Secondary only** | 496 |
| **ShowHN** | Public Hacker News Show HN posts, 1 Jan 2025 to 1 Oct 2026, at least 20 points | Launches on their own main domain with no subdomain, shared platforms removed, YC sites removed, 1,000 drawn with seed 2020. A non-YC group of small products; many are individuals' projects, and it reports aggregates only. **Secondary only** | 1,000 |
| **NL-Cbw** | Public member and index lists per sector (§ 3.1) | Energy, drinking water, telecom, digital infrastructure, banking, transport, and listed firms in the law's annex sectors. No government, no health. **Secondary only**, homepage only | 268 |
| **T10k** | Tranco `ZJ8PG` full list | 1,000 ranks drawn from 1,001 to 10,000 without replacement, seed 2020. **Secondary only** | 1,000 |
| **T100k** | Tranco `ZJ8PG` full list | 1,000 ranks drawn from 10,001 to 100,000 without replacement, seed 2020 | 1,000 |

7,031 unique sites in all; example.com and www.example.com count as one site. A host on two lists is visited once per pass and counted in both. We expect about 650 graded in T1k and in T100k, about 400
in YC-new, about 300 in YC-25 and about 560 in YC-old. **YC-recent** below means
YC-new and YC-25 together.

**Why these older batches.** One summer batch every two years gives a spread of
company ages while keeping the season fixed, and YC-25 fills the gap between the
newest batches and the two-year-old ones. Only `Active` companies count, because a
closed company's domain says nothing about a company of that age. That choice is
a survivorship bias, which we state next to every age result.

### 3.1 NL-Cbw

The Cyberbeveiligingswet and the Wet weerbaarheid kritieke entiteiten took effect
on 15 August 2026, and cover about 8,000 organizations in 18 sectors, of which about
500 are critical entities. The register of covered organizations is not public, and
we make no attempt to reconstruct it. Companies decide for themselves whether they
are covered, so this cohort is **organizations in Cbw sectors**, never "covered by
the law". One snapshot after the law took effect shows nothing about its effect,
because no earlier measurement exists.

Extra limits apply to this cohort:

- homepage only: the runner never follows an app or login link for these hosts, also
  when a host is on another list;
- every member of a public list goes in, with no hand-picking;
- results by sector only for groups of at least 20 sites;
- only the list's hash and method are published, not the file.

If a passive check ever shows a real security risk at a site in the study, the
maintainer reports it privately following the NCSC's coordinated vulnerability
disclosure rules: the owner first, through security.txt or a published contact,
and the NCSC as intermediary if that fails, or directly for Dutch central
government systems. Findings stay private until fixed, and we do no more than the
check already did. We send no other notice to the NCSC, by the maintainer's
decision. The NCSC's own rules say that missing HTTP headers and version numbers
usually do not qualify, so we expect no reports from this study.

**Same rows for T1k and YC-new.** A site that opted out or asked for removal since
E20 is dropped. None has so far.

## 4. What is sent, and what changes in the instrument

The requests are those of E20 § 4: robots.txt, one homepage, security.txt, public
DNS, and one same-site app or login page where linked. Two public DNS lookups are
new, MX and NS, stored only as a provider label. The rate is the same: 4
workers with a 1-second pause, enforced in code. The user agent stays
`Penthera-Research/E20` with the study URL, and the robots.txt opt-outs apply.

**Unchanged:** every check and every weight in the grader. Scores stay comparable
with E20.

### 4.1 New evidence stored

For each homepage, robots.txt and security.txt response, the runner also stores:

- response header names, plus the values of a fixed list of edge and challenge
  headers;
- cookie **names** only, never values;
- the SHA-256 of the body;
- for a response outside 2xx only, the first 4 KB of the body, kept privately for
  the classifier and the labeling in § 4.3, and deleted with the raw data.

Bodies of 2xx pages are never stored. This is a change from E20 § 8.7, which is why
the study page must say so before the run.

### 4.2 Response classifier (deterministic, frozen before the run)

Each homepage response gets one label from fixed rules in code, tested on fixtures:

| Label | Meaning | Evidence, in order |
|---|---|---|
| `challenge` | An edge network tests the client | `cf-mitigated: challenge`, `x-amzn-waf-action: challenge`, `x-vercel-mitigated: challenge`, or a known challenge body signature |
| `block` | An edge network or firewall refuses the client | A known block body signature or edge error page, without a challenge marker |
| `origin-error` | The site itself answers with an error | Status 400 or above, no edge marker |
| `page` | A normal page | Status under 400, no challenge or block marker |

A 2xx response with a challenge marker counts as `challenge`. This is the known
gap in E20's status-code filter. The signature list is fixed at registration and
published. Cloudflare's own documentation says the status code alone is unreliable,
so the marker comes first.

**No model decides a label** (AGENTS.md rule 4). A model acts only as a second
labeler in § 4.3, and its labels never change a finding.

### 4.3 Validation sample

150 responses from pass 1, drawn with seed 2020 and stratified by label and edge,
with `challenge` and `block` oversampled. Two labelers work independently from the
stored evidence alone, with no new visits: the maintainer, and an AI agent as
second labeler, disclosed as such. They label the response class, and whether the
grader's outcome on three header checks matches the stored headers.

We report Cohen's kappa and the classifier's precision and recall against the
adjudicated labels. A human and a model are a weaker pair than two people, and the
results say so.

## 5. Procedure

- **Order.** One shuffled order across all cohorts, seed 2020, so that time is not
  confounded with cohort. Pass 2 uses a new shuffle, seed 2021.
- **Passes.** Pass 1 no earlier than 12 hours after the updated study page is live, as
  in E20, and pass 2 seven days later at the same hour of the day. Running close to
  E20 keeps the comparison with E20 (C12, C13) as free of time as it can be. One pass takes about 2 to 3 hours.
- **No retries.** A failure is recorded by code.
- **IPv4 only**, so that one published address accounts for every request.

## 6. Hypotheses

Fifteen confirmatory claims, written after seeing E20 and based on the sources
named. Each is a claim about new data. T1k and YC-new were seen in E20, so C1 to C4
are replications. Directions come from E20 or from the literature.

| # | Claim | Check | Prediction | Basis |
|---|---|---|---|---|
| C1 | YC-new minus T1k | `csp` | Lower | E20: −24.2 |
| C2 | YC-new minus T1k | `spf+dmarc` | Lower | E20: −34.9 |
| C3 | YC-new minus T1k, Cloudflare and Akamai sites | `https+hsts` | Lower | E20 post hoc: −18.0 |
| C4 | YC-new minus T1k, all other sites | `https+hsts` | Higher | E20 post hoc: +33.1 |
| C5 | T100k minus T1k | `csp` | Lower | Popularity gradient (Van Goethem et al., 2014; Lavrenovs and Melon, 2018) |
| C6 | T100k minus T1k | `spf+dmarc` | Lower | Hu and Wang (2018): falls with rank |
| C7 | YC-recent minus T100k | `spf+dmarc` | **Higher** | Länge et al. (2026): about 55% valid DMARC on the top 100,000, 47% of those enforcing, so about a quarter enforcing against 39.7% for startups in E20 |
| C8 | YC-recent minus T100k | `https+hsts` | Higher | Gray-literature data: about 31% across the top million (Helme, 2026) |
| C9 | YC-recent minus T100k | `csp` | Lower | Gray-literature data: about 21% across the top million |
| C10 | YC-old minus YC-new | `spf+dmarc` | Higher | Mail set-up matures with a company |
| C11 | YC-old minus YC-new | `csp` | Higher | Same reasoning |
| C12 | `challenge` + `block` share, server against the E20 403 share, T1k, same sites | Paired | Higher | Datacenter addresses carry less trust (secondary sources only) |
| C13 | Same, YC-new | Paired | Higher | Same reasoning |
| C14 | Agreement between passes on `https+hsts`, `csp`, `framing`, `nosniff`, `referrer`, `permissions`, `spf+dmarc`, `caa` and `security-txt`: median Cohen's kappa | Kappa | Lower bound ≥ 0.80 | Deterministic checks on stable sites |
| C15 | Agreement between passes on the response label | Kappa | Lower bound ≥ 0.60 | Bot decisions vary more than headers |

**The claim that matters most is C7.** If startups beat the less popular sample on
mail authentication, then E20's gap against the top 1,000 says more about the top
1,000 than about startups, and the paper's framing changes.

**Secondary (reported, not decided).** The T10k, Europe, SP500, YC-scale, ShowHN and NL-Cbw cohorts against YC-recent and T1k on every check. Every check by site trait (login link, payment provider, shop, a public security or trust page), read by fixed rules from the homepage already fetched, for groups of at least 20 sites. Mail and DNS providers (MX and NS) as a possible explanation of the DMARC and CAA gaps. The challenge share by edge. Origin headers
seen on robots.txt and security.txt responses of challenged sites. Whether cookies
on challenge pages are edge bot cookies. The trend across all YC batches. CAA
in every comparison. Sub-measure B on all cohorts.

## 7. Analysis

The analysis code is committed and tested on synthetic data before registration. Anything else is
post hoc and labeled so.

- **By industry (secondary).** Every check by industry, from YC's directory, GICS sectors, the NL-Cbw sectors and the health list, for groups of at least 20 sites. The host-to-industry map stays private.
- **Replication with E20's exclusions.** Because the health sites E20 excluded are now included, claims C1 to C4 are also reported without them, so the comparison with E20 is like for like.
- **Primary pass.** Claims C1 to C13 use pass 1. Pass 2 feeds C14, C15 and a stated
  replication table.
- **Intervals.** A cluster bootstrap over organizations (registrable domain from `src/utils/url.js`), 20,000 resamples, seed 2020, stratified by
  cohort. Newcombe intervals are reported next to them for comparison with E20.
- **Decision level.** Bonferroni over 15 claims: 99.67% two-sided (z = 2.9352 for
  normal-based intervals). Each decision tail then rests on about 33 resamples.
- **Rules.** As E20 § 6.5: supported when the interval excludes zero on the predicted
  side, refuted when it excludes zero on the other side, otherwise inconclusive.
  An interval wholly within ±10 points is reported as no meaningful difference.
  HTTP claims also use the S and R rule of § 2. Claims C3 and C4 use S and R within
  the named stratum.
- **Standardization.** Every HTTP difference is also reported standardized to the
  pooled edge mix, and with worst-case bounds that treat non-`page` responses as
  unknown. These are reported, not decided.
- **C12 and C13.** Paired on sites graded in both E20 and pass 1. The E20 side uses
  HTTP 403, the only measure E20 stored, so the comparison is approximate. The
  pass 1 to pass 2 drift gives the size of change that time alone produces. A
  vantage effect is claimed only when the difference exceeds that drift.
- **Exact tests** for any secondary check with a 100% cell.
- **Precision.** With a design effect of 1.3, the decision half-widths are about ±9
  points for C1 and C2, about ±9 for C7 to C9, ±11 for C10 and C11, and ±12 on the R view
  of T1k against YC-new. Gaps under 10 points may stay inconclusive.
- **Groups under 20 sites** are never shown.
- **Not in E20-R.** The logistic model and the clustering. The E20 review found the
  model uninformative.

## 8. Ethics, law and data

E20 § 8 applies in full, with these changes.

- **A second and third visit.** E20 § 8.1 promised no second pass *in E20*, and
  § 8.3 requires a new registration for a repeat. This is that registration. T1k
  and YC-new get two more visits, and new cohorts get two. The study page says so
  before any run.
- **Provider notified.** E20 § 8.3 requires telling the hosting provider in advance.
  The maintainer tells Hetzner about the run, its rate and the study page, by
  support ticket, before pass 1.
- **Source signalled.** Reverse DNS on `research.penthera.org`, a short notice page
  at that name, and the address on the study page. This meets the ZMap practice
  that E20 could not follow.
- **Exclusions.** An agent read the new non-YC lists and marked candidates, and the
  maintainer accepted them with this registration. When unsure, a domain is listed.
  The list holds 245 entries: the E20 list without its health entries, plus 215 new
  ones.
- **YC cohorts.** Every YC company stays in, except NSFW sites; none was found
  (maintainer, 30 Oct 2026).
- **Health is included.** The maintainer decided on 30 Oct 2026 to include health
  sites, patient-facing ones too, because knowing which industries are exposed is the
  point of the study. This reverses E20, which excluded them. In return, health sites
  are homepage only (a hashed list; never a link to a login or patient portal), they
  are reported only as an industry total of at least 20 sites, and their domains are
  left out of the public lists (hash and method only). Adult, gambling, government and
  at-risk sites stay excluded.
- **Founder notes.** The product line in E20 § 8.8 is removed, which reconciles the
  notes with § 8.1(5). A note gives one finding and a free fix, without a pitch.
  Only YC-new may get notes, and only once.
- **New data.** Header names and values, cookie names and short error-page excerpts
  (§ 4.1). All private, deleted 12 months after publication, never published per site.
- **Conflict of interest.** Stated in the report's first page, as for E20.
- **No ethics board or outside reader** reviewed this study (decided by the
  maintainer, 30 Oct 2026), and the results say so.

### 8.1 What is published, and removal

- **Downloadable at the study page:** every target list except NL-Cbw and health sites, which are redacted, the exclusion
  categories, the classifier rules, all code, every aggregate and analysis file, and
  the figures, under CC BY 4.0. NL-Cbw and the health list are published as a hash and a method only.
- **Never published:** per-site results, stored evidence, or anything that ranks,
  names or scores a site.
- **Removal.** Anyone who controls a domain can ask to be removed, by email or through
  robots.txt. The domain goes on a removal list that the runner reads before each
  pass, its records are deleted from the raw data, the aggregates are recomputed, and
  the published list drops it. The count of removals is reported. This is the one list
  that may change after registration, and it can only take sites out.

## 9. Limits

- A single datacenter address is not "the web's view", and neither was one home
  connection.
- E20 and pass 1 differ in time as well as vantage, so C12 and C13 are weak evidence.
- Older YC batches suffer survivorship. YC companies are not all startups. Tranco
  ranks domains, and its sample is drawn from the list, not the web.
- The classifier knows only the signatures we listed. New vendors fall into
  `origin-error` or `page`, and the validation sample estimates how often.
- The predictions were written after seeing E20 for two of four cohorts.
- Presence is not protection: a CSP can be weak, and an SPF record can be unsafe.
- The DMARC check reads `p` alone. `sp` and `pct` are added as a secondary measure.

## 10. Decisions

Taken by the maintainer on 30 Oct 2026.

1. **Vantage.** Server only, compared with E20. No run from the home connection.
2. **Cohorts.** All four older YC batches (Summer 2024, 2022, 2020, 2018), Summer and Winter 2025 as YC-25, and T10k, Europe, SP500, YC-scale, ShowHN and NL-Cbw as secondary cohorts. No accelerator portfolio pages: none grants permission and several forbid collection. Governments stay excluded, as in E20. Software vendors are left out, because no neutral list exists.
3. **Error pages.** First 4 KB of non-2xx bodies kept privately, as in § 4.1.
4. **Ethics read.** None. No outside reader before the run.
5. **Timing.** Pass 1 as soon as the study page has been live 12 hours, pass 2 seven days later.
6. **NCSC.** No notice before the run. The CVD form only if something serious turns up.

## Amendment 1 (30 Oct 2026, before any data)

The maintainer decided to run pass 1 only, as a single snapshot, before pass 1 started
and before any E20-R data existed. A second pass may follow later, under its own
registration. The text above stays as registered, and this section overrides it.

- **C14 and C15** (agreement between passes) are not run, and are reported as not run.
- **C12 and C13** are still reported, but no vantage effect can be claimed: without
  pass 2, nothing measures how much changes from time alone. They are described as a
  difference between E20 and the server run, and nothing more.
- **The correction stays at 15 claims.** That keeps the registered decision level, which
  is slightly stricter than 13 claims would need.
- **What is lost.** Test-retest reliability stays unmeasured, so a change between runs
  cannot be separated from day-to-day noise. The results say so next to the numbers.

## Deviation 1 (30 Oct 2026)

Pass 1 started at 12:15 UTC on 30 October 2026, about 12 minutes after the updated
study page went live, by the maintainer's decision. The protocol required at least 12
hours, and the notice to the hosting provider said 31 October. Site owners therefore
had almost no notice from the page before the visit, though the user agent and the
robots.txt opt-out applied as registered, and removal stays open at any time. This
was decided before any E20-R data existed, and it does not change a check, a list or
an analysis. The run stays a registered, one-pass snapshot, and this deviation is
reported with the results.

## Amendment 2: E20-R2 (adopted 31 Oct 2026, after the pass 1 data was seen)

**Status: adopted.** 31 October 2026. No request had been sent under this amendment at
adoption. It takes effect through the commit that merges this line and the Amendment 2 row
to `main`. The runner reads both. It registers
**E20-R2**, a second run under this file. It overrides every section above where they
differ.

Amendment 1 said a second pass could follow under its own registration. This is that
registration. It was written with the pass 1 results in hand, and nothing in it is a
blind prediction.

**Status of each run.** Pass 1 is a pilot and instrument audit, not a confirmatory study.
Pass 2 is a prospective corrected remeasurement of claims already seen. It
is not a blind or independent confirmation. The study is a low-interaction active
measurement: it sends requests to sites, so this file and the page no longer call it
passive.

### Why

A line-by-line check of this protocol against the code, an outside review, a code review
and a validity audit found faults that only a new run can fix:

- 2xx bodies were not stored, so `page` and `challenge` on 2xx responses could not be
  validated. 3,495 of 5,882 graded responses have no stored body.
- The classifier missed Cloudflare codes representing 66.0% of enhanced-rule refusal
  matches: 1,388 of 2,102. Code 1010 alone is 65.7%. Two signatures also fire on normal
  pages.
- DNS ran only after HTTP worked, so 1,149 of 7,031 listed sites have no DNS result. Of
  those, 755 failed to connect and are eligible. Pass 2 recovers those. The other 394
  were excluded or opted out, and stay out. DNS also read the final host, which for 379
  of 5,882 graded responses is another organization.
- Robots rules were read at the first origin only, and an unreadable robots.txt meant
  "go on", which RFC 9309 does not allow.
- A redirect could reach a host on the exclusion list. Two graded sites ended on one.
- The deployed commit was not recorded. Request counts and bytes were not kept.
- 8 seconds per site lost slow sites: pass 1 has 199 timeouts and 17 budget stops.

### Design rule: no evasion

The study measures what a declared research client receives. A refusal is a result, not
an obstacle. So the run keeps the same honest User-Agent, and uses no browser
impersonation, no TLS fingerprint changes, no residential or rotating addresses and no
challenge solving, and it does not retry after a block. Any change to this rule needs a
new registration.

Pass 2 is a scheduled repeat, sent whatever a site answered in pass 1. It is not a retry
of a block. Sites that refused in pass 1 are visited once more on that basis.

### What changes in the instrument

1. **Source.** One address, IPv4 only, recorded in the Source address row below, on
   `research.penthera.org`, a rented server. The pass 1 server is deleted, so the address
   differs. Any difference between the runs can come from the address, the date or the
   instrument. The runner refuses unless this machine's only public IPv4 is that address.
2. **Time.** The site budget rises from 8 to 15 seconds, shared with any `www.` attempt, and
   the hard cap from 20 to 30 seconds. Per-request limits stay 6 seconds for the homepage and
   4 seconds for robots.txt and security.txt. The request rate stays 4 workers with a 1-second
   pause. Each visit runs in its own thread, which is ended at the hard cap, because a page
   can hold a regex longer than any timer on that thread could fire.
3. **No app page.** Pass 2 never sends the app or login page request, for any site. No claim
   uses it. It is a change from § 4. The homepage-only list stays hashed and checked: a run
   is refused if an entry matches no listed site.
4. **Robots at every origin (RFC 9309).** robots.txt is read at each new origin, up to 5
   redirects and 500 KiB, and the path plus search of each hop is checked against it,
   with a matcher that uses no regex. A 2xx is parsed. A 4xx means no rules. A 5xx, or a 429, which the RFC counts as 4xx,
   stops the visit as `robots_unavailable`. So do a spent budget, a 3xx with no Location,
   a compressed file, a
   file cut off at the cap, and a file with NUL bytes or a UTF-16 mark, because none of
   them can be read as rules. CR, LF and CRLF all end a line, a `User-agent` name ends at a
   slash or a space, and rule and path compare in one percent-encoded form (RFC 9309
   § 2.2.2). A malformed escape stays literal, so a path can't dodge a rule by it, and a
   Disallow also matches on the decoded form, so a reserved character can't either. A file that can't be reached ends the visit with the outcome the homepage would have given: `not_found`,
   `timeout`, `unreachable`, `tls_invalid`, `tls_handshake` or `not_public`. Pass 1 went on in all these
   cases, and 70 of its graded sites had a 5xx or no robots answer, so some sites drop out,
   and the count is reported.
5. **Every hop is checked.** A redirect into an excluded domain stops as `exclusion_redirect`
   before any request reaches it, for robots.txt redirects too. A redirect to a literal IP
   address stops, IPv4 or IPv6, so one published address accounts for every request. A hop back into
   an origin whose robots.txt failed stops, so a failed request isn't repeated. A redirect
   into another organization that opted out stops as `redirect_opted_out`, or as
   `redirect_disallow_path` when its rules cover that path, and the listed site's DNS is
   still read, and it stays eligible. Each record lists the hosts it requested.
6. **Fallbacks.** A name that doesn't resolve gets one try at `www.`, and a host where the
   HTTPS connection is refused or unreachable, or fails its certificate or handshake, gets
   one try over HTTP. Unlike pass 1, these run only when nothing from the listed origin has
   answered. A reset is not a fallback case, because it may be a refusal, and neither is a
   timeout, as in pass 1. § 5's "no retries" meant the same request isn't repeated. Pass 1
   also ran both fallbacks, and neither was stated before.
7. **TLS.** `tls_invalid` stays its own outcome, reported apart from other failures, with
   the reason code, also when plain HTTP then fails. A failed handshake is `tls_handshake`,
   except an alert that denies access, which is a refusal and gets no fallback.
   When HTTP answered, the record keeps why HTTPS failed. Each error keeps the system's
   code, so a resolver failure can be told from a name that doesn't exist.
8. **Hosts.** Each record stores listed host, final host, listed organization and final
   organization apart, with a redirect class: none, same organization, other organization. The
   same list decides whether two names are one site: `www.example.com` is `example.com`, and
   `www.github.io` isn't `github.io`.
   Organizations come from a pinned Public Suffix List, private suffixes included, vendored
   under `bench/front-door/psl/` for the study only. It is used for organization domains,
   DNS domain choice, clustering, deduplication and redirect classes. The grader keeps its
   own parser, so the registered reading is unchanged. In pass 1 the list changes 19 of
   7,031 listed hosts and 10 of 5,882 final hosts, 6 of them mail lookups. No decision
   changes, and intervals move by at most 0.5 points.
9. **DNS apart from HTTP.** SPF, DMARC, CAA, MX and NS are read outside the visit's thread and
   clock, on the listed name, including for sites that time out, don't resolve, fail TLS or
   refuse the client. When a redirect moved to another host, all five are read for the final
   host too, and one organization asks each name once. The
   grader's DNS checks run there too, and join the score as they did in pass 1. **DNS isn't
   read** for a site on the exclusion list, removed, dropped as a pilot site or an earlier
   opt-out, a `NOT_A_HOMEPAGE` host, or a site whose robots.txt opts out or disallows the
   homepage. **It is read** when the stop was ours or someone else's: `robots_unavailable`,
   `exclusion_redirect`, `ipv6_literal`, `ipv4_literal`, `redirect_opted_out` and `redirect_disallow_path`.
   Each query keeps its exact
   name, type and result, for every CAA ancestor too: an answer, NXDOMAIN, NODATA or a resolver
   failure. A resolver failure is unknown, never a failed check.
10. **Mail, frozen here.**
    - *SPF record present:* exactly one `v=spf1` record on the organization domain. Includes,
      redirects and lookup limits are not validated. The record is stored up to 2,048
      characters.
    - *DMARC:* a valid record is the single `v=DMARC1` record with a known `p`. We follow
      RFC 7489: the host's record, then the organization domain's, where `sp` applies. RFC
      9989 replaced RFC 7489 and is said to drop `pct` and use a tree walk. We did not read
      it for this rule, and don't follow it, so that pass 2 stays comparable with pass 1.
      Most records still carry the older tags.
    - *Declared:* `p=quarantine` or `p=reject`. *Effective enforcement:* the applicable
      policy is `quarantine` or `reject`, and `pct` is above 0. `pct=0` is never enforcing.
    - `quarantine` counts as enforcement in the decision. `p=reject` alone is reported beside
      it, because in pass 1 it flips C7 and C10.
    - `pct` under 100 and `sp=none` are reported apart. Neither fails a domain.
    - The registered measure, SPF with a restrictive `all` plus `p` read alone, is reported
      beside each result.
11. **CAA.** Read for the listed hostname and the final hostname, climbing the parent tree as
    RFC 8659 says. The registered reading stops at the registrable domain and stays beside it.
12. **Classifier.** Rules are in `bench/front-door/classify.mjs`, frozen by the hash below.
    - Cloudflare `error code: 1xxx` is `block`, except 1001, 1016, 1033 and 1101, which are
      DNS, tunnel and Worker errors.
    - Block lines, error lines and scripts that also sit on normal pages count only on status
      400 or above, or in a body under 8,192 characters. A long page may quote them.
    - A block page wins over a script it carries. CloudFront's refusal lines are `block`. An
      empty 401, 403, 406 or 429 at an edge is `block`. DDoS-Guard is a new challenge.
    - A bare 403 is `block` under its own rule, `unrecognized-403`, so a view can drop it.
    - The fallback classes are renamed `candidate-page` and `unrecognized-error-response`,
      because neither is proof of what the response was.
    - **These rules were written after reading the pass 1 labels.** Agreement with them on
      that sample is in-sample and says little. The rules for 2xx bodies could not be tested
      on it at all.
    - Each record keeps the label from the original rules beside the corrected one, and every
      signature of every rule set as a boolean, so a label can be replayed.
13. **Evidence.** A 2xx homepage keeps its title, up to 4,096 characters of visible text,
    the first 300 characters of `noscript`, counts of scripts, forms and links, and a meta
    refresh flag, with no markup. This changes § 4.1, which said 2xx bodies are never stored.
    Robots.txt and security.txt get the body hash and the non-2xx excerpt § 4.1 promised.
    Every stored text is scrubbed of IP addresses, emails in the forms we know, form fields,
    query strings, fragments, tokens, identifiers and long numbers, before it is cut. Cookie
    and header names that look like tokens are dropped. SPF records keep their addresses,
    which are mail servers named on purpose. Names and street addresses in page text are not
    scrubbed. That is why item 16 exists. A bracketed `at` takes both neighbouring words with it, and
    a bare `at` before something with a dot is read as an address, so some ordinary text is lost.
    Forms the scrub can't see are listed in `bench/front-door/KNOWN-LIMITS.md`.
14. **Header values.** For each homepage: CSP directive names, a script-control flag and an
    open-sources flag, computed on the full header, not the grader's 160 characters. "CSP
    controls scripts" means `script-src`, `script-src-elem` or `default-src` is present. It
    is reported next to "CSP present", for C1, C5, C9 and C11.
15. **Run record.** Each record counts requests and redirects. Its byte count is a lower bound: a
    redirect's body counts as far as it arrives while the visit goes on, and a response cut off at
    the hard cap as far as it was reported. Bytes are observed response-body bytes. They exclude
    request bytes, headers, TLS overhead and DNS. A manifest
    holds the commit, whether the tree is clean, the protocol,
    amendment and study page hashes, lockfile, classifier, study code and runtime hashes,
    Node and OS, the suffix list's version and hash, the complete configuration, list and
    removal hashes, the seed and the times, and at the end the raw and aggregate hashes and
    totals. The code hash covers every file the study imports, and the data files it reads.
    All of these, lists included, are read again at the end, and the manifest names anything
    that changed. A run with a change ends in a stop. The runner refuses a dirty tree,
    any commit but the current tip of main on the remote, read at the start, a file git hides
    from `status`, a placeholder in this file or the page, a page that doesn't name the
    address, and any classifier, suffix list or prior opt-out list that doesn't match its
    frozen hash. Pass 2 and each pilot round have one fixed folder, so a second start can't
    revisit sites. **Limits:** a fresh clone has no such folder, so that lock is one
    machine's, and the rule behind it is the maintainer's. The address check reads this
    machine's interfaces. It can't see NAT or a proxy. It would need a request to an echo
    service, which this study doesn't send. The legacy `run.mjs` refuses every run off
    loopback.
16. **Excerpts are deleted.** After the audit draw, `validation-sample.mjs` removes title, text and
    `noscript` from every unsampled normal page for good. Error excerpts stay until the 12-month
    deletion. From every pilot record, and from a pass that stopped, it removes all of these. Hashes,
    counts and flags stay. Pruning writes a second manifest with the old and new
    raw hashes, so the run's own manifest stays true of what was recorded.
17. **Skips.** Sites that opted out in pass 1, removal requests and pilot sites are skipped, and
    each is counted in its own category.

### Primary endpoints and estimands

These order the reporting. They add no test.

- **Primary refusal endpoint.** Among graded responses in pass 2, the share with a `challenge`
  or `block` label backed by a signature, so without `unrecognized-403`, with a cluster
  bootstrap 95% interval. All refusals and the original rules' share stand beside it. It is a
  rule-match rate, not a measure of how often a site refuses visitors. It describes one
  declared client, and is descriptive.
- **Primary HTTP endpoint.** C1, CSP present, with "CSP controls scripts" beside it.
- **Primary DNS endpoint.** C7, on effective enforcement.
- **HTTP estimands.** S: what the client received on every graded response, on the final host.
  R: the same among `candidate-page` responses.
- **DNS estimand.** The listed domain, for every eligible site whose domain exists, clustered on
  the listed organization. The graded-only reading on the final host is reported beside it, and
  decides nothing.

### Claims and correction

- **C1 to C11 are the inferential family**, with their registered directions, on pass 2.
  Bonferroni over 11: 99.55% two-sided, 20,000 resamples, seed 2020. This replaces the 15 of § 7.
- **C12 to C15 are descriptive reproducibility.** They get intervals and no decision. C12 and C13
  use the original labels, and stay a difference between runs. C14 and C15 compare pass 1 and pass
  2 on all sites graded in both, the original labels for C15, with 2,000 resamples. Their lower bound
  is the 2.5th percentile of the percentile bootstrap, the lower limit of a two-sided 95% interval. Time, address and limits differ between the passes, so agreement says less than § 6 hoped.
- **Margin.** The ±10 points is kept because it was registered, not because it is substantively
  justified.
- **Common-support floor.** A difference needs at least 20 organizations with a judged response on
  each side, in each view it uses. Below that it is "not estimable". Standardization drops an edge
  stratum under that floor and names it.
- **Reading an interval.** Statistical direction and practical equivalence are reported as separate
  outcomes for each view, next to the registered decision. Newcombe intervals and exact tests stand
  beside the bootstrap. An organization in both groups is resampled as one, which keeps the covariance.
- **Missingness.** Each HTTP claim reports coverage per list, and worst-case bounds that count every
  eligible site without a judged value either way. Our own stops stay eligible; an owner's opt-out
  and our exclusions don't. C3 and C4 are edge strata, which only a graded response shows, so their
  bounds cover graded sites. HTTP claims make no statement about ungraded sites, and nothing here
  can say what a browser would have seen. DNS values with a resolver failure are unknown, are left
  out, and are counted.
- **Registered inputs.** Pass 1's raw file, both E20 raw files, the industry map and the E20
  exclusion file stay private and local. Their hashes are frozen above, and `analyze-r.mjs` refuses
  any other file.
- **Secondary analyses, narrowed.** This replaces the secondary lists of § 6 and § 7. Built: the six
  secondary cohorts against YC-new and T1k on every check, HTTP checks on
  graded responses, and SPF, DMARC and CAA from the DNS records of every site whose domain exists;
  checks by site trait and by industry, on graded responses, for `https+hsts`, `csp`, `framing`,
  `nosniff`, `referrer`, `permissions`, `spf+dmarc`, `caa` and `security-txt`; the challenge share by
  edge, with a Wilson 95% interval; MX and NS counts in the aggregates. Their intervals are labeled
  naive row-level, with no clustering: Newcombe for differences, Wilson for one share. They
  corroborate nothing. Sub-measure B isn't run, because Amendment 2 has no app page.
- **Post hoc, if reported at all, and marked so.** Providers as an explanation of the DMARC and CAA
  gaps, the trend across YC batches, origin headers on robots.txt and security.txt responses of
  challenged sites, and cookies on challenge pages.
- **Intervals.** Public shares carry descriptive 95% intervals. Claims C1 to C11 are decided on
  99.55% intervals.
- **Analysis.** `analyze-r.mjs` holds the claims, the bounds and the standardization on both
  views, C3 and C4 included, the secondary cohorts, and reports traits per cohort. C12 and C13 pair with their own E20 file. In it, `--pass1`
  takes pass 2 and `--pass2` takes pass 1.

### Single-human audit with model comparison

One human labeler and the AI agent, as in pass 1. This is a single-human audit with model comparison,
never independent validation. **It misses the outside reviewer's requirement of two human labelers and
a third adjudicator.** The figures are reported as checked by one person.

- **Strata**, drawn from pass 2 with seed 2021 by `validation-sample.mjs`, with no pilot sites:
  `candidate-page` 150, `challenge` 50, signature-backed `block` 50, `unrecognized-403` 30,
  `unrecognized-error-response` 20. All 300 rows, or every row in a smaller stratum.
- **Blinding.** Rows are shuffled, and the sheet has no label, stratum or host field. Page text
  can still name a site, and can't be blinded from that.
- **`unsure`.** It stays a recorded answer and is never forced. Unsure rows are left out of kappa,
  precision and recall, and counted. Weights are taken over the answered rows of each stratum. A
  sensitivity keeps `unsure` as an answer no rule gives, so each one is a disagreement.
- **Labels.** Scoring takes the human's and the agent's file, reports where they differ, and refuses
  a missing, duplicate, unknown or invalid row.
- **Disagreement.** The agent never settles a label. The human's label stands, and every
  disagreement is counted.
- **`unsure` between the human and the model.** Each one's total is reported apart. The main kappa
  uses rows where neither is unsure, and a sensitivity counts any `unsure` as a disagreement.
  Both state their denominators.
- **Header checks.** This amendment removes the inherited requirement that labelers judge whether
  the grader's outcome on three header checks matches the stored headers. Those outcomes are fixed
  rules reading the same stored values, so a label would repeat a deterministic read and say little
  about the study's real risk, the response class. The audit covers the class alone. The grader's
  header outcomes rest on its tests, and no human audits them.
- **`body-unavailable`.** A compressed answer's body isn't read. It takes this label, not
  `candidate-page`, so it counts in S and not in R, and it isn't sampled.
- **Weighted metrics.** Each row carries stratum size over rows drawn. Precision and recall use
  these weights, with intervals from a stratified bootstrap, seed 2021, 20,000 resamples. Kappa
  is reported unweighted. `validation-sample.mjs` draws the sample, writes the blind sheet and
  scores the labels.
- **Who sees evidence.** The maintainer, and one labeler under a written note. The note says what
  the sheet holds, that it stays private, and that copies are deleted after labeling. An AI agent,
  a hosted model, also reads the sampled rows, so they leave the machine for that provider, and the
  12-month deletion can't reach what that provider keeps.

### Pilot

- Exactly 50 sites from the claim lists, seed 2026, at the same rate and under the same rules. Two
  live rounds at most. Each round has a higher number than the last, and the rounds' order is the
  order they started.
- Pilot sites are dropped for good from pass 2 visits and analyses, and counted.
- **Stop rules.** The run does not go on while any of these holds, and `pilot-report.mjs` prints
  them: a privacy scrub miss, an internal error, under 90% of 2xx responses with an excerpt, an
  eligible site without a DNS read, any site over 20 requests, any hop to a host on any of the
  four skip lists, under half of eligible sites graded, over 20% of eligible sites with a
  resolver failure on any exact query of the listed or final name, over 20% of SPF or DMARC reads
  unanswered, no eligible site, or under 30 eligible sites, 25 graded sites or 10 2xx responses. The
  report also gives coverage per claim cohort. Scrub misses, internal errors, excluded hops and
  request-cap violations have zero tolerance.
  Also stop on a complaint from a site owner or the provider, or if the source address isn't the
  registered one. A stop file is checked between sites, and so is the source address, which is
  read again at the end.
- **Manual decision.** A person reads the report and records go or no-go before pass 2, with
  `pilot-report.mjs --decide`, in `pilot-decision.json`: the decision, the report and seal hashes,
  the reviewer and the time. Pass 2 needs `go` for the final round. For each claim cohort the report
  gives selected, eligible, graded, 2xx and DNS-complete sites and each class. The automatic rule
  rejects a cohort with no graded site or no complete DNS read, so it detects only total cohort
  failure. The reviewer must also reject severe attrition in a cohort.
- **Gate.** After the pilot, `pilot-report.mjs --seal` writes its result, bound to the pilot's manifest
  and raw hash, and to the exclusion, removal, prior opt-out and earlier pilot lists that run used. Then
  `validation-sample.mjs prune` deletes its text. A round with a finished manifest, stopped or not,
  is sealed and then pruned. A hard kill leaves no finished manifest and is only pruned. Its sites
  go on the dropped list either way. Pass 2 refuses unless the last round passed under the
  code, protocol, suffix list and lists in force, every finished round has a seal that matches its own
  hash and its stored report, every round proves its text is gone, and the rounds on disk match an
  append-only log kept outside the results folder. After a failed round, the next needs changed code or a changed protocol, or a
  recorded explanation. The pass 2 manifest records each round's manifest and seal hashes.
  `npm run e20r:acceptance` injects each stop condition on loopback and shows pass 2 refused through
  the run's own command. Labels come after pass 2, so for them it shows that scoring refuses. No pilot
  round can start once pass 2 has. A removal list over 5% of the sites is refused.
- **Analysis gate.** `analyze-r.mjs` and the audit draw refuse any run that didn't finish, stopped,
  changed under itself or doesn't match its raw hash. So a stopped pass 2 can't decide a claim.
  Analysis reads only the `raw.jsonl` the gate checked. Both also refuse without a clean privacy
  report: `pilot-report.mjs --privacy` runs the pilot's scan over the headers, cookies, DNS, checks
  and excerpts of the finished pass, before the draw.
- **Immutability.** At the end the runner rehashes the code, protocol and lists, the exclusion,
  homepage-only, removal, prior opt-out and pilot-dropped files, and reads the source address. It
  keeps the git state from the start and the end and compares them.
- **Deletion's limit.** Pruning covers the raw file in the run's folder. It can't reach a copy made
  before it ran, so none is made, and deleted text can't be audited later.
- **A failed privacy report on pass 2.** The run stops, and a person reviews the flagged fields
  first, on the server, printing them to no shared place, so a false fire doesn't cost the run. A
  confirmed false fire is recorded with a note and reported as a deviation. A real miss goes to
  purge.
- **Purge.** `validation-sample.mjs purge` deletes the whole per-site raw file, the audit sheet and
  the key, with no field-level cleaning. It then checks they are gone, and only then writes a proof
  with the original hash and the run's disposition, by atomic rename. It refuses without `--confirm`
  and the first 12 characters of the raw hash. Every reader of a proof checks its kind, manifest,
  raw hash, disposition, and that all those files are absent. A purged run decides nothing.
- **Privacy-failed rounds.** `prune` refuses a run that stores a privacy miss, because it can't clear
  one outside the excerpts. Pass 2 refuses a pilot round with a miss unless it has a verified purge
  or a recorded human-reviewed false fire.
- **Signals.** SIGINT or SIGTERM ends a run between sites, with a manifest, as a partial run. Every
  exit other than success is followed by `validation-sample.mjs prune`, which reads the file back
  to prove the text is gone. A kill leaves no end manifest and takes the same prune. A stop that
  lands during the last site still makes the run partial. The final manifest is written to a temp
  file and renamed. The semantic boundary is the last stop check, just before that rename, and
  nothing yields between them. A signal handled by that check makes the run partial. Any later
  signal is post-run and changes nothing.
- **An interrupted pilot.** Its sites count as used, by the list hash its manifest recorded at the
  start. Its text is deleted, and the next round runs on other sites.
- **An interrupted pass 2.** It isn't resumed or restarted, because a restart would visit sites
  twice. What ran is reported as a partial run, with its coverage, and it decides no claim. A
  new run needs a new registration.
- **A stop in flight.** Pass 2 watches itself: a privacy scrub miss in page or error text stops it at
  once, and so does a share of resolver failures over 20% across its last 200 sites. It reads no SPF
  record for this. It then counts as interrupted, and all its text is deleted.
- **A pilot-driven rule change.** Update this amendment, re-freeze the hashes, and rerun the pilot
  as the next round, on other sites. Those sites leave pass 2 too. `--pilot-dropped` must hold
  exactly the sites of every finished round, checked against each manifest's hash.
- **No rule changes after pass 2 starts.** The runner checks the frozen classifier hash at the
  start, and the manifest records that it held at the end. A complaint during pass 2 stops the run
  the same way, and what ran is reported.

### Deviations and limits, stated plainly

- **No waiting period.** The run follows as soon as this amendment and the study page are live.
  This departs from the 12 hours of § 5, and owners get almost no notice. Notice means the public
  study page and this amendment. No email goes to site owners.
- **The seven-day spacing of § 5 is not kept.**
- **Outside review.** An outside reviewer gave a technical go on 31 October 2026. That is not an
  ethics endorsement.
- **No independent human ethics board reviewed this study.** AI and external technical reviews have
  occurred.
- **Provider notice.** One advance notice was sent on 30 October 2026, naming the first server. It
  wasn't repeated for the new address, by the maintainer's decision.
- **Notice page, changing § 8.** § 8 promised a notice page at `research.penthera.org`. The server's
  firewall opens port 22 only, so that page can't be served, and it was not served in pass 1. Owners
  reach the study through the User-Agent's URL and reverse DNS.
- **One human labeler**, as above.
- Pass 2 sees most sites a second time, and T1k and YC-new a third.
- The new rules were fitted on pass 1, and pass 2 is the first data they have not seen.
- Coverage still depends on who answers this client. No part of this design can answer what a
  browser would have received.
- `unrecognized-403` is a label without vendor evidence.
- A compressed page body isn't read, and takes the label `body-unavailable`: 23 responses in pass 1.
- `platformOf` now reads Akamai's other headers as the classifier does, so a few pass 1 and pass 2
  strata for C3 and C4 can differ for that reason.
- SPF semantics and DMARC reporting are not validated.

## Amendment 3: E20-R2 after a false stop (draft, 31 Oct 2026)

**Status: draft.** Adoption changes this line and the Amendment 3 row to adopted, and takes effect
through the commit that merges them to `main`. The runner reads both. It overrides Amendment 2 where
they differ.

**What happened.** Pass 2 stopped itself at 10:30 UTC on 31 October 2026, 2 minutes after it began.
It had processed 188 of its 7,031 records. 177 of those were visits. The other 11 were sites on a skip
list, 9 on the exclusion list and 2 earlier opt-outs, which were never visited. Its in-flight check
flagged an email in `evidence.pageExcerpt.text` of one record.

**The false fire.** The scrub replaces an address and leaves `at <email>.` The frozen detector joins
the words after a bare `at`, so `Reach us at <email>. Open daily` reads `<email>. Open` as a name and a
top-level domain. The exact trigger needs both the period and an alphabetic word after it: `Reach us at
<email>.` alone doesn't fire. That reasoning came from code review on a synthetic string. The person's
review below is the evidence that this fire was false. This file doesn't say which words tripped it.

**The legacy finding.** The frozen detector is kept under its hash, and is used for this alone. Before
any prune, `pilot-report.mjs --legacy-findings` scanned the original raw file and wrote a private
report, bound to the manifest and the raw hash, with record order and field path and no flagged text.
It gave 1 finding and reproduced the stop. The gates don't trust that report's summary: they check
every finding's order, path, kind and count, and derive for themselves that one sits at a path the
stop reads.

**A person's review.** Daan van der Zwaag read the flagged field of the one flagged record on the
server, on 31 October 2026, as the run sheet sets out, and found no email address in any form. The
review was recorded at 12:27:03 UTC with a note, SHA-256
`eaf6d5767391ce342ebf0f3bb14b6305f6fcdc20ca85054bf5a6014084dc833c`, and is bound to the finding report's
hash. That person is the study's maintainer, so this isn't an independent check. The text was then pruned,
at 12:27:13 UTC. `prune` refuses this stop before the review, and a clean scan can't be called a false
fire without that report.

**The pruned file.** The privacy report is clean over the 188 records, and the prune proof binds the
original raw hash to the pruned file, SHA-256 starting `3e2cd5393328`, which is the file on disk.

**The partial run.** It is reported as a partial run with its coverage, and it decides no claim. Its
records aren't pooled with any other run. Nobody reads its results before pass 3 ends.
The steps ran in this order: the legacy finding, a replay, the person's review, the prune. Page text in
the stopped pass no longer exists, so it can't be replayed at the final classifier hash.

### The detector

`classify.mjs` holds both the labels and the detector, `scrubMisses`, so the fix changes its frozen
hash. It can't sit elsewhere, because the detector is what the stop reads.

- **What changed.** Inside `scrubMisses`, the helpers it calls and the constants they use, and nowhere
  else in the file. After a bare `at`, or an `@` set apart by spaces or brackets, what follows counts
  only if it is a whole domain: past an opening bracket or quote, one or more labels joined by dots, the
  word `dot` or a bracketed dot, ending in a label of at least two letters, or in punycode, that nothing carries on from. A label starts with a letter or number, ends with one or a combining mark, may hold hyphens
  inside, and takes Unicode letters and numbers. `$29.`, `5:30.`, `Joe's.`, `100%.` and paths hold
  characters no label can, and web URLs, and anything followed by a path, query, fragment or port, fail the same test. What precedes it must look like a local
  part, and one of our own scrub tokens or `<redacted>` never does. Wide forms, invisible characters and
  spaces spelled as entities don't break the reading. A JWT now has to open at a token's edge, so
  `keyJ.value` isn't one.
- **What still counts.** Bracketed and quoted domains, such as `john at (example.com)`, on purpose, and
  anything else shaped like a whole domain. So `Look at (example.com). Open daily` still fires, and so
  does `updated at 12.34.56.pm yesterday`, because `123.456.com` is a valid name. This detector is the
  backstop for retained addresses, so it stays strict there, and a fire no longer costs a run. See
  "Withheld text".
- **Old hash.** `7023106f7bd73c1e4122d80e9479f63a4a04091f1426327be70621951fe71d3b`.
- **New hash.** `ffd44cf9df79d0de10079cbe9e367420226c5034a0ee4a78461cd474419a8ed7`.
- **No graded result changes.** `classify`, `classifyRegistered`, `scrub`, `evidenceOf` and every other
  export keep their source, byte for byte, so a label, a stored excerpt or a grade can't differ. The detector's reach changed in both directions, so its effect was measured, below. Pilot round 1 isn't regraded, and its seal isn't redone. Its raw file is pruned,
  so a replay would read no excerpts, and we don't count one as evidence.
- **What it departs from.** "No rule changes after pass 2 starts". This touches only what the stop check
  and the privacy reports read. The scrub and the labels are unchanged.

**How often it fires.** We ran `pageExcerpt` and each detector over 17,039 clean development pages of
BrowseSafe, a public corpus of synthetic web pages, as counts only. It holds no study data.

| Detector | Clean pages that fire | Rate |
|---|---:|---:|
| The one that stopped pass 2 | 235 | 1.38% |
| First fix, own tokens and URLs only | 82 | 0.48% |
| This one | 18 | 0.11% |

The last row is the frozen classifier, `c79fd69519fb3813b11271c2a401d36d2a61ce55d80131cd3ccd9f0d3b86f324`.
Its Wilson 95% interval is 0.07% to 0.17%. Of its 18 pages, 13 fired on an email, 4 on a fragment and 1
on a long hex run. It fires on more pages than a draft at 7, because it reads domains that draft
missed. Most of those fires are one timestamp-like shape in a corpus template. We left that shape in,
because narrowing it would be tuning on the corpus, and it would miss valid names.

Over the 7,031 records and 691,594 stored strings of pass 1, this classifier and the one that stopped
pass 2 gave 0 label differences and 0 scrub differences. This one fired less on 1 string and more on
none. In particular, none of the 2,387 pass 1 records with a stored error excerpt fired. Pass 1 stored
few excerpts of normal pages, so that says little about them.

**What was replayed on the stopped pass.** A replay at the first fix, classifier
`280c4633f3d003371203957774b867889e596db9bd8b716f2e0e9c1fb49efbac`, flagged 0 of 188 records. It ran before
the prune, and it is the only replay of that page text. Classifier `c79fd695...` has never read that
text, and can't now. It did read what the prune left of pilot round 1 and the stopped pass, 238 records
with no page or error text, and flagged 0. That covers stored fields such as headers and DNS records,
and says nothing about page text.

The last row's rules were written after reading the shapes behind the second, on the same corpus, so it
is in-sample, and the real rate may differ. Pass 3 should see about 3,350 2xx pages. At 0.11% that is
about 3.5 fires, and about a 3% chance of none. So a tighter detector doesn't remove the problem. A run
that ended at the first fire would almost certainly not finish, and a false fire in the last pilot round
would leave no route to pass 3.

### Withheld text

This replaces "A stop in flight" of Amendment 2 for scrub misses, and its zero tolerance for scrub
misses in page and error text, for pilot round 2 and pass 3. Pilot round 1 and pass 2 aren't changed.
The stop on resolver failures stays.

- **The rule.** The visit's thread checks the page and error text with the detector, once labels and
  checks are done. On any fire it removes `evidence.pageExcerpt.title`, `.text` and `.noscript`,
  `evidence.excerpt` and every `evidence.others[].excerpt`, and marks the record `textWithheld`, with
  counts per detector kind and of fields, and nothing else. Only then does the record leave the thread.
  The runner repeats the check on the content before anything is written, aggregated, logged or passed
  on, whatever marker the record carries, and removes the same text if anything still fires. No record
  leaves that step with text the detector flags. The run goes on.
- **What stays.** Labels, signatures, checks and score, CSP and traits, status, header names, kept
  header values, cookie names, body hashes, counters, robots outcomes, DNS, cohorts and order. They were
  computed on the response in memory, as for every other record.
- **What a fire means.** The detector saw a shape it doesn't trust. It may be a missed address, ordinary
  text, or both, and nobody can tell afterwards, because the text is gone by design. Fires are reported
  as counts, and never as false.
- **Its limit.** This covers the study's own write paths. It says nothing of process memory, swap, a
  core dump or a compromised host.
- **Pass 3 doesn't stop on this.** However many records are withheld, pass 3 goes on. No count of fires
  ends the only run that decides claims. Once a fire's text is gone, a high count is no longer a storage
  risk. It is a sign about the audit, and the audit-quality rule handles it.
- **Claims.** Withheld records count in every claim, because their labels and checks are intact.
- **Reporting.** Withheld records and their share, overall and by cohort, by audit stratum and label, by
  HTTP status class, by edge or platform group, and by detector kind. A group under 20 sites joins
  `other`. A record with several findings counts once as a record, and each finding counts for its kind.
- **Everything else stays.** The final privacy report still reads every stored field, headers and DNS
  included, and a miss there goes to a person, as Amendment 2 says.

### Pilot round 2

The code changed, so a new pilot round is required, as the next round, on other sites and under the same
rules, as this section changes them. It also skips the 188 records of the stopped pass. The gate of
Amendment 2 applies to it in full, and pass 3 refuses unless it started after the stopped pass.

- **Its limit on withheld text.** The round fails if more than 2 of its 50 records are withheld. This is
  a check for systematic failure, set before the round. Zero, one or two can seal and take a `go`.
- **The excerpt rule.** Readable 2xx responses are 2xx responses less those withheld. Amendment 2's 90%
  excerpt rule now applies to readable 2xx responses, and withheld 2xx responses are reported apart.
- **Other fields.** Scrub misses in any field the round still stores keep zero tolerance.
- **It is the last live round.** A failed round 2 can't lead to pass 3 without a new amendment.
- **Its text.** See "Text copies" below.

### Audit quality

Set by the outside reviewer's answer, before pilot round 2 and before any pass 3 data, and not changed
after. Withheld records have no text, so nobody can label them. The audit therefore covers
**non-withheld records only**. Its precision, recall and kappa describe that frame, and not the run as a
whole. Withheld records aren't missing at random: on the corpus they lean towards particular shapes of
page.

For each audited stratum, `N` is every audit-eligible record in it before withholding, which means its
graded records, withheld ones included. `W` is the withheld ones, and `F = N - W` is the frame. The
withheld share is `w = W / N`. The draw takes its rows and weights from `F`.

- **The rule.** The headline audit is **not estimable** if `w` exceeds 2.0% in any audited stratum. The
  test is on the exact fraction, with no rounding. Otherwise the headline audit stands, on its frame.
- **Always reported, whichever way it goes.** The withheld share overall and per stratum, and the
  worst-case bounds below for every label with figures. When the audit is not estimable, the figures
  for its frame stay in a table, marked as not the audit's result.
- **Sample sizes don't change.** Each stratum draws its registered rows, or every row of its frame if
  that is fewer, and the shortfall is reported.
- **Figures under 20.** Figures are per label, and a label's frame is the sum of its strata's frames:
  `page` from `candidate-page`, `challenge` from its own, `error` from `unrecognized-error-response`,
  and `block` from `block-signature` and `block-unrecognized-403` together. A label with a frame under 20
  gets no precision, recall, interval or worst-case figure, and says so, because this study quotes no
  group under 20. Kappa covers the whole audit, under the same floor. This doesn't decide the headline,
  and it doesn't lift when the headline is not estimable. The 2.0% rule stays per stratum, so each block
  stratum meets it alone. A silent label's rows still count in other labels' recall, at their weights.
- **One small stratum can decide it.** In a stratum under 50 records, one withheld record is over 2.0%.
  That is the rule working as written, and it won't be relaxed afterwards.

**Worst-case bounds.** Each treats every withheld rule label as wrong. `TP`, `C` and `A` are the weighted
totals of the frame for a label: rule and human agree, rule says it, human says it. `W_L` is the withheld
records whose rule label is that label, and `W_other` the other withheld records in audited strata.

- Precision: `TP / (C + W_L)`.
- Recall: `TP / (A + W_other)`.

Kappa has no bound, and says so.

**"Audit not estimable" is an outcome.** It is reported in the summary, beside the claims. It changes no
claim's decision and no main analysis, which rest on the registered rules. The real-page view of each
HTTP claim then carries a line saying its `candidate-page` label wasn't validated on this run.

**What it never triggers.** No pass 4, no second draw, no substitute rows, no new labeling to recover a
stratum, and no change to this rule.

**One report.** `bench/front-door/report-tables.mjs` is the only step that joins the claims and the
audit. It is part of the study's frozen code. It works the score and the analysis out again from the
run's own files and the registered inputs, and writes nothing if either differs from what it was given.
The headline stands above the claims, and when the audit is not estimable, every real-page view it
prints says so. The same file holds the registered secondary figures, which corroborate nothing. MX and
NS counts stay in the run's aggregate file. The chain from the run to that report is bound by hashes:
the manifest and post-draw raw file, the audit frame, sheet and key, each labeler's labels, the score and
the analysis.

**One state.** The score, the analysis and the report run from the run's own commit and refuse anything
else: code, classifier, protocol, study page, suffix list, lockfile and Node version must all match the
run's manifest. So this file doesn't change between the start of pass 3 and the final report. Dated notes
go on `main` after that. A laptop's Node binary can't match the server's, so the version is compared and
the two binaries' hashes are only printed.

### Text copies

**Deviation.** Amendment 2 says pruning can't reach a copy made before it ran, "so none is made". One was
made.

`pilot-label-sheet.csv` was built from pilot round 1 at 10:21:53 UTC on 31 October 2026, before that
round's prune at 10:27:41, to check its labels and its go decision. It held 47 rows: 22 titles, 15
visible texts and 23 error excerpts, 29,087 characters in all. A key beside it mapped rows to sites.
Copies sat on the server and on the maintainer's laptop, and in one zip file. An AI agent, a hosted
model, read it and labeled it, so that text reached that provider, and no deletion here can reach what
the provider keeps. One row, a generic error page, also reached another AI session while the study was
checked. The outside labeler also received the sheet, and confirmed deleting it on 31 October 2026.

Every copy we hold, and the key, were deleted on 31 October 2026, on the maintainer's instruction.
Their hashes before deletion:

- Sheet: `b1257bf709f15e858965aa8bc1e532bd3075d7b0ea34e8857d2c97ea93fb10da`.
- Key: `ff01d3f78f563f1ba61f7efeb6c34bd901121d6becdfc35c235ccb4866a38a71`.
- Zip: `f69f243bf1040cb0d7703962eff4e2e4597ba805995970164f5272729e22b96b`.

The model's labels stay, as `id,label` rows. With the key gone they can't be tied to a site. The gate's
proof that a round's text is gone covers its raw file only, so it didn't catch this, and it can't.

**Pilot round 2.** If anyone reads that round's text, a sheet is made on the server only, read there by
a named person, and deleted before the prune. It goes to no laptop, no labeler and no hosted model.

**Pass 3.** The draw writes the audit sheet on the server, and the key stays there until both sets of
labels exist. One copy of the sheet goes to the maintainer's machine, and from it to the one labeler and
the model, as Amendment 2 says. The labeler deletes theirs, and the date is recorded. Our copies stay
until the 12-month deletion.

Neither rule is enforced by code. They are rules for the people running the study.

### Pass 3

A new pass replaces pass 2 under the rules of Amendment 2, with `--pass 3`, in its own fixed folder
`e20r-pass3`, with pass 2's seed, 2021, because nothing here needs another. Everything Amendment 2 says
of pass 2 as the run that decides claims applies to pass 3. It runs once. The lock on pass 2 stays, so
pass 2 can't start again. Pilot round 2 and pass 3 refuse unless the stopped pass is pass 2 itself, real
and unchanged at its end, stopped for exactly this registered privacy reason, with its original raw hash
and count, a validated legacy finding at a place the stop reads, a named review bound to that report and
to the manifest and original raw hash, and a prune proof that matches its raw file. Any other partial
run is not covered: SIGTERM, resolver failures, the stop file or a changed source address need a new
amendment.

### No site is visited twice under E20-R2

Pass 3 skips the 50 sites of pilot round 1, the sites of pilot round 2 and every site in the stopped
pass's 188 records, and they are counted. The sites come from the pruned raw file of the stopped pass, so
a purged pass can't be followed by pass 3. These sites were visited once in pass 1, and pass 3 will visit
the others for the second time, as Amendment 2 says.

### Precision

Of the 7,031 listed sites, 389 can't be visited, because of the exclusion list and earlier opt-outs. That
leaves 6,642. Pass 3 loses up to 277 of them, 4.2%, and can visit up to 6,365, before robots rules:

- 50 sites of pilot round 1.
- 177 sites visited in the stopped pass. Its other 11 records were already on a skip list.
- Up to 50 sites of pilot round 2.

The loss isn't even, because pilots draw only from the claim lists. Overall, intervals widen by about
2%. The claim lists, with both pilot rounds counted:

| List | Sites that can be visited | Lost | Share | Intervals wider by about |
|---|---:|---:|---:|---:|
| YC-25 | 316 | 29 | 9.2% | 5% |
| YC-new | 416 | 33 | 7.9% | 4% |
| T100k | 866 | 44 | 5.1% | 3% |
| T1k | 918 | 45 | 4.9% | 3% |
| YC-old | 607 | 28 | 4.6% | 2% |

The order of the stopped pass was fixed before collection, by the seed. Its stopping position was
outcome-dependent: the last record is in because of what it held, and the number of sites before it
depends on earlier responses. So the removal isn't claimed to be at random. The analysis reports skipped
sites per cohort and reason, and a site keeps the first reason it was skipped.

### Review

The outside reviewer's technical go of 31 October in Amendment 2 was given on Amendment 2. It doesn't
cover this amendment. That reviewer gave a technical no-go on packages 6, 7 and 8.
<GAP-REVIEW-STATUS> This is not an ethics endorsement, and no independent human ethics board reviewed
this study.

### Limits

Sites in the stopped pass were visited under Amendment 2 and aren't in the claims. The decision to run
again came after the stop. This changes a stop rule after a stop. It was written before pilot round 2,
with no claim's data read, it stores less than the rule it replaces, and it can't move a label or a grade.
The scrub's forms and the detector's other limits don't change. Rates for the detector come from a
synthetic corpus and one real fire, and the tightened detector was fitted on that corpus.
