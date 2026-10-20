# E1: Penthera's accuracy on real code (pre-registration)

| | |
|---|---|
| Experiment | E1 in [vision-2.0.md](../../vision-2.0.md#experiments) |
| Plan | [plan-1.8.md](../plan-1.8.md) |
| Status | **Registered.** The commit that merges this file to `main` is the registration timestamp. |
| Date written | 2026-10-20 |
| Authors | Daan van der Zwaag (PI, labeller A); labeller B named in an amendment before calibration starts |
| Data collected before registration | None. No corpus frame has been built, no corpus repository has been cloned or scanned. The 10-project pilot runs after registration on projects excluded from the frame (§ 6.4). |
| Structure | The AsPredicted questions (§ 1 to § 9 map onto them), plus the OSF Preregistration sections AsPredicted lacks: sampling frame, stopping rule, blinding, deviations |

## 1. Research questions and hypotheses

**RQ.** How accurate is Penthera's static analysis (`--repo`, `deps`, `agents`)
on real, third-party web applications and agent setups that its authors did
not write?

The primary estimands are **precision** and **recall**, overall and per
category, each with a 95% interval. The hypotheses are stated so that they can
fail; the estimates are reported whatever the outcome.

| | Hypothesis | Test | Supported when |
|---|---|---|---|
| H1 | Overall precision (level 1, "correct") is above 0.70 | Wilson 95% interval of the primary precision estimate (§ 8.1) | The lower bound is above 0.70 |
| H2 | Findings labelled `confirmed` are more precise than findings labelled `potential` | Difference of two proportions, Newcombe hybrid score interval (method 10) | The 95% interval of p(confirmed) − p(potential) lies above 0 |
| H3 | Recall is lower than precision (the scanner is tuned for few false positives) | Paired cluster bootstrap over projects of precision − recall | The 95% percentile interval lies above 0 |

H1 to H3 are one family; their p-values (where a test gives one) are adjusted
with Holm–Bonferroni and both raw and adjusted values are reported. Everything
else (per category, per framework, level 2 "actionable") is secondary and
descriptive.

Why 0.70 in H1: it is the precision below which a developer-facing scanner is
commonly considered too noisy to keep using, and it sits well below the 0.86
measured on Penthera's own labs, so the test is not set up to pass trivially.
It is a threshold for a claim, not a prediction.

## 2. Dependent variables

Two binary labels per labelling unit, given by each labeller independently:

- **Level 1, correct (primary).** For a flagged unit: is the stated condition
  actually present at the stated location? (The key is a real-looking
  credential, not a placeholder; the route really has no authentication on the
  path described; the package really contains the capability shown; the MCP
  config really runs an unpinned package.) For an unflagged unit: is an issue
  of the unit's category present?
- **Level 2, actionable (secondary).** Only for units labelled correct: should
  the project's owner change something because of it? (A real `network`
  capability in an HTTP client library is correct but not actionable.)

Labels are `yes`, `no`, or `cannot tell`. `cannot tell` is kept and reported;
in the primary analysis it counts as `no` for flagged units (a finding a
competent reviewer cannot confirm is not credited) and as `no` for unflagged
units (no issue credited as missed). A sensitivity analysis drops these units.

## 3. Population, sampling frame and strata

### 3.1 Population

Public GitHub repositories that (a) are web applications or APIs built on
**Next.js, Express, Fastify, Hono, or FastAPI**, or (b) are **agent setups**:
repositories whose purpose is a set of AI agent skills, an MCP server
configuration, agent hooks or plugins, or agent instruction files.

### 3.2 Inclusion criteria (all must hold at the frame date)

1. Licence detected by GitHub as one of: MIT, Apache-2.0, BSD-2-Clause,
   BSD-3-Clause, ISC, 0BSD, Unlicense.
2. Not a fork, not archived, not a template repository.
3. At least one commit on the default branch in the 24 months before the frame
   date.
4. At least 10 stars (to exclude abandoned toy repositories; this narrows the
   population and is reported as such).
5. Web-app strata: the framework is a declared dependency in a manifest
   (`package.json` `dependencies` for `next`, `express`, `fastify`, `hono`;
   `pyproject.toml`, `requirements*.txt`, `uv.lock`, `poetry.lock` or
   `Pipfile` for `fastapi`) at the repository root or in one level of
   workspace folder, and the repository has at least 10 source files.
   A repository matching several frameworks is assigned to the one its
   root manifest names; if still ambiguous, the first in the order Next.js,
   Hono, Fastify, Express, FastAPI (most specific first, the order
   Penthera's framework detection uses).
6. Agent-setup stratum: the repository contains at least one of `SKILL.md`,
   `.mcp.json`, `mcp.json`, `.claude/settings.json`, `.claude/settings.local.json`,
   `.cursor/mcp.json`, a hooks configuration, a plugin `marketplace.json`,
   `AGENTS.md`, `CLAUDE.md` or `.cursorrules`, and its README or file layout
   shows that agent configuration is its purpose rather than incidental.

### 3.3 Exclusion criteria

- Deliberately vulnerable or training applications (OWASP Juice Shop, DVWA,
  NodeGoat, crAPI, and anything describing itself as intentionally insecure).
  They would inflate recall.
- The frameworks' own repositories, their official examples, and starter
  templates or tutorials with no application code of their own.
- Repositories that are more than 50% vendored, minified, or generated code by
  file count.
- Repositories with no default-branch commit in the clone (empty) or that fail
  to clone at the pinned commit (recorded, replaced from the reserve list).
- Anything authored or co-authored by Penthera's authors or labellers.
- Projects in the pilot (§ 6.4).

Exclusions are applied in two passes: automated (criteria checkable from API
metadata and manifests) and a manual screen of the README by labeller A before
any scan. Each exclusion is logged with its reason in the manifest
(`excluded` entries are kept, not deleted).

### 3.4 Sampling frame

The frame is built once, with the GitHub REST repository search API, within
its published rate limits (authenticated, sequential, backing off on `403`,
`429` and `Retry-After`). Search returns at most 1,000 results per query, so
queries are segmented by star range and creation year until each segment
returns fewer than 1,000. The queries, the date, and the raw candidate list
are saved; the frame is the candidate list after automated inclusion and
exclusion. Manifest checks read files from `raw.githubusercontent.com` at the
default-branch commit, which is pinned in the frame at that moment.

The frame is frozen: a JSON snapshot with a SHA-256 hash, committed (URLs and
metadata only, no code) before the draw.

### 3.5 Strata and allocation

| Stratum | Projects | Within-stratum strata |
|---|---:|---|
| Next.js | 30 | Popularity tercile (stars, computed within the stratum's frame): 10 per tercile |
| Express | 30 | Same |
| Fastify | 30 | Same |
| Hono | 30 | Same |
| FastAPI | 30 | Same |
| Agent setups | 50 | Popularity tercile: 17 / 17 / 16 (low / mid / high) |
| **Total** | **200** | |

Allocation is equal across frameworks, not proportional, so that no framework
dominates the overall estimate (Next.js and Express would). Population shares
from the frame are reported so a reader can reweight.

### 3.6 Draw

Within each cell, the frame is ordered by a SHA-256 of `seed + repo full
name`, where the seed is the SHA-256 of the frozen frame file. Projects are
taken in that order; the next ones in the same order form the reserve list for
replacements (§ 3.3) and for the stopping rule (§ 4.3). Labeller A screens the
drawn projects (README check) before anything is cloned; a screened-out
project is replaced from the reserve and logged.

## 4. Sample size

### 4.1 Precision

To estimate a proportion near p = 0.85 with a 95% interval half-width of
E = 0.04:

n = z² · p(1 − p) / E² = 1.96² × 0.85 × 0.15 / 0.04² = 3.8416 × 0.1275 / 0.0016 = 306.1

So **at least 307 labelled flagged units** (196 for E = 0.05). At p = 0.85
the Wilson interval for n = 307 is [0.806, 0.886], half-width ≈ 0.04.

### 4.2 Clustering and the per-project cap

Findings within a project are correlated (one codebase, one author's habits).
With an intra-project correlation ρ and m findings sampled per project, the
design effect is DEFF = 1 + (m − 1)ρ. To keep it small, at most **3 flagged
units per project per category** are sampled. Planning assumption:
ρ = 0.10 and m̄ ≈ 2, so DEFF ≈ 1.1 and the target becomes ⌈307 × 1.1⌉ =
**338 flagged units**. The realised DEFF is estimated from the data (§ 8.3) and
reported.

### 4.3 Stopping rule

Data collection stops when **both** hold: at least 200 projects scanned per
§ 3.5, and at least 338 flagged units sampled. If the 200 projects yield fewer
than 338 eligible flagged units, more projects are added from the reserve
lists, one per web-app stratum in rotation, until the target is met or the
reserve is exhausted. The number of added projects is reported. No look at any
label happens before the stopping rule is met (labels are not yet produced at
that point; sampling uses only Penthera's output).

### 4.4 Recall sample

Recall needs a labelled sample of units Penthera did **not** flag (§ 7). The
minimum is **80 unflagged units per category, 400 in total**, drawn after
flagged units, at most 2 per project per category. The base rate of issues in
unflagged units is unknown; the pilot (§ 6.4) estimates it, and if 80 per
category would give a recall interval wider than ±0.20 at the pilot's base
rate, the size is increased by a dated amendment before main labelling. If the
base rate is so low that no feasible sample narrows the interval, that is
reported as the result, not hidden.

### 4.5 Calibration set

60 units (12 per category; half flagged, half unflagged) drawn from the same
projects, used only for calibration (§ 6.2) and excluded from the analysis.
Each further calibration round draws a fresh 60.

## 5. Units and categories

| Category | Penthera source | Unit | Flagged unit | Unflagged unit (recall sample) |
|---|---|---|---|---|
| Secrets | `--repo` secret scan | A source or config file | A finding's file and line | A random file of a type the secret scan reads, not flagged |
| Route and auth boundary | `--repo` route and trust-boundary analysis | A route handler (method + path + file) | A finding on that route | A random discovered route with no finding |
| Code pattern | `--repo` risky-pattern analysis | A route handler file | A finding on that file | A random discovered route file with no finding |
| Dependency capability | `deps` | A (package@version, capability) pair, or (package@version, typosquat) | A non-info `deps` finding, keyed by its package and first capability | A random (package, capability) pair from the capability catalogue for which Penthera reports neither a finding nor an inventory entry, for a package whose source was readable |
| Agent configuration | `agents` | A configuration file (skill, MCP config, hook, settings, instruction file) | A finding's file and rule | A random discovered agent config file with no finding |

Info-severity findings are not units (they are inventory, not claims). A
finding that names several locations is one unit at its first location.
Several findings on the same unit (two secret patterns in one file) make one
flagged unit; its confidence label is the highest of them. `deps` also lists
capabilities in its inventory without raising a finding (an HTTP client's
`network`); such pairs are neither flagged nor eligible for the unflagged
sample, because Penthera neither warns about them nor stays silent on them.

Coverage limits that are known now and reported, not hidden:

- **FastAPI:** Penthera's route discovery reads JavaScript and TypeScript only.
  For FastAPI projects the route and code-pattern categories are **not
  applicable** and are reported as such, not as zero findings or perfect
  precision. FastAPI projects contribute secrets, dependency, and agent units.
- **Dependency recall** is estimated only for packages of at most 200 KB of
  unpacked source (a labeller can review that in bounded time). The share of
  packages above the limit is reported; recall for large packages is not
  estimated.
- **Python dependency capabilities** need package source; § 6.1 states how it
  is obtained. Packages with no wheel on PyPI are reported as not readable.

## 6. Procedure

### 6.1 Collection (static only)

1. **Fetch.** Each project is cloned (shallow, then the pinned commit) into a
   cache outside the repository (`$PENTHERA_BENCH_CACHE`). Only `git` runs.
2. **Dependency sources.** For npm, every registry entry of `package-lock.json`
   is added to an isolated npm cache with `npm cache add <name>@<version>`,
   run from an empty working directory (so no project `.npmrc` is read) with
   the public registry set explicitly and `--ignore-scripts`. This downloads
   and integrity-checks tarballs; it runs no package code. Git, file and
   tarball-URL dependencies are not fetched and are reported as not readable.
   For Python, for every package whose lockfile pins sha256 hashes, the
   matching wheel is downloaded from PyPI (located through PyPI's JSON API),
   its sha256 checked against the lockfile, and stored in an isolated pip
   cache folder where Penthera reads it. Nothing is installed and sdists are
   never built (that would run `setup.py`). Packages without hashes or without
   a matching wheel are reported as not readable. Projects without a
   lockfile get lockfile-free results only, as Penthera does for a user.
3. **Scan.** The frozen Penthera version (§ 6.3) runs as a child process, once
   per project:
   `penthera --repo <clone> --offline --json`, `penthera deps <clone> --json`,
   `penthera agents <clone> --json`, with `HOME` set to an empty temporary
   folder (no local memory store, no user config), `npm_config_cache`,
   `PIP_CACHE_DIR` and `UV_CACHE_DIR` set to the isolated caches, and a
   preloaded guard that refuses every non-loopback network connection. A
   project whose scan fails is logged and replaced from the reserve.
4. Nothing is installed into a project, no project script, build, test or
   server runs, and no deployment of any project is contacted.

### 6.2 Labelling

- **Labellers.** A: the PI. B: a fellow researcher with security background,
  credited as co-author, named by amendment before calibration. Neither may
  have contributed to any sampled project. A third person, named the same way,
  resolves deadlocks.
- **Blinding.** Each labeller works alone, on their own machine, from their own
  queue file; neither sees the other's labels until both have finished a set.
  Flagged and unflagged units are mixed and shuffled (seeded) in one queue.
  The labeller sees the code region and the category question ("Is a
  hardcoded, real-looking credential present in this file?"), never Penthera's
  verdict, severity, or confidence label. Where a flagged unit needs the claim
  to be judged (a specific capability in a package, a specific rule on a
  config file), the question names the condition, and unflagged units of the
  same category are phrased the same way, so the wording does not reveal which
  is which.
- **Codebook.** A written codebook with the decision rule and one positive and
  one negative worked example per category, frozen before calibration.
  Revisions after a failed calibration round are versioned and dated.
- **Calibration.** Both label the 60-unit calibration set. Full labelling
  starts only when Cohen's κ ≥ 0.70 on level 1 (pooled over categories), and
  no category has κ below 0.50. Otherwise the codebook is revised and a fresh
  60-unit set is labelled, at most three rounds. If round three fails, the
  study continues, the failure is reported prominently, and categories below
  0.70 are reported as unreliable.
- **Full labelling.** Both labellers label every analysis unit (flagged and
  unflagged). κ with a 95% interval is reported on the full set, overall and
  per category.
- **Adjudication.** Units where the labellers disagree are discussed against
  the codebook after both have finished. If they agree, the agreed label is
  final. If not, the third person decides. Every adjudication is logged with
  both original labels, the final label, and a one-line reason. The analysis
  uses the adjudicated labels; κ uses the original independent labels.

### 6.3 Frozen scanner

E1 measures **Penthera 1.7.0 as published on npm** (tarball integrity hash
recorded in the results), with only its bundled detection rules, run by
Node.js 22 LTS. No Penthera rule, pattern or threshold is changed on the basis
of anything seen in the corpus until E1's results are published. Rule changes
prompted by the study ship in a later release and are evaluated on a fresh
sample, so the study never grades its own tuning.

### 6.4 Pilot (not part of the sample)

Before the frame is built, 10 projects (two per web-app framework) are chosen
by the PI from public, permissively licensed repositories, listed with pinned
commits in `bench/real-world/pilot/corpus.json`, and excluded from the frame
by URL. The pilot exercises fetch, scan, unit sampling, labelling, κ and
scoring end to end, times the labelling, and estimates the base rate of issues
in unflagged units for § 4.4. Its results are published only as a pipeline
check, headed "Pilot, not part of the pre-registered sample". Any protocol
change it prompts is a dated amendment to this file, merged before the frame
is built.

### 6.5 Seeded issues (secondary recall estimate)

A fixed set of 25 synthetic issues, five per category, is defined in
`bench/real-world/seeds/` before the frame is built: for example a
provider-format key whose value is generated from a seed and assembled at run
time, a public route without authentication or rate limiting, an `eval` of a
request parameter in a route, a dependency tarball with an install script, an
MCP server that runs `npx -y` on an unpinned package. Each seed is inserted
into temporary copies of two projects drawn at random (seeded) from the
sample, giving 50 seeded instances. The copies are never committed or pushed.
Truth is known, so no labelling is needed. Seeds are inert static text: no
working exploit, no payload against any system.

## 7. Estimating recall

The full set of real issues in an arbitrary repository is unknown, so recall
cannot be measured directly. Two estimates are reported, with their limits.

**Primary: labelled sample of unflagged units.** For category c, let TP_c be
the number of flagged units labelled correct (scaled to all flagged units of
the category, if flagged units were subsampled), U_c the number of
unflagged units of the category in the scanned projects, and π̂_c the share of
sampled unflagged units labelled as containing an issue. Then

FN̂_c = π̂_c · U_c, recall_c = TP_c / (TP_c + FN̂_c),

and overall recall pools TP and FN̂ over categories. The 95% interval comes
from a cluster bootstrap over projects (10,000 resamples, fixed seed) that
resamples projects and recomputes both the flagged and unflagged parts.

Limits: (1) It measures recall only for the categories and unit types
Penthera claims to cover; issues of other kinds (business logic, stored
injection, authorization logic) are outside the estimate and the results say
so. (2) If real issues are rare in unflagged units, π̂ is close to zero with a
wide interval, and recall's upper bound will be near 1 whatever the truth. The
interval is reported as it comes out. (3) Labellers can miss issues too, so
FN̂ is a lower bound on misses and recall an upper bound; double labelling
reduces this but does not remove it.

**Secondary: seeded issues.** Recall on the 50 seeded instances with a Wilson
interval, per category. Limit: seeds are written knowing what the rules look
for, so this is an optimistic bound and is never reported as the headline.

**Not used: capture–recapture with a second tool.** Lincoln–Petersen needs
two detectors that find issues independently. Pattern-based scanners share
patterns, which biases the population estimate downward and recall upward. It
may be reported as exploratory.

## 8. Analysis

### 8.1 Precision

Per category c, precision_c = (flagged units labelled correct) / (flagged
units labelled), with a Wilson 95% interval.

**Primary overall precision** is the stratified estimate over categories,
weighted by each category's share W_c of all non-info findings in the scanned
projects: p̂ = Σ W_c · p̂_c. Its 95% interval is the Wilson interval computed
at the Kish effective sample size of the weighted sample. The unweighted
pooled proportion with its Wilson interval is reported next to it. Precision
per confidence label (for H2), per framework, and per popularity tercile are
reported the same way.

Level 2 ("actionable") precision is computed the same way, over all flagged
units, counting units that are not correct as not actionable.

### 8.2 Recall

As in § 7. H3 uses the same bootstrap resamples to form the distribution of
precision − recall.

### 8.3 Clustering

The realised design effect is estimated from the between-project variance of
per-project precision. A cluster bootstrap interval for overall precision is
reported next to the Wilson interval. If the two disagree by more than 0.02 at
either bound, the results say so and the cluster bootstrap interval is the one
used for H1 (decided now, not after seeing the data).

### 8.4 Agreement

Cohen's κ for labeller A vs B, level 1 and level 2, overall and per category,
with 95% intervals (analytic standard error, Fleiss, Cohen and Everitt 1969).
Raw percentage agreement and the label prevalence are reported too, because
κ is low when prevalence is extreme even if agreement is high.

### 8.5 Missing data and failures

Projects that fail to clone or scan are replaced from the reserve and counted.
Units a labeller skips are labelled later; units still unlabelled at the end
are reported and left out of the analysis (no imputation). Packages whose
source was not readable are counted per stratum.

### 8.6 Software and reproducibility

All computations are in `bench/real-world/` (Node.js, no statistics
dependencies), with unit tests against hand-computed examples. The results
file records the Penthera version and tarball hash, Node version, frame hash,
seeds, manifest hash, and label-file hashes. The manifest, the queries, the
frame snapshot, the codebook, and the adjudicated labels (without secret
values or code excerpts, § 9) are published.

## 9. Safety, ethics and disclosure

- Static analysis of public code only; no live scanning of any project's
  systems; no project code executed; no attack payloads generated.
- Third-party source is never committed to Penthera's repository. Only the
  manifest (URLs, commits, licences, strata) is.
- **Responsible disclosure.** If labelling confirms a real issue in a project
  (above all, a credential that looks live), the PI reports it privately to the
  owner through GitHub private vulnerability reporting or the contact in their
  `SECURITY.md`, and allows 90 days before any detail is published. The
  disclosure log is kept outside the public repository. Published labels
  include no secret values and no code excerpts; locations of confirmed issues
  are published only after a fix or after the 90 days.
- **Ethics.** The study analyses code, not people. Labellers are research
  staff. Before calibration starts, the PI obtains the university ethics
  office's written view on whether E1 needs review, and records it by
  amendment.

## 10. Deviations and amendments

- Any change to this plan after registration is added below as a dated
  amendment, with its reason, **before** the data it affects are collected.
- A change made after the affected data were collected is reported as a
  deviation in the results, with the planned and the actual analysis side by
  side.
- Analyses not described here are labelled exploratory wherever they appear.
- Results are published whatever they show, including if H1 fails.

## 11. Timeline

| Step | Target |
|---|---|
| Registration (this file merged) | 2026-10 |
| Tooling merged, pilot run, amendments if any | 2026-11 |
| Ethics view, labeller B named, codebook frozen | 2026-11 |
| Frame frozen and sample drawn | 2026-12 |
| Calibration and full labelling | 2027-01 to 2027-02 |
| Analysis and publication in `bench/real-world/RESULTS.md` | 2027-03 |

Dates are targets, not part of the registered protocol; slipping them is not a
deviation.

## Amendments

None yet.
