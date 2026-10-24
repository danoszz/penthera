# E11: Penthera on public benchmarks (pre-registration)

> **Project page.** For researchers asking "how does Penthera do on public
> datasets that other people labelled?"

| | |
|---|---|
| Experiment | E11. Not yet listed in [vision-2.0.md](../../vision-2.0.md#experiments); adding it there is an open decision (§ 13) |
| Related | [E1](E1-real-world-accuracy.md) (real-world accuracy, our own labels) and [E10](E10-known-vulnerable-apps.md) (known-vulnerable apps, answer keys we wrote from the apps' docs). E11 uses answer keys that neither we nor Penthera's rules had a hand in |
| Status | **Registered on the first commit of this branch; results added in later commits.** The commit that adds this file, before any Penthera run on these datasets, is the registration timestamp. The maintainer can still reject the design in review; then the results are reported as exploratory |
| Date written | 2026-10-24 |
| Authors | Daan van der Zwaag (PI). Drafted and run with Claude (AI-assisted) |
| Data collected before registration | Dataset metadata only, to fix scope and sample sizes: CredData's `meta/*.csv` (label counts per category and file extension), SecBench.js's per-vulnerability `package.json` files (class, package, version, sink location), and the file listing of DataDog's `samples/` tree (sample counts per ecosystem and category; two sample archives listed with `unzip -l`, not extracted, then deleted). **No Penthera run on any of the three datasets** |
| Scanner under test | Penthera at commit `58ae9d7` (package version 1.9.0), bundled rules only, no `--rules`, no AI mode |
| Structure | Mirrors E10: questions and hypotheses, datasets, scope, procedure, scoring, analysis, threats, safety, deviations |

## 1. Research questions and hypotheses

E11 runs one public benchmark per Penthera capability:

| | Capability | Benchmark | Question |
|---|---|---|---|
| RQ1 | Secret scan (`--repo`, `lib/whitebox/secrets.js`) | Samsung CredData | What share of Penthera's secret hits are real credentials (precision), and what share of labelled credentials in classes it has a rule for does it find (recall)? |
| RQ2 | Code-execution sinks (`--repo`, `lib/whitebox/code-sinks.js`) | SecBench.js | Of the npm vulnerabilities in classes Penthera claims (command injection, code injection), how many does its repo scan report at the documented sink? |
| RQ3 | Dependency capability scan (`penthera deps`, `lib/deps/`) | DataDog malicious software packages | What share of real malicious npm and PyPI packages does it flag, and what share of popular, benign packages does it flag with the same rule? |

The hypotheses are stated so that they can fail. The estimates are reported
whatever the outcome.

| | Hypothesis | Test | Supported when |
|---|---|---|---|
| H1 | Secret precision (primary run, § 6.1) is above 0.70 | Wilson 95% interval over labelled hit units | The lower bound is above 0.70 |
| H2 | Secret recall over in-scope true credentials is above 0.50 | Wilson 95% interval over in-scope `T` rows | The lower bound is above 0.50 |
| H3 | Recall on in-scope SecBench.js vulnerabilities, at the sink file, is above 0.50 | Wilson 95% interval over in-scope vulnerabilities with a sink location | The lower bound is above 0.50 |
| H4 | The primary malware rule (§ 6.3) flags more than 0.70 of malicious-intent packages, in each ecosystem | Wilson 95% interval, npm and PyPI separately | Both lower bounds are above 0.70 |
| H5 | The same rule flags fewer than 0.10 of benign popular packages, in each ecosystem | Wilson 95% interval, npm and PyPI separately | Both upper bounds are below 0.10 |

Why these thresholds: 0.70 and 0.50 are E1's and E10's thresholds, kept so
the studies read together. For H4, 0.70 is a level at which a user would
see most malware flagged before install. For H5, 0.10 is the false-positive
rate above which a pre-install check is commonly switched off.

**Predictions, written down before the runs.** These are expectations, not
hypotheses, recorded so the reader can see what surprised us:

- H2 is likely to fail. At least 38% of CredData's true credentials are in
  `.txt` and `.md` files alone, which the secret scan does not read.
- H3 is likely to fail for command injection. The sink check calls an `exec`
  "tainted" only when request data (`req.body`, `req.query`, ...) reaches it.
  A library's vulnerable function takes ordinary parameters, so most of
  these sinks look untainted, and untainted `exec` is not reported by design.
  Code injection should do better: `eval` or `new Function` with a
  non-literal argument is reported at `potential` without taint.
- H4: install-script malware should be flagged often; malware that only
  runs on `require` without obfuscation or exfiltration shape may not be.

H1 to H5 are one family. Decisions are made on the intervals. Where a test
gives a p-value, raw and Holm–Bonferroni-adjusted values are both reported.
Everything else (per rule, per category, per file type, other thresholds,
the CLI-reported run) is secondary and descriptive.

## 2. Datasets and versions

| Dataset | Source | Pin | Licence | Answer key |
|---|---|---|---|---|
| CredData | [github.com/Samsung/CredData](https://github.com/Samsung/CredData) | `main` at `c49ed10629d9139eb88b71b6b7ab4054fff806ea` (2026-10-23) | Code MIT; data files keep their repos' licences (CredData README) | `meta/*.csv`: 67,896 labelled lines; 15,753 `T`, 48,061 `F`, 4,082 `X` |
| SecBench.js | [github.com/cristianstaicu/SecBench.js](https://github.com/cristianstaicu/SecBench.js) (ICSE 2023) | `main` at `5d362353550a8baa42bba34edd26e5fb86d41b60` (2026-08-20) | As in its repository | `<class>/<pkg>_<version>/package.json`: package, version, advisory, `sink` (`file:line:col`) |
| DataDog malicious software packages | [github.com/DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) | `main` at `2182244321c324af3e94133bbe0c0043cdaeac30` (2026-10-21) | Apache-2.0 | Every sample was triaged as malicious by a person (dataset README). npm: 23,062 `malicious_intent` and 1,448 `compromised_lib` archives; PyPI: 2,503 and 29 |
| Benign baseline | npm registry and PyPI, latest release of names sampled from Penthera's vendored popular lists (`lib/deps/popular-packages.json.gz`, 7,765 names; `popular-pypi.json.gz`, 8,000 names) | Version and SHA-256 of each artifact recorded at download | Each package's own | Assumed benign (§ 9) |

CredData is materialised with its own `download_data.py` at the pinned
commit (Python 3.12). It shallow-fetches each of 297 repositories at the
commit in `snapshot.json`, copies the labelled files, and obfuscates the
credential values (§ 9). Repositories that fail to download are listed; their
rows leave both numerator and denominator.

## 3. Units

- **CredData.** A labelled row: one line (or line range) of one file, with
  `GroundTruth` `T` (looks like a real credential), `F` or `X` (not one, or
  a test value or placeholder). `T` is positive; `F` and `X` are negative.
- **SecBench.js.** One vulnerability: one folder under a class directory,
  naming one package version.
- **DataDog.** One package: a distinct package name. When a name has several
  sample archives (versions), one is drawn at random (§ 5.3).
- **Benign.** One package: a name from the popular list, at its latest
  release.

## 4. Scope

### 4.1 CredData: rule families

Each row's `Category` is a colon-separated list of CredSweeper rule names.
A row belongs to the first family below whose categories it carries:

| Family | CredData categories | Penthera rules that claim it | In primary scope |
|---|---|---|---|
| `provider` | `AWS Client ID`, `AWS Multi`, `Github Classic Token`, `Google API Key`, `Stripe Credentials`, `Anthropic API Key`, `Perplexity API Key`, and any OpenAI, Hugging Face, Groq, Replicate, xAI, LangSmith, Pinecone or OpenRouter category | AWS access key, GitHub token, Google API key, Stripe secret key, and the AI-provider keys in `lib/rules/core/secrets.json` | Yes |
| `private-key` | `PEM Private Key` | Private key block, GCP/Firebase service account | Yes |
| `password` | `Password` | Hardcoded password | Yes |
| `api-key` | `API` | Generic API key assignment | Yes |
| `partial` | `Key`, `Secret` (and no category above) | Generic API key assignment (`api_key`, `secret_key`), JWT secret, session secret: a subset of the variable names CredSweeper's rules cover | No: reported separately |
| `out` | Everything else: `Token`, `UUID`, `Auth`, `Basic Authorization`, `Bearer Authorization`, `URL Credentials`, `JSON Web Token`, `JWK`, `Nonce`, `Salt`, `SQL Password`, `CMD Password`, `NTLM Token`, `PASETO`/`PASERK`, `NKEY Seed`, `Twilio`, `Dropbox`, `Slack Token`, `Firebase Domain`, `AWS S3 Bucket`, `BASE64` keys, and the rest | None | No: listed with counts, never counted as misses |

`Stripe Credentials` includes publishable and test keys, which Penthera's
`sk_live_` rule does not claim; it stays in `provider` and the per-category
table shows the effect. Files Penthera's secret scan does not read (by
extension or folder, `isSecretScanTarget`) are **in** primary scope: not
reading `.txt` is a property of the tool, so those rows count as misses.
A secondary recall restricts to files the scan reads.

### 4.2 SecBench.js: classes

| SecBench.js class | Folder | Vulnerabilities | In scope | Penthera sink pattern |
|---|---|---:|---|---|
| Command injection | `command-injection` | 101 (101 with a sink) | Yes | `command-injection` |
| Arbitrary code injection | `code-injection` | 40 (33 with a sink) | Yes | `eval` |
| Path traversal | `path-traversal` | 170 | No: no static path-traversal rule | |
| Prototype pollution | `prototype-pollution` | 192 | No: only URL fuzzing probes, which need a running server | |
| ReDoS | `redos` | 97 | No: no rule | |

Out-of-scope classes are not scanned. They are listed so the reader sees
that Penthera's static JS check covers 141 of SecBench.js's 600
vulnerabilities by class.

### 4.3 DataDog: what counts as flagged

Penthera has no "malicious" verdict. `penthera deps` reports findings on
what a package can do. A package is **flagged** by a rule over those
findings:

| Rule | Flagged when the package has | Role |
|---|---|---|
| `code-medium` | A capability-scan finding (`riskFindings`) or a content IOC finding (campaign host or dropped file) of severity medium or higher | **Primary** (H4, H5) |
| `code-high` | The same, severity high or critical | Secondary |
| `code-any` | The same, any severity (includes a plain install script, low) | Secondary |
| `name` | A typosquat hit against the popular list, treating the package as a direct dependency, or a rule-pack IOC listing of its name and version | Secondary: name and list signals, not code analysis |
| `any` | `code-medium` or `name` | Secondary |

"Could not be scanned" (Penthera fails closed and reports high severity)
counts as flagged, as a user sees it; a sensitivity analysis counts it as
not flagged. Both categories (`malicious_intent`, `compromised_lib`) are
scanned and reported separately; H4 uses `malicious_intent` only.

## 5. Procedure

All of it is in `bench/public/` (`npm run bench:public`). It is never part of
`npm test` and not in the npm package. Datasets go to a cache outside the
repository (`$PENTHERA_BENCH_CACHE/public`, default
`~/.cache/penthera-bench/public`); malware samples go only to
`/private/tmp/penthera-e11-malware` (§ 10).

### 5.1 CredData

1. Clone CredData, check out the pin, run `download_data.py` in a
   virtualenv with its `requirements.txt`.
2. For every labelled file, run the secret rules (`findSecretsInText`) on
   its full text, and record each hit's rule and line.
3. Separately, run the CLI on each repository folder
   (`penthera --repo <dir> --offline --json`) and keep the `secrets` findings.
4. Score (§ 6.1).

### 5.2 SecBench.js

1. Clone SecBench.js and check out the pin.
2. For each in-scope vulnerability, take the package and version from the
   folder name and its `dependencies`, fetch that version's tarball from the
   npm registry, verify its `dist.integrity`, and write its files to a
   cache folder with Penthera's own tar reader (regular files only, no
   `..`). Nothing is installed, built or run; no dependencies are fetched.
   A version no longer on the registry is excluded and counted.
3. Run `penthera --repo <dir> --offline --json`.
4. Also run the capability scan (`scanPackage`) on the same tarball, for the
   secondary analysis.
5. Score (§ 6.2).

### 5.3 DataDog and the benign baseline

1. List `samples/npm` and `samples/pypi` at the pin through the GitHub API.
2. Draw the sample with mulberry32 (`bench/prng.js`), seed `20261024`: sort
   the distinct package names of each ecosystem and category, shuffle them
   (Fisher–Yates), take the first N, and for each pick one of its archives
   at random. N = 300 for `malicious_intent` in each ecosystem; all
   `compromised_lib` names for PyPI and 50 for npm. Archives over 50 MB are
   skipped and counted, and the next name is taken.
3. Download each archive into `/private/tmp/penthera-e11-malware/zips`,
   extract it with `unzip -P infected` into its own folder under
   `/private/tmp/penthera-e11-malware/x`. Package root: the shallowest folder
   with a `package.json` (npm), or with `setup.py`, `pyproject.toml`,
   `setup.cfg` or `PKG-INFO` (PyPI), else the shallowest folder holding a
   `.py` file. A sample with no root is excluded and counted.
4. Scan the root with the functions `penthera deps` uses: `scanPackage` or
   `scanPythonPackage` with the bundled IOCs, `riskFindings`, `iocFindings`,
   `findTyposquats` and `typosquatFindings`. No install, no import, no
   execution of any sample file.
5. Delete every archive and extracted file when the run ends, also on
   failure.
6. Benign: draw 300 names per ecosystem from the popular lists with the same
   seed; fetch the latest release (npm: the `latest` tarball, integrity
   checked; PyPI: the latest release's sdist, else its first wheel, SHA-256
   checked); scan it in memory with the same functions. A name with no
   downloadable artifact is skipped and the next taken.
7. Score (§ 6.3).

Every scan step runs offline: the child process that scans has
`scripts/ci/net-guard.cjs` preloaded and an empty `HOME`. Its count of
blocked connections must be zero and is reported. Downloads happen only in
the fetch steps before.

**Frozen scanner.** No rule changes because of anything seen here until the
results are published. Rule ideas go to a follow-up list.

## 6. Scoring

### 6.1 CredData

- **Match.** A hit matches a row when the file is the same and the hit's
  line is within `LineStart` to `LineEnd`.
- **Precision unit.** A distinct (file, line) with at least one hit. It is
  *labelled* when it matches at least one row; *correct* when a matching row
  is `T`. Primary precision = correct / labelled. Unlabelled units are
  reported; a sensitivity analysis counts them as incorrect (a lower bound).
  Precision is also given per Penthera rule.
- **Recall.** In-scope `T` rows matched by any hit / in-scope `T` rows, per
  family and per CredData category, with a secondary restricted to files the
  scan reads.
- **Runs.** Primary: rule hits in the files the repo scan reads (§ 5.1 step
  2, filtered by `isSecretScanTarget`). Secondary: rules on every labelled
  file whatever its extension ("rules only"), and the CLI's reported findings
  ("as reported": the CLI reports the first hit per rule per file, so its
  line-level recall is lower by construction).

### 6.2 SecBench.js

- **Strict (primary).** Found when the repo scan reports a `code-pattern`
  finding with the class's pattern (`command-injection` or `eval`) in the
  sink's file. Denominator: in-scope vulnerabilities with a sink location
  whose package could be fetched.
- **Lenient.** Found when such a finding is anywhere in the package.
  Denominator: all fetched in-scope vulnerabilities.
- **By confidence.** Strict hits split by `likely` and `potential`.
- **Capability scan (secondary, exploratory).** Whether `scanPackage` lists
  `shell` (command injection) or `eval` (code injection) with evidence in
  the sink file. A capability is "can do X", not "is vulnerable"; this bounds
  what the deps view sees.
- Precision is not estimated: SecBench.js labels one vulnerability per
  package, so other findings are neither confirmed nor refuted. Their count
  is reported.

### 6.3 DataDog

- **Detection rate** = flagged / scanned malicious packages, per ecosystem,
  category and rule (§ 4.3).
- **False-positive rate** = flagged / scanned benign packages, per ecosystem
  and rule.
- Which findings fired, by kind, on both sides; IOC-list hits shown
  separately (a list entry is knowledge, not analysis).

## 7. Analysis

Proportions get Wilson 95% intervals (`wilson` in
`bench/known-vuln/score.mjs`), with the sample size. Hypotheses are judged
on the intervals as in § 1. No pooling across benchmarks: each capability is
reported on its own. Results go to `bench/public/RESULTS.md`, with the
Penthera commit, Node version, dataset pins, sample lists (names and
versions, not contents) and the net-guard count.

### 7.1 Sample sizes

CredData and SecBench.js are scored in full. For DataDog, N = 300 gives a
Wilson half-width of at most about 0.056 at p = 0.5 and about 0.035 at
p = 0.1 or 0.9. Benign N = 300 gives an upper bound of about 0.012 when no
package is flagged and about 0.06 at 3%.

## 8. What is not measured

- Live URL checks, `--deep` probes, AI mode, `penthera agents`.
- Whether a flagged malicious package would also be blocked by
  `penthera install` (it uses the same scan, plus registry metadata online).
- Real-world base rates: H4 and H5 are rates, not the precision a user sees.

## 9. Threats to validity

- **Obfuscated credentials.** CredData replaces real values with example
  values (fixed-pattern keys) or random strings of the same character set and
  length. Prefix rules see realistic shapes; a rule that keys on entropy or
  checksums would not, and Penthera's placeholder filter (`example`, `test`)
  may skip an example value a real key would not have. Reported per family.
- **CredData's labelling frame.** Rows were labelled from the output of
  other scanners. A Penthera hit on an unlabelled line may be a real
  credential no other tool found; primary precision ignores those lines and
  the sensitivity analysis counts them wrong. Test-folder credentials are
  labelled `T` by CredData's rules, which counts test fixtures as positives.
- **Category mapping is ours.** The family table in § 4.1 is a judgment. It
  was fixed before any run and is shown in full so a reader can redo it.
- **SecBench.js sink locations.** The `sink` field is the advisory's or the
  benchmark authors' call; a package may have the same flaw elsewhere. The
  lenient score covers that. Libraries are not servers: Penthera's taint
  sources are request fields, so this benchmark tests a use the sink check
  was not designed for. That is a real limit for users scanning libraries,
  and it is reported as one, not explained away.
- **Dataset selection bias.** DataDog's samples were mostly found by
  GuardDog's rules (dataset README), so they over-represent what heuristic
  scanners already catch. Penthera's IOC list may name some of the same
  packages; those hits are shown separately.
- **Sample format.** DataDog archives hold the extracted package, sometimes
  with tool metadata beside it. The root rule in § 5.3 is ours. PyPI samples
  are mostly source trees; the benign baseline prefers sdists to match.
- **Benign baseline.** Popular packages are older, larger and better
  maintained than the long tail, and are on the typosquat list by
  construction, so the `name` rule cannot fire on them. The false-positive
  rate applies to popular packages, not to every benign package.
- **Moving targets.** The benign baseline takes `latest` on the run date;
  versions and hashes are recorded. A later run may draw different
  artifacts.
- **AI assistance.** The protocol, runner and report were drafted with
  Claude. Every number comes from the runner's output, not from a model.

## 10. Safety

The DataDog samples are real malware.

- **Static only.** Samples are never installed (`npm install`, `pip
  install`), executed, imported or `require`d. Penthera's scanners read
  files as text. Python is not run on them at all; extraction uses `unzip`.
- **Contained.** Archives and extracted files live only under
  `/private/tmp/penthera-e11-malware`, outside the repository, and are
  deleted when the run ends, also on failure. The runner refuses to extract
  anywhere else.
- **Never committed.** `RESULTS.md` holds package names, versions, sample
  paths and which findings fired. No sample code, no snippets from samples,
  no IOC values taken from samples.
- **Offline scans.** The scan child runs under the network guard; any
  attempted connection is logged and counted.
- **SecBench.js packages** are vulnerable, not malicious. They are unpacked,
  read, and never installed or run. CredData repositories are read only.

## 11. Deviations and amendments

As in E1 § 10: changes after registration are dated amendments made before
the data they affect; changes made after are reported as deviations with the
planned and the actual analysis side by side; other analyses are labelled
exploratory; results are published whatever they show.

## 12. Reporting

`bench/public/RESULTS.md` gives every number in §§ 6 and 7 with its interval
and n, the hypothesis verdicts, what could not be run and why, and rule
ideas the results suggest, as follow-ups for later pull requests.

## 13. Open decisions for the maintainer

1. Adding E11 to `vision-2.0.md`.
2. Whether the numbers appear on the site, and next to which claim.
3. Whether to repeat E11 on each minor release, with fresh benign samples.

## Amendments

None yet.
