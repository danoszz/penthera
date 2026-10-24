# E11b: improving Penthera on E11, without fooling ourselves (amendment)

> **Project page.** For researchers asking "how will Penthera be tuned on E11's benchmarks, and how do we keep the 'after' numbers honest?"

| | |
|---|---|
| Amends | [E11](E11-public-benchmarks.md). E11's registered result (`bench/public/RESULTS.md`, baseline as run on all data) stays as it is |
| Status | **Approved by Daan van der Zwaag, 2026-10-24, as drafted (commit `262745c`).** Pass 1 started after approval |
| Date written | 2026-10-24 |
| Authors | Daan van der Zwaag (PI, decides every rule change). Drafted with Claude (AI-assisted) |
| Seen before this amendment | E11's aggregate results on all data and the handful of named cases in its `RESULTS.md`. No per-item error lists. After the split was sealed (commit `72d3149`), the dev half was scored for the baseline in § 4 and the reference tools in § 5. The test half has not been scored |

## 1. Why an amendment

E11 measured Penthera once, on whole datasets. Tuning rules on the same data
and reporting on it again would give numbers that look better and mean less.
E11b splits each benchmark into a **dev** half, where we look at errors and
tune, and a sealed **test** half, which is scored exactly once, at the end.
Only the test half's numbers are published as "after".

## 2. The split

Seeded (mulberry32, seed `20261024`), stratified, 50/50, written by
`bench/public/split.mjs` and committed as id manifests before any half was
scored. The manifests hold ids and hashes only, no data.

| Benchmark | Unit | Strata | Dev | Test | Manifest | SHA-256 of the manifest |
|---|---|---|---:|---:|---|---|
| CredData | File (a file's lines never land on both sides) | Family x file extension of `T` rows, plus `F` and `X` totals; greedy balance, largest file first | 5,515 | 5,515 | `bench/public/split/creddata.json` | `2c1356cc0bfd848be766925bfb2cdfc1d811fe34bf4fb189dcbd6d000966ac47` |
| SecBench.js | Vulnerability folder (in-scope classes) | Class | 71 | 70 | `bench/public/split/secbench.json` | `7b6e2c0bb90e5ff9053cd79d508ea9dae5c5fac537585904b442881116e34aa2` |
| DataDog | Sample archive | Ecosystem x group (`malicious_intent`, `compromised_lib`) | 334 | 333 | `bench/public/split/malware.json` | `c29de260d69b085d62e3dab98c08d406d023f43f738063b5e6074a4192eccb69` |
| Benign baseline | Package (`eco/name@version`) | Ecosystem | 300 | 300 | `bench/public/split/benign.json` | `082a6838576dd04a642dc4dfdcf8ad8fa1708e710506856734c3e869fbe70093` |

Each hash in a manifest pins its item: for CredData the item's labelled rows,
for SecBench.js the npm tarball, for DataDog and the benign baseline the
archive. A CredData file with no labelled line goes to the side given by the
parity of the SHA-256 of its path.

**CredData balance.** The repository level was tried first, as preferred, and
rejected before anything was scored: single repositories hold whole strata
(all 786 private keys in `.txt` files sit in one repository). At the file
level the in-scope `T` rows split as follows; one file still holds most of
the out-of-scope `partial` family.

| Family | Dev | Test |
|---|---:|---:|
| provider | 140 | 126 |
| private-key | 557 | 636 |
| password | 1,424 | 1,354 |
| api-key | 118 | 104 |
| partial (out of scope) | 4,002 | 1,476 |
| out (out of scope) | 2,867 | 2,949 |
| `F` / `X` rows | 24,032 / 2,043 | 24,029 / 2,039 |

`npm run bench:public -- --split dev|test|all` selects a half. `all` is the
default, so E11's registered run stays reproducible. The runner refuses
`--split test` without `--final`.

## 3. Scoring units

E11's units stay. CredData gets two more, so a counting effect is visible:

| Unit | What counts once | Found when |
|---|---|---|
| **Row** (E11's unit, "per secret") | One labelled credential. CredData encodes a PEM block or any multi-line value as one row with `LineStart` < `LineEnd` (1,154 of 1,193 true private-key rows span several lines); rows never overlap | Any hit on a line in the range |
| **Line** | Every line of a true row's range | A hit on that line |
| **File** | A file with at least one in-scope true row | "Matched": a hit on one of its true rows. "Any": any secret hit in the file, which is what a user of the CLI sees |

File precision: a file with a hit is correct when it holds any true row.
SecBench.js and DataDog keep E11's units.

## 4. Dev baseline (Penthera as in E11, no rule changed)

See `bench/public/RESULTS.md`, section "E11b dev baseline". It is the
reference every pass is compared against.

## 5. Reference tools (not part of E11's hypotheses)

Open-source tools, pinned, run locally on the same split with all network
access denied (macOS `sandbox-exec`; GuardDog applies its own kernel sandbox,
which always blocks the network), scored with the same code:
gitleaks 8.30.1 and detect-secrets 1.5.0 on CredData; GuardDog 3.2.0 on the
malware and benign sets (static only, E11 § 10 safety rules). TruffleHog was
left out: its latest release was a day old, and it was named as an
alternative only. These numbers are reference points: the tools have
different scopes, and GuardDog found most of DataDog's dataset in the first
place (E11 § 9), so its detection rate there is inflated by construction.

## 6. Guards, checked on every pass

A change that breaks a guard is rejected, whatever it gains.

| Guard | Limit |
|---|---|
| Benign npm false alarms (dev) | ≤ 0.02 |
| Benign PyPI false alarms (dev) | ≤ 0.08, target ≤ 0.03 |
| Bundled benchmark (`bench/RESULTS.md`, audit gate) | No drop in precision or recall above 0.02 |
| E10 known-vulnerable apps | No new false positive, no lost root cause, without a written reason |
| Self-scan (`audit/baseline.json`) | No new finding |
| Scan time | No slowdown above about 10% on the bundled benchmark |
| Package budget | Unchanged, unless the maintainer agrees |

## 7. Targets (on the sealed test half)

| Benchmark | Target |
|---|---|
| CredData | Precision ≥ 0.70 and in-scope row recall ≥ 0.50 (E11's H1 and H2 thresholds) |
| DataDog npm `malicious_intent` | Flag rate ≥ 0.70, with benign npm ≤ 0.02 |
| DataDog PyPI | Benign false alarms ≤ 0.03, with malicious PyPI ≥ 0.78 |
| SecBench.js | Command-injection strict recall ≥ 0.50 in a library mode, only if the maintainer decides to build one (D0 in the plan) |

Registered 2026-10-24, after the dev-split analysis and before the test half
was scored (maintainer's decisions):

- **npm malware, two rows.** The main npm score counts packages that carry a
  payload. Packages with none (registry spam that republishes itself, empty
  `npm init` packages, harmless proofs of concept, security holding
  placeholders) are reported as their own row with their own rate, never
  dropped. The kind of each test sample is assigned by the same written
  criteria as on dev (`b1` taxonomy), before Penthera's result on it is seen.
  The ≥ 0.70 target applies to the payload row; E11's all-packages rate is
  reported next to it.
- **SecBench.js, library mode.** Built (D0 decided yes). A function whose whole
  job is to run its argument is reported at `potential` and counted as found.
  The command-injection rate without those cases is reported next to it.

**Ranking (registered 2026-10-24, before the test half is read).** Each
benchmark ranks Penthera against the free tools measured on the same half,
with the mean and median of those tools: secrets by the F1 of strict precision
and in-scope recall; malware by Youden's J, the share of malicious packages
caught minus the share of benign packages flagged (npm on the payload row);
SecBench.js by strict recall, command and code injection pooled. A tool
trained on the dataset (CredSweeper) is shown, not ranked. Paid tools are
listed as having no public results on these benchmarks. A rank is shown only when at
least five other free tools were measured on that benchmark; with fewer, the
tables give the scores and no rank.

## 8. Human-in-the-loop protocol

Each pass handles one rule or one gap:

1. Claude prepares a review sheet from the **dev half only**: 10 false
   positives and 10 misses, drawn at random, with the line and its context
   (CredData values are obfuscated already; malware is shown only as file
   structure and finding kinds, never code), a guess at the root cause, and
   one or two candidate rule changes.
2. The maintainer marks each item agree, disagree or unsure, and picks one
   change or none.
3. The change is implemented with unit tests, run on dev only, and shown as a
   delta: precision and recall with intervals, items newly found and newly
   lost, and every guard.
4. Keep or roll back. At most three passes per gap; stop earlier when the dev
   target is met.
5. Every decision is logged (date, items, decision, delta) in a lab notebook.

## 9. What a change may be based on

- A **general pattern**, stated in words ("YAML values are unquoted"), never
  a dataset artifact (a CredData file name, a DataDog package name, a value).
- Each change gets **unit tests from our own fixtures**, not from dataset
  content.
- Rules decide; a model only proposes (AGENTS.md rule 4).

## 10. The final run

After the last pass: one run on the sealed test half
(`--split test --final`), the same run of the unchanged E11 scanner on the
test half for the "before" column, and one independent check on data never
used for tuning (mcp-vulnbench or E1's projects). `RESULTS.md` keeps E11's
baseline as run and adds "After the improvement study (sealed test split)"
with before and after on the same test half and the decision log.

## 11. Deviations

As in E11 § 11. Looking at the test half before the final run, or changing a
manifest, voids the "after" claim, and is reported as such.

Logged so far:

- 2026-10-24: the SecBench.js analysis ran a prototype library rule on 10
  cached repositories (`~/.cache/penthera-bench/repos/`) to count false alarms
  in apps. E1 has not drawn its sample yet, so these may later fall in E1's
  frame. They are listed here so E1 can exclude them. The independent check in
  § 10 uses mcp-vulnbench, not E1.
- 2026-10-24: after pass 1 the maintainer delegated the per-pass review (§ 8)
  to one review at the end: "continue with fixing the gaps one by one and
  report back to me once all is done". Each later pass still keeps its review
  sheet (the random sample of new hits, new false alarms and misses), its
  general justification (§ 9) and its guard results, so the maintainer can
  accept or roll back each pass on its own before the test half is run.
- 2026-10-24: the final run (§ 10) was started on main `2db5a71` and 1.9.0,
  then stopped when the maintainer asked for one more improvement round
  before publishing. Penthera's before and after runs on the test half had
  finished; the reference tools had just started. Nobody read any of it. The
  outputs were packed into one archive, unopened, its SHA-256 recorded
  (`7fc4125987e9dbc462940f3fd736d5d76ca9fd98f3a34f714a2a15619f30a21f`), and
  every readable copy deleted. Round 2 tunes on dev only, as before. At the
  end, the archive is opened and published next to the round-2 test run, so
  both test runs are reported and none is chosen after the fact.
