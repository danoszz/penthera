# Public benchmarks (E11)

> **Pro.** For "how does Penthera do on public datasets that other people labelled?"

This runner scores Penthera against three public datasets, one per
capability. The protocol is pre-registered in
[E11-public-benchmarks.md](../../docs/research/prereg/E11-public-benchmarks.md);
the numbers are in [RESULTS.md](RESULTS.md).

| Benchmark | Capability | Dataset pin |
|---|---|---|
| [Samsung CredData](https://github.com/Samsung/CredData) | Secret scan | `c49ed106` |
| [SecBench.js](https://github.com/cristianstaicu/SecBench.js) | Code-execution sinks (`--repo`) | `5d362353` |
| [DataDog malicious packages](https://github.com/DataDog/malicious-software-packages-dataset) | Dependency capability scan (`penthera deps`) | `21822443` |

## Reproduce

```bash
export GH_TOKEN=$(gh auth token)                 # the malware sample is drawn through the GitHub API
npm run bench:public                             # all three
npm run bench:public -- --only secbench          # one: creddata, secbench or malware
npm run bench:public -- --only creddata --skip-fetch   # reuse the cache
npm run bench:public -- --split dev              # E11b: score the dev half only
npm run bench:public -- --competitors --split dev        # E11b: reference secret scanners and GuardDog on dev
npm run bench:public -- --competitors --split dev --only secbench --tools codeql,semgrep  # E11b: a subset of the SecBench.js tools
```

E11b splits each benchmark into a dev half and a sealed test half
([split/](split/), ids and hashes only; protocol in
[E11b-improvement-study.md](../../docs/research/prereg/E11b-improvement-study.md)).
The default, `--split all`, reproduces E11 as registered. `--split test`
is refused without `--final`: the test half runs once, at the end.

Needs Node.js 22 or later, git, `unzip`, Python 3.10 or later (for CredData's
own `download_data.py`), network access for the fetch steps, and about 3 GB
of disk. CredData's download fetches 297 repositories and takes about 15
minutes. The runner is never part of `npm test`, and none of `bench/` is in
the npm package.

Datasets go to `$PENTHERA_BENCH_CACHE/public` (default
`~/.cache/penthera-bench/public`), outside the repository. Scores and a
markdown summary per benchmark go to `results/` there. Nothing downloaded is
committed.

## How a run works

1. **Fetch** (network). Clone the dataset at its pin; for SecBench.js, fetch
   each vulnerable version's tarball from the npm registry and check its
   integrity; for DataDog, draw the seeded sample and download it; for the
   benign baseline, fetch the latest release of 300 popular names per
   ecosystem and check its hash.
2. **Scan** (offline). A child process runs every scan with
   [net-guard.cjs](../../scripts/ci/net-guard.cjs) preloaded and an empty
   `HOME`. The count of blocked connections is in the results and must be
   zero.
3. **Score.** Wilson 95% intervals, from `wilson` in
   [../known-vuln/score.mjs](../known-vuln/score.mjs).

## Reference tools on SecBench.js

`--competitors --only secbench` runs seven static analyzers on the
SecBench.js packages of the current split and on the benign npm packages of
the same split. `--tools codeql,semgrep` runs a subset and keeps the other
rows in the results file.

| Tool | Pin | Rules |
|---|---|---|
| njsscan | 1.0.1 (PyPI, own venv) | its bundled rules |
| CodeQL | CLI bundle 2.27.2 (`codeql-bundle-v2.27.2`, 2026-10-07), sha256 checked against the release's `.checksum.txt` | `javascript-security-extended`, from the bundled `codeql/javascript-queries` |
| Semgrep | 1.180.0 (PyPI, own venv, 2026-10-07) | [semgrep-rules](https://github.com/semgrep/semgrep-rules) at `9bbf021d` (2026-10-08), `javascript/` only, cloned locally |
| eslint-plugin-security | 4.2.0 with ESLint 10.12.0 (npm, `--ignore-scripts`) | the plugin's `recommended` config |
| Bearer CLI | 2.1.1 (release binary, sha256 checked against `checksums.txt`) | [bearer-rules](https://github.com/Bearer/bearer-rules) v0.48.4 `javascript.tar.gz`, sha256 pinned, passed with `--external-rule-dir` |
| graudit | commit `849d7c7` (2026-05-20) | its `js` signature database |
| ODGen | commit `c5157ee` (2023-07-06), own venv | its `os_command` and `code_exec` checks |

How a run works:

- Each package is unpacked to a temp folder and scanned under
  `sandbox-exec` with all network access denied. Before the scans, a curl to
  the npm registry runs under each profile and must fail.
- CodeQL builds one database per package
  (`--language=javascript --build-mode=none`) and writes SARIF. The bundle
  holds the query packs, so nothing is downloaded at scan time.
- Semgrep runs with `--metrics=off --disable-version-check` and the local
  rules folder. It never uses `--config auto` or a registry config, which
  fetch rules at scan time. The main row keeps Semgrep's default ignore list
  (it skips `build/`, `dist/` and test folders). The variant
  `semgrep, every file` puts an empty `.semgrepignore` in the package, which
  turns that list off.
- Bearer fetches its default rules at scan time, so they are turned off
  (`--disable-default-rules`) and the pinned bearer-rules folder takes their
  place. Its scan workers talk to the main process over TCP on 127.0.0.1, so
  Bearer runs under a profile that allows loopback and denies every other IP
  connection.
- ODGen's `requirements.txt` is unpinned and its `install.sh` runs npm with
  install scripts. The runner pins the four Python packages it needs to
  releases from before its last commit, and installs its AST exporter's three
  npm dependencies with `--ignore-scripts`. Each package scans in its own
  copy of ODGen, because ODGen writes logs into its working folder.
- A finding counts for a class by the CWE its rule carries: CWE-78 for
  command injection, CWE-94 or CWE-95 for code injection. Three tools report
  no CWE, so their rules are classed by what they look for:
  eslint-plugin-security (`detect-child-process` is command injection;
  `detect-eval-with-expression` and `detect-non-literal-require` are code
  injection), graudit (a line matching its `.exec`/`.spawn` concatenation
  signature is command injection, one matching an `eval(` signature is code
  injection) and ODGen (an attack path that ends in a `child_process` call is
  command injection, also in a `code_exec` run). Scoring is the same
  as for Penthera: strict recall needs the finding in the sink file, lenient
  recall counts it anywhere in the package, with Wilson 95% intervals.
- On the benign packages, a false alarm is a package with at least one
  command or code injection finding. Findings per package (all rules) are a
  noise indicator.
- Each package has a deadline: 15 minutes for CodeQL, 10 for every other
  tool. A package that fails or times out is left out of that tool's
  denominators and counted under errors or timeouts. CodeQL refuses a
  package with no JavaScript source (a types-only package, for example), so
  those count as its errors.

Licenses: the CodeQL CLI is under the GitHub CodeQL Terms and Conditions,
which allow academic research and analysis of open-source codebases, and not
automated analysis or CI outside those. The semgrep-rules are under the
Semgrep Rules License v1.0. Bearer CLI is under the Elastic License 2.0,
eslint-plugin-security under Apache-2.0 and graudit under GPL-3.0. ODGen's
repository states no license. Every tool goes to
`$PENTHERA_BENCH_CACHE/public/tools`, never a global install.

## Malware safety

The DataDog samples are real malware. The runner:

- downloads and extracts them only under `/private/tmp/penthera-e11-malware`,
  and refuses any other path;
- extracts with `unzip -P infected` and reads the files as text with
  Penthera's scanners; it never installs, imports, requires or runs a sample;
- deletes that folder when the malware benchmark ends, also on failure;
- writes only names, versions, sample paths, hashes and finding kinds to its
  results, never code or snippets.

Do not run the malware benchmark on a machine where an accidental `npm
install` or `pip install` in that folder would matter.

## Files

| File | What |
|---|---|
| `run.mjs` | Fetch, offline scan child, score, write results |
| `common.mjs` | Paths, seeded sampling, downloads, the offline child |
| `creddata.mjs` | Rule families, CSV reader, line matching, precision and recall |
| `secbench.mjs` | Package resolution, sink matching, capability check |
| `malware.mjs` | Sampling, extraction, root detection, flag rules, and the E11b payload kind of each npm sample (from its files alone, never from Penthera's result) |
| `split.mjs`, `split/` | E11b: the seeded, stratified dev/test split and its manifests |
| `competitors.mjs` | E11b: pinned reference tools, run offline, scored the same way |
