# Penthera Bench v1: accuracy on real code

The tooling for experiment E1: how accurate Penthera's static analysis
(`--repo`, `deps`, `agents`) is on real, third-party web apps and agent setups.
The method is fixed in the
[pre-registration](../../docs/research/prereg/E1-real-world-accuracy.md); this
folder implements it. The lab benchmark one folder up measures regressions on
targets we wrote ourselves; this one measures accuracy on code we did not
write.

Only the manifests and aggregate results live in this repository. Clones,
package sources, scan output, and labels stay in a cache outside it
(`$PENTHERA_BENCH_CACHE`, default `~/.cache/penthera-bench`); the tools refuse a
cache inside the repository.

## Pipeline

```bash
CORPUS=bench/real-world/pilot/corpus.json

# 1. Clone each project at its pinned commit, fetch dependency sources, and fetch the frozen scanner
node bench/real-world/fetch.js --corpus $CORPUS --deps --scanner 1.7.0

# 2. Scan statically with the frozen scanner, network refused
node bench/real-world/run.js --corpus $CORPUS --scanner 1.7.0

# 3. Build labelling units and draw the blind samples
node bench/real-world/units.js --corpus $CORPUS

# 4. Each labeller, on their own: calibration first
node bench/real-world/label.js --corpus $CORPUS --labeller A --set calibration

# 5. Agreement and the calibration gate (kappa >= 0.70 overall, >= 0.50 per category)
node bench/real-world/kappa.js --corpus $CORPUS --set calibration
#    If it fails: revise the codebook, draw a fresh calibration set (at most three rounds), label it
node bench/real-world/units.js --corpus $CORPUS --calibration-round 2

# 6. After the gate passes, label the analysis set, then check agreement again
node bench/real-world/label.js --corpus $CORPUS --labeller A --set analysis
node bench/real-world/kappa.js --corpus $CORPUS --set analysis

# 7. Adjudicate disagreements (see below), then score
node bench/real-world/score.js --corpus $CORPUS
```

`score.js` writes `RESULTS.md` next to the manifest:
[`pilot/RESULTS.md`](pilot/RESULTS.md) for the pilot, `RESULTS.md` here for E1.

| Script | What it does |
|---|---|
| [`fetch.js`](fetch.js) | Clones at the pinned commit (only `git`: no hooks, no submodules, no LFS, symlinks as plain files, commit verified). With `--deps`: npm tarballs into an isolated cache with `npm cache add` from an empty folder and empty config, and hash-pinned Python wheels from PyPI, sha256-checked. Nothing is installed, no package code runs, no sdist is built. Sequential, with a delay and back-off on 403/429. `--scanner <v>` fetches `penthera@<v>` from npm and records its integrity |
| [`run.js`](run.js) | Runs `penthera --repo --offline`, `deps`, and `agents` on each clone as child processes, with `HOME` set to an empty folder, the isolated caches, and [`no-network.mjs`](no-network.mjs) preloaded so any non-loopback connection or DNS lookup is refused and logged. Never runs project code |
| [`units.js`](units.js) | Turns findings into units (E1 § 5), draws the flagged sample (at most 3 per project per category), the unflagged sample for recall (round-robin, at most 2 per project per category), and the calibration set. Writes `units-key.jsonl` (truth from Penthera's side) and one blind queue per labeller |
| [`label.js`](label.js) | Keyboard-driven, resumable labelling. Shows the code and the category question only: never Penthera's verdict, never the other labeller's answer. Appends to `labels-<A|B>.jsonl`. The analysis set stays locked until the calibration gate passes |
| [`kappa.js`](kappa.js) | Cohen's kappa with the Fleiss–Cohen–Everitt interval, level 1 and level 2, overall and per category; the calibration gate; a disagreement list |
| [`score.js`](score.js) | Precision (stratified by category, Wilson at the Kish effective n), recall from the unflagged sample, cluster bootstrap over projects, H1 to H3 with Holm, writes `RESULTS.md`. Aggregates only: no paths, code, or secret values |
| [`stats.js`](stats.js) | Wilson, Newcombe method 10, kappa, Kish, bootstrap, Holm. No dependencies |
| [`synthetic-labels.js`](synthetic-labels.js) | Generated labels for a pipeline check only. `score.js --synthetic` marks the report as meaningless as a measurement |

Tests: [`tests/bench-real-world.test.js`](../../tests/bench-real-world.test.js)
checks the statistics against published examples, the manifest rules, that
queues are blind, the network guard, and a hermetic end-to-end run on fixture
repositories cloned over `file://`.

## Blinding

Labellers must not know which units Penthera flagged. So unit ids are opaque
hashes, flagged and unflagged units of a category get the same question, both
are shuffled into one queue (a different order per labeller), and the queue
files carry no verdict, severity, confidence, or rule. `units-key.jsonl` holds
that information; labellers do not open it, and only `score.js` reads it.

## Adjudication

After both labellers finish a set, `kappa.js` writes
`disagreements-<set>.jsonl`. Discuss each one against the codebook; record the
outcome in `adjudications.jsonl` in the study folder, one line per unit:

```json
{"id": "3f2a…", "correct": "yes", "actionable": "no", "by": "A+B", "reason": "test fixture key, not a credential"}
```

Unresolved disagreements go to the third person (`"by": "C"`). `score.js`
uses the adjudicated label; kappa always uses the original independent labels.

## Safety

- Static analysis of public code only. No project is installed, built, run, or
  contacted at its deployment.
- Third-party code never enters this repository; the committed manifests hold
  URLs, commits, and licences.
- Labels and disagreements stay in the cache. Results contain aggregates only.
- A real issue found while labelling (above all a live-looking credential) is
  reported privately to the project's owner, with a 90-day window, and logged
  outside the public repository. Its location is published only after a fix or
  after the 90 days.

## Manifests

| File | Contents |
|---|---|
| [`corpus.json`](corpus.json) | The E1 corpus. Empty until the frame is frozen and the sample drawn. `excludedUrls` keeps the pilot projects out |
| [`pilot/corpus.json`](pilot/corpus.json) | Ten hand-picked projects, two per framework, for the pilot. Not part of the pre-registered sample |

A project entry: `url` (`https://github.com/<owner>/<repo>`), `commit` (40-hex
SHA), `license` (SPDX id from the accepted list), `stratum` (`nextjs`,
`express`, `fastify`, `hono`, `fastapi`, or `agents`), `framework`, and
optionally `excluded` with a reason (kept in the manifest, not deleted).

## Not built yet

- The frame builder (E1 § 3.4: segmented GitHub search, manifest checks,
  frozen snapshot) and the seeded draw. They come before the E1 sample is
  drawn, after the pilot.
- Seeded issues (E1 § 6.5), the secondary recall estimate.
