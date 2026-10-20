# E4: Does a classifier catch malicious packages that rules miss? (draft pre-registration)

| | |
|---|---|
| Experiment | E4 in [vision-2.0.md](../../vision-2.0.md#experiments) |
| Status | **Draft, not registered.** Registered only when the data sources are confirmed and the feature extractor is frozen. No E4 data has been collected. |
| Date of this draft | 2026-10-20 |

## 1. Hypotheses

- **H1.** On packages published after the split date, an interpretable
  gradient-boosted classifier over the capability features `penthera deps`
  extracts has a higher ROC AUC than Penthera's rules alone (DeLong's test for
  correlated AUCs, two-sided, α = 0.05).
- **H2.** At the recall the rules achieve on the test set, the classifier's
  precision is at least as high as the rules' (bootstrap interval of the
  difference).

## 2. Data

- **Malicious:** public collections with source available, such as the OSV
  `malicious-packages` advisories (for labels and dates) together with
  academic and industry sample sets that distribute the code (for example the
  Backstabber's Knife Collection and published malicious-package datasets).
  Each source, its licence, and its access terms are listed in the registered
  version.
- **Benign:** a random sample of npm and PyPI packages from the same periods,
  stratified by download popularity, excluding names in any malicious list.
- **Temporal split:** train and tune on packages first published before the
  split date; test on packages first published after it. The split date is
  chosen so that the test period has at least 500 malicious and 5,000 benign
  packages. Packages of the same name, or near-duplicates by content hash,
  never appear on both sides.

## 3. Features and model

Features are those `penthera deps` already computes (capability flags, counts,
evidence locations, install-script shape, obfuscation signals, typosquat
distance), frozen before the test set is touched. Model: gradient-boosted
trees with monotonic constraints where the direction is known; each score is
reported with the features that drove it (SHAP values or tree paths), never a
bare verdict. The rules' score for the AUC comparison is the count of
high-or-critical deps findings (an ordinal score, so ROC is defined).

## 4. Sample size

With 500 malicious and 5,000 benign test packages, Hanley–McNeil variances for
AUC = 0.85 (rules) and 0.90 (classifier) give standard errors of 0.011 and
0.009. Assuming a correlation of 0.5 between the two AUCs (same packages),
the standard error of the difference is 0.0103, so the smallest difference
detectable with power 0.80 at α = 0.05 is (1.960 + 0.842) × 0.0103 ≈
**0.029 AUC**. The registered version recomputes this with the actual counts
and the correlation estimated on the training data.

## 5. Analysis

- Primary: ΔAUC with DeLong's 95% interval and test.
- Secondary (Holm within E4): precision at the rules' recall, recall at 1%
  false-positive rate, per-ecosystem results, and errors by malware family.
- Calibration plot and Brier score for the classifier's probabilities.

## 6. Safety

Malicious samples are **never executed or installed**. They are downloaded
once into an isolated, offline environment, stored encrypted at rest, read
only by the static feature extractor, and never committed to this repository.
Only features and labels (no code) leave that environment. Changes after
registration are dated amendments made before the test set is touched.
