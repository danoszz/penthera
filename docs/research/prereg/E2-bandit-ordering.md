# E2: Does a bandit find real issues faster than a fixed order? (draft pre-registration)

| | |
|---|---|
| Experiment | E2 in [vision-2.0.md](../../vision-2.0.md#experiments) |
| Status | **Draft, not registered.** It is registered (status changed, merged as a separate PR) only when the bandit is built and E1's corpus and labels exist. No E2 data has been collected. |
| Date of this draft | 2026-10-20 |
| Depends on | E1 (labelled findings as ground truth), the bandit implementation (milestone 1.9) |

## 1. Hypothesis

**H1.** On held-out targets, a contextual Thompson-sampling bandit that orders
Penthera's probes and fix recipes reaches the first true finding with fewer
requests than Penthera's current fixed order.

Two-sided test, α = 0.05. The hypothesis is directional in the claim: the
bandit ships only if it is better and the interval excludes zero.

## 2. Arms

- **Fixed (control):** the probe order of Penthera 1.7.x (the order in
  `src/scan-url.js` and the adaptive engine as shipped), with the local memory
  store disabled.
- **Bandit (treatment):** Thompson sampling over probes (and over recipes in the
  fix phase), context = framework, detected stack features, and route shape.
  Priors are fitted on the **development** targets only (§ 4) and frozen.

Both arms run the same probes; only the order changes. Each arm stops at its
first true finding or when its probe budget is spent.

## 3. Outcome

- **Primary:** number of HTTP requests until the first true positive (a
  finding that matches a labelled vulnerability of the target). A run that
  finds nothing within the budget is censored at the budget.
- **Secondary:** wall-clock time to first true positive; true positives found
  within a fixed budget of 500 requests; false positives before the first true
  positive.

## 4. Targets and the authorization constraint

E2 needs live HTTP targets. Penthera never scans systems it does not own, and
the E1 corpus is analysed statically only; **E1 projects are not started or
scanned live for E2.** Targets are therefore:

1. Penthera's own labs (`bench/targets`), and
2. deliberately vulnerable applications run locally in containers without
   outbound network (OWASP Juice Shop, crAPI, DVWA, NodeGoat, and similar),
   whose vulnerabilities are labelled in `bench/ground-truth.json` with a
   reference for each label (the challenge or documented flaw).

Targets are split by target, not by run: development targets (for fitting the
bandit's priors) and test targets (for the experiment) never overlap. The
split is drawn with a published seed before any E2 run.

**Open decision (maintainer):** whether E2 may also use E1 projects started
locally in a sandbox (container, no network, seeded data). That would execute
third-party code, which E1 forbids; it needs its own safety review. The
default in this draft is **no**.

## 5. Design and sample size

Within-target paired comparison: each test target is run with both arms under
the same seed; arm order is counterbalanced. A **paired run** is one (target,
seed) pair.

Paired t-test on the difference in log requests to first true positive,
d = 0.3 (a small-to-medium effect; the smallest improvement worth the
complexity), α = 0.05 two-sided, power 0.80:

n = ((z₀.₉₇₅ + z₀.₈₀) / d)² + z₀.₉₇₅² / 2 = ((1.960 + 0.842) / 0.3)² + 1.92 = 89.1 → **90 paired runs**

If the paired differences are clearly non-normal (Shapiro–Wilk p < 0.01 on
the log differences), the pre-specified fallback is the Wilcoxon signed-rank
test, for which 90 / 0.955 (its asymptotic relative efficiency) ≈ 95 runs are
collected from the start. Runs are spread over test targets as evenly as
possible, with different seeds per target; the analysis accounts for target
clustering with a mixed model (random intercept per target) as a sensitivity
analysis.

## 6. Analysis

- Primary: mean paired difference in log requests with its 95% interval;
  paired t-test (or Wilcoxon, by the rule above). Censored runs enter at the
  budget; a sensitivity analysis uses a paired survival comparison
  (stratified log-rank by target).
- Secondary outcomes are reported with intervals, Holm-adjusted within E2.
- Explainability check (not a hypothesis): for every bandit run, the logged
  reason for the first three choices is reported for a random sample of 10
  runs.

## 7. Deviations and safety

Changes after registration are dated amendments made before the affected data
are collected; otherwise they are reported as deviations. Targets are local
and owned; payload probes are the existing benign markers; no outbound
network from the targets.
