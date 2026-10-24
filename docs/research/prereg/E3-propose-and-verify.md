# E3: Does propose-and-verify fix more than recipes alone? (draft pre-registration)

| | |
|---|---|
| Experiment | E3 in [vision-2.0.md](../../vision-2.0.md#experiments) |
| Status | **Draft, not registered.** Registered only when the propose-and-verify loop is built and E1's labelled findings exist. No E3 data has been collected. |
| Date of this draft | 2026-10-20 |
| Depends on | E1 (true findings to fix), the local-model fixing loop (milestone 1.9) |

## 1. Hypothesis

**H1.** For the same findings, recipes plus a local model that proposes fixes
(kept only when verified) close a larger share of findings, fixed **and**
verified with no test regressions, than recipes alone.

McNemar's test, two-sided, α = 0.05.

## 2. Arms

- **Recipes (control):** Penthera's deterministic fix recipes as shipped.
- **Recipes + propose-and-verify (treatment):** recipes first; when no recipe
  matches, or a recipe fails verification, a local open-weight model proposes
  a diff. The diff is applied on a local branch, the finding is re-scanned,
  and the project's tests run. It is kept only if the finding is gone, no new
  finding appears, and no test that passed before fails.

The model, its version, the prompt, temperature (0), and the maximum number of
attempts per finding (3) are fixed in the registered version. Hosted models
are an opt-in secondary arm only, never the primary comparison.

## 3. Outcome

Binary per finding: **fixed and verified** (finding absent on re-scan, no new
finding of equal or higher severity, test suite no worse than before). A human
reviewer also rates each kept diff as acceptable or not (secondary, blind to
arm), because a passing check is not the same as a good fix.

## 4. Findings and the execution constraint

Findings are E1 flagged units labelled correct and actionable, plus labelled
lab findings. Verification needs the project's tests, which **executes
third-party code**. E1 forbids that. So E3 runs only:

- in an isolated container per project, without outbound network, with no
  credentials and a throwaway copy of the clone; and
- on projects whose tests run offline in that container.

Findings in projects that cannot be tested this way are excluded and counted.

**Open decisions (maintainer):** approve this sandbox policy, or restrict E3 to
Penthera's own fixtures and labs (smaller, but no third-party execution).

## 5. Sample size

Paired design (both arms on every finding). McNemar with discordant
proportions p₁₀ = 0.15 (only treatment fixes) and p₀₁ = 0.05 (only control
fixes), p_disc = 0.20, Δ = 0.10:

n = [z₀.₉₇₅ √p_disc + z₀.₈₀ √(p_disc − Δ²)]² / Δ² = [1.960 × 0.447 + 0.842 × 0.436]² / 0.01 = 154.6 → **155 findings**

If the arms had to be unpaired (for example, a finding cannot be reset between
arms), 40% → 55% fixed needs 173 per arm (two-proportion test, α 0.05, power
0.80). The paired design is the registered one.

## 6. Analysis

- Primary: McNemar's exact test on the discordant pairs; the difference in
  proportions fixed with a Newcombe interval for paired data.
- Secondary (Holm within E3): share of kept diffs rated acceptable by the
  blind reviewer; regressions caught by verification (proposals rejected);
  per-category results.
- Every rejected proposal is logged with its reason, so the cost of the
  treatment is visible.

## 7. Deviations and safety

Diffs are never pushed or proposed upstream. Any real issue found remains
under E1's disclosure process. Changes after registration are dated
amendments made before the affected data are collected.
