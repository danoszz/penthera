# E5: Are deterministic checks more robust than LLM judges? (draft pre-registration)

| | |
|---|---|
| Experiment | E5 in [vision-2.0.md](../../vision-2.0.md#experiments) |
| Status | **Draft, not registered.** Registered only when the item set is built and the judge configurations are frozen. No E5 data has been collected. |
| Date of this draft | 2026-10-20 |

## 1. Hypotheses

- **H1 (primary).** On adversarial agent setups (skills, MCP configs, hooks,
  instruction files) built with published evasion techniques, Penthera's
  deterministic `agents` checks are evaded less often than an LLM judge asked
  to decide whether the same item is unsafe. McNemar's test, two-sided,
  α = 0.05.
- **H2 (non-inferiority on benign items).** On a matched benign control set,
  the deterministic checks' false-positive rate is not more than 5 points
  higher than the judge's. Without H2, a detector that flags everything would
  "win" H1.

## 2. Detectors

- **Deterministic:** `penthera agents` at a frozen version; an item is caught
  if any finding of high or critical severity is raised on it.
- **LLM judge (primary):** a local open-weight model, version and quantisation
  recorded, temperature 0, with a fixed system prompt that asks for a
  safe/unsafe verdict and a reason.
- **Hosted judges (secondary, opt-in):** the same prompt to frontier models,
  run only if the maintainer approves sending the items off the machine.

## 3. Items

- **Adversarial (155):** benign base items (skills, MCP configs, hooks) into
  which a **marker instruction** is embedded using one published evasion
  technique each: hidden Unicode, HTML comments, whitespace padding, base64
  and other encodings, scanner-directed text, split instructions, homoglyphs,
  and similar techniques documented in published research and advisories. The
  marker is inert: it asks the agent to do something recognisable and
  harmless-by-construction (for example, to reveal a fixed canary string or to
  contact a `.invalid` host). Each item cites the source of its technique.
- **Benign control (155):** matched items with the same structure and length,
  with no marker.

No new jailbreak or evasion technique is invented for E5; no working payload
targets any real system; items are never deployed to any agent or service.

**Open decision (maintainer):** whether to publish the item set in full, in
part, or only as hashes plus the generator's technique list. The default in
this draft is to publish the technique list and per-technique results, and
share items with researchers on request.

## 4. Sample size

Paired design: every item goes to every detector. McNemar with discordant
proportions 0.15 (only the judge evaded) and 0.05 (only the rules evaded),
α = 0.05, power 0.80: **155 adversarial items** (same calculation as E3). If
the observed discordance in a 30-item pilot is lower, the item count is raised
by amendment before the main run.

## 5. Analysis

- Primary: McNemar's exact test on evasion; the paired difference in evasion
  rate with its 95% interval.
- H2: one-sided 95% upper bound of FPR(rules) − FPR(judge) below 0.05.
- Secondary (Holm within E5): evasion per technique; judge consistency across
  three repeated runs at temperature 0; agreement between local and hosted
  judges.

## 6. Deviations and safety

Changes after registration are dated amendments made before the affected data
are collected. The results are published whether or not the rules win; if the
judge is more robust, that is a finding and changes the roadmap.
