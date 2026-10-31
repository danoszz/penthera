---
title: We benchmarked {{fact:secrets.of}} free secret scanners on {{fact:secrets.n}} labelled secrets. We came {{fact:secrets.penthera.place}}.
nav: Secret scanner test
category: Benchmark
description: gitleaks, trufflehog, deepsecrets, Nosey Parker and five more on Samsung CredData's sealed half, with intervals, the limits, and where Penthera loses.
date: 2026-10-28
approved: 2026-10-28
sources: bench/public/published.json, bench/public/RESULTS.md, docs/research/prereg/E11b-improvement-study.md, bench/public/README.md, docs/references.md
keywords: secret scanner benchmark, gitleaks vs trufflehog, open source secret scanner, CredData
---
> Which free secret scanner finds the most leaked secrets, on data none of them wrote?

On the sealed test half of Samsung CredData ({{fact:secrets.n}} labelled secrets), deepsecrets ranked first of {{fact:secrets.of}} free tools with F1 {{fact:secrets.deepsecrets.score}}. Penthera {{fact:secrets.penthera.version}} ranked {{fact:secrets.penthera.place}} with {{fact:secrets.penthera.score}}. Nosey Parker was close behind with {{fact:secrets.noseyparker.score}}. Read the limits below before you use any of these numbers. Every tool, with its counts, is on [the secrets benchmark page](/benchmarks/secrets).

## The ranking

F1 balances precision (how many reported secrets were real) and recall (how many real secrets were reported). Intervals are 95% Wilson.

- deepsecrets: F1 {{fact:secrets.deepsecrets.score}}. Precision {{fact:secrets.deepsecrets.p}} ({{fact:secrets.deepsecrets.precisionCI}}), recall {{fact:secrets.deepsecrets.r}} ({{fact:secrets.deepsecrets.recallCI}}).
- Penthera: F1 {{fact:secrets.penthera.score}}. Precision {{fact:secrets.penthera.p}} ({{fact:secrets.penthera.precisionCI}}), recall {{fact:secrets.penthera.r}} ({{fact:secrets.penthera.recallCI}}).
- Nosey Parker: F1 {{fact:secrets.noseyparker.score}}. Precision {{fact:secrets.noseyparker.p}}, recall {{fact:secrets.noseyparker.r}}.
- gitleaks: F1 {{fact:secrets.gitleaks.score}}. Precision {{fact:secrets.gitleaks.p}}, recall {{fact:secrets.gitleaks.r}}.
- ripsecrets {{fact:secrets.ripsecrets.score}}, kingfisher {{fact:secrets.kingfisher.score}}, detect-secrets {{fact:secrets.detect-secrets.score}}, secretlint {{fact:secrets.secretlint.score}}, whispers {{fact:secrets.whispers.score}}, trufflehog {{fact:secrets.trufflehog.score}}.

The median F1 of the other free tools was {{fact:secrets.median.f1}}.

![Scatter plot of precision against recall for every secret scanner on the CredData test half, each point with 95% Wilson whiskers, over curves of equal F1. deepsecrets sits furthest to the right; Penthera sits higher, with fewer false hits and lower recall; trufflehog and whispers sit near the bottom left.](figures/secrets-precision-recall.svg)
Precision against recall for every tool, with 95% Wilson intervals as whiskers and curves of equal F1. Up is fewer false hits, right is more secrets found. Drawn by `blog/figures/make.mjs` from published.json.

## Where Penthera loses

deepsecrets finds more. Its recall is {{fact:secrets.deepsecrets.r}} against Penthera's {{fact:secrets.penthera.r}}, and the intervals do not overlap. Penthera reports fewer false hits: precision {{fact:secrets.penthera.p}} against {{fact:secrets.deepsecrets.p}}. If missing a secret costs you more than reading a false alarm, that trade goes the wrong way for you.

So the rank depends on how you weigh the two. F1 weighs them equally. F0.5 weighs precision more: there Penthera scores {{fact:secrets.penthera.f05}} and deepsecrets {{fact:secrets.deepsecrets.f05}}, so Penthera would rank first of the ranked tools. F2 weighs recall more: deepsecrets scores {{fact:secrets.deepsecrets.f2}} and Penthera {{fact:secrets.penthera.f2}}, so Penthera stays second. The registered score is F1.

Counted over every true credential row, not only the in-scope ones, Penthera's recall is 0.25 and it would place 5th by F1. The registered ranking counts in-scope rows. This check is exploratory: it was done after the registered ranking ([re-analysis](https://github.com/danoszz/penthera/blob/main/bench/public/RESULTS.md#exploratory-re-analysis-29-oct-2026-after-the-registered-analysis)).

kingfisher has the highest precision of the ranked tools, {{fact:secrets.kingfisher.p}}, at a recall of {{fact:secrets.kingfisher.r}}.

## gitleaks and trufflehog

These two are what most teams run, and the comparison pages people search for have no measurements. Here, gitleaks scored F1 {{fact:secrets.gitleaks.score}} and trufflehog {{fact:secrets.trufflehog.score}}. That gap undersells trufflehog, for two reasons:

- trufflehog's main feature is verifying a key with its provider. Every tool ran offline, so verification was off.
- CredData replaces every real secret with random characters of the same shape. A verified-secrets tool has nothing real to verify, and a pattern tool loses nothing.

So read this as "gitleaks finds more look-alike secrets in source files than trufflehog does without verification", not as "gitleaks is the better tool".

## Not ranked

CredSweeper scored F1 {{fact:secrets.credsweeper.score}}. It is made by the CredData authors, and its model was trained with CredData, so it is shown and not ranked. Semgrep's secrets rules were skipped: they download from the Semgrep registry at scan time and cannot run offline.

## The limits

- CredData's labels lean partly on other scanners' output.
- CredData is split by file, so most repositories have files on both halves. The leakage audit found that removing the one repository it flagged moves Penthera's F1 from 0.742 to 0.738.
- Penthera was tuned on the dev half; the other tools ran on their defaults.
- Paid scanners ({{fact:paid}}) publish no results on CredData, and we cannot measure them.
- CredData is not your code.

## Method and sources

- **Dataset.** Samsung CredData, a set of files from open-source projects with hand-reviewed credential labels (Yun et al., 2021). Only its sealed test half was scored, once, as the [method post](/blog/sealed-half-benchmark) describes.
- **Intervals.** Precision and recall carry 95% Wilson intervals (Wilson, 1927). F1, F0.5 and F2 are computed from the two rates and have no interval of their own here.
- **Figure.** The plot under the ranking is drawn by `blog/figures/make.mjs` from published.json ([the SVG](https://github.com/danoszz/penthera/blob/main/blog/figures/secrets-precision-recall.svg)).
- **Other work.** Meli et al. (2019) measured how secrets leak on GitHub at scale. SecretBench is another labelled set of real secrets (Basak et al., 2023). Numbers on those sets are not comparable with these.

## Check it yourself

- Every number: [published.json](https://github.com/danoszz/penthera/blob/main/bench/public/published.json) and [the secrets page](/benchmarks/secrets).
- The method and the protocol: [how we benchmarked against the free tools](/blog/sealed-half-benchmark), and [E11b](https://github.com/danoszz/penthera/blob/main/docs/research/prereg/E11b-improvement-study.md).
- Scan your own repo for secrets: `npx penthera@{{fact:secrets.penthera.version}} --repo .`
- Rerun the secrets benchmark: `npm run bench:public -- --only creddata`, with the requirements in [bench/public/README.md](https://github.com/danoszz/penthera/blob/main/bench/public/README.md#reproduce). The test half needs `--split test --final`.

## References


Basak, S. K., Neil, L., Reaves, B., & Williams, L. (2023). SecretBench: A dataset of software secrets. In *2023 IEEE/ACM 20th International Conference on Mining Software Repositories (MSR)* (pp. 347–351). IEEE. [https://doi.org/10.1109/MSR59073.2023.00053](https://doi.org/10.1109/MSR59073.2023.00053) ([entry](https://github.com/danoszz/penthera/blob/main/docs/references.md#basak2023secretbench))

Meli, M., McNiece, M. R., & Reaves, B. (2019). How bad can it Git? Characterizing secret leakage in public GitHub repositories. In *Proceedings 2019 Network and Distributed System Security Symposium*. Internet Society. [https://doi.org/10.14722/ndss.2019.23418](https://doi.org/10.14722/ndss.2019.23418) ([entry](https://github.com/danoszz/penthera/blob/main/docs/references.md#meli2019bad))

Wilson, E. B. (1927). Probable inference, the law of succession, and statistical inference. *Journal of the American Statistical Association*, *22*(158), 209–212. [https://doi.org/10.1080/01621459.1927.10502953](https://doi.org/10.1080/01621459.1927.10502953) ([entry](https://github.com/danoszz/penthera/blob/main/docs/references.md#wilson1927probable))

Yun, J., Choi, S., Lee, Y., Sokol, O., Shim, W., Melkonyan, A., & Kuzmenko, D. (2021). *Project CredData: A dataset of credentials for research*. GitHub. Retrieved October 29, 2026, from [https://github.com/Samsung/CredData](https://github.com/Samsung/CredData) ([entry](https://github.com/danoszz/penthera/blob/main/docs/references.md#yun2021creddata))

## Changes

- 2026-10-28: published.
- 2026-10-29: added the method and sources, the figure link, the rerun link and the references. No claim or number changed.
