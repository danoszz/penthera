section: Docs

- **E11: Penthera on public benchmarks.** A pre-registered study
  (`docs/research/prereg/E11-public-benchmarks.md`) and a runner
  (`npm run bench:public`, in `bench/public/`) score Penthera on datasets other
  people labelled: Samsung CredData for the secret scan, SecBench.js for
  code-execution sinks, and DataDog's malicious npm and PyPI packages, against
  a popular-package baseline, for the dependency scan. Results, with Wilson
  intervals, limits and rule ideas, are in `bench/public/RESULTS.md`. On
  CredData, secret precision is 0.58 [0.55, 0.60] and in-scope recall 0.27
  [0.26, 0.29], mostly because `.txt` and `.md` files are not read. On
  SecBench.js, no library command injection was found (0 of 96). The
  dependency scan flags 0.80 [0.75, 0.84] of malicious PyPI and 0.44 [0.39,
  0.50] of malicious npm packages, and 0.08 [0.06, 0.12] of popular PyPI and
  0 of 300 popular npm packages. Malware
  samples are only read as text, under `/private/tmp`, and deleted after the
  run. No rule changed.
- **E11b: a sealed dev/test split for improving on E11.** A draft amendment
  (`docs/research/prereg/E11b-improvement-study.md`) fixes the split, its
  SHA-256 hashes, the scoring units, the guards and the targets before any
  rule is tuned. `npm run bench:public -- --split dev` scores only the dev
  half; the test half runs once, at the end. The dev baseline and reference
  runs of gitleaks, detect-secrets and GuardDog are in
  `bench/public/RESULTS.md`.
- **E11b: eight more secret scanners on CredData dev.** TruffleHog,
  Nosey Parker, Kingfisher, ripsecrets, secretlint, Whispers, deepsecrets
  and CredSweeper run pinned, offline and scored the same way as gitleaks and
  detect-secrets. The table and its limits are in `bench/public/RESULTS.md`.
  CredSweeper was trained on CredData, so its row is not comparable.
