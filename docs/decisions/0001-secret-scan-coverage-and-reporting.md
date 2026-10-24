# ADR 0001: secret-scan coverage, reporting, and library mode

> **Project page.** For maintainers and researchers asking "why does the
> secret scan read these files, report this way, and when will Penthera treat
> code as a library?"

| | |
|---|---|
| Status | Accepted by the maintainer (Daan van der Zwaag), 2026-10-24, including the speed cost |
| Date | 2026-10-24 |
| Context | E11b improvement study (`docs/research/prereg/E11b-improvement-study.md`, in PR #155), pass 1. PRs #159 (coverage) and the stacked A6 PR (reporting) |
| Authors | Daan van der Zwaag decides. Drafted with Claude (AI-assisted) |

These decisions change the product for every user, not only the benchmark
score. They are written down here so they can be judged on their own merits.

## Decision 1: read docs, with fixed-shape rules only

**Context.** The secret scan read source and config files only. E11 found that
47% of the true secrets in CredData sat in files it never opened: key files,
PHP, C#, Java and server configs, and docs. Meli et al. (2019) report the same
for GitHub at large: keys leak through notes and docs too.

**Decision.**

- The scan reads key files (`.pem`, `.key`, `.p8`, `.ppk`), `.php`, `.cs`,
  `.properties`, `.conf`, `.xml` and `.tfstate`. It also reads a file with no
  extension when it starts with a private-key header.
- In `.txt` and `.md`, only rules that match a fixed shape run: provider key
  prefixes and private keys. The assignment guesses (`password = "..."`) do
  not, because docs are full of example passwords.
- One function, `secretRulesFor()`, decides this for the repo scan, the
  commit hook and the benchmark replay, so the benchmark measures what users
  run.

**Consequences.**

- On the CredData dev split, strict precision went from 0.56 to 0.75 and
  recall from 0.27 to 0.41. The bundled benchmark improved too: precision
  0.875 to 0.917, recall 0.913 to 0.957.
- A scan reads more bytes. On a docs-heavy repo (Penthera's own) it takes about
  18% longer. Per megabyte the speed is unchanged. E11b's guard was about 10%,
  so the maintainer has to accept this cost explicitly.
- The report's coverage section still lists an extensionless key file as
  "file type not read", because coverage decides by path only. That is a known
  gap.

## Decision 2: a secret finding lists every line

**Context.** The scan kept one finding per rule per file, pointing at the first
hit. A file with ten keys showed one place to fix. On CredData the CLI's
reported recall was 0.15 while the engine found 0.41.

**Options.**

1. **One finding per hit.** Every hit would be a separate finding. Finding ids
   hash the source, category, file and title, not the line, so the ids would
   collide. Changing the id would break every saved baseline and suppression.
2. **One finding per rule and file, listing every line.** Keep today's id.
   Add `lines`, an extra sentence in the description, `+N more` in the
   terminal, and SARIF `relatedLocations`.

**Decision.** Option 2. Baselines (`--baseline`) and suppressions keep working, and
the user sees every place to fix. At most 200 lines are listed per finding.

**Consequences.** JSON reports gain a `lines` field when a rule hit more than
once in a file. GitHub code scanning shows the other lines as related
locations.

## Decision 3: library mode (decided, design pending)

**Context.** Penthera treats code as an app: only request data is untrusted.
In a library, every exported function's parameters can come from a caller.
That is why it found 0 of 49 command injections in SecBench.js's dev split.

**Decision.** Penthera audits libraries too (maintainer, 2026-10-24).

- Library findings are reported at `potential` confidence, below app findings.
- A function whose whole job is to run its argument as a command is reported
  too, at `potential`, with the note that callers must not pass untrusted
  input (maintainer, 2026-10-24).
- The mode turns on with a flag, or automatically when `package.json`
  declares no app framework. The exact trigger is decided after the dev-split
  analysis of SecBench.js (workstream D) and recorded here.
- App scans must not gain false alarms from it. The benign baselines and E10
  are the guard.

**Trigger and design, as built (2026-10-24, proposed in the library-mode
pull request, for the maintainer to accept).** `--library` turns it on and
`--no-library` off. Without a flag it is on when `package.json` has `main`,
`exports` or `bin` (or an `index.js` beside it), is not `"private": true`, and
lists no app framework (Express, Koa, Fastify, Next.js and similar) in
`dependencies`. Library findings are severity high; a function that only runs
its argument is severity medium. In library mode the scan reads `dist/` or
`build/` when `package.json` points there and skips tooling, example and docs
folders. Flows are followed inside the exported function, and one call
further into a named function in the same file, and through fields a
constructor or setter keeps on `this` (round 2, proposed).

**Consequences.** New findings for library authors and for anyone auditing a
dependency. It ships in 1.10 with a release candidate first, not in a patch.

## References

- Meli, McNiece and Reaves (2019), *How Bad Can It Git?* (`meli2019bad` in
  [references.bib](../references.bib)).
- E11b results and lab notes: `bench/public/` (in
  PR #155).
