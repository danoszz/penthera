# E20-R2 known limits

For an outside reviewer. These are the gaps that remain in the runner and its gate after five reviews. The protocol is `docs/research/prereg/E20r-front-door-replication.md`, Amendment 2.

## The gate proves what a run recorded, not what a person did

- **Local files are unsigned.** Manifests, seals, reports and the rounds log are plain files on the server, and their hashes aren't keyed. Anyone with the account can rewrite a raw file, its manifest, seal and report together, and every check will pass.
- **A determined operator can get past every lock.** The locks stop mistakes, not intent. Someone can edit the runner, change the deps seam, delete the rounds log, or run from a fresh clone. The honest record of a run is the public commit plus what the maintainer reports.
- **The rounds log is one file.** Deleting a round's folder and its log line together leaves no trace, and the two-round cap counts what's there.
- **Label manifests record what the operator says.** They bind a file to a sheet's hash, and can't show the labeler saw that sheet.
- **Prune proofs, seals, privacy reports, the validation key, score and analysis** are bound to the run by plain hashes. Each binding catches a mix-up between runs. None catches an operator who rewrites both sides.
- **Registered analysis inputs are checked by hash only.** The files stay private, so a reader can't recompute the hashes.
- **The repeat lock lives on one machine.** A fresh clone has no `e20r-pass2` folder, so a second start from there would revisit sites.
- **The commit check trusts GitHub and a clean tree.** It proves the checkout is the tip of `main` at the start, not what the Node process loaded afterwards.

## The address check reads local interfaces

It can't see NAT, a proxy or a VPN. Proving the egress address would take a request to an echo service, which the study doesn't send.

## Scrub forms it can't catch

The scrub removes patterns. These get through, and neither it nor its detector will flag them:

- Names, street addresses and postal codes in page text. These are why unsampled text is deleted.
- Addresses written in words with no bracket and no dot, such as `john at example`. They read like "Meet me at home".
- Addresses split over markup or across lines beyond the small gaps it allows.
- Addresses in images, in scripts built at run time, or in encodings it doesn't decode, such as base64.
- Phone numbers under 9 digits, national ID numbers and similar identifiers.
- Short tokens: under 16 characters, or under 3 digits, unless a key name such as `token=` stands next to them.
- Decimal IPv4 such as `35491250`.

It also over-scrubs on purpose. `(AT) Wien`, `Look at example.com`, `We are at home. Today` and `pkg@1.2.3` all lose text. That costs excerpt text, not labels, because labels run on the unscrubbed body before anything is stored.

The detector shares no pattern with the scrub, but it was written by the same author against the same list of forms. A form missing from both is invisible to both.

## What a clean run still can't show

- What a browser would have received. Only one declared client from one address was tested.
- Why a site refused. Identity, fingerprint and address can't be told apart.
- That a `candidate-page` is a page. The audit samples 150 of them, with one human.
- The rule changes on data they haven't seen, until the audit of pass 2.
- SPF semantics: includes, redirects and lookup limits aren't followed.

## Data that leaves the machine

The audit sheet goes to one labeler and to a hosted model. The 12-month deletion can't reach what either keeps. Sheets are blinded by field, but page text can still name a site.

## Other

- DNS traffic isn't in the byte counters, and the byte counts are a lower bound: a redirect's body counts only as far as it arrives while the visit goes on, and a hard-capped site only to its last tick.
- A compressed page body isn't read. It's labeled `body-unavailable` and counts against excerpt coverage.
- The 50% floor, 20% ceilings, the 30, 25 and 10 count floors, the 90% excerpt floor, the two-round cap and the 5% removal cap are judgment calls, not derived values.

## After the stopped pass 2

- The detector now skips a bracketed `at` whose next word is one of our own tokens. Stored text is scrubbed, so that neighbour is ours unless a page itself prints such a token.
- After a bare `at`, the detector counts only what could be a domain: past an opening bracket or quote, a label that starts and ends with a letter or number, then a dot and a word. Paths no longer fire, which reverses the earlier package's choice, because `/` can't be in a label. It still finds `john at (example.com)`, which the scrub leaves in place, and it can't tell that form from prose such as `Look at (example.com). Open daily`.
- Withholding protects the study's write paths. It doesn't protect process memory, swap, a core dump or a compromised host.
- From pilot round 2, a fire doesn't stop a run. The record's title, text, `noscript` and error excerpts are withheld before anything is written. So a real address that fires is never studied, and nobody can say afterwards whether a fire was true. Fires are a count, per kind, never a verdict.
- `fragment` and `longHex` fires can't be tightened by what a character may be, so they are left to withholding.
- Withheld records leave the audit's frame, and they aren't missing at random. Audit metrics describe non-withheld records, with worst-case bounds beside them. The headline audit is not estimable past 2.0% withheld in any stratum, so in a stratum under 50 records one withheld record decides it. A label whose pooled frame is under 20 gives no figures of its own.
- Withholding covers page and error text. A miss in a header, cookie, DNS field or check still goes to the final privacy report and a person.
- `john (at example.com)`, with the bracket on the word `at`, and a local part ending in a quote or bracket, such as `"john" at example.com`, reach neither layer. Names joined by a zero-width character aren't read as one label.
- The frozen detector in `legacy/` runs only for the legacy finding report. That report names record order and field path, so it stays on the server.
- Pass 3 learns which sites to skip from the stopped pass's pruned raw file. A purge deletes that file, so a purged pass 2 can't be followed by pass 3.
- A false-fire review rests on one named person's note. Only its hash is kept with the run, bound to the legacy finding report.
- The realistic corpus in the tests is hand-written. It finds common sentence forms, and it says nothing about forms nobody wrote down.

## Stated deviations

- **Pilot label sheets.** Amendment 2 says no text copy is made before a prune. Pilot round 1's label sheets were copied before its prune. All copies were deleted on 31 Oct 2026, and their hashes are kept privately. The raw prune proof doesn't cover such copies.

## Stops

- A signal or the stop file takes effect between sites, so visits in flight finish, up to the 30-second hard cap each.
- The final hashing and git reads stay synchronous and block signal delivery while they run. Handlers stay on, the loop is yielded after them, and the last stop check, just before the rename, is the semantic boundary. A signal handled by that check makes the run partial, so a signal in finalization is late, not lost. Any later signal is post-run, even one that arrives before the rename finishes.
- SIGKILL, a crash or a full disk leave no end manifest. The run counts as interrupted, and the prune is a step on the run sheet that nothing enforces for pass 2.
- The privacy report scans every stored string, with the same detector as the scrub limits above. Its exceptions are hashes, and addresses in SPF records. After a miss a person reviews it. A false fire is a recorded deviation that rests on that one person's note, and a real miss ends in `purge`, which ends the run's data.
- The source-address check reads local interfaces between sites, so it shares the address check's limit.

## Audit and analysis

- The audit covers the response class. Grader header outcomes rest on the test suite, and no human audits them.
- Secondary intervals are naive row-level, with no clustering, and corroborate nothing.
- Provider explanations, the YC trend, origin headers and challenge cookies are not built. Anything on them would be post hoc.
- Kappa between the human and the model is on rows where neither is unsure, which can leave out the hardest rows.
