section: Changed

- **The brief puts what an attacker can reach first.** Critical comes first,
  then high, then the rest, so no number of highs or mediums can push a
  critical out of the top. Within each, groups are ordered by reach (an entry point such as a route, a Server
  Action, a webhook or the live site, then other server code, then config and
  CI, then prose), then by whether the value comes from the request, then by
  severity and confidence, then the smaller group first. A committed key, an
  open database rule or a vulnerable dependency counts as reachable wherever it
  sits.
- **Do this first** is the top critical or high finding in Act on and Check
  first together, so a high in Check first comes before a medium in Act on.
- The first three lines to act on hold at most one line per rule, within the
  same severity tier.
- Each item in the JSON brief has `rank_reasons`, so you can check its place.
  Command and eval findings now say whether request data reaches them
  (`tainted`).
- **Sample secrets in prose are noise.** A medium or low secret in Markdown or
  other prose, prose in `docs`, `.env.example` and its kin, seed data,
  snapshots or stories counts as an example. A finding below high in a library
  copied in under its own versioned name (`public/js/jquery-3.4.1.js`) counts
  as vendored. A file name never moves a code finding, a critical or high
  finding, or a hit that takes a value from the request.
- Order and sections only: no severity and no exit code changes.
