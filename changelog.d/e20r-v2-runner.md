section: Docs

- **E20-R2 (adopted 31 Oct 2026).** Amendment 2 and the study page describe a corrected
  replication of E20-R, a low-interaction active measurement: robots.txt at every
  origin under RFC 9309, the exclusion list on every hop, no app page, DNS read
  whether or not a site answers, a frozen classifier, CSP directive names, a
  scrubbed excerpt of normal pages that is deleted after sampling, a pinned Public
  Suffix List for the study only, a run manifest and a pilot with stop rules. The
  page now says that stored evidence can contain addresses, and who sees it. It
  sends nothing until the maintainer adopts it. The legacy E20 runner now works on
  loopback only.

The E20-R2 run sheet is `bench/front-door/run-sheet.md`. Runs now stop cleanly on a signal, a stop file or a changed source address, and analysis needs a clean privacy report. A failed privacy report ends in `purge`, which deletes the whole per-site file. `npm run e20r:preflight` runs the checks on the server.
