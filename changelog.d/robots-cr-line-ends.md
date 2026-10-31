section: Fixed

- **The live check now reads two more forms of opt-out in robots.txt.** A file with
  bare CR line ends, which RFC 9309 allows, and a `User-agent` line with words after
  the name, such as `Penthera-QuickCheck bot`, used to be missed. Its other requests
  and scores do not change.
