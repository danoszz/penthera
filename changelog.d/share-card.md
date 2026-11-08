section: Added

- **`--card`: a security receipt to post.** `penthera --card` scans the folder
  you are in and writes one image of the result, 1080 × 1350 for X and
  1200 × 630 for link previews, as PNG and SVG. It shows the brief's own
  verdict, what was read (code, dependencies, AI-agent configs, the live
  site), what was not checked, the number to fix first and the top fix. On
  `penthera agents . --card` the audit's grade is the big letter, with its
  score out of 100; repo and URL cards have no score, and none is made up.
  It also works on URL scans and on `penthera brief <reports...> --card`, which puts a repo, deps and agents scan
  on one card. It is made on your machine with Penthera's own renderer and
  pixel font: nothing is fetched or uploaded, and there is no new dependency.
  A run that read nothing shows a `?`, never a 0, and the card carries no file
  paths, file contents, hidden characters or key-shaped strings. See
  [docs/commands/scan.md](../docs/commands/scan.md#share-card).
