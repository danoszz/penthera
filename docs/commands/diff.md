---
title: "Only what this branch added: penthera diff"
sidebarTitle: "Diff against main"
description: "penthera diff shows only the findings your branch added, compared with the merge-base with main."
---

> **Pro.** For "what did my branch add, and nothing else?"

`penthera diff` scans your repo twice: as it is now, and as it was at the
merge-base of `HEAD` and `main`. It shows only the findings the merge-base
does not have. Old findings you did not touch stay out of the way, so a pull
request review or a pre-push check is about your change.

```bash
penthera diff                         # against main (then origin/main, master)
penthera diff main --sarif new.sarif  # name the branch, tag or commit; SARIF of the new findings only
penthera diff --json                  # the new findings, the counts and the merge-base
```

It exits 1 when a new finding is critical or high, 0 when none is, and 2 when
it cannot compare (not a git repo, no such ref, no commit in common).

## What counts as new

A finding is new when the merge-base has no finding with the same identity,
or its severity went up, or a secret or an eval or exec sink holds more than
it did. It is the same comparison as
[`--baseline`](scan.md#what---baseline-counts-as-new). A key moved to another
line is not new. A second key in the same file is.

The current side is your working tree, so uncommitted changes count. A
finding in a file git ignores (a local `.env`, say) is left out: it is on no
branch. The brief's Not checked section says how many findings the
merge-base had too and how many your branch fixed.

## How it works

1. `git merge-base HEAD <ref>` finds the commit your branch started from.
2. `git archive` writes that commit's files into a temporary folder. Nothing
   in your repo, its index or its work tree changes, and the folder is
   removed afterwards.
3. Penthera scans both folders with the same rules and compares them.

It runs offline: nothing is fetched, so `<ref>` is what your clone has. In CI
or a fresh clone, run `git fetch origin main` first and compare with
`origin/main`.

## Limits

- It is a repo scan (`--repo`). Dependencies (`penthera deps --base origin/main`)
  and agent config have their own commands.
- A file marked `export-ignore` in `.gitattributes` is missing from the
  merge-base side, so its findings show as new.
- It scans twice, so it takes about twice as long as `penthera --repo .`.
