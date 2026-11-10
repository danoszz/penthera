section: Added

- **`penthera diff [ref]`: only the findings your branch added.** It scans
  the repo now and at the merge-base with `main` (then `origin/main`,
  `master`), and shows what the merge-base does not have, compared the way
  `--baseline` compares. A key that moved is not new; a second key in the same
  file is. Uncommitted work counts, files git ignores do not. It reads the
  merge-base with `git archive` into a temporary folder, changes nothing in
  the repo, and runs offline. `--json`, `-o`, `--markdown` and `--sarif`
  write the new findings only; it exits 1 when one is critical or high. See
  [docs/commands/diff.md](../docs/commands/diff.md).
- **The brief leads with one step, in plain words.** A **Do this first** line
  under the verdict names the first step for the top finding, where it is and
  why it matters. Each Act on and Check first item gets a "Why it matters"
  line for someone who is not in security, from a fixed table tuned for
  Next.js, Supabase, Stripe and Vercel apps and the AI keys they hold. No
  model writes them, and they never move a finding or change the verdict. New
  JSON fields: `first`, and `why_it_matters` and `first_step` on each item.
  The MCP reply contract and the Agent Skill ask the assistant to keep both.
