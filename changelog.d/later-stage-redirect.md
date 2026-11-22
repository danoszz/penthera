section: Fixed

- A crafted instruction file with many `<|` or `>|` fragments after a download no
  longer makes the agent audit slow down quadratically. The pipe of a redirection
  (`>|`, and `<|`, `2<|`, which ksh reads as input redirections) is no longer read as
  the start of a new stage, so `curl … >| sh`, which writes a file named `sh`, is no
  longer reported as a download piped to a shell. A shell after a real pipe is still
  found, also behind `2<| file` (Vercel 01M81W6NMFBR969DTHNXZAWCER).
  docs: none, no command, flag or rule changes.
