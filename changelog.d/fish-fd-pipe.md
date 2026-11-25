section: Fixed
docs: none, no command, flag or rule changes

- **A download piped into a wrapped shell with fish's `1>|` or `2>|` is found again.**
  fish reads `2>|` as a pipe, and bash as a redirection, so the agent audit now reads
  that pipe both ways, as it does zsh's number glob. `curl … 1>| timeout 5 sh` is
  reported again, also in a later stage (Vercel 01M826TST03SK5EX81H6YP0VW6).
