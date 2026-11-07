section: Changed
docs: none, the integration's own README, privacy notice and terms are updated; nothing in the CLI, MCP tools, rules or Action changed

- **The Vercel integration turns its check on by itself.** Vercel does not
  let an integration import a GitHub check, so "Turn on the check" now adds a
  check the integration owns. For each production deploy, the workflow's last
  step sends `vercel.penthera.org/report` the deployment id, the project id and
  pass or fail, with a token GitHub signs for your repo and that one
  deployment. The server checks the
  token, the repo, the project and the deployment against Vercel, sets the
  check's result, and keeps nothing about the deploy. Findings stay in GitHub. The commit status
  stays too, for a GitHub check added by hand. The workflow now needs
  `id-token: write`. For upkeep the server counts anonymous daily totals
  (received, passed, failed, refused by reason), with no ids and no IP,
  deleted after 90 days.
