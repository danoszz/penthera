section: Changed
docs: none, this repository's own pull request check; CONTRIBUTING describes the triage

- **The pre-CI check on outside pull requests puts its verdict up front.** The comment now shows Penthera's one-line verdict without opening anything, and the full brief as plain text, without the notes about logins and server routes that never apply to a pull request's few changed files. Text quoted from a pull request's files stays in a code block.
- **Vercel builds the site only from `main`.** Pull requests, including ones from forks, no longer start a Vercel deployment, so a fork no longer shows a red "Authorization required to deploy" check and fork code never builds on Vercel.
