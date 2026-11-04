section: Changed
docs: none, CI for this repository only; CONTRIBUTING.md describes it

- **Two Penthera checks per commit in this repository.** The Penthera GitHub App sums up every CI job as **Penthera: security** and **Penthera: safe build**, each with a table of what ran. Pull requests run the install matrix on Ubuntu only, and the full matrix runs on `main`. A CODEOWNERS file asks for the maintainer's review on CI, install and agent files. The PR triage comment now comes from the app.
