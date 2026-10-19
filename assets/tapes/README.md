# Demo tapes

[VHS](https://github.com/charmbracelet/vhs) scripts for the GIFs in `assets/`.
`.github/workflows/demo-media.yml` renders them on every release (and on
demand) and opens a PR with the new GIFs. Locally, from the repo root:

```bash
vhs assets/tapes/scan.tape
```

| Tape | Output | Shows |
|------|--------|-------|
| `scan.tape` | `assets/demo-scan.gif` | URL scan of the local mock server |
| `agents.tape` | `assets/demo-agents.gif` | `penthera agents` on a malicious AI-tooling fixture |
| `deps-diff.tape` | `assets/demo-deps-diff.gif` | `penthera deps --diff` between two lockfile trees |

`_settings.tape` holds the shared size and theme. A tape whose name starts with
`_` is not rendered on its own. To add a clip (for example the dashboard once
`penthera ui --demo` ships), add a tape here; the workflow picks up every
`*.tape`.
