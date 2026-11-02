section: Fixed

- **The terminal report no longer writes color codes into a pipe or a file.** Only `NO_COLOR` used to turn them off, so `penthera --repo . --verbose > scan.txt` filled the file with escape codes. The report now follows the rest of the CLI: colors only when stdout is a terminal, `NO_COLOR` still turns them off, and `FORCE_COLOR=1` keeps them in a pipe, for the CLI's other output too.
