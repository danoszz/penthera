section: Fixed

- **`penthera init` no longer crashes in a new folder under a stray git repository.**
  A repository at the filesystem root or in your home folder (a dotfiles repo) was
  taken for the project, so the wizard tried to write `/reports/penthera-<date>`
  and stopped with a stack trace. It now works in the folder you run it in, and a
  folder it can't write ends the run with one clear line (issue 341, thanks to
  @sharukmsd).
