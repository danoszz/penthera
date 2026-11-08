section: Security
docs: none, the sink check finds the same code, only faster on crafted files

- **The command-injection check stays fast on crafted files.** Now that minified
  files are scanned and files up to 4 MiB are read, a long string, a long name
  or a long run of blank space could make it run for hours. Each such file now
  takes well under a second.
