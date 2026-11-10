section: Fixed
docs: none, the command and its output are unchanged

- **`penthera diff` works on Windows with Git for Windows' tar.** That tar
  read the merge-base's `C:\...` path as a remote host, so every diff failed
  there. Penthera now unpacks the merge-base with relative names.
