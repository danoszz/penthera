section: Security
docs: none, the command-injection check finds more; no flag or output changes, and a file it can't finish now exits 2 as other unread files do

- **Request data is followed however far it goes.** The command-injection
  check followed a value only 300 characters into its statement, a
  destructured list only 300 characters, and only 6 steps of assignments, so
  padding past those limits made a tainted command look clean. It now reads
  every value and list whole, in one pass, and follows chains to the end.
- **Library mode has no silent limits either.** A long value, list, index,
  pushed value or helper call no longer drops a parameter's taint. When a file
  needs more work than the check allows, or more than 200 helper calls, the
  run says so and exits 2.
- **An apostrophe in prose no longer hides a pipe into a shell.** In a skill or
  instruction file, `it's` or `don't` before `curl … | sudo -u root bash` read
  as an open quote, and the rest of the line was skipped. Both readings are
  checked now.
- **Library mode finds functions with long TypeScript types.** A return type
  longer than 400 characters, a parameter list longer than 20,000, and any
  arrow function with a return type (`(cmd: string): void => …`) were skipped,
  so their parameters were never followed. They are read whole now; a file
  that would cost more than the check allows exits 2.
