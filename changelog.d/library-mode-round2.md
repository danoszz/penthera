section: Detection

- **Library mode follows one helper call and values kept on `this`.** When an
  exported function passes a parameter to a named function in the same file,
  that function's parameter is followed too, one call deep, and the finding
  names the helper. A parameter a constructor or setter stores on `this` is
  followed into the other methods of the same class or prototype, and so is an
  instance an exported factory returns (`return new Stat(dir)`). Members copied
  onto `exports` in a `for...in` loop or with `Object.assign(module.exports,
  api)` count as exported. On the SecBench.js dev half, command-injection
  recall went from 40 to 46 of 49 (0.94, 95% CI 0.83 to 0.98), with no new finding in 150 benign npm packages or 16 app
  repositories ([scan.md](../docs/commands/scan.md#library-mode-scanning-a-package)).
- **One long line no longer hides a file from the code-sink check.** A file is
  skipped as minified only when lines over 5,000 characters hold more than half
  of it, so a generated parser with one long table line is read. On the
  SecBench.js dev half, code-injection recall went from 10 to 11 of 16 (0.69,
  95% CI 0.44 to 0.86).
