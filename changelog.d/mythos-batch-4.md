section: Detection

- **The eval and exec check knows the Web Request API and Server Actions.**
  `const { cmd } = await request.json(); exec(cmd)`, a command built from
  `formData.get(...)` or `searchParams.get(...)`, and a Server Action that runs
  its own argument (in any form: exported, in an export list, an arrow, or a
  function with an inline `'use server'`) are now reported as request data
  reaching a command.
- **More ways to run a string as code are found:** `eval?.(x)`,
  `eval.call(null, x)`, `Function(x)()` without `new`, the vm module under any
  name (`import { runInNewContext } from "node:vm"`, `const vm2 = require("vm")`,
  `require("vm").runInNewContext(...)`) and `const e = eval` or `(0, eval)`. The route list uses the same list, so the two no
  longer disagree.
- **Route files get the eval and exec check too.** Where it traces request
  data, its finding stands in for the route's, at the same severity, so the
  route's own pattern match is no longer the only check there.
