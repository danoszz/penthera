section: Changed

- **The brief's top no longer points at third-party or sample code.** Vendored
  and minified files (`vendor/`, `public/js/lib/`, `*.min.js`) and examples or
  samples (`examples/`, `samples/`, `demos/`) now go to Likely noise, and so do
  the test folders other runners use (`test/`, `test_*`, `e2e/`, `cypress/`,
  `playwright/`). A real route in a folder named `build` or `out`, such as
  `app/api/build/route.ts`, is no longer hidden as build output. Noise is
  still listed and counted, a critical or high finding still fails the run,
  and signs of planted code (suspicious files, malicious packages, agent
  config) keep their bucket wherever they sit. Found by E9: in two tasks the
  brief's first step pointed an agent at a bundled jQuery file and at 20
  sample keys.
