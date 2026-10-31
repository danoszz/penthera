import { defineConfig } from "vitest/config";
import { availableParallelism } from "node:os";

// Files whose tests start real processes (node bin/penthera.js, git, npm) or
// whole scans against a local server. On a busy laptop each of those children
// competes with everything else for CPU, so:
//  - at most a few of these files run at once (they are already the critical
//    path; more of them in parallel only makes every one slower), and
//  - their tests and hooks get a long budget. The timeout here is only a hang
//    detector: a spawn that takes 3 s idle can take 60 s+ when starved, and
//    failing it then says nothing about the code.
// Everything else is in-process and fast, and keeps tight timeouts so a real
// hang there is reported quickly. New spawn-heavy files go in this list
// (see CONTRIBUTING.md, "Writing tests that stay reliable").
const SPAWN_HEAVY = [
  "tests/adaptive-scan.test.js",
  "tests/agent.test.js",
  "tests/agents.test.js",
  "tests/bench.test.js",
  "tests/cli-smoke.test.js",
  "tests/deps-python.test.js",
  "tests/deps.test.js",
  "tests/docs-commands.test.js",
  "tests/egress.test.js",
  "tests/evidence.test.js",
  "tests/fix.test.js",
  "tests/giants-cli.test.js",
  "tests/git-safety.test.js",
  "tests/hook.test.js",
  "tests/init.test.js",
  "tests/install.test.js",
  "tests/memory.test.js",
  "tests/onboarding.test.js",
  "tests/pentest-adaptive.test.js",
  "tests/pentest-live.test.js",
  "tests/pentest-mock.test.js",
  "tests/pentest-recon.test.js",
  "tests/ui.test.js",
  "tests/validate-report.test.js",
  "tests/verdict-exit-help.test.js",
];

const shared = {
  environment: "node",
  globals: true,
  // Private HOME, git config, npm cache and PENTHERA_HOME per worker.
  setupFiles: ["tests/setup/isolate-env.js"],
};

// Tests stay offline: site/build.mjs would otherwise read the star count from
// api.github.com and rewrite site/stars.json.
const TEST_ENV = { PENTHERA_SITE_STARS: "off" };

export default defineConfig({
  test: {
    projects: [
      {
        extends: true,
        test: {
          ...shared,
          name: "unit",
          env: TEST_ENV,
          include: ["tests/**/*.test.{js,ts}"],
          exclude: SPAWN_HEAVY,
          testTimeout: 20_000,
          hookTimeout: 20_000,
          sequence: { groupOrder: 0 },
        },
      },
      {
        extends: true,
        test: {
          ...shared,
          name: "spawn",
          env: TEST_ENV,
          include: SPAWN_HEAVY,
          testTimeout: 180_000,
          hookTimeout: 180_000,
          maxWorkers: Math.max(2, Math.ceil(availableParallelism() / 2)),
          // Runs after the unit group: vitest needs projects with different
          // maxWorkers in separate groups.
          sequence: { groupOrder: 1 },
        },
      },
    ],
  },
});
