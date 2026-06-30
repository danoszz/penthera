#!/usr/bin/env node
/**
 * Interactive scan — delegates to PostHog-style onboarding wizard.
 * Alias: penthera-scan
 */
import { runOnboarding } from "../src/cli/onboarding.js";

runOnboarding().catch((e) => {
  console.error(e.message);
  process.exit(2);
});
