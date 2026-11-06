// Minimal lint: real mistakes only (unused code, undefined names, unreachable
// code). No style rules; dev-only, never shipped.
import js from "@eslint/js";
import globals from "globals";
import regexp from "eslint-plugin-regexp";

export default [
  { ignores: ["node_modules/", "audit/logs/", "reports/", "coverage/", "bench/out/", "**/fixtures/**", "site/dist/", "lib/vendor/"] },
  js.configs.recommended,
  {
    languageOptions: { ecmaVersion: "latest", sourceType: "module", globals: { ...globals.node } },
    linterOptions: { reportUnusedDisableDirectives: "error" },
    rules: {
      "no-unused-vars": ["error", { args: "none", caughtErrors: "none", ignoreRestSiblings: true }],
      // Scanners match control characters, odd whitespace and combining marks
      // on purpose; the rest are style, not mistakes.
      "no-control-regex": "off",
      "no-irregular-whitespace": "off",
      "no-misleading-character-class": "off",
      "no-useless-escape": "off",
      "no-useless-assignment": "off",
      "no-sparse-arrays": "off",
      "preserve-caught-error": "off",
      "no-empty": ["error", { allowEmptyCatch: true }],
    },
  },
  // Scanners run regexes on untrusted text: super-linear backtracking there is a
  // denial of service (QA standard step 3a; Vercel Security Review M, 2.3.2).
  {
    files: ["lib/**/*.js", "lib/**/*.mjs", "src/**/*.js", "src/**/*.mjs"],
    plugins: { regexp },
    rules: {
      "regexp/no-super-linear-backtracking": "error",
      "regexp/no-super-linear-move": "error",
    },
  },
  { files: ["src/ui/static/**", "site/check/**", "site/theme.js", "site/track.js", "site/pro.js", "site/gopro.js"], languageOptions: { globals: { ...globals.browser } } },
  { files: ["site/theme.js", "site/track.js", "site/pro.js", "site/gopro.js"], languageOptions: { sourceType: "script" } },
  { files: ["**/*.cjs"], languageOptions: { sourceType: "commonjs" } },
  // The Vercel integration server logs only through its redacting logger.
  { files: ["integrations/vercel/**/*.mjs"], ignores: ["integrations/vercel/lib/log.mjs"], rules: { "no-console": "error" } },
];
