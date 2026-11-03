// Minimal lint: real mistakes only (unused code, undefined names, unreachable
// code). No style rules; dev-only, never shipped.
import js from "@eslint/js";
import globals from "globals";

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
  { files: ["src/ui/static/**", "site/check/**", "site/theme.js", "site/track.js", "site/pro.js", "site/gopro.js"], languageOptions: { globals: { ...globals.browser } } },
  { files: ["site/theme.js", "site/track.js", "site/pro.js", "site/gopro.js"], languageOptions: { sourceType: "script" } },
  { files: ["**/*.cjs"], languageOptions: { sourceType: "commonjs" } },
];
