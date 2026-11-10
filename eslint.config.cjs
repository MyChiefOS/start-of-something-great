// ESLint, errors only (harness/STANDARDS.md gap 9). Only rules that catch real bugs: an undefined name, unreachable
// code, a duplicate key, a self-assignment, a condition that can never change, and the like. No style rules, so no file
// is restyled. Unused variables warn and never fail the build. Run: npm run lint (CI fails on errors only).
'use strict';

const globals = require('globals');

const bugs = {
  'no-undef': 'error',
  'no-unused-vars': ['warn', { args: 'none', caughtErrors: 'none', ignoreRestSiblings: true }],
  'no-unreachable': 'error',
  'no-dupe-keys': 'error',
  'no-dupe-args': 'error',
  'no-dupe-class-members': 'error',
  'no-dupe-else-if': 'error',
  'no-duplicate-case': 'error',
  'no-self-assign': 'error',
  'no-self-compare': 'error',
  // A constant condition is a bug in an if or a ternary; `while (true)` with a break is deliberate.
  'no-constant-condition': ['error', { checkLoops: false }],
  'no-constant-binary-expression': 'error',
  'no-cond-assign': ['error', 'except-parens'],
  'no-const-assign': 'error',
  'no-class-assign': 'error',
  'no-func-assign': 'error',
  'no-import-assign': 'error',
  'no-ex-assign': 'error',
  'no-global-assign': 'error',
  'no-redeclare': 'error',
  'no-shadow-restricted-names': 'error',
  'no-delete-var': 'error',
  'no-compare-neg-zero': 'error',
  'use-isnan': 'error',
  'valid-typeof': 'error',
  'no-unsafe-finally': 'error',
  'no-unsafe-negation': 'error',
  'no-unsafe-optional-chaining': 'error',
  'no-unexpected-multiline': 'error',
  'no-sparse-arrays': 'error',
  'no-obj-calls': 'error',
  'no-new-native-nonconstructor': 'error',
  'no-invalid-regexp': 'error',
  'no-empty-character-class': 'error',
  'no-misleading-character-class': 'error',
  'no-useless-backreference': 'error',
  'no-loss-of-precision': 'error',
  'no-setter-return': 'error',
  'getter-return': 'error',
  'no-async-promise-executor': 'error',
  'no-empty-pattern': 'error',
  'for-direction': 'error',
  'no-debugger': 'error',
};

const node = { ...globals.node };
const browser = { ...globals.browser };

module.exports = [
  {
    // Vendored code (kept byte for byte as published), the design records (not served: .vercelignore) and the
    // Edge Functions' TypeScript entry points, which ESLint can't parse without a plugin.
    ignores: ['node_modules/**', 'verifier/noble-ed25519-*.js', 'design/**', 'supabase/functions/**/*.ts', '.claude/**'],
  },
  {
    linterOptions: { reportUnusedDisableDirectives: 'warn' },
  },
  // The site's own scripts, run by browsers as classic scripts.
  {
    files: ['*.js', 'account/**/*.js', 'admin/**/*.js', 'errors/**/*.js'],
    languageOptions: { ecmaVersion: 'latest', sourceType: 'script', globals: browser },
    rules: bugs,
  },
  // Node: the API, the database layer, sign-in, the scripts, the tests, the tools and the research code (CommonJS).
  {
    files: ['eslint.config.cjs', 'launch.js', 'api/**/*.js', 'db/**/*.js', 'signin/**/*.js', 'notify/**/*.js', 'scripts/**/*.js',
      'test/**/*.js', 'tools/**/*.js', 'harness/**/*.js', 'redteam/**/*.js', 'secondlook/**/*.js', 'thirdlook/**/*.js', 'research/**/*.js'],
    languageOptions: { ecmaVersion: 'latest', sourceType: 'commonjs', globals: node },
    rules: bugs,
  },
  // The browser checks run in Node and hand functions to Playwright's page.evaluate, which runs them in the page, so
  // these files use both Node's names and the browser's.
  {
    files: ['scripts/check-*.js', 'test/perf/browser-measure.js'],
    languageOptions: { globals: { ...node, ...browser } },
  },
  // ES modules: the Edge Functions' shared code and the verification tools (Node or Deno), and the browser verifier.
  {
    files: ['**/*.mjs'],
    languageOptions: { ecmaVersion: 'latest', sourceType: 'module', globals: node },
    rules: bugs,
  },
  {
    files: ['verifier/**/*.js'],
    languageOptions: { ecmaVersion: 'latest', sourceType: 'module', globals: { ...browser, ...globals.worker } },
    rules: bugs,
  },
];
