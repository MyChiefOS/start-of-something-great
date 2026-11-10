// STANDARDS.md gap 9: ESLint, errors only. The linter is pinned, CI runs it, its rules only catch bugs (nothing that
// restyles a file), and it really does fail on a bug and only warn on an unused variable.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');

test('gap 9: ESLint is a pinned dev dependency, run by npm run lint and by CI', () => {
  const pkg = JSON.parse(read('package.json'));
  assert.match(pkg.devDependencies.eslint, /^\d+\.\d+\.\d+$/, 'eslint is pinned to one exact version');
  assert.match(pkg.devDependencies.globals, /^\d+\.\d+\.\d+$/, 'globals is pinned to one exact version');
  assert.strictEqual(pkg.scripts.lint, 'eslint .');
  const lock = JSON.parse(read('package-lock.json'));
  assert.strictEqual(lock.packages['node_modules/eslint'].version, pkg.devDependencies.eslint, 'the lockfile has the pinned eslint');
  const step = read('.github/workflows/checks.yml').split('- name: Lint (')[1];
  assert.ok(step, 'checks.yml has a Lint step');
  assert.match(step.split('\n      - ')[0], /run: npm run lint\n/);
  assert.doesNotMatch(step.split('\n      - ')[0], /continue-on-error/, 'a lint error fails the job');
});

test('gap 9: the config has bug rules only, every one an error except unused variables, which warn', () => {
  const config = require(path.join(root, 'eslint.config.cjs'));
  // Rules that find bugs. Anything else (spacing, quotes, semicolons, naming) would restyle files and is not allowed here.
  const allowed = new Set(['no-undef', 'no-unused-vars', 'no-unreachable', 'no-dupe-keys', 'no-dupe-args', 'no-dupe-class-members',
    'no-dupe-else-if', 'no-duplicate-case', 'no-self-assign', 'no-self-compare', 'no-constant-condition', 'no-constant-binary-expression',
    'no-cond-assign', 'no-const-assign', 'no-class-assign', 'no-func-assign', 'no-import-assign', 'no-ex-assign', 'no-global-assign',
    'no-redeclare', 'no-shadow-restricted-names', 'no-delete-var', 'no-compare-neg-zero', 'use-isnan', 'valid-typeof', 'no-unsafe-finally',
    'no-unsafe-negation', 'no-unsafe-optional-chaining', 'no-unexpected-multiline', 'no-sparse-arrays', 'no-obj-calls',
    'no-new-native-nonconstructor', 'no-invalid-regexp', 'no-empty-character-class', 'no-misleading-character-class',
    'no-useless-backreference', 'no-loss-of-precision', 'no-setter-return', 'getter-return', 'no-async-promise-executor',
    'no-empty-pattern', 'for-direction', 'no-debugger']);
  let seen = 0;
  for (const block of config) {
    for (const [rule, setting] of Object.entries(block.rules || {})) {
      seen++;
      assert.ok(allowed.has(rule), rule + ' is not a bug rule');
      const level = Array.isArray(setting) ? setting[0] : setting;
      assert.strictEqual(level, rule === 'no-unused-vars' ? 'warn' : 'error', rule);
    }
  }
  assert.ok(seen > 0);
});

test('gap 9: a planted bug is an error, an unused variable only a warning, in browser and in Node files', async () => {
  const { ESLint } = require('eslint');
  const eslint = new ESLint({ cwd: root });
  const cases = [
    // A misspelt name in a browser script, and a duplicate key in the API: errors.
    ['home.js', 'document.title = titel;\n', 'no-undef', 2],
    ['api/planted.js', "'use strict';\nmodule.exports = { a: 1, a: 2 };\n", 'no-dupe-keys', 2],
    ['db/planted.js', "'use strict';\nfunction f() { return 1; console.log('never'); }\nmodule.exports = f;\n", 'no-unreachable', 2],
    // An unused variable: a warning, which never fails the build.
    ['scripts/planted.js', "'use strict';\nconst unused = 1;\n", 'no-unused-vars', 1],
  ];
  for (const [file, code, rule, severity] of cases) {
    const [r] = await eslint.lintText(code, { filePath: path.join(root, file) });
    const hit = r.messages.find((m) => m.ruleId === rule);
    assert.ok(hit, file + ': ' + rule + ' was not reported');
    assert.strictEqual(hit.severity, severity, file + ': ' + rule);
  }
  // Ordinary browser and Node code passes clean.
  const [ok] = await eslint.lintText("'use strict';\nconst fs = require('fs');\nmodule.exports = () => fs.existsSync(__dirname) && process.pid;\n", { filePath: path.join(root, 'scripts/planted.js') });
  assert.deepStrictEqual(ok.messages, []);
});
