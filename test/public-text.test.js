// Review R-5 (harness/REVIEW-2026-10-26.md, Oct 26, 2026): nothing the site serves may promise a private preview or a
// date that has passed, or call Release 2 done before it is proven live (INTEGRITY.md: nothing public is called done
// until it is). Aaron, Oct 24: "NO preview systems", so LAUNCH_STAGE=preview counts as closed.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
// Everything a visitor or an agent is served: pages, browser scripts, llms.txt and the API's own text.
const served = [
  ...fs.readdirSync(root).filter((f) => /\.(html|js|txt)$/.test(f)),
  ...fs.readdirSync(path.join(root, 'api')).filter((f) => f.endsWith('.js')).map((f) => 'api/' + f)
];

test('R-5: no served page, script, API message or llms.txt promises a preview or November 6', () => {
  const bad = [];
  for (const f of served) {
    fs.readFileSync(path.join(root, f), 'utf8').split('\n').forEach((line, i) => {
      // The status page keeps the dropped milestone as history: "dropped Oct 24: no private preview (Aaron)".
      if (/dropped Oct 24: no private preview/.test(line)) return;
      if (/private preview|with the preview|november 6|nov\.? 6\b/i.test(line)) bad.push(f + ':' + (i + 1));
    });
  }
  assert.deepStrictEqual(bad, []);
});

test('R-5: the status page doesn\'t call Release 2 done until it is', () => {
  const { status } = require('../api/_lib');
  assert.ok(!/Release 2 live/.test(status.phase.current), 'the current phase doesn\u2019t say Release 2 is live');
  const text = fs.readFileSync(path.join(root, 'api', '_lib.js'), 'utf8');
  assert.ok(!/27 days early/.test(text), 'no "done, 27 days early" for Release 2');
  const line = text.split('\n').find((l) => l.includes("'Release 2 public: every role working"));
  assert.match(line, /actual: null/);
  assert.match(line, /not yet/);
});

test('R-5: "preview" is not a stage: setting it closes the site, never opens it', () => {
  const launch = require('../launch');
  assert.deepStrictEqual(launch.STAGES, ['closed', 'public']);
  const open = { stage: 'public' };
  assert.strictEqual(launch.stage({ LAUNCH_STAGE: 'preview' }, open), 'closed');
  assert.strictEqual(launch.stage({ LAUNCH_STAGE: 'public' }, open), 'public');
  assert.strictEqual(launch.stage({}, { stage: 'preview' }), 'closed', 'nor in the repository\'s file');
});

test('R-5: llms.txt says how agents take part on GitHub today, and that the thresholds are public', () => {
  const t = fs.readFileSync(path.join(root, 'llms.txt'), 'utf8');
  assert.match(t, /\/agent register <name>/);
  assert.match(t, /enforce mode since Oct 24, 2026/);
  assert.ok(!/the scores that decide are not/.test(t));
  assert.match(t, /2025-03-26 through 2026-07-28/, 'the same range as /connect and ACCEPTANCE C6');
  assert.match(t, /not yet used by a real agent/, 'the GitHub agent path isn\u2019t proven live yet');
  assert.ok(!/repository's Discussions/.test(t), 'only /talk, which keeps the regional redirect');
});
