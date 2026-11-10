// RK147 and RK149's public text. SECURITY.md exists and says what a reporter needs; security.txt points to it and is
// still valid; /security says only what the witness, after RK149's fix and the log-witness ruleset, really does.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const POLICY_URL = 'https://github.com/MyChiefOS/start-of-something-great/blob/main/SECURITY.md';

test('RK147: SECURITY.md exists, with how to report, the scope, response targets, safe harbour and no bounty', () => {
  assert.ok(fs.existsSync(path.join(root, 'SECURITY.md')), 'SECURITY.md is at the repository root, where GitHub looks for it');
  const md = read('SECURITY.md');
  for (const h of ['How to report', 'What\'s in scope', 'What to expect', 'Safe harbour', 'No bounty']) assert.match(md, new RegExp('^## ' + h + '$', 'm'), 'section: ' + h);
  assert.match(md, /security\/advisories\/new/, 'GitHub\'s private vulnerability reporting');
  // The email is the one security.txt gives, never another.
  const txtContact = read('.well-known/security.txt').match(/^Contact: mailto:(\S+)$/m)[1];
  const emails = [...md.matchAll(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g)].map((m) => m[0]);
  assert.deepStrictEqual([...new Set(emails)], [txtContact], 'the only address is security.txt\'s contact');
  for (const s of ['dayonegreat.com', 'https://dayonegreat.com/api/', 'https://dayonegreat.com/api/mcp', 'supabase/functions']) assert.ok(md.includes(s), 'in scope: ' + s);
  assert.match(md, /targets we aim for, not promises/, 'response times are targets');
  assert.match(md, /no bug bounty/i);
});

test('RK147: security.txt points to SECURITY.md and is still valid (RFC 9116)', () => {
  const txt = read('.well-known/security.txt');
  const fields = txt.split('\n').filter((l) => l && !l.startsWith('#')).map((l) => l.split(/: (.*)/s).slice(0, 2));
  const one = (k) => { const v = fields.filter(([f]) => f === k); assert.strictEqual(v.length, 1, 'exactly one ' + k); return v[0][1]; };
  assert.strictEqual(one('Policy'), POLICY_URL);
  assert.ok(fields.some(([f, v]) => f === 'Contact' && /^mailto:/.test(v)), 'a contact');
  const exp = new Date(one('Expires'));
  assert.ok(!Number.isNaN(exp.getTime()) && /Z$/.test(one('Expires')), 'Expires is an RFC 3339 time');
  assert.ok(exp > new Date(), 'Expires is in the future; renew it (RFC 9116 recommends under a year ahead)');
  assert.strictEqual(one('Canonical'), 'https://dayonegreat.com/.well-known/security.txt');
  for (const [f] of fields) assert.ok(['Contact', 'Expires', 'Policy', 'Preferred-Languages', 'Canonical', 'Acknowledgments', 'Encryption', 'Hiring', 'CSAF'].includes(f), 'a field RFC 9116 defines: ' + f);
});

test('RK149: /security says only what the witness does: its job keeps the alarm, the key and the history; people with write access and the owner are named', () => {
  const html = read('security.html');
  const main = html.match(/<main[\s\S]*?<\/main>/)[0].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ');
  // The three sentences the CLJO named, as they were: each promised more than the witness delivered.
  assert.ok(!/pinned key changes only by a reviewed change to its branch/.test(main), 'no "reviewed change to its branch": nothing on that branch is reviewed');
  assert.ok(!/which the repository’s owner could rewrite\./.test(main), 'the ruleset stops rewriting; the owner could switch it off');
  assert.ok(!/It stays unverified until a reviewed migration clears the alarm/.test(main), 'the site and Verify checks are said apart');
  // What is true now.
  assert.match(main, /The witness’s own job can’t take the alarm back\. It refuses to write a state that drops the alarm, lowers its last good checkpoint, changes its pinned key or restarts its count of runs, and it starts a fresh branch only when GitHub says there is none\./);
  assert.match(main, /The witness’s job never removes it there; anyone with write access to this repository can, with an ordinary commit to the branch\. That commit stays in the branch’s public history, but a Verify check reads only the branch’s latest state\./);
  assert.match(main, /The witness’s own job refuses to change its copy, and a copy that differs from the repository’s pin shows as an alarm on the witness’s next run\./);
  assert.match(main, /A ruleset stops anyone deleting the branch or rewriting its history, but the repository’s owner could switch the ruleset off and then do either, and anyone with write access to the repository, Claude’s sessions included, can add an ordinary commit that looks like the witness’s own\./);
  assert.match(main, /while the alarm is still on the branch, the site raises it again/);
  // The report card links the policy and GitHub's private reporting.
  assert.ok(main.includes('SECURITY.md') && html.includes('href="' + POLICY_URL + '"'));
  assert.ok(html.includes('href="https://github.com/MyChiefOS/start-of-something-great/security/advisories/new"'));
  // No stale date or dropped stage named on this page.
  assert.ok(!/Nov 6|November 6|preview/i.test(html), 'no "Nov 6", "November 6" or "preview" on /security');
});

test('RK149: the witness’s header and the rulesets README say what is true', () => {
  const w = read('tools/verify/witness.mjs');
  assert.ok(!/until a person removes it by\s*\n?\/\/\s*a reviewed change/.test(w) && !/removes it by a reviewed change/.test(w), 'no reviewed change on the branch is claimed');
  assert.match(w, /record\(\) refuses a state\.json that drops or changes the branch's alarm/);
  const r = read('.github/rulesets/README.md');
  assert.ok(!/only ever adds commits/.test(r), 'the witness job adding commits never kept the record whole by itself');
  assert.match(r, /GitHub's import takes\s+a file from your own computer/);
  assert.match(r, /^Optional, only if the GitHub CLI is set up on Aaron's computer/m, 'the command-line route is optional');
});
