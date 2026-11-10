// The public log's jobs (038), run by the timer route every minute (api/cron.js), each in its own transaction after
// the timers, as an anonymous visitor: JEVs's queued decisions whose hour has ended; the next signed checkpoint; and,
// since 057, the check that the witness has stopped (12 hours with no report: app.log_witness_check, which takes
// nothing from the caller). A failure in one never stops the others or the timers: it changes nothing, and the next
// minute tries again.
// Since 057 (RISKS.md RK112, RK144) the site no longer reads Aaron's proposal decisions or the witness's copy from
// GitHub, and its role can't record them: the GitHub facts workflow sends the proposal decisions, and the witness
// workflow (.github/workflows/log-witness.yml) its own result, each to the dog-github function, which accepts only
// those workflows on main, proved by GitHub's identity token. witnessRequest below shapes the witness's report for that
// workflow (node db/logjobs.js witness-request <state.json> <request.json>); it needs no packages.
'use strict';

const fs = require('fs');

async function step(name, out, fn) {
  try { out[name] = await fn(); } catch (e) { out[name] = { failed: String((e && (e.code || e.name)) || 'error').replace(/[^A-Za-z0-9_]/g, '').slice(0, 32) }; }
}

// The witness's state.json: its last good checkpoint and its alarm, if any. Only these fields are passed on.
function readWitness(state) {
  if (!state || typeof state !== 'object') return null;
  const good = state.good && typeof state.good === 'object' ? state.good : null;
  const size = good && Number.isSafeInteger(good.size) && good.size > 0 ? good.size : null;
  const root = good && typeof good.root === 'string' && /^[A-Za-z0-9+/]{43}=$/.test(good.root) ? Buffer.from(good.root, 'base64') : null;
  const at = typeof state.last_run === 'string' && !Number.isNaN(Date.parse(state.last_run)) ? new Date(state.last_run) : null;
  const alarm = state.alarm ? String(state.alarm.reason || state.alarm).slice(0, 300) : null;
  return { size, root, at, alarm };
}

// The request the witness workflow sends dog-github: {mode: "witness", report: {size, root, at, alarm}}. Throws if the
// state has no time of its run (nothing to report).
function witnessRequest(state) {
  const w = readWitness(state);
  if (!w || !w.at) throw new Error('the witness\'s state has no time of its last run');
  const whole = w.size !== null && w.root !== null;
  return { mode: 'witness', report: { size: whole ? w.size : null, root: whole ? w.root.toString('base64') : null, at: w.at.toISOString(),
    alarm: w.alarm ? w.alarm : null } };
}

async function run(runDb) {
  const out = {};
  const as = (fn) => runDb({ actor: 'anon' }, fn);
  // JEVs's queued decisions, 250 a call, each call its own short transaction (the review of 038, H4), up to 8 calls.
  await step('jevs', out, async () => {
    let total = 0;
    for (let i = 0; i < 8; i++) {
      const n = Number((await as((t) => t`select app.log_jevs_hours() as n`))[0].n);
      total += n;
      if (n < 250) break;
    }
    return total;
  });
  await step('checkpoint', out, () => as((t) => t`select app.log_checkpoint() as n`).then((r) => (r[0].n === null ? null : Number(r[0].n))));
  await step('witness', out, () => as((t) => t`select app.log_witness_check() as s`).then((r) => r[0].s));
  return out;
}

// The witness workflow's step: node db/logjobs.js witness-request <state.json> <request.json>.
function main(argv) {
  if (argv[0] !== 'witness-request' || argv.length !== 3) throw new Error('usage: node db/logjobs.js witness-request <state.json> <request.json>');
  const req = witnessRequest(JSON.parse(fs.readFileSync(argv[1], 'utf8')));
  fs.writeFileSync(argv[2], JSON.stringify(req));
  console.log('the witness ran at ' + req.report.at + (req.report.size ? '; last good checkpoint ' + req.report.size : '; no good checkpoint yet')
    + (req.report.alarm ? '; it raised an alarm' : ''));
}

if (require.main === module) {
  try { main(process.argv.slice(2)); } catch (e) { console.error(String((e && e.message) || e)); process.exit(1); }
}

module.exports = { run, readWitness, witnessRequest, main, _reset: () => {} };
