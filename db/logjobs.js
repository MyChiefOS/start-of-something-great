// The public log's jobs (038), run by the timer route every minute (api/cron.js), each in its own transaction after
// the timers, as an anonymous visitor: JEVs's queued decisions whose hour has ended; Aaron's decisions on proposals as GitHub
// shows them (at most every 10 minutes per running copy); the next signed checkpoint; and the witness's copy on GitHub
// (at most every 5 minutes per running copy). A failure in one never stops the others or the timers: it changes
// nothing, and the next minute tries again. Everything the database is told is checked there again.
'use strict';

const log = require('./log');

const PROPOSALS_MS = 10 * 60 * 1000;
const WITNESS_MS = 5 * 60 * 1000;
let lastProposals = 0, lastWitness = 0;
const DECIDED = new Set(['approved', 'declined', 'shipped']);

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

async function run(runDb, { getProposals = null, fetchImpl = null, now = Date.now } = {}) {
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
  if (getProposals && now() - lastProposals >= PROPOSALS_MS) {
    lastProposals = now();
    await step('proposals', out, async () => {
      const list = await getProposals();
      let added = 0;
      for (const p of (list && list.proposals) || []) {
        if (!DECIDED.has(p.status) || !Number.isSafeInteger(p.number)) continue;
        const [r] = await as((t) => t`select app.log_proposal(${p.number}, ${p.status}) as seq`);
        if (r.seq !== null) added++;
      }
      return added;
    });
  }
  await step('checkpoint', out, () => as((t) => t`select app.log_checkpoint() as n`).then((r) => (r[0].n === null ? null : Number(r[0].n))));
  if (fetchImpl && now() - lastWitness >= WITNESS_MS) {
    lastWitness = now();
    await step('witness', out, async () => {
      const r = await fetchImpl(log.WITNESS.state, { headers: { Accept: 'application/json' } });
      // No branch yet (the job hasn't run): nothing to compare, and nothing is wrong.
      const w = r.status === 404 ? null : r.ok ? readWitness(await r.json()) : (() => { throw Object.assign(new Error('witness'), { code: 'HTTP' + r.status }); })();
      const [x] = await as((t) => t`select app.log_witness_report(${w ? w.size : null}, ${w ? w.root : null}, ${w ? w.at : null}, ${w ? w.alarm : null}) as s`);
      return x.s;
    });
  }
  return out;
}

module.exports = { run, readWitness, _reset: () => { lastProposals = 0; lastWitness = 0; } };
