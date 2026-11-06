// Review for a limited, fallible human (041; the design handoff of Nov 5, 2026, CODING_AGENT_SPEC.md section 2, as
// Aaron decided it: JEVs and Second Look take the volume, items reach him by risk, no second reviewer, planted tests
// test Second Look). The database decides and counts; this file reads its answers and checks the canaries' promises.
//   adminView(t)        the administrator's view for /admin/controls: today's budget, the sample, the alerts, and every
//                       revealed canary checked against the append-only audit log (checkCanaries)
//   checkCanaries(...)  the check itself: each canary's truth and nonce hash to the commitment logged when it was
//                       planted, the commitment was logged before the decision, and the table and the log agree
//   oversight(t)        the public counts for /decisions and /status (app.public_oversight): JEVs and Second Look only
'use strict';

const crypto = require('crypto');

const int = (x) => (x === null || x === undefined ? 0 : Math.max(0, Math.trunc(Number(x)) || 0));
const few = (x) => (x === null || x === undefined ? null : int(x)); // 1 to 4 comes back null: "fewer than 5"
const num = (x) => (x === null || x === undefined || !Number.isFinite(Number(x)) ? null : Number(x));
const sha256hex = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');

// rows: the revealed canaries (app.review_admin); log: their audit entries ({ subject_id, action, detail, at }).
// Returns { checked, ok, problems: [plain words] }. The commitment logged before use is SHA-256 of
// "id:truth:nonce:SHA-256(text)" (041, after its review: L6), so the reveal must hash to it, the text shown must hash to
// the text hash, the commitment must have been logged before the decision, and the table and the log must agree.
function checkCanaries(rows, log) {
  const by = new Map();
  for (const e of log || []) {
    const k = String(e.subject_id);
    if (!by.has(k)) by.set(k, {});
    by.get(k)[e.action] = e;
  }
  const problems = [];
  for (const c of rows || []) {
    const e = by.get(String(c.id)) || {};
    const planted = e['review.canary'];
    const result = e['review.canary_result'];
    const name = 'planted test ' + c.id;
    if (!planted) { problems.push(name + ': no commitment in the audit log from before it was used'); continue; }
    if (!result) { problems.push(name + ': no reveal in the audit log'); continue; }
    const logged = planted.detail && planted.detail.commitment;
    const r = result.detail || {};
    if (sha256hex(c.id + ':' + r.truth + ':' + r.nonce + ':' + r.text_sha256) !== logged) problems.push(name + ': the revealed truth, nonce and text hash don’t hash to the commitment logged before it was used');
    if (c.body !== undefined && sha256hex(c.body) !== r.text_sha256) problems.push(name + ': its text isn’t the text whose hash was committed');
    if (c.commitment !== logged || r.commitment !== logged) problems.push(name + ': the commitment in the table differs from the one logged');
    if (c.truth !== r.truth || c.nonce !== r.nonce || (c.text_sha256 !== undefined && c.text_sha256 !== r.text_sha256)) problems.push(name + ': the truth, nonce or text hash in the table differs from the one revealed in the log');
    if (!(new Date(planted.at) <= new Date(result.at))) problems.push(name + ': the commitment was logged after the decision');
  }
  return { checked: (rows || []).length, ok: problems.length === 0, problems };
}

const mineWin = (w) => ({ decided: int(w && w.decided), approved: int(w && w.approved), removed: int(w && w.removed), undone: int(w && w.undone),
  median_seconds: num(w && w.median_seconds), p10_seconds: num(w && w.p10_seconds), hours: num(w && w.hours), median_wait_minutes: num(w && w.median_wait_minutes) });
const alertsOf = (a) => (Array.isArray(a) ? a : []).map((x) => ({ id: String(x.id), title: String(x.title), text: String(x.text) }));

async function adminView(t) {
  const [r] = await t.savepoint((s) => s`select app.review_admin() as r`);
  const a = r.r;
  const ids = (a.canaries || []).map((c) => c.id);
  const log = ids.length ? await t.savepoint((s) => s`select subject_id, action, detail, at from app.audit_log
      where action in ('review.canary', 'review.canary_result') and subject_kind = 'canary' and subject_id = any(${ids}::uuid[])`) : [];
  const canaries = a.canaries || [];
  const answered = canaries.filter((c) => !c.no_answer);
  const bad = answered.filter((c) => c.truth === 'bad');
  const good = answered.filter((c) => c.truth === 'good');
  return {
    daily_budget: int(a.daily_budget), decided_today: int(a.decided_today), sample_rate: num(a.sample_rate), sample_on: Number(a.sample_rate) > 0,
    sample_daily_cap: int(a.sample_daily_cap), samples_today: int(a.samples_today), canary_rate: num(a.canary_rate), canaries_waiting: int(a.canaries_waiting),
    alerts: alertsOf(a.alerts),
    // Aaron's own reviewing: for him only, never in a public answer.
    mine: { d7: mineWin(a.mine && a.mine.d7), d30: mineWin(a.mine && a.mine.d30) },
    canaries: { revealed: canaries.length, no_answer: canaries.length - answered.length, bad: bad.length,
      bad_caught: bad.filter((c) => c.decision !== 'clear').length, good: good.length, good_cleared: good.filter((c) => c.decision === 'clear').length,
      check: checkCanaries(canaries, log) }
  };
}

// The public figures (041): JEVs and Second Look only, counted once a day. Post counts of 1 to 4 stay null ("fewer than
// 5"); the sample's outcomes come as parts with "other", so none can be found by subtraction.
const kParts = (x) => ({ parts: (Array.isArray(x && x.parts) ? x.parts : []).map(few), other: few(x && x.other), shown: int(x && x.shown) });
function shapeWindow(w) {
  const c = (w && w.canaries) || {};
  return { days: int(w && w.days), jevs_held: few(w && w.jevs_held), github_hidden: few(w && w.github_hidden), sample_flagged: few(w && w.sample_flagged),
    sl_decisions: few(w && w.sl_decisions), sl_clears: few(w && w.sl_clears), sl_published: few(w && w.sl_published), sample: kParts(w && w.sample),
    canaries: { used: int(c.used), no_answer: int(c.no_answer), bad: int(c.bad), bad_caught: int(c.bad_caught), good: int(c.good), good_cleared: int(c.good_cleared) } };
}
function shapeOversight(d) {
  const l = d.limits || {};
  const w = d.windows || {};
  return {
    counted_through: d.counted_through ? String(d.counted_through).slice(0, 10) : null,
    limits: { sample_on: l.sample_on === true, sample_rate: num(l.sample_rate), sample_daily_cap: int(l.sample_daily_cap), canary_rate: num(l.canary_rate) },
    d7: shapeWindow(w.d7), d30: shapeWindow(w.d30),
    alerts: alertsOf(d.alerts)
  };
}

async function oversight(t) {
  const [r] = await t`select app.public_oversight() as d`;
  return shapeOversight(r.d);
}

module.exports = { adminView, checkCanaries, oversight, shapeOversight, sha256hex };
