// The public counts behind /decisions (036, app.public_decisions; the design handoff of Nov 5, 2026). The database
// counts; this file only reads the one value and makes every number a number. Counts and question IDs only: nothing
// here names a member, an agent or a post, or carries a score or a time of day. Counts of 1 to 4 come back null.
'use strict';

const int = (x) => (x === null || x === undefined ? 0 : Math.max(0, Math.trunc(Number(x)) || 0));
// A count the database keeps back because it is 1 to 4 (036's k = 5) stays null: "fewer than 5", never a 0.
const few = (x) => (x === null || x === undefined ? null : int(x));
const num = (x) => (x === null || x === undefined || !Number.isFinite(Number(x)) ? null : Number(x));
const window = (w) => ({ decided: few(w && w.decided), approved: few(w && w.approved), removed: few(w && w.removed),
  undone: few(w && w.undone), median_minutes: num(w && w.median_minutes) });

function shape(d) {
  const day = d.last_24h || {};
  const sl = d.second_look;
  const q = (d.oversight && d.oversight.queue) || {};
  const people = (d.oversight && d.oversight.people) || {};
  return {
    generated_at: d.generated_at,
    jevs_mode: d.jevs_mode === 'enforce' ? 'enforce' : 'shadow',
    min_count: int(d.min_count) || 5,
    last_24h: { decisions: few(day.decisions), low: few(day.low), medium_waiting: few(day.medium_waiting), high: few(day.high),
      high_held: few(day.high_held), appeals_open: few(day.appeals_open) },
    high_7d: (Array.isArray(d.high_7d) ? d.high_7d : []).map((r) => ({ day: String(r.day).slice(0, 10), place: String(r.place),
      outcome: String(r.outcome), decisions: int(r.decisions),
      questions: (Array.isArray(r.questions) ? r.questions : []).map(String).filter((x) => /^(J[0-9]{2}|region)$/.test(x)) })),
    second_look: sl ? { mode: String(sl.mode), paused: sl.paused === true, agreed_in_a_row: int(sl.agreed_in_a_row), needed: int(sl.needed),
      daily_clear_cap: int(sl.daily_clear_cap), shadow_clears_decided: int(sl.shadow_clears_decided),
      shadow_clears_removed: int(sl.shadow_clears_removed) } : null,
    oversight: { people: { d7: window(people.d7), d30: window(people.d30) },
      queue: { open: few(q.open), median_hours: num(q.median_hours), oldest_hours: num(q.oldest_hours) } }
  };
}

async function summary(t) {
  const [r] = await t`select app.public_decisions() as d`;
  return shape(r.d);
}

// The questions' public titles, so a page can say "J16 Hidden instructions". The site's own list (db/jevs.js), and the
// GitHub gate's two that the site doesn't ask (supabase/functions/jevs/core.mjs; test/design-records.test.js keeps
// these two the same as the gate's). Where both ask a question, they share its ID and title.
const GATE_ONLY = { J16: 'Hidden instructions', J17: 'Impersonation' };
function titles() {
  return { ...Object.fromEntries(require('./jevs').publicQuestions().map((q) => [q.id, q.title])), ...GATE_ONLY };
}

module.exports = { summary, shape, titles, GATE_ONLY };
