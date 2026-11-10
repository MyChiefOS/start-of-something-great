// The red-team copy's first check (RK141; harness/STANDARDS.md gap 1; OWASP A01, CWE-862): every security-definer
// function the site's role (dog_app) can run must check who is acting, or carry a reviewed reason in
// redteam/reviewed-functions.json. It reads Postgres's own catalog on a throwaway copy built from the migrations, so its
// answer is the same every run, and it gates. RK140 (app.work_github_sync, open to dog_app with no actor check since 042)
// is the kind of hole it stops: a new function like it fails the build until it is checked or its reason is recorded.
//
// "Checks who is acting" means its body calls, directly or through other app functions it calls (followed by name, up to
// eight levels), one of the database's actor checks: app.actor_kind(), app.current_actor_id(), or app.current_member()
// and app.current_agent(), which themselves require the stamp (019_actor_stamp.sql). Trigger functions can't be called
// directly and are left out. A name match can't see a check made some other way, which is why the list has reasons.
'use strict';

const CHECKS = /\bapp\.(actor_kind|current_actor_id|current_member|current_agent|stamp_ok)\s*\(/;

async function unchecked(sql) {
  const all = await sql.unsafe(`select p.proname as name, p.oid::regprocedure::text as fn, p.prosecdef as definer,
      p.prorettype = 'trigger'::regtype as trig, has_function_privilege('dog_app', p.oid, 'execute') as app, p.prosrc as src
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'app'`);
  const byName = new Map();
  for (const f of all) byName.set(f.name, [...(byName.get(f.name) || []), f]);
  const ok = new Map(all.map((f) => [f.fn, CHECKS.test(f.src)]));
  for (let level = 0; level < 8; level++) {
    for (const f of all) {
      if (ok.get(f.fn)) continue;
      const called = [...f.src.matchAll(/\bapp\.([a-z_0-9]+)\s*\(/g)].map((m) => m[1]);
      if (called.some((c) => (byName.get(c) || []).some((g) => ok.get(g.fn)))) ok.set(f.fn, true);
    }
  }
  return all.filter((f) => f.app && f.definer && !f.trig && !ok.get(f.fn)).map((f) => f.name).sort();
}

// What the reviewed list says about today's catalog: functions with no reason (new), reasons for functions that no
// longer need one (stale), and the open holes (each names its risk).
function compare(found, reviewed) {
  const names = new Set(found);
  return {
    unreviewed: found.filter((n) => !reviewed[n]),
    stale: Object.keys(reviewed).filter((n) => !n.startsWith('_') && !names.has(n)).sort(),
    open: found.filter((n) => reviewed[n] && reviewed[n].risk).map((n) => n + ' (' + reviewed[n].risk + ')')
  };
}

module.exports = { unchecked, compare, CHECKS };
