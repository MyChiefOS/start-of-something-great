// Which database this copy of the runner serves (the preview copy, RK141; design/preview-copy.md). The same runner code
// is deployed twice: to production (project nksagchwpyljvjiwolmp) and to the one Supabase preview branch. Each decides
// once, when it starts, from its own SUPABASE_URL, which Supabase sets for every function and which no one can set by
// hand ("A secret name can't start with SUPABASE_", Supabase's documents, read Nov 10). Nothing a request sends is
// ever read for this. The rule is the key broker's (../dog-keys/target.mjs), kept here as the runner's own file so the
// two functions deploy independently; test/preview-migrate.test.js checks that they always agree.
//
//   production's own address, or anything that isn't a Supabase project address: production, exactly as before
//     (database.yml on main, at production's own address; "apply" and "status"). A missing or odd setting can't turn
//     production into the copy.
//   any other project's address (the preview branch): only preview-copy.yml on main, by a push or by hand, at the
//     branch's own address, and only "rebuild" (./copy.mjs): reset the copy, migrate it from main, reseed it.
// PRODUCTION's values are the ones index.ts writes out in full (tested), so production's code is the old code.

export const PROJECT_REF = 'nksagchwpyljvjiwolmp';
const REF = /^[a-z]{20}$/; // a Supabase project reference: 20 lowercase letters (branches have their own)
const runnerAt = (ref) => 'https://' + ref + '.supabase.co/functions/v1/dog-migrate';
const COPY_WORKFLOW = '.github/workflows/preview-copy.yml';

export const PRODUCTION = Object.freeze({
  environment: 'production', ref: PROJECT_REF, audience: runnerAt(PROJECT_REF), workflow: '.github/workflows/database.yml',
  events: Object.freeze(['push', 'workflow_dispatch', 'schedule']), modes: Object.freeze(['apply', 'status'])
});

const branch = (ref) => Object.freeze({
  environment: 'preview', ref, audience: runnerAt(ref), workflow: COPY_WORKFLOW,
  events: Object.freeze(['push', 'workflow_dispatch']), modes: Object.freeze(['rebuild'])
});

export function target(supabaseUrl) {
  let host = '';
  try { host = new URL(String(supabaseUrl || '')).hostname; } catch { host = ''; }
  const ref = host.endsWith('.supabase.co') ? host.slice(0, -'.supabase.co'.length) : '';
  if (!REF.test(ref) || ref === PROJECT_REF) return PRODUCTION;
  return branch(ref);
}

// True only for a branch exactly as target() makes it: never production's reference, never a hand-made look-alike.
export function isBranch(where) {
  if (!where || where.environment !== 'preview' || typeof where.ref !== 'string' || !REF.test(where.ref) || where.ref === PROJECT_REF) return false;
  const want = branch(where.ref);
  return where.audience === want.audience && where.workflow === want.workflow
    && Array.isArray(where.events) && where.events.join() === want.events.join()
    && Array.isArray(where.modes) && where.modes.join() === want.modes.join();
}
