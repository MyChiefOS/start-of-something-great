// Which database this function serves (the preview copy, RK141; design/preview-copy.md). dog-copy is deployed only to
// the one Supabase preview branch (Aaron, Nov 10: production carries none of the copy's code). It still decides, once,
// when it starts, from its own SUPABASE_URL, which Supabase sets for every function and which no one can set by hand
// ("A secret name can't start with SUPABASE_", Supabase's documents, read Nov 10); nothing a request sends is read for
// this. The rule is the key broker's (../dog-keys/target.mjs); test/preview-migrate.test.js checks that they agree.
//
//   production's own address, or anything that isn't a Supabase project address: PRODUCTION, which describes
//     production's own runner (dog-migrate: database.yml on main, at production's address) for the tests, and which
//     dog-copy refuses outright (./copy.mjs: isBranch is false), so a dog-copy deployed by mistake to production does
//     nothing.
//   any other project's address (the preview branch): only preview-copy.yml on main, by a push or by hand, at the
//     branch's own dog-copy address, and only "rebuild" (./copy.mjs): reset the copy, migrate it from main, reseed it.

export const PROJECT_REF = 'nksagchwpyljvjiwolmp';
const REF = /^[a-z]{20}$/; // a Supabase project reference: 20 lowercase letters (branches have their own)
const runnerAt = (ref) => 'https://' + ref + '.supabase.co/functions/v1/dog-migrate';
const copyAt = (ref) => 'https://' + ref + '.supabase.co/functions/v1/dog-copy';
const COPY_WORKFLOW = '.github/workflows/preview-copy.yml';

export const PRODUCTION = Object.freeze({
  environment: 'production', ref: PROJECT_REF, audience: runnerAt(PROJECT_REF), workflow: '.github/workflows/database.yml',
  events: Object.freeze(['push', 'workflow_dispatch', 'schedule']), modes: Object.freeze(['apply', 'status'])
});

const branch = (ref) => Object.freeze({
  environment: 'preview', ref, audience: copyAt(ref), workflow: COPY_WORKFLOW,
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
