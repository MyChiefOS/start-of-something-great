// Which site this copy of the key broker serves (the preview copy, RK141; design/preview-copy.md). The same broker
// code is deployed twice: to production (project nksagchwpyljvjiwolmp) and to the one Supabase preview branch. Each
// decides once, when it starts, from its own SUPABASE_URL, which Supabase sets for every function and which no one can
// set by hand ("A secret name can't start with SUPABASE_", Supabase's documents, read Nov 10). Nothing a request sends
// is ever read for this.
//
//   production's own address, or anything that isn't a Supabase project address: production, exactly as before
//     (the pinned check, ../_shared/vercel-oidc.mjs, with its default environment "production"; the login
//     dog_web.nksagchwpyljvjiwolmp; the four Vault values). A missing or odd setting can't lock production out.
//   any other project's address (the preview branch): only Vercel identity tokens that say environment "preview",
//     for our own team and project, are accepted; the login it hands out is the branch's own (dog_web.<branch ref>);
//     and it hands out nothing unless the branch's own Vault carries the preview copy's mark, which only the seed
//     (../_shared/preview-seed.mjs) makes, and only on an empty database. So even if production were ever told it
//     was a branch, it would still hand out nothing: production's Vault has no mark.
// The pinned check isn't edited (its digest is pinned): its environment option, which production leaves at its
// default, is the only thing chosen here.
import { PROJECT_REF } from './core.mjs';

export const PREVIEW_MARKER = 'dog_preview_copy';
const REF = /^[a-z]{20}$/; // a Supabase project reference: 20 lowercase letters (branches have their own)

export function target(supabaseUrl) {
  let host = '';
  try { host = new URL(String(supabaseUrl || '')).hostname; } catch { host = ''; }
  const ref = host.endsWith('.supabase.co') ? host.slice(0, -'.supabase.co'.length) : '';
  if (!REF.test(ref) || ref === PROJECT_REF) return Object.freeze({ environment: 'production', ref: PROJECT_REF, marker: null });
  return Object.freeze({ environment: 'preview', ref, marker: PREVIEW_MARKER });
}

// The broker's checks for this target: the pinned verify with this target's environment, and the Vault read with the
// mark when one is required. verify: ../_shared/vercel-oidc.mjs verify (its keys and clock are the caller's).
export function checksFor(where, { verify, read }) {
  return {
    verify: (token, opts = {}) => verify(token, { ...opts, environment: where.environment }),
    read: (sql) => read(sql, where.marker ? [where.marker] : []),
    ref: where.ref,
    marker: where.marker
  };
}
