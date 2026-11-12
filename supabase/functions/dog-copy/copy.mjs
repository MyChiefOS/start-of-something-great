// The preview copy's rebuild (RK141; design/preview-copy.md, "Building and reseeding the copy"), in its own function,
// dog-copy, deployed only to the preview branch (Aaron, Nov 10: production carries none of this code). index.ts
// sends a request here only when ./target.mjs, reading the function's own SUPABASE_URL at start, said "preview", and
// each function below refuses again unless it is the branch.
//
// The seed (../_shared/preview-seed.mjs) refuses any database that already holds data, and it must keep doing so. So
// each rebuild starts the copy from empty instead, all in ONE transaction, under the runner's lock:
//   1. the database's own guard (resetRefusal): only the marked copy, or a database holding nothing of ours, may be
//      reset. Production holds members and its three site keys in Vault and has no mark: refused, two ways over;
//   2. the reset: the app schema dropped (as dog_owner, as the Oct 24 fresh build did), and the three site keys and the
//      mark that the seed made deleted from Vault. Nothing else: the dog_* roles are shared by the cluster and reused
//      by the migrations, and migration 022 gives the copy's login (dog_web) a new password in Vault;
//   3. every migration of the merged commit, by the runner's own code (../dog-migrate/core.mjs run, unchanged), which also checks
//      the result, records the run in app.change_log and records the token so it can't be used again;
//   4. the seed: new made-up members, agents, posts, tasks, site keys and the mark.
// If anything fails, nothing changes: the old copy stands. Returns versions, counts and check names only.
import { MARKER, SITE_KEYS, seed } from '../_shared/preview-seed.mjs';
import { run, tokenUsed } from '../dog-migrate/core.mjs';
import { isBranch } from './target.mjs';

const LOCK = 'dayonegreat.migrate'; // the runner's own lock (../dog-migrate/core.mjs): one run at a time, here too
const NOT_BRANCH = "refused: not the preview copy's runner";

// Why this database may not be reset, or null when it may. Read-only. Takes a transaction.
export async function resetRefusal(t) {
  const [s] = await t`select to_regnamespace('vault') is not null as vault, to_regclass('app.members') is not null as app`;
  if (!s.vault) return 'no Vault: the preview copy runs only on a Supabase database';
  // The mark counts only as the key broker reads it: the value "yes" (../dog-keys/core.mjs). A count, never the value.
  const [m] = await t`select count(*)::int as n from vault.decrypted_secrets where name = ${MARKER} and decrypted_secret = 'yes'`;
  if (m.n) return null;
  const [v] = await t`select count(*)::int as n from vault.secrets where name = any(${SITE_KEYS})`;
  if (v.n) return 'site keys in Vault and no preview mark: this is not the preview copy';
  if (!s.app) return null; // a new branch: nothing of ours yet
  // Counted with row-level security off, so a row the login can't see makes this fail loudly instead of reading 0.
  await t`set local row_security = off`;
  const [n] = await t`select (select count(*) from app.members)::int + (select count(*) from app.agents)::int
    + (select count(*) from app.posts)::int as n`;
  await t`reset row_security`;
  if (n.n) return 'members, agents or posts and no preview mark: this is not the preview copy';
  return null;
}

// Resets, migrates and reseeds the copy in one transaction. loaded: ../dog-migrate/core.mjs load() of the merged commit; claims: the
// checked identity token; where: ./target.mjs's choice.
export async function rebuild(sql, { files }, claims, where) {
  if (!isBranch(where)) throw new Error(NOT_BRANCH);
  return sql.begin(async (t) => {
    await t`select pg_advisory_xact_lock(hashtext(${LOCK}))`;
    const why = await resetRefusal(t);
    if (why) throw new Error('reset refused: ' + why);
    await t`set local role dog_owner`;
    await t`drop schema if exists app cascade`;
    await t`reset role`;
    await t`delete from vault.secrets where name = any(${[MARKER, ...SITE_KEYS]})`;
    // The runner's code and the seed each open their own transaction; here each becomes a savepoint inside this one,
    // so the reset, the migrations and the seed commit together or not at all.
    const inside = Object.assign((...a) => t(...a), { begin: (fn) => t.savepoint(fn) });
    const result = await run(inside, { files, reset: null }, claims);
    // run() leaves the owner role set for the rest of the transaction; the seed starts as the runner's own login.
    await t`reset all`;
    await t`reset role`;
    const seeded = await seed(inside);
    return { ...result, rebuilt: true, seeded };
  });
}

// One request to the branch's dog-copy, after index.ts has read its body. On production it is never deployed, and if it
// ever were, every request would be refused before any check: isBranch(PRODUCTION) is false.
//   verify: ../_shared/github-oidc.mjs verify (its keys and clock are the caller's); load(commit): that commit's files.
export async function handleCopy({ body, token }, { where, sql, verify, Refused, load }) {
  if (!isBranch(where)) return { status: 500, body: { ok: false, error: NOT_BRANCH } };
  if (!body || typeof body !== 'object' || body.mode !== 'rebuild') return { status: 400, body: { ok: false, error: 'mode must be rebuild' } };
  let claims;
  try {
    claims = await verify(token, { audience: where.audience, workflow: where.workflow, events: [...where.events], seen: (jti) => tokenUsed(sql, jti) });
  } catch (e) {
    if (e instanceof Refused) return { status: 401, body: { ok: false, error: 'refused: ' + e.message } };
    throw e;
  }
  const result = await rebuild(sql, await load(claims.sha), claims, where);
  return { status: result.ok ? 200 : 500, body: result };
}
