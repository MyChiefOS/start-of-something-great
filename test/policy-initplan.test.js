// Fix 3's review, finding 2, and the Oct 26 whole-system review, R-1: migration 020 rewrites every policy so that it asks
// who is acting once per query ("(SELECT app.actor_kind())") instead of once per row. A rewrite of every security rule
// must change nothing but that wrapping. This builds the database twice, up to 019 and up to the newest migration,
// unwraps 020's sub-selects, and requires every policy to read exactly as before: same table, command, roles and text.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const postgres = require('postgres');
const { migrate } = require('../scripts/migrate');

const root = path.join(__dirname, '..');
const SERVER = process.env.TEST_DATABASE_URL;
const FNS = 'actor_kind|current_member|current_agent|current_actor_id|is_reviewer';
const WRAPPED = new RegExp('\\(\\s*SELECT (app\\.(?:' + FNS + ')\\(\\)) AS \\w+\\)', 'g');
const BARE = new RegExp('(?<!SELECT )app\\.(?:' + FNS + ')\\(\\)');

async function policies(sql) {
  return sql`select c.relname as tbl, p.polname as name, p.polcmd as cmd, p.polpermissive as permissive,
      array(select r.rolname from pg_roles r where r.oid = any(p.polroles) order by 1)::text as roles,
      coalesce(pg_get_expr(p.polqual, p.polrelid), '') as qual, coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '') as chk
    from pg_policy p join pg_class c on c.oid = p.polrelid join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'app' order by 1, 2`;
}

if (!SERVER) {
  test('policy rewrite tests need TEST_DATABASE_URL', { skip: !process.env.CI && 'set TEST_DATABASE_URL' }, () => { if (process.env.CI) assert.fail('no database'); });
} else {
  const names = ['dog_initplan_a_', 'dog_initplan_b_'].map((p) => p + crypto.randomBytes(4).toString('hex'));
  let server, before, after, upTo019, upTo020;
  const at = (name) => { const u = new URL(SERVER); u.pathname = '/' + name; return u.toString(); };

  test.before(async () => {
    server = postgres(SERVER, { max: 1, onnotice: () => {} });
    for (const n of names) await server.unsafe('create database ' + n);
    // The migrations up to 019 alone, in a directory of their own.
    upTo019 = fs.mkdtempSync(path.join(os.tmpdir(), 'dog-019-'));
    for (const f of fs.readdirSync(path.join(root, 'db', 'migrations'))) {
      if (/^\d{3}_.*\.sql$/.test(f) && Number(f.slice(0, 3)) <= 19) fs.copyFileSync(path.join(root, 'db', 'migrations', f), path.join(upTo019, f));
    }
    // And up to 020, so a later migration that changes a policy on purpose (021's sign-in alert) isn't counted as 020's.
    upTo020 = fs.mkdtempSync(path.join(os.tmpdir(), 'dog-020-'));
    for (const f of fs.readdirSync(path.join(root, 'db', 'migrations'))) {
      if (/^\d{3}_.*\.sql$/.test(f) && Number(f.slice(0, 3)) <= 20) fs.copyFileSync(path.join(root, 'db', 'migrations', f), path.join(upTo020, f));
    }
    before = postgres(at(names[0]), { max: 1, onnotice: () => {} });
    after = postgres(at(names[1]), { max: 1, onnotice: () => {} });
    await migrate(before, { dir: upTo019 });
    await migrate(after, { dir: upTo020 });
  });
  test.after(async () => {
    for (const x of [before, after]) if (x) await x.end({ timeout: 5 });
    if (server) { for (const n of names) await server.unsafe(`drop database if exists ${n} with (force)`); await server.end({ timeout: 5 }); }
    if (upTo019) fs.rmSync(upTo019, { recursive: true, force: true });
    if (upTo020) fs.rmSync(upTo020, { recursive: true, force: true });
  });

  test('R-1: 020 changes nothing in any policy except asking who is acting once per query', async () => {
    const old = await policies(before), now = await policies(after);
    const key = (p) => p.tbl + '.' + p.name;
    assert.deepStrictEqual(now.map(key), old.map(key), 'the same policies, on the same tables');
    let rewritten = 0;
    for (let i = 0; i < old.length; i++) {
      const o = old[i], n = now[i];
      assert.deepStrictEqual([n.cmd, n.permissive, n.roles], [o.cmd, o.permissive, o.roles], key(n) + ': command, kind and roles');
      for (const part of ['qual', 'chk']) {
        if (n[part] !== o[part]) rewritten++;
        // Exact text, brackets included: stripping them would hide a regrouping such as a AND (b OR c) → (a AND b) OR c
        // (PR #49 review). Both databases run on the same server, so both print alike.
        assert.strictEqual(n[part].replace(WRAPPED, '$1'), o[part], key(n) + ' ' + part + ': only the wrapping changed');
        assert.ok(!BARE.test(n[part]), key(n) + ' ' + part + ': no call left that runs once per row');
      }
    }
    assert.ok(rewritten > 40, 'the rewrite reached the policies (' + rewritten + ' expressions)');
  });
}
