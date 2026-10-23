// One-time migration runner for the Day One Great database (GATEWAY.md; Aaron's approval, Oct 23, 2026).
// Does what scripts/migrate.js does, inside Supabase: each migration file is fetched from the public repository
// at one fixed commit, must match its SHA-256 below, and is applied in its own transaction under an advisory lock,
// then recorded in app.schema_migrations. Already-applied files are skipped (and must match). Running it again
// changes nothing. It returns only version names and counts: no data, no settings, no secrets.
import postgres from "npm:postgres@3.4.9";

const COMMIT = "9b1fcd769075033092c07d14fe668a11dac55a09";
const FILES: [string, string][] = [["001_foundation", "58d9bba8a8703bb3220b2e164e90bf616c67ead7315498038275a82afef4f737"], ["002_signin", "f26d977343fb773b68122832eedf46f36fcd9cabd86ee31fda45df3d8b964408"], ["003_posts", "ba4b47b5bc286ba4789dc468b24ba5c13fe31db13ca029d4b35c8a579b850c53"], ["004_review", "61ab05faf7c62770b57c26c1889f70ba4e7e71854c4ced57cf80f99e4d027ae9"], ["005_agents", "d33e71eff1e4cd68d39336af1e99e6ef1151e05263b9723e7f7e803b0bd210c8"], ["006_owner_controls", "5806d73e03a4ec2f7ed565544178c040ba246db30cddc4516b5c93a71fae454c"], ["007_account_deletion", "f5b0b58c269b605ee3811caee224e98b56da946cafe8bcd552d40e508941d28f"], ["008_delegated_agency", "3a29442e8021cbc9b929cae288b2a1238dda46cfa5efffcb640f29980780968e"], ["009_fresh_delete", "0f5d32eb8ff295c0c1a09e310d5eb498133fe78b6fb37bc0b1cc5b4b2ff77001"], ["010_jevs", "157d8fc66017e22898a985eb0923f89a7976696006ba877d3aa8a7521a461d59"], ["011_notifications", "9316ac0072037444de2667a348d9da6d8b5548d44f2dc405e5352b72c90316a4"], ["012_signin_fixes", "3291f5ccb763ef43f296bfb126337cb948cb2b036a5446145f28796d0d745acb"], ["013_setup_audit", "957e455c3a78a2f8010718ead0a24db2123f660677ecbbf0fa17bf852fb1f12f"], ["014_passkeys", "56e45811f334653cbd3cd40f10dd840f525c60e8758e852dc89fa99803c14854"], ["015_subagents", "58a93e2138dae621ef702e5ae59829b01b80a65859a85cac10e2b09e753f0f2e"], ["016_security_batch1", "1d601b0350c012e412da19c46c07e8b784d5c0f3fa508359a2f58b6d50c5b403"], ["017_gateway", "923890f214d3b2e5097e780596c48f42fc0ad84c1aa7c152249ae41f9a3176aa"]];
const RAW = "https://raw.githubusercontent.com/MyChiefOS/start-of-something-great/" + COMMIT + "/db/migrations/";

async function sha256(text: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return new Response("POST only", { status: 405 });
  const sql = postgres(Deno.env.get("SUPABASE_DB_URL")!, { max: 1, prepare: false, onnotice: () => {} });
  const applied: string[] = [];
  try {
    for (const [version, want] of FILES) {
      const r = await fetch(RAW + version + ".sql");
      if (!r.ok) throw new Error(version + ": fetch " + r.status);
      const text = await r.text();
      if (await sha256(text) !== want) throw new Error(version + ": fingerprint does not match");
      const ran = await sql.begin(async (t) => {
        await t`select pg_advisory_xact_lock(hashtext('dayonegreat.migrate'))`;
        const [{ exists }] = await t`select to_regclass('app.schema_migrations') is not null as exists`;
        if (exists) {
          await t`set local role dog_owner`;
          const have = await t`select sha256 from app.schema_migrations where version = ${version}`;
          await t`reset role`;
          if (have.length) {
            if (have[0].sha256 !== want) throw new Error(version + " changed after it was applied");
            return false;
          }
        }
        await t.unsafe(text);
        await t`set local role dog_owner`;
        await t`insert into app.schema_migrations (version, sha256) values (${version}, ${want})`;
        return true;
      });
      if (ran) applied.push(version);
    }
    return Response.json({ ok: true, commit: COMMIT, applied, total: FILES.length });
  } catch (e) {
    return Response.json({ ok: false, error: String((e as Error).message).slice(0, 300), applied }, { status: 500 });
  } finally {
    await sql.end({ timeout: 5 });
  }
});
