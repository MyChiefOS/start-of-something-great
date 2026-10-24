// The JEVs gate (USE-CASES.md row 16): JEVs wrapped around the database. It accepts one caller, the "JEVs" workflow
// (.github/workflows/jevs.yml) running on main, proved by a GitHub identity token, and only for the GitHub events
// that workflow handles. It scores the event in one transaction as dog_jevs and answers with the decision, which the
// workflow carries out on GitHub (a reply to /agent commands, an alert, and in enforce mode hiding a post).
// Deployed from the merged commit with Supabase's own JWT check off (supabase/config.toml), like dog-migrate.
// The site (Vercel) holds no database login; nothing else can write here.
import postgres from "npm:postgres@3.4.9";
import { Refused, verify } from "../_shared/github-oidc.mjs";
import { tokenUsed } from "../dog-migrate/core.mjs";
import { BadEvent, handle } from "./gate.mjs";

const AUDIENCE = "https://nksagchwpyljvjiwolmp.supabase.co/functions/v1/jevs";
// GitHub allows 65,536 characters; in JSON, writing outside Latin script can take up to 6 bytes a character.
const MAX_REQUEST = 400_000;
const reply = (status: number, body: unknown) => Response.json(body, { status });

let hashKey: string | null = null; // read once from Supabase Vault; never logged or returned

Deno.serve(async (req) => {
  if (req.method !== "POST") return reply(405, { ok: false, error: "POST only" });
  if (Number(req.headers.get("content-length") || "0") > MAX_REQUEST) return reply(413, { ok: false, error: "request too large" });
  const sql = postgres(Deno.env.get("SUPABASE_DB_URL")!, { max: 1, prepare: false, idle_timeout: 5, onnotice: () => {} });
  try {
    try {
      await verify((req.headers.get("authorization") || "").replace(/^Bearer /, ""), {
        audience: AUDIENCE,
        workflow: ".github/workflows/jevs.yml",
        events: ["discussion", "discussion_comment"],
        seen: (jti: string) => tokenUsed(sql, jti),
      });
    } catch (e) {
      if (e instanceof Refused) return reply(401, { ok: false, error: "refused: " + e.message });
      throw e;
    }
    const text = await req.text();
    if (text.length > MAX_REQUEST) return reply(413, { ok: false, error: "request too large" });
    let ev;
    try { ev = JSON.parse(text); } catch { return reply(400, { ok: false, error: "body must be JSON" }); }
    if (!hashKey) {
      const [r] = await sql`select decrypted_secret as k from vault.decrypted_secrets where name = 'dog_fingerprint_key_1'`;
      if (!r || !r.k) throw new Error("hash key missing from Vault");
      hashKey = r.k;
    }
    return reply(200, await handle(sql, ev, { key: hashKey! }));
  } catch (e) {
    if (e instanceof BadEvent) return reply(400, { ok: false, error: "bad event: " + e.message });
    // Only the error's kind, never its text: it could carry post content.
    return reply(500, { ok: false, error: "JEVs failed (" + String((e as { code?: string; name?: string }).code || (e as Error).name || "error").slice(0, 32) + ")" });
  } finally {
    await sql.end({ timeout: 5 });
  }
});
