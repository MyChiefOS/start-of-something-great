// dog-looks (RISKS.md RK135 and RK100; migration 057): Second Look and Third Look, run here instead of in the site, so
// the site's database role can no longer record their answers. It accepts one caller, a production function of our own
// Vercel project, proved by Vercel's identity token (the key broker's check, ../_shared/vercel-oidc.mjs), and uses the
// same token for Vercel's AI Gateway. It claims, asks and records as dog_looks, the one role that may. The work is in
// core.mjs.
// Deployed from the merged commit with Supabase's own JWT check OFF (supabase/config.toml), like dog-keys: Vercel's
// token is not a Supabase token, so that check would refuse it before this code runs. This code does the checking.
// Every answer carries x-source-digest: the SHA-256 digest of this function's source files on the commit it was
// deployed from (./source-digest.mjs, written by scripts/function-digests.js), read by the daily watch
// (.github/workflows/watch.yml). It logs nothing, and never the token.
import postgres from "npm:postgres@3.4.9";
import { Refused, verify } from "../_shared/vercel-oidc.mjs";
import { handle } from "./core.mjs";
import { SOURCE_DIGEST } from "./source-digest.mjs";

const reply = (status: number, body: unknown) => Response.json(body, { status, headers: { "Cache-Control": "no-store", "x-source-digest": SOURCE_DIGEST } });

Deno.serve(async (req) => {
  let sql: ReturnType<typeof postgres> | null = null;
  const db = () => (sql ??= postgres(Deno.env.get("SUPABASE_DB_URL")!, { max: 1, prepare: false, idle_timeout: 5, onnotice: () => {} }));
  try {
    const out = await handle(
      { method: req.method, authorization: req.headers.get("authorization"), contentLength: req.headers.get("content-length"), text: () => req.text() },
      { verify: (t: string) => verify(t), Refused, db },
    );
    return reply(out.status, out.body);
  } catch (e) {
    // Only the error's kind, never its text.
    return reply(500, { ok: false, error: "dog-looks failed (" + String((e as { code?: string; name?: string }).code || (e as Error).name || "error").slice(0, 32) + ")" });
  } finally {
    if (sql) await (sql as ReturnType<typeof postgres>).end({ timeout: 5 });
  }
});
