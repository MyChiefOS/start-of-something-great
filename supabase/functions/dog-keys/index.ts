// The key broker (route B). Accepts only a production function of one of our own two Vercel projects, the site or,
// since 057, the looks project (Second and Third Look), proved by Vercel's identity token, sent as "Authorization:
// Bearer <token>". The site's token gets the site's login and keys; the looks project's gets its own login only. Deployed from the merged commit with Supabase's own JWT
// check off (supabase/config.toml), like dog-migrate and jevs: it checks its callers itself. Deployed to the preview
// copy's branch too, where it accepts only that project's preview functions and serves only the branch's own values:
// which one it is, it decides once, here, from its own SUPABASE_URL (./target.mjs), never from a request.
// Every answer is never cached. A refusal says which check failed, never anything about the keys. The token is never
// logged or stored.
import postgres from "npm:postgres@3.4.9";
import { Refused, verify } from "../_shared/vercel-oidc.mjs";
import { handle, read } from "./core.mjs";
import { SOURCE_DIGEST } from "./source-digest.mjs";
import { checksFor, target } from "./target.mjs";

const checks = checksFor(target(Deno.env.get("SUPABASE_URL")), { verify, read });

// x-source-digest on every answer (R-3): the SHA-256 digest of this function's source files on the commit it was
// deployed from (./source-digest.mjs), read by the daily watch (.github/workflows/watch.yml).
const reply = (status: number, body: unknown) =>
  Response.json(body, { status, headers: { "Cache-Control": "no-store", "x-source-digest": SOURCE_DIGEST } });

Deno.serve(async (req) => {
  if (Number(req.headers.get("content-length") || "0") > 1024) return reply(413, { ok: false, error: "request too large" });
  const token = (req.headers.get("authorization") || "").replace(/^Bearer /, "");
  let sql: ReturnType<typeof postgres> | null = null;
  try {
    const out = await handle({ method: req.method, token }, {
      // The site's project and, since 057, the looks project (LOOKS_PROJECT_ID; while it is empty, the site's only).
      verify: (t: string) => checks.verify(t, { projects: ["site", "looks"] }),
      Refused,
      values: async (project: string) => {
        sql = postgres(Deno.env.get("SUPABASE_DB_URL")!, { max: 1, prepare: false, idle_timeout: 5, onnotice: () => {} });
        return checks.read(sql, project);
      },
      ref: checks.ref,
      marker: checks.marker,
      // The hour's count of hand-outs or failures (027; migration 027 makes app.broker_note). Counts only.
      note: async (outcome: string) => {
        if (sql) await (sql as ReturnType<typeof postgres>)`select app.broker_note(${outcome})`;
      },
    });
    // Who was answered, for the function's log: the outcome only, never a value.
    console.log(JSON.stringify({ broker: out.status, error: (out.body as { error?: string }).error || null }));
    return reply(out.status, out.body);
  } catch (e) {
    return reply(500, { ok: false, error: "broker failed (" + String((e as { name?: string }).name || "error").slice(0, 32) + ")" });
  } finally {
    if (sql) await (sql as ReturnType<typeof postgres>).end({ timeout: 5 });
  }
});
