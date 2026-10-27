// The site's key broker (route B). Accepts only a production function of our own Vercel project, proved by Vercel's
// identity token, sent as "Authorization: Bearer <token>". Deployed from the merged commit with Supabase's own JWT
// check off (supabase/config.toml), like dog-migrate and jevs: it checks its callers itself.
// Every answer is never cached. A refusal says which check failed, never anything about the keys. The token is never
// logged or stored.
import postgres from "npm:postgres@3.4.9";
import { Refused, verify } from "../_shared/vercel-oidc.mjs";
import { handle, read } from "./core.mjs";

const reply = (status: number, body: unknown) =>
  Response.json(body, { status, headers: { "Cache-Control": "no-store" } });

Deno.serve(async (req) => {
  if (Number(req.headers.get("content-length") || "0") > 1024) return reply(413, { ok: false, error: "request too large" });
  const token = (req.headers.get("authorization") || "").replace(/^Bearer /, "");
  let sql: ReturnType<typeof postgres> | null = null;
  try {
    const out = await handle({ method: req.method, token }, {
      verify: (t: string) => verify(t),
      Refused,
      values: async () => {
        sql = postgres(Deno.env.get("SUPABASE_DB_URL")!, { max: 1, prepare: false, idle_timeout: 5, onnotice: () => {} });
        return read(sql);
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
