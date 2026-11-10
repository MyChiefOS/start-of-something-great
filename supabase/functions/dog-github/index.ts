// dog-github (RISKS.md RK140; migration 055): GitHub's facts about this repository's pull requests and issues, from
// GitHub only. It accepts one caller, the "GitHub facts" workflow (.github/workflows/github-facts.yml) running on main,
// proved by a GitHub identity token, and records what that workflow read from GitHub's API as dog_ghsync, the one role
// that may. The site's role can't. The work is in core.mjs.
// Deployed from the merged commit with Supabase's own JWT check OFF (supabase/config.toml), like dog-migrate and jevs:
// GitHub's token is not a Supabase token, so that check would refuse it before this code runs. This code does the checking.
// Every answer carries x-source-digest: the SHA-256 digest of this function's source files on the commit it was
// deployed from (./source-digest.mjs, written by scripts/function-digests.js), read by the daily watch
// (.github/workflows/watch.yml). It logs nothing.
import postgres from "npm:postgres@3.4.9";
import { Refused, verify } from "../_shared/github-oidc.mjs";
import { tokenUsed } from "../dog-migrate/core.mjs";
import { handle } from "./core.mjs";
import { SOURCE_DIGEST } from "./source-digest.mjs";

const reply = (status: number, body: unknown) => Response.json(body, { status, headers: { "Cache-Control": "no-store", "x-source-digest": SOURCE_DIGEST } });

Deno.serve(async (req) => {
  let sql: ReturnType<typeof postgres> | null = null;
  const db = () => (sql ??= postgres(Deno.env.get("SUPABASE_DB_URL")!, { max: 1, prepare: false, idle_timeout: 5, onnotice: () => {} }));
  try {
    const out = await handle(
      { method: req.method, authorization: req.headers.get("authorization"), contentLength: req.headers.get("content-length"), text: () => req.text() },
      { verify, Refused, seen: (jti: string) => tokenUsed(db(), jti), db },
    );
    return reply(out.status, out.body);
  } catch (e) {
    // Only the error's kind, never its text.
    return reply(500, { ok: false, error: "dog-github failed (" + String((e as { code?: string; name?: string }).code || (e as Error).name || "error").slice(0, 32) + ")" });
  } finally {
    if (sql) await (sql as ReturnType<typeof postgres>).end({ timeout: 5 });
  }
});
