// dog-migrate v3: the only way the database changes (USE-CASES.md row 15). It accepts one caller: the "Database
// migrations" workflow (.github/workflows/database.yml) running on main, proved by a GitHub identity token. It then
// applies the files of the exact commit that token names, fetched from the public repository. No password, key or
// token is stored anywhere for this; the database login is the one Supabase gives every function.
// Deployed once per change from the merged commit (OPERATIONS.md records each deploy). The work is in core.mjs.
//
//   POST {"mode": "apply"}   apply the merged commit (reset first, if its manifest says so)
//   POST {"mode": "status"}  the live ledger, for the drift check
import postgres from "npm:postgres@3.4.9";
import { Refused, verify } from "../_shared/github-oidc.mjs";
import { load, run, status, tokenSeen } from "./core.mjs";

const AUDIENCE = "https://nksagchwpyljvjiwolmp.supabase.co/functions/v1/dog-migrate";
const RAW = "https://raw.githubusercontent.com/MyChiefOS/start-of-something-great/";
const reply = (status: number, body: unknown) => Response.json(body, { status });

Deno.serve(async (req) => {
  if (req.method !== "POST") return reply(405, { ok: false, error: "POST only" });
  if (Number(req.headers.get("content-length") || "0") > 1024) return reply(413, { ok: false, error: "request too large" });
  let mode = "apply";
  try {
    const body = await req.json();
    if (body && (body.mode === "apply" || body.mode === "status")) mode = body.mode;
    else return reply(400, { ok: false, error: "mode must be apply or status" });
  } catch {
    return reply(400, { ok: false, error: "body must be JSON" });
  }

  const notices: string[] = [];
  const sql = postgres(Deno.env.get("SUPABASE_DB_URL")!, {
    max: 1, prepare: false, idle_timeout: 5,
    onnotice: (n: { message?: string }) => { if (notices.length < 20) notices.push(String(n.message || "").slice(0, 200)); },
  });
  try {
    const auth = req.headers.get("authorization") || "";
    let claims;
    try {
      claims = await verify(auth.replace(/^Bearer /, ""), {
        audience: AUDIENCE,
        workflow: ".github/workflows/database.yml",
        events: ["push", "workflow_dispatch"],
        seen: (jti: string) => tokenSeen(sql, jti),
      });
    } catch (e) {
      if (e instanceof Refused) return reply(401, { ok: false, error: "refused: " + e.message });
      throw e;
    }
    if (mode === "status") return reply(200, { ok: true, ledger: await status(sql) });

    const fetchText = async (path: string) => {
      const r = await fetch(RAW + claims.sha + "/" + path, { redirect: "error" });
      if (!r.ok) throw new Error(path + ": fetch " + r.status);
      return r.text();
    };
    const result = await run(sql, await load(fetchText), claims);
    return reply(result.ok ? 200 : 500, { ...result, notices });
  } catch (e) {
    return reply(500, { ok: false, error: String((e as Error).message).slice(0, 300), notices });
  } finally {
    await sql.end({ timeout: 5 });
  }
});
