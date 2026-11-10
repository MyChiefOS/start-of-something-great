// dog-copy: the preview copy's rebuild (RK141; design/preview-copy.md, "Building and reseeding the copy"). Deployed
// ONLY to the one Supabase preview branch, never to production (Aaron, Nov 10: production carries none of the copy's
// code; its runner, dog-migrate, is main's own). It accepts one caller: .github/workflows/preview-copy.yml on main, by a
// push or by hand, proved by a GitHub identity token addressed to this function at the branch's own address. Then it
// empties the copy, applies every migration of the merged commit with the runner's own code (../dog-migrate/core.mjs,
// unchanged) and reseeds it with made-up data (../_shared/preview-seed.mjs), all in one transaction (./copy.mjs).
// Which database it serves is decided once, here, from its own SUPABASE_URL (./target.mjs), never from a request; on
// production's address it refuses everything. Deployed with Supabase's own JWT check off (supabase/config.toml), as the
// runner is: GitHub's token is not a Supabase token, and this code does the checking. Every answer carries
// x-source-digest (./source-digest.mjs, R-3).
import postgres from "npm:postgres@3.4.9";
import { Refused, verify } from "../_shared/github-oidc.mjs";
import { load } from "../dog-migrate/core.mjs";
import { handleCopy } from "./copy.mjs";
import { SOURCE_DIGEST } from "./source-digest.mjs";
import { target } from "./target.mjs";

const RAW = "https://raw.githubusercontent.com/MyChiefOS/start-of-something-great/";
const reply = (status: number, body: unknown) => Response.json(body, { status, headers: { "x-source-digest": SOURCE_DIGEST } });
const where = target(Deno.env.get("SUPABASE_URL"));

Deno.serve(async (req) => {
  if (req.method !== "POST") return reply(405, { ok: false, error: "POST only" });
  if (Number(req.headers.get("content-length") || "0") > 1024) return reply(413, { ok: false, error: "request too large" });
  if (where.environment !== "preview") return reply(404, { ok: false, error: "not the preview copy" });
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return reply(400, { ok: false, error: "body must be JSON" });
  }
  const notices: string[] = [];
  const sql = postgres(Deno.env.get("SUPABASE_DB_URL")!, {
    max: 1, prepare: false, idle_timeout: 5,
    onnotice: (n: { message?: string }) => { if (notices.length < 20) notices.push(String(n.message || "").slice(0, 200)); },
  });
  try {
    const out = await handleCopy({ body, token: (req.headers.get("authorization") || "").replace(/^Bearer /, "") }, {
      where, sql, verify, Refused,
      load: (commit: string) => load(async (path: string) => {
        const r = await fetch(RAW + commit + "/" + path, { redirect: "error" });
        if (!r.ok) throw new Error(path + ": fetch " + r.status);
        return r.text();
      }),
    });
    return reply(out.status, { ...out.body, notices });
  } catch (e) {
    return reply(500, { ok: false, error: String((e as Error).message).slice(0, 300), notices });
  } finally {
    await sql.end({ timeout: 5 });
  }
});
