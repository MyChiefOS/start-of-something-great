// dog-looks's work (RISKS.md RK135 and RK100; migration 057), shared by the Supabase function (index.ts) and the tests,
// so the code the tests run is the code production runs. Plain JavaScript, so it runs in Supabase (Deno) and in Node.
//
// Second Look (held posts) and Third Look (finished work) used to run in the site's timer, which claimed the items,
// asked the model and recorded the answers through the site's database role, so whoever held that role could record
// any answer. Now the site's timer only asks this function to run, once a minute for each look, and sends the site's
// Vercel identity token. The token is checked as the key broker checks it (../_shared/vercel-oidc.mjs: Vercel's
// signature, our team and project, production only, not expired). Then, acting as dog_looks inside its own
// transactions, the function claims the next items itself, asks the model itself through Vercel's AI Gateway with the
// same token (the gateway's one fixed address, never redirected: Vercel issued the token and runs the gateway), decides
// by code and records the answer. The caller chooses nothing but which look runs: not the items, not the text, not the
// answer. The database paces each look (at most once every 50 seconds, within its daily cap), so a caller asking more
// often changes nothing.
// No password, key or token is stored anywhere for this; the database login is the one Supabase gives every function,
// and the identity token is used for this request only, never logged or kept.
//
//   POST {"look": "second"} -> {ok, claimed, decided}
//   POST {"look": "third"}  -> {ok, claimed, decided, released}

import * as second from './second.mjs';
import * as third from './third.mjs';

export const MAX_REQUEST = 1024;
export const LOOKS = ['second', 'third'];

export class BadRequest extends Error {}

export function parse(text) {
  if (typeof text !== 'string' || text.length > MAX_REQUEST) throw new BadRequest('request too large');
  let body;
  try { body = JSON.parse(text); } catch { throw new BadRequest('body must be JSON'); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new BadRequest('body must be an object');
  if (Object.keys(body).some((k) => k !== 'look')) throw new BadRequest('body has an unknown field');
  if (!LOOKS.includes(body.look)) throw new BadRequest('look must be second or third');
  return { look: body.look };
}

// One short transaction as dog_looks: no lock is held while a model answers.
const asLooks = (sql, fn) => sql.begin(async (t) => {
  await t`set local role dog_looks`;
  await t`set local statement_timeout = '30s'`;
  return fn(t);
});

// Second Look (034, 041): the next eligible held posts, each put to the model and decided by code; in on mode the
// database publishes a clear. Every failure leaves the post held for Aaron, as before (one try each).
export async function runSecond(sql, token, { fetchImpl, n = 3, now } = {}) {
  const claimed = await asLooks(sql, (t) => t`select * from app.sl_claim(${n})`);
  let decided = 0;
  for (const p of claimed) {
    const r = await second.review({ text: p.body, held: p.held || [], accountDays: p.account_days, signIn: p.sign_in, token, model: p.model, fetchImpl, now });
    try {
      await asLooks(sql, (t) => t`select app.sl_decide(${p.post_id}::uuid, ${r.version}, ${r.model}, ${r.decision},
        ${r.answers ? t.json(r.answers) : null}::jsonb, ${r.risk}, ${r.reason}, ${r.failClosed}, ${r.error}, ${r.latencyMs})`);
      decided++;
    } catch {
      // The post stays held, and is never claimed again (one try each): Aaron decides it as before.
    }
  }
  return { claimed: claimed.length, decided };
}

// Third Look (044 to 057): the next work it may look at, with the changed files GitHub's read gave the GitHub facts
// workflow. A refused or failed model call gives the work back (app.tl_release): its try isn't spent. Anything else is
// recorded; in on mode a pass passes the work.
export async function runThird(sql, token, { fetchImpl, n = 3, now } = {}) {
  const claimed = await asLooks(sql, (t) => t`select * from app.tl_claim(${n})`);
  let decided = 0, released = 0;
  for (const it of claimed) {
    const r = await third.review({ item: { taskTitle: it.task_title, taskDescription: it.task_description, note: it.note, prTitle: it.pr_title },
      files: Array.isArray(it.files) ? it.files : null, token, model: it.model, fetchImpl, now });
    try {
      if (r.release) {
        await asLooks(sql, (t) => t`select app.tl_release(${it.submission_id}::uuid, ${r.release}) as r`);
        released++;
      } else {
        await asLooks(sql, (t) => t`select app.tl_decide(${it.submission_id}::uuid, ${r.version}, ${r.model}::text, ${r.suggestion},
          ${r.answers ? t.json(r.answers) : null}::jsonb, ${r.reason}, ${r.failClosed}, ${r.truncated}, ${r.latencyMs}::integer)`);
        decided++;
      }
    } catch {
      // Not recorded: the claim runs out after 3 minutes and the next claim gives the work back (057). Nothing passes.
    }
  }
  return { claimed: claimed.length, decided, released };
}

// One request: { method, authorization, contentLength, text() } -> { status, body }. db() opens the database only once
// the token has passed (a GET, the daily watch's, opens nothing).
export async function handle(req, { verify, Refused, db, fetchImpl, now }) {
  if (req.method !== 'POST') return { status: 405, body: { ok: false, error: 'POST only' } };
  if (Number(req.contentLength || '0') > MAX_REQUEST) return { status: 413, body: { ok: false, error: 'request too large' } };
  const token = String(req.authorization || '').replace(/^Bearer /, '');
  try {
    const claims = await verify(token);
    if (!claims || typeof claims !== 'object') return { status: 401, body: { ok: false, error: 'refused: no claims' } };
  } catch (e) {
    if (e instanceof Refused) return { status: 401, body: { ok: false, error: 'refused: ' + e.message } };
    throw e;
  }
  let ask;
  try {
    ask = parse(await req.text());
  } catch (e) {
    if (e instanceof BadRequest) return { status: e.message === 'request too large' ? 413 : 400, body: { ok: false, error: e.message } };
    throw e;
  }
  const out = ask.look === 'second' ? await runSecond(db(), token, { fetchImpl, now }) : await runThird(db(), token, { fetchImpl, now });
  return { status: 200, body: { ok: true, ...out } };
}
