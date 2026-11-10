// dog-github's work (RISKS.md RK140; migration 055), shared by the Supabase function (index.ts) and the tests, so the
// code the tests run is the code production runs. Plain JavaScript, so it runs in Supabase (Deno) and in Node.
//
// It accepts one caller: the "GitHub facts" workflow (.github/workflows/github-facts.yml) running on main of this
// repository, proved by a GitHub identity token, for the events that workflow runs on. The token is checked by the same
// code as the database runner's and the JEVs gate's (../_shared/github-oidc.mjs: GitHub's signature, the issuer, the
// audience, its age, the repository and its owner by number, main, the exact workflow file, the event, and one use
// only), and, beyond it, the repository's name. Then, acting as dog_ghsync inside its own transaction (as the JEVs gate
// acts as dog_jevs), it either answers which merged pull requests the database wants GitHub's read of, or records the
// facts the workflow read from GitHub. No password, key or token is stored anywhere for this; the database login is
// the one Supabase gives every function. Answers carry counts and pull request numbers only.
//
//   POST {"mode": "wanted"}                                   -> {ok, wanted: [numbers]}
//   POST {"mode": "sync", "facts": {prs, issues, details, refused}} -> {ok, prs, tasks, closed}

export const AUDIENCE = 'https://nksagchwpyljvjiwolmp.supabase.co/functions/v1/dog-github';
export const WORKFLOW = '.github/workflows/github-facts.yml';
// pull_request_target, not pull_request: a pull_request run's token names the pull request's own ref and its own copy
// of the workflow, which the check refuses (and must). pull_request_target runs main's workflow file, on main.
export const EVENTS = ['pull_request_target', 'issues', 'schedule', 'workflow_dispatch'];
export const REPOSITORY = 'MyChiefOS/start-of-something-great';
// 100 pull requests with up to 20 claim codes each, 100 issues and 20 details fit well inside this.
export const MAX_REQUEST = 400_000;
const LISTS = ['prs', 'issues', 'details'];

export class BadRequest extends Error {}

// The token's claims if every check passes; throws Refused (from the shared check) otherwise, naming the first failure.
export async function checkToken(token, { verify, Refused, seen, keys, now }) {
  const claims = await verify(token, { audience: AUDIENCE, workflow: WORKFLOW, events: EVENTS, seen, keys, now });
  if (claims.repository !== REPOSITORY) throw new Refused('wrong repository name');
  return claims;
}

// The request body, checked: its shape only (the database checks every field again).
export function parse(text) {
  if (typeof text !== 'string' || text.length > MAX_REQUEST) throw new BadRequest('request too large');
  let body;
  try { body = JSON.parse(text); } catch { throw new BadRequest('body must be JSON'); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new BadRequest('body must be an object');
  if (body.mode === 'wanted') return { mode: 'wanted' };
  if (body.mode !== 'sync') throw new BadRequest('mode must be wanted or sync');
  const f = body.facts;
  if (!f || typeof f !== 'object' || Array.isArray(f)) throw new BadRequest('facts must be an object');
  if (Object.keys(f).some((k) => !LISTS.includes(k) && k !== 'refused')) throw new BadRequest('facts has an unknown field');
  for (const k of LISTS) {
    if (f[k] === undefined) continue;
    if (!Array.isArray(f[k]) || f[k].length > 100 || f[k].some((x) => !x || typeof x !== 'object' || Array.isArray(x))) {
      throw new BadRequest(k + ' must be a list of at most 100 objects');
    }
  }
  if (f.refused !== undefined && !(Number.isSafeInteger(f.refused) && f.refused >= 0 && f.refused <= 999)) throw new BadRequest('refused must be a count');
  return { mode: 'sync', facts: { prs: f.prs || [], issues: f.issues || [], details: f.details || [], refused: f.refused || 0 } };
}

// As dog_ghsync, in one transaction each. The functions themselves refuse any other role (055).
export async function wanted(sql) {
  return sql.begin(async (t) => {
    await t`set local role dog_ghsync`;
    await t`set local statement_timeout = '30s'`;
    const rows = await t`select number from app.work_github_wanted(20)`;
    return rows.map((r) => r.number);
  });
}
export async function sync(sql, facts) {
  return sql.begin(async (t) => {
    await t`set local role dog_ghsync`;
    await t`set local statement_timeout = '60s'`;
    const [r] = await t`select app.work_github_sync(${t.json(facts)}::jsonb) as r`;
    return r.r;
  });
}

// One request: { method, authorization, contentLength, text() } -> { status, body }. db() opens the database only once
// the token has passed (a GET, the daily watch's, opens nothing).
export async function handle(req, { verify, Refused, seen, db, keys, now }) {
  if (req.method !== 'POST') return { status: 405, body: { ok: false, error: 'POST only' } };
  if (Number(req.contentLength || '0') > MAX_REQUEST) return { status: 413, body: { ok: false, error: 'request too large' } };
  try {
    await checkToken(String(req.authorization || '').replace(/^Bearer /, ''), { verify, Refused, seen, keys, now });
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
  if (ask.mode === 'wanted') return { status: 200, body: { ok: true, wanted: await wanted(db()) } };
  try {
    const r = await sync(db(), ask.facts);
    return { status: 200, body: { ok: true, prs: r.prs, tasks: r.tasks, closed: r.closed } };
  } catch (e) {
    // The database's own check of the facts (22023) or of a field's type (22P02, 22007, 22008): the request was wrong.
    if (e && ['22023', '22P02', '22007', '22008'].includes(e.code)) return { status: 400, body: { ok: false, error: 'bad facts (' + e.code + ')' } };
    throw e;
  }
}
