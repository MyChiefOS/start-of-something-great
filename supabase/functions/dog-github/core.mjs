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
// Since 057 (RK112, RK135, RK144) the same facts also carry the changed files of the pull requests Third Look wants to
// read (recorded with app.tl_files_record) and Aaron's proposal decisions as GitHub's labels show them
// (app.log_proposals_record), both as dog_ghsync; and the public log's witness workflow (.github/workflows/log-witness.yml)
// reports its own result here, proved the same way by its own token, recorded as dog_witness. Each workflow may ask
// only for its own modes: a token from the witness can't send facts, and one from the facts workflow can't report
// the witness.
//
//   github-facts.yml: POST {"mode": "wanted"}  -> {ok, wanted: [numbers], files: [numbers]}
//                     POST {"mode": "sync", "facts": {prs, issues, details, refused, files, proposals}}
//                                              -> {ok, prs, tasks, closed, files, proposals}
//   log-witness.yml:  POST {"mode": "witness", "report": {size, root, at, alarm}} -> {ok, status}

export const AUDIENCE = 'https://nksagchwpyljvjiwolmp.supabase.co/functions/v1/dog-github';
export const WORKFLOW = '.github/workflows/github-facts.yml';
// pull_request_target, not pull_request: a pull_request run's token names the pull request's own ref and its own copy
// of the workflow, which the check refuses (and must). pull_request_target runs main's workflow file, on main.
export const EVENTS = ['pull_request_target', 'issues', 'schedule', 'workflow_dispatch'];
export const WITNESS_WORKFLOW = '.github/workflows/log-witness.yml';
export const WITNESS_EVENTS = ['schedule', 'workflow_dispatch'];
// Each workflow this function accepts, the events it runs on, and the modes it may ask for.
export const WORKFLOWS = {
  [WORKFLOW]: { events: EVENTS, modes: ['wanted', 'sync'] },
  [WITNESS_WORKFLOW]: { events: WITNESS_EVENTS, modes: ['witness'] }
};
export const REPOSITORY = 'MyChiefOS/start-of-something-great';
// 100 pull requests with up to 20 claim codes each, 100 issues, 20 details, 100 proposals and the changed files of up
// to 5 pull requests (at most 100,000 bytes each, the database's limit) fit inside this.
export const MAX_REQUEST = 1_000_000;
const LISTS = ['prs', 'issues', 'details', 'files', 'proposals'];
const LIMITS = { prs: 100, issues: 100, details: 100, files: 10, proposals: 100 };

export class BadRequest extends Error {}

// Which of the accepted workflows the token says it comes from, read before the check so the check is made against
// that workflow's own file and events: the witness's when the token names it, the facts workflow's otherwise (so any
// other token gets the shared check's usual first refusal). Nothing is trusted from this read: the shared check then
// verifies the signature and that exact workflow_ref.
function claimedWorkflow(token) {
  try {
    const part = String(token || '').split('.')[1];
    const bin = atob(part.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((part.length + 3) % 4));
    const ref = String(JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)))).workflow_ref || '');
    if (ref.startsWith(REPOSITORY + '/' + WITNESS_WORKFLOW + '@')) return WITNESS_WORKFLOW;
  } catch { /* not readable: the shared check refuses it */ }
  return WORKFLOW;
}

// The token's claims, with the workflow they were checked against, if every check passes; throws Refused (from the
// shared check) otherwise, naming the first failure.
export async function checkToken(token, { verify, Refused, seen, keys, now }) {
  const workflow = claimedWorkflow(token);
  const claims = await verify(token, { audience: AUDIENCE, workflow, events: WORKFLOWS[workflow].events, seen, keys, now });
  if (claims.repository !== REPOSITORY) throw new Refused('wrong repository name');
  return { ...claims, checked_workflow: workflow };
}

// The request body, checked: its shape only (the database checks every field again).
export function parse(text) {
  if (typeof text !== 'string' || text.length > MAX_REQUEST) throw new BadRequest('request too large');
  let body;
  try { body = JSON.parse(text); } catch { throw new BadRequest('body must be JSON'); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new BadRequest('body must be an object');
  if (body.mode === 'wanted') return { mode: 'wanted' };
  if (body.mode === 'witness') return { mode: 'witness', report: witnessReport(body.report) };
  if (body.mode !== 'sync') throw new BadRequest('mode must be wanted, sync or witness');
  const f = body.facts;
  if (!f || typeof f !== 'object' || Array.isArray(f)) throw new BadRequest('facts must be an object');
  if (Object.keys(f).some((k) => !LISTS.includes(k) && k !== 'refused')) throw new BadRequest('facts has an unknown field');
  for (const k of LISTS) {
    if (f[k] === undefined) continue;
    if (!Array.isArray(f[k]) || f[k].length > LIMITS[k] || f[k].some((x) => !x || typeof x !== 'object' || Array.isArray(x))) {
      throw new BadRequest(k + ' must be a list of at most ' + LIMITS[k] + ' objects');
    }
  }
  if (f.refused !== undefined && !(Number.isSafeInteger(f.refused) && f.refused >= 0 && f.refused <= 999)) throw new BadRequest('refused must be a count');
  return { mode: 'sync', facts: { prs: f.prs || [], issues: f.issues || [], details: f.details || [], refused: f.refused || 0 },
    files: f.files || [], proposals: f.proposals || [] };
}

// The witness's result (tools/verify/witness.mjs's state.json, as the log-witness workflow just recorded it): its last
// good checkpoint's size and root (32 bytes, base64), when it ran, and its alarm if it raised one.
function witnessReport(r) {
  if (!r || typeof r !== 'object' || Array.isArray(r)) throw new BadRequest('report must be an object');
  if (Object.keys(r).some((k) => !['size', 'root', 'at', 'alarm'].includes(k))) throw new BadRequest('report has an unknown field');
  const size = r.size == null ? null : r.size;
  if (size !== null && !(Number.isSafeInteger(size) && size > 0)) throw new BadRequest('size must be a positive whole number');
  const root = r.root == null ? null : r.root;
  if (root !== null && !(typeof root === 'string' && /^[A-Za-z0-9+/]{43}=$/.test(root))) throw new BadRequest('root must be 32 bytes in base64');
  if ((size === null) !== (root === null)) throw new BadRequest('size and root come together');
  if (typeof r.at !== 'string' || r.at.length > 40 || Number.isNaN(Date.parse(r.at))) throw new BadRequest('at must be a time');
  const alarm = r.alarm == null ? null : r.alarm;
  if (alarm !== null && !(typeof alarm === 'string' && alarm.length >= 1 && alarm.length <= 300)) throw new BadRequest('alarm must be text of at most 300 characters');
  return { size, root, at: new Date(r.at).toISOString(), alarm };
}

// As dog_ghsync, in one transaction each. The functions themselves refuse any other role (055).
export async function wanted(sql) {
  return sql.begin(async (t) => {
    await t`set local role dog_ghsync`;
    await t`set local statement_timeout = '30s'`;
    const rows = await t`select number from app.work_github_wanted(20)`;
    const files = await t`select number from app.tl_files_wanted(5)`;
    return { wanted: rows.map((r) => r.number), files: files.map((r) => r.number) };
  });
}
export async function sync(sql, facts, { files = [], proposals = [] } = {}) {
  return sql.begin(async (t) => {
    await t`set local role dog_ghsync`;
    await t`set local statement_timeout = '60s'`;
    const [r] = await t`select app.work_github_sync(${t.json(facts)}::jsonb) as r`;
    const [f] = await t`select app.tl_files_record(${t.json(files)}::jsonb) as n`;
    const [p] = await t`select app.log_proposals_record(${t.json(proposals)}::jsonb) as n`;
    return { ...r.r, files: f.n, proposals: p.n };
  });
}
// As dog_witness: the witness's own result. Returns the log's witness status.
export async function witness(sql, report) {
  return sql.begin(async (t) => {
    await t`set local role dog_witness`;
    await t`set local statement_timeout = '30s'`;
    const root = report.root === null ? null : Uint8Array.from(atob(report.root), (c) => c.charCodeAt(0));
    const [r] = await t`select app.log_witness_report(${report.size}, ${root}, ${report.at}::timestamptz, ${report.alarm}) as s`;
    return r.s;
  });
}

// One request: { method, authorization, contentLength, text() } -> { status, body }. db() opens the database only once
// the token has passed (a GET, the daily watch's, opens nothing).
export async function handle(req, { verify, Refused, seen, db, keys, now }) {
  if (req.method !== 'POST') return { status: 405, body: { ok: false, error: 'POST only' } };
  if (Number(req.contentLength || '0') > MAX_REQUEST) return { status: 413, body: { ok: false, error: 'request too large' } };
  let claims;
  try {
    claims = await checkToken(String(req.authorization || '').replace(/^Bearer /, ''), { verify, Refused, seen, keys, now });
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
  // Each workflow only for its own modes.
  if (!WORKFLOWS[claims.checked_workflow].modes.includes(ask.mode)) return { status: 403, body: { ok: false, error: 'not for this workflow' } };
  if (ask.mode === 'wanted') return { status: 200, body: { ok: true, ...(await wanted(db())) } };
  try {
    if (ask.mode === 'witness') return { status: 200, body: { ok: true, status: await witness(db(), ask.report) } };
    const r = await sync(db(), ask.facts, { files: ask.files, proposals: ask.proposals });
    return { status: 200, body: { ok: true, prs: r.prs, tasks: r.tasks, closed: r.closed, files: r.files, proposals: r.proposals } };
  } catch (e) {
    // The database's own check of the facts (22023) or of a field's type (22P02, 22007, 22008): the request was wrong.
    if (e && ['22023', '22P02', '22007', '22008'].includes(e.code)) return { status: 400, body: { ok: false, error: 'bad facts (' + e.code + ')' } };
    throw e;
  }
}
