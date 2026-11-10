// Second Look v1's runner (034). Since 057 (RISKS.md RK100) Second Look runs in the Supabase function dog-looks, not
// here: the site's database role can no longer claim held posts or record Second Look's decisions (only dog_looks,
// dog-looks's role, can). The timer route (/api/cron, every minute) only asks dog-looks to run, sending the site's own
// Vercel identity token, which dog-looks checks (as the key broker does: our team and project, production only) and uses
// for Vercel's AI Gateway, as the site did. dog-looks claims the next eligible held posts itself (at most 3, at most
// once every 50 seconds, never in off mode), asks the model, decides by code and records the decision; in on mode the
// database publishes a clear. The caller chooses nothing but that Second Look runs now. Every failure leaves the posts
// held for Aaron, as before. The answer is counts only; nothing here is logged.
'use strict';

const FN_URL = 'https://nksagchwpyljvjiwolmp.supabase.co/functions/v1/dog-looks';

// POSTs {look} to dog-looks with the identity token, to its one fixed address, never redirected. Never throws: a
// failure is { failed }.
async function callLooks(look, token, { fetchImpl = (...a) => globalThis.fetch(...a), timeoutMs }) {
  if (typeof token !== 'string' || token.length < 20) return { failed: 'no identity token' };
  try {
    const r = await fetchImpl(FN_URL, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(timeoutMs),
      headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' }, body: JSON.stringify({ look }) });
    if (r.status !== 200) return { failed: 'dog-looks ' + r.status };
    const b = await r.json();
    return b && b.ok === true ? b : { failed: 'dog-looks answer' };
  } catch (e) {
    return { failed: e && (e.name === 'TimeoutError' || e.name === 'AbortError') ? 'timeout' : 'network' };
  }
}

// runTx is no longer used: dog-looks reaches the database itself. Kept so the timer route's call is unchanged.
async function run(runTx, token, { fetchImpl } = {}) {
  return callLooks('second', token, { fetchImpl, timeoutMs: 30_000 });
}

module.exports = { run, callLooks, FN_URL };
