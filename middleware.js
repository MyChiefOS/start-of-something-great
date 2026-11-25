// The Agentic Wall's firewall in front of every request (083). Runs on Vercel's Routing Middleware, before any page
// or API code. The decisions are wall/firewall.js (tested there); this file only reads the request, keeps the threat
// list fresh, and answers. Anything that fails here lets the request through: a broken firewall never takes the site
// down (Aaron, Oct 23: "A denial of service against our selves is not the goal").
import { next, ipAddress, geolocation, waitUntil } from '@vercel/functions';
import firewall from './wall/firewall.js';

// Pages and the API; not static files (083 review: assets would count toward the rate limit and cost time each).
export const config = { runtime: 'nodejs', matcher: ['/((?!.*\\.(?:css|js|mjs|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|map|txt|xml|webmanifest)$).*)'] };

// The wiki's threat addresses, from the site's own API, kept for 10 minutes per instance.
const LIST = '/api/work/wall_edge';
// Refreshed in the background (083 review): a request never waits for it; until the first answer the list is empty
// and every rule but the country only logs.
let list = { at: 0, addresses: [], since: null };
function refresh(origin) {
  if (Date.now() - list.at < 600000) return;
  list.at = Date.now();
  waitUntil(fetch(origin + LIST, { headers: { 'x-wall-internal': '1' }, signal: AbortSignal.timeout(3000) })
    .then((r) => (r.status === 200 ? r.json() : null))
    .then((b) => { if (b && Array.isArray(b.addresses)) list = { at: list.at, addresses: b.addresses.slice(0, 100000).map(String), since: b.firewall_since || null }; })
    .catch(() => { /* keep the last list */ }));
}

export default function middleware(request) {
  try {
    const url = new URL(request.url);
    if (url.pathname === LIST) return next();
    const req = { method: request.method, path: url.pathname, query: url.search.slice(1), ua: request.headers.get('user-agent') || '',
      ip: ipAddress(request) || '', country: (geolocation(request) || {}).country || '' };
    refresh(url.origin);
    const d = firewall.decide(req, { badAddresses: list.addresses, since: list.since });
    if (d.action === 'allow') return next();
    // One line per hit for the runtime log and the digest: the rule, what kind, and whether it was enforced. No address
    // or path is written out (people's data stays out of logs).
    console.log(JSON.stringify({ wall: d.rule, kind: d.kind, action: d.action, enforced: d.enforced }));
    if (!d.enforced) return next({ headers: { 'x-wall': d.rule + ' ' + (d.action === 'flag' ? 'flagged' : 'logged') } });
    const body = d.status === 429 ? 'Too many requests. Try again in a minute.\n' : 'Refused by the Agentic Wall (' + d.rule + ').\n';
    return new Response(body, { status: d.status, headers: Object.assign({ 'content-type': 'text/plain; charset=utf-8', 'x-wall': d.rule + ' blocked', 'cache-control': 'no-store' },
      d.status === 429 ? { 'retry-after': '60' } : {}) });
  } catch {
    return next();
  }
}

