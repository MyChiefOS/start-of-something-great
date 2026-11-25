// The Agentic Wall's firewall in front of every request (083). Runs on Vercel's Routing Middleware, before any page
// or API code. The decisions are wall/firewall.js (tested there); this file only reads the request, keeps the threat
// list fresh, and answers. Anything that fails here lets the request through: a broken firewall never takes the site
// down (Aaron, Oct 23: "A denial of service against our selves is not the goal").
import { next, ipAddress, geolocation } from '@vercel/functions';
import firewall from './wall/firewall.js';

export const config = { runtime: 'nodejs' };

// The wiki's threat addresses, from the site's own API, kept for 10 minutes per instance.
const LIST = '/api/work/wall_edge';
let list = { at: 0, addresses: [] };
async function addresses(origin) {
  if (Date.now() - list.at < 600000) return list.addresses;
  list.at = Date.now();
  try {
    const r = await fetch(origin + LIST, { headers: { 'x-wall-internal': '1' }, signal: AbortSignal.timeout(1500) });
    if (r.status === 200) { const b = await r.json(); if (Array.isArray(b.addresses)) list.addresses = b.addresses.slice(0, 100000).map(String); }
  } catch { /* keep the last list */ }
  return list.addresses;
}

export default async function middleware(request) {
  try {
    const url = new URL(request.url);
    if (url.pathname === LIST) return next();
    const req = { method: request.method, path: url.pathname, query: url.search.slice(1), ua: request.headers.get('user-agent') || '',
      ip: ipAddress(request) || '', country: (geolocation(request) || {}).country || '' };
    const d = firewall.decide(req, { badAddresses: await addresses(url.origin) });
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

