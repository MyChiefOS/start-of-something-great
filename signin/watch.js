// The JEVs behaviour watch's web indicators (Aaron, Oct 29; 030), at every signed-in request: whether the session moved
// to another browser or country, travel too fast to be possible, an unusual hour, and an unusual number of requests.
// The database decides and alerts Aaron; this file only turns the request into keyed hashes and a sealed place. Alerts
// only: nothing here can fail, slow much or refuse a request, and a failure is logged without any detail of who.
//   * Browser kind: its name and system only ("firefox/windows"), never the user-agent string or its version, keyed
//     with the first fingerprint key and the member's ID, as 026 keys countries.
//   * Place: the host's estimate of the network's location (x-vercel-ip-latitude and -longitude), rounded to whole
//     degrees (about 100 km), sealed with AES-256-GCM under a key derived from the first fingerprint key, so the
//     database holds only text it can't read. Kept by the database at most a day (030's sweep).
'use strict';

const crypto = require('crypto');
const c = require('./crypto');
const config = require('./config');
const region = require('./region');
const store = require('../db/signin');

// The first fingerprint key (FINGERPRINT_KEY_1, from the key broker under route B), or null when sign-in is off.
function key(env = process.env) {
  const keys = config.keysFromEnv(env);
  const k = keys && keys.find((x) => x.version === 1);
  return k ? k.key : null;
}
const placeKey = (k) => crypto.createHmac('sha256', k).update('watch-place v1', 'utf8').digest();

// A browser's name and system, from its user-agent; null when there is none.
function family(ua) {
  const s = String(ua || '').slice(0, 512);
  if (!s.trim()) return null;
  const browser = /\bEdg(?:e|A|iOS)?\//.test(s) ? 'edge' : /\bOPR\/|\bOpera\b/.test(s) ? 'opera'
    : /\bFirefox\/|\bFxiOS\//.test(s) ? 'firefox' : /\bChrome\/|\bCriOS\/|\bChromium\//.test(s) ? 'chrome'
    : /\bSafari\//.test(s) ? 'safari' : /^(?:curl|Wget|python|Python|node|Go-http-client|axios|okhttp|Java)\b/.test(s) ? 'script' : 'other';
  const os = /\bWindows\b/.test(s) ? 'windows' : /\b(?:iPhone|iPad|iPod)\b/.test(s) ? 'ios' : /\bAndroid\b/.test(s) ? 'android'
    : /\bCrOS\b/.test(s) ? 'chromeos' : /\bMac OS X\b|\bMacintosh\b/.test(s) ? 'mac' : /\bLinux\b/.test(s) ? 'linux' : 'other';
  return browser + '/' + os;
}

// The request's place, rounded to whole degrees; null when the host gave none.
function place(req) {
  const hd = (req && req.headers) || {};
  const la = Number(hd['x-vercel-ip-latitude']), lo = Number(hd['x-vercel-ip-longitude']);
  if (hd['x-vercel-ip-latitude'] === undefined || hd['x-vercel-ip-longitude'] === undefined) return null;
  if (!Number.isFinite(la) || !Number.isFinite(lo) || Math.abs(la) > 90 || Math.abs(lo) > 180) return null;
  return { la: Math.round(la), lo: Math.round(lo) };
}

// Great-circle distance in km (haversine).
function km(a, b) {
  const r = (d) => (d * Math.PI) / 180;
  const dla = r(b.la - a.la), dlo = r(b.lo - a.lo);
  const x = Math.sin(dla / 2) ** 2 + Math.cos(r(a.la)) * Math.cos(r(b.la)) * Math.sin(dlo / 2) ** 2;
  return 2 * 6371 * Math.asin(Math.min(1, Math.sqrt(x)));
}

const isPlace = (p) => p && Number.isInteger(p.la) && Number.isInteger(p.lo) && Math.abs(p.la) <= 90 && Math.abs(p.lo) <= 180;

// The error's code only (a database error code, or 'error'): never its message, which could name a value.
function logFailure(e) {
  const code = e && typeof e.code === 'string' && /^[A-Z0-9_]{1,20}$/.test(e.code) ? e.code : 'error';
  console.error('JEVs: behaviour watch failed (' + code + ')');
}

// Inside the transaction that resolved the session (each step in its own savepoint, so a failure undoes only itself).
async function request(t, req, sessionHash, memberId, k = key()) {
  if (!k || !sessionHash || !memberId) return;
  try {
    const fam = family(req && req.headers ? req.headers['user-agent'] : null);
    const country = region.country(req);
    const out = await t.savepoint((x) => store.watchSession(x, { sessionHash,
      ua: fam ? c.hmacHex(k, 'watch-ua:' + memberId + ':' + fam) : null,
      country: country ? c.hmacHex(k, 'watch-country:' + memberId + ':' + country) : null }));
    if (!out || !out.place) return;
    const here = place(req);
    const prev = typeof out.place.sealed === 'string' ? out.place.sealed : null;
    const before = prev ? c.open(placeKey(k), prev) : null;
    const dist = here && isPlace(before) ? Math.min(25000, Math.round(km(before, here))) : null;
    await t.savepoint((x) => store.watchTravel(x, { sessionHash, place: here ? c.seal(placeKey(k), here) : null,
      km: dist, prev: dist === null ? null : prev }));
  } catch (e) {
    logFailure(e);
  }
}

module.exports = { key, family, place, km, request };
