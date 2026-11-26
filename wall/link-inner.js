// The inside of the link sandbox (095; wall/links.js starts it). Runs inside bubblewrap with its own empty network
// namespace: the only way out is the Unix socket /tmp/w/proxy.sock, the outside proxy that lets through HTTPS to the
// submitted host and nothing else. This file forwards 127.0.0.1:18080 to that socket, starts headless Chrome with a
// fresh profile in the sandbox's empty /tmp, downloads denied (and recorded), drives it over its DevTools pipe, and
// prints what the page did as one JSON line: every request and redirect, each response's type, the downloads it tried,
// its forms and its scripts' text (capped). It decides nothing: wall/links.js reads this into the Wall's flags.
//
//   node wall/link-inner.js <chrome binary> <url>
'use strict';

const net = require('net');
const { spawn } = require('child_process');

const PORT = 18080;
const NAV_MS = 15000;
const SETTLE_MS = 2500;
const MAX_SCRIPTS = 12;
const MAX_SCRIPT = 200000;

const log = { ok: false, requests: [], responses: [], downloads: [], failed: [], forms: { password: 0, card: 0 }, scripts: [], final: null, error: null };
const cap = (a, n, x) => { if (a.length < n) a.push(x); };

function forwarder() {
  return new Promise((resolve, reject) => {
    const s = net.createServer((c) => {
      const u = net.connect('/tmp/w/proxy.sock');
      c.pipe(u); u.pipe(c);
      c.on('error', () => u.destroy()); u.on('error', () => c.destroy());
    });
    s.on('error', reject);
    s.listen(PORT, '127.0.0.1', () => resolve(s));
  });
}

async function main(chrome, url) {
  const fw = await forwarder();
  const child = spawn(chrome, ['--headless=new', '--no-sandbox', '--remote-debugging-pipe', '--user-data-dir=/tmp/profile', '--no-first-run',
    '--no-default-browser-check', '--disable-background-networking', '--disable-sync', '--disable-extensions', '--disable-component-update',
    '--disable-default-apps', '--disable-gpu', '--mute-audio', '--disable-dev-shm-usage', '--proxy-server=http://127.0.0.1:' + PORT, '--proxy-bypass-list=<-loopback>',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp', '--disable-features=DnsOverHttps,MediaRouter,OptimizationHints', 'about:blank'],
  { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
  const out = child.stdio[3];
  const inp = child.stdio[4];
  let id = 0;
  const waiting = new Map();
  const handlers = [];
  let buf = '';
  inp.on('data', (d) => {
    buf += d.toString('utf8');
    let at;
    while ((at = buf.indexOf('\0')) >= 0) {
      const msg = buf.slice(0, at); buf = buf.slice(at + 1);
      let m; try { m = JSON.parse(msg); } catch { continue; }
      if (m.id && waiting.has(m.id)) { const w = waiting.get(m.id); waiting.delete(m.id); if (m.error) w.reject(new Error(m.error.message)); else w.resolve(m.result); }
      else if (m.method) for (const h of handlers) h(m);
    }
  });
  const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const n = ++id;
    waiting.set(n, { resolve, reject });
    out.write(JSON.stringify({ id: n, method, params, ...(sessionId ? { sessionId } : {}) }) + '\0');
  });
  let loaded = false;
  const scriptIds = [];
  handlers.push((m) => {
    const p = m.params || {};
    if (m.method === 'Network.requestWillBeSent') {
      cap(log.requests, 300, { url: String(p.request && p.request.url).slice(0, 500), type: p.type || '', from: p.redirectResponse ? String(p.redirectResponse.url).slice(0, 500) : null });
    } else if (m.method === 'Network.responseReceived') {
      const h = (p.response && p.response.headers) || {};
      const disp = Object.keys(h).find((k) => k.toLowerCase() === 'content-disposition');
      cap(log.responses, 300, { url: String(p.response.url).slice(0, 500), status: p.response.status, mime: String(p.response.mimeType || '').slice(0, 100), type: p.type || '', disp: disp ? String(h[disp]).slice(0, 200) : '' });
      if (p.type === 'Script' && scriptIds.length < MAX_SCRIPTS) scriptIds.push({ id: p.requestId, session: m.sessionId });
    } else if (m.method === 'Network.loadingFailed') {
      cap(log.failed, 100, { error: String(p.errorText || '').slice(0, 100), type: p.type || '' });
    } else if (m.method === 'Browser.downloadWillBegin') {
      cap(log.downloads, 20, { url: String(p.url).slice(0, 500), name: String(p.suggestedFilename || '').slice(0, 200) });
    } else if (m.method === 'Page.loadEventFired') loaded = true;
  });
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  try {
    await send('Browser.setDownloadBehavior', { behavior: 'deny', eventsEnabled: true });
    const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
    await send('Network.enable', {}, sessionId);
    await send('Page.enable', {}, sessionId);
    await send('Page.navigate', { url }, sessionId).catch((e) => { log.error = String(e.message).slice(0, 100); });
    for (let t = 0; t < NAV_MS && !loaded; t += 200) await sleep(200);
    await sleep(SETTLE_MS);
    const r = await send('Runtime.evaluate', { returnByValue: true, expression: `(() => {
      const ins = [...document.querySelectorAll('input')];
      const card = ins.filter((i) => /cc-(number|csc|exp)/.test(i.autocomplete || '') || /card.?num|cvv|cvc|ccnum/i.test((i.name || '') + ' ' + (i.id || '') + ' ' + (i.placeholder || ''))).length;
      return { href: location.href, password: ins.filter((i) => i.type === 'password').length, card,
        inline: [...document.scripts].filter((s) => !s.src).slice(0, ${MAX_SCRIPTS}).map((s) => s.text.slice(0, ${MAX_SCRIPT})) };
    })()` }, sessionId).catch(() => null);
    const v = r && r.result && r.result.value;
    if (v) {
      log.final = String(v.href).slice(0, 500);
      log.forms = { password: Number(v.password) || 0, card: Number(v.card) || 0 };
      for (const s of v.inline || []) cap(log.scripts, MAX_SCRIPTS * 2, String(s));
    }
    for (const s of scriptIds) {
      const b = await send('Network.getResponseBody', { requestId: s.id }, s.session).catch(() => null);
      if (b && typeof b.body === 'string' && !b.base64Encoded) cap(log.scripts, MAX_SCRIPTS * 2, b.body.slice(0, MAX_SCRIPT));
    }
    log.ok = true;
    await send('Browser.close').catch(() => {});
  } catch (e) {
    log.error = String((e && e.message) || e).slice(0, 100);
  }
  child.kill('SIGKILL');
  fw.close();
  process.stdout.write(JSON.stringify(log));
  process.exit(0);
}

if (require.main === module) {
  const [chrome, url] = process.argv.slice(2);
  main(chrome, url).catch((e) => { log.error = String((e && e.message) || e).slice(0, 100); process.stdout.write(JSON.stringify(log)); process.exit(0); });
}
