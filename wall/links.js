// The Agentic Wall's link sandbox (095; Aaron, Nov 24: the oversight diagram's "sandboxed penetration tester", "no
// cutting corners"; Nov 26: "I should only look at high risk cases after several reviews and sandbox testing"). Each
// link submitted for work and not yet decided is opened in headless Chrome inside bubblewrap, in GitHub's own runner:
// a fresh profile in an empty /tmp (nothing kept), the disk read-only, no environment, its own network namespace with
// no network. Its only way out is a Unix socket to the proxy below, which lets through HTTPS (CONNECT to port 443) to
// the submitted link's own host and nothing else, and never to a private, local or cloud-metadata address (checked on
// the address the name resolves to, so a name can't point it inside). Downloads are denied and recorded. What the page
// did (wall/link-inner.js's log, and what the proxy refused) is read here into the Wall's flags:
//
//   W51   block  the page started a download of a program or installer on its own; it loads a crypto-miner; or it
//                tried to reach a cloud-metadata address
//   W51b  flag   it started a download of an archive or disk image; it redirected to a different site; it has a
//                password or payment-card form; its scripts hide code (eval of decoded text, a packer); it tried to
//                reach a private or local address; or it could not be opened
//
// The hosts and addresses it reached or tried go to the database too, where the security wiki's threat lists are
// checked against them (W28 blocks, W28b flags, as for any link). The run happens in its own job of the facts workflow,
// which holds no identity token, no write permission and no secret. No regular expressions read the page's text (as 083).
'use strict';

const fs = require('fs');
const os = require('os');
const net = require('net');
const dns = require('dns');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const TIME_LIMIT = 40;
const MAX_LINKS = 5;
const MAX_BYTES = 20 * 1024 * 1024;
const EXEC = ['exe', 'msi', 'scr', 'com', 'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'jse', 'wsf', 'hta', 'jar', 'apk', 'dmg', 'pkg', 'deb', 'rpm', 'appimage', 'elf', 'bin', 'run', 'sh', 'lnk', 'cpl', 'dll', 'msix', 'appx', 'xap', 'ipa'];
const EXEC_MIME = ['application/x-msdownload', 'application/x-msdos-program', 'application/x-dosexec', 'application/x-executable', 'application/x-elf',
  'application/vnd.microsoft.portable-executable', 'application/x-msi', 'application/x-ms-installer', 'application/java-archive', 'application/vnd.android.package-archive',
  'application/x-apple-diskimage', 'application/x-sh', 'application/x-shellscript', 'application/hta'];
const ARCHIVE = ['zip', 'rar', '7z', 'iso', 'img', 'vhd', 'vhdx', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'cab', 'arj', 'lzh', 'ace', 'zst'];
const ARCHIVE_MIME = ['application/zip', 'application/x-zip-compressed', 'application/x-rar-compressed', 'application/vnd.rar', 'application/x-7z-compressed',
  'application/x-iso9660-image', 'application/x-tar', 'application/gzip', 'application/x-gzip', 'application/vnd.ms-cab-compressed'];
const MINERS = ['coinhive', 'coin-hive', 'cryptonight', 'cryptoloot', 'crypto-loot', 'coinimp', 'webminepool', 'minero.cc', 'jsecoin', 'deepminer', 'monerominer',
  'webmine.pro', 'stratum+tcp://', 'stratum+ssl://', 'coinhive.anonymous', 'cryptonight_hash', 'miner.start(', 'nfwebminer', 'browsermine'];
const HIDDEN = ['eval(atob(', 'eval(unescape(', 'eval(decodeuricomponent(', 'eval(string.fromcharcode(', 'function(atob(', 'new function(atob(',
  'document.write(unescape(', 'document.write(atob(', 'eval(function(p,a,c,k,e,', 'settimeout(atob(', 'eval(window.atob('];
// Two-label public suffixes common enough to matter for "the same site" (a full public suffix list is not shipped).
const SUFFIX2 = ['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'edu.au', 'co.jp', 'ne.jp', 'or.jp', 'co.nz', 'com.br', 'co.in',
  'co.za', 'com.mx', 'com.cn', 'com.tw', 'co.kr', 'com.sg', 'com.tr', 'github.io', 'gitlab.io', 'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev',
  'herokuapp.com', 'blogspot.com', 'appspot.com', 'web.app', 'firebaseapp.com', 'cloudfront.net', 'azurewebsites.net', 'onrender.com', 'fly.dev', 'glitch.me', 'replit.app'];

const add = (flags, code, why, label) => {
  const t = (code + ' link sandbox: ' + why + ': ' + label).slice(0, 240);
  if (flags.length < 10 && !flags.includes(t)) flags.push(t);
};

function hostOf(u) { try { return new URL(u).hostname.toLowerCase().replace(/^\[|\]$/g, ''); } catch { return ''; } }

// The site a host belongs to: its last two labels, or three under a two-label suffix. An address is its own site.
function siteOf(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h || net.isIP(h)) return h;
  const p = h.split('.');
  if (p.length <= 2) return h;
  return SUFFIX2.includes(p.slice(-2).join('.')) ? p.slice(-3).join('.') : p.slice(-2).join('.');
}

// 'metadata', 'private' (local, private, link-local, shared, multicast, reserved) or '' for an ordinary public address.
function addressKind(addr) {
  const a = String(addr || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (a === '169.254.169.254' || a === '169.254.170.2' || a === 'fd00:ec2::254' || a === '100.100.100.200' || a === '168.63.129.16') return 'metadata';
  if (net.isIPv4(a)) {
    const [x, y] = a.split('.').map(Number);
    if (x === 0 || x === 10 || x === 127 || x >= 224 || (x === 169 && y === 254) || (x === 172 && y >= 16 && y <= 31) || (x === 192 && y === 168)
      || (x === 100 && y >= 64 && y <= 127) || (x === 192 && y === 0) || (x === 198 && (y === 18 || y === 19))) return 'private';
    return '';
  }
  if (net.isIPv6(a)) {
    // An IPv4 address written as IPv6 (mapped, in dotted or hex form, or NAT64 64:ff9b::/96): judge the IPv4 inside.
    const v4in = (tail) => {
      if (net.isIPv4(tail)) return tail;
      const h = tail.split(':');
      if (h.length !== 2 || !h.every((x) => /^[0-9a-f]{1,4}$/.test(x))) return '';
      const n = h.map((x) => parseInt(x, 16));
      return [n[0] >> 8, n[0] & 255, n[1] >> 8, n[1] & 255].join('.');
    };
    for (const p of ['::ffff:', '64:ff9b::', '::']) {
      if (a.startsWith(p) && a !== '::' && a !== '::1') { const v = v4in(a.slice(p.length)); if (v) return addressKind(v) || (p === '::' ? 'private' : ''); }
    }
    // 6to4 (2002::/16) and Teredo (2001:0::/32) carry an IPv4 address the proxy can't judge: refused.
    if (a.startsWith('2002:') || /^2001:0?:/.test(a)) return 'private';
    if (a === '::' || a === '::1' || a.startsWith('fc') || a.startsWith('fd') || a.startsWith('fe8') || a.startsWith('fe9') || a.startsWith('fea') || a.startsWith('feb') || a.startsWith('ff')) return 'private';
    return '';
  }
  return '';
}

// A name that is itself local or metadata, before any lookup.
function nameKind(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (h === 'metadata.google.internal' || h === 'metadata' || h === 'instance-data' || h === 'instance-data.ec2.internal') return 'metadata';
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.internal') || h.endsWith('.local') || h.endsWith('.lan') || h.endsWith('.home.arpa')) return 'private';
  return net.isIP(h) ? addressKind(h) : '';
}

function extOf(name) {
  const n = String(name || '').toLowerCase().split('?')[0].split('#')[0];
  const base = n.slice(n.lastIndexOf('/') + 1);
  return base.includes('.') ? base.slice(base.lastIndexOf('.') + 1) : '';
}
function dispName(d) {
  const s = String(d || '');
  const i = s.toLowerCase().indexOf('filename');
  if (i < 0) return '';
  return s.slice(s.indexOf('=', i) + 1).split(';')[0].trim().replace(/^utf-8''/i, '').replace(/^"|"$/g, '');
}

// What the page did, read into flags, and the hosts and links it reached or tried (for the threat lists).
// log: wall/link-inner.js's output; proxy: [{ host, port, refused }] from the proxy; url: the submitted link.
function analyze(log, proxy, url) {
  const flags = [];
  const label = String(url || '').slice(0, 120);
  const L = log && typeof log === 'object' ? log : {};
  const start = siteOf(hostOf(url));
  const seen = new Set([String(url || '').slice(0, 500)]);
  const looks = (code, why) => add(flags, code, why, label);
  // Downloads: what Chrome tried to save (denied), and any response that would have been one.
  const dls = [];
  for (const d of Array.isArray(L.downloads) ? L.downloads : []) dls.push({ name: String(d.name || '') || String(d.url || ''), mime: '', url: String(d.url || '') });
  for (const r of Array.isArray(L.responses) ? L.responses : []) {
    const disp = String(r.disp || '').toLowerCase();
    if (disp.startsWith('attachment') || (r.type === 'Document' && (EXEC_MIME.includes(String(r.mime)) || ARCHIVE_MIME.includes(String(r.mime))))) {
      dls.push({ name: dispName(r.disp) || String(r.url || ''), mime: String(r.mime || ''), url: String(r.url || '') });
    }
  }
  for (const d of dls) {
    const e = extOf(d.name);
    if (EXEC.includes(e) || EXEC_MIME.includes(d.mime)) looks('W51', 'started a download of a program (' + (e || d.mime).slice(0, 30) + ')');
    else if (ARCHIVE.includes(e) || ARCHIVE_MIME.includes(d.mime)) looks('W51b', 'started a download of an archive (' + (e || d.mime).slice(0, 30) + ')');
    else looks('W51b', 'started a download (' + (e || d.mime || 'unknown type').slice(0, 30) + ')');
  }
  // Redirects and navigations to another site, and every host it asked for.
  for (const r of Array.isArray(L.requests) ? L.requests : []) {
    const u = String(r.url || '');
    if (!u.startsWith('http')) continue;
    if (seen.size < 50) seen.add(u.slice(0, 500));
    if (r.type === 'Document' && siteOf(hostOf(u)) !== start) looks('W51b', 'redirected to a different site (' + hostOf(u).slice(0, 80) + ')');
    const k = nameKind(hostOf(u));
    if (k === 'metadata') looks('W51', 'tried to reach a cloud-metadata address (' + hostOf(u).slice(0, 60) + ')');
    else if (k === 'private') looks('W51b', 'tried to reach a private or local address (' + hostOf(u).slice(0, 60) + ')');
  }
  if (L.final && siteOf(hostOf(L.final)) !== start && String(L.final).startsWith('http')) looks('W51b', 'redirected to a different site (' + hostOf(L.final).slice(0, 80) + ')');
  for (const p of Array.isArray(proxy) ? proxy : []) {
    const h = String(p.host || '').toLowerCase();
    if (seen.size < 50 && h) seen.add(h.slice(0, 255));
    if (p.refused === 'metadata') looks('W51', 'tried to reach a cloud-metadata address (' + h.slice(0, 60) + ')');
    else if (p.refused === 'private') looks('W51b', 'tried to reach a private or local address (' + h.slice(0, 60) + ')');
  }
  // Forms that ask for a password or a payment card.
  const f = L.forms || {};
  if (Number(f.password) > 0) looks('W51b', 'has a password form');
  if (Number(f.card) > 0) looks('W51b', 'has a payment-card form');
  // Scripts: a miner, or code hidden behind decoding.
  for (const s of Array.isArray(L.scripts) ? L.scripts.slice(0, 30) : []) {
    const t = String(s).slice(0, 400000).toLowerCase().split(' ').join('').split('\n').join('').split('\t').join('');
    const m = MINERS.find((x) => t.includes(x.split(' ').join('')));
    if (m) looks('W51', 'loads a crypto-miner (' + m + ')');
    const h = HIDDEN.find((x) => t.includes(x));
    if (h) looks('W51b', 'hides code (' + h.slice(0, 30) + ')');
  }
  // 094 review: a link that isn't https on port 443, or that the proxy refused to reach, wasn't really opened.
  let target = null;
  try { target = new URL(String(url || '')); } catch { target = null; }
  if (!target || target.protocol !== 'https:' || (target.port && target.port !== '443')) looks('W51b', 'could not be opened (not https on port 443)');
  else {
    const refused = (Array.isArray(proxy) ? proxy : []).find((e) => e && e.refused && String(e.host) === target.hostname.toLowerCase().replace(/^\[|\]$/g, ''));
    if (refused) looks(refused.refused === 'metadata' ? 'W51' : 'W51b', (refused.refused === 'metadata' ? 'reached for a cloud-metadata address' : 'could not be opened (' + String(refused.refused).slice(0, 30) + ')'));
  }
  if (!L.ok) looks('W51b', 'could not be opened (' + String(L.error || 'no answer').slice(0, 40) + ')');
  return { flags, seen: [...seen].slice(0, 50) };
}

// The proxy: HTTPS (CONNECT to port 443) to the allowed host only, and only to a public address. Every request it sees
// is recorded in events, refused or not. Listens on a Unix socket (the sandbox's only way out).
function proxy(sock, allowed, events, { lookup = dns.lookup } = {}) {
  let bytes = 0;
  const server = net.createServer((c) => {
    c.setTimeout(TIME_LIMIT * 1000, () => c.destroy());
    c.on('error', () => {});
    let head = Buffer.alloc(0);
    const onData = (d) => {
      head = Buffer.concat([head, d]);
      const end = head.indexOf('\r\n\r\n');
      if (end < 0) { if (head.length > 8192) c.destroy(); return; }
      c.removeListener('data', onData);
      const line = head.subarray(0, head.indexOf('\r\n')).toString('latin1').split(' ');
      const rest = head.subarray(end + 4);
      const refuse = (host, port, why) => { if (events.length < 200) events.push({ host, port, refused: why }); c.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'); };
      if (line[0] !== 'CONNECT') return refuse(hostOf(line[1] || ''), 80, 'not https');
      const target = String(line[1] || '');
      const at = target.lastIndexOf(':');
      const host = target.slice(0, at).toLowerCase().replace(/^\[|\]$/g, '');
      const port = Number(target.slice(at + 1));
      const nk = nameKind(host);
      if (nk) return refuse(host, port, nk);
      if (port !== 443) return refuse(host, port, 'not https');
      if (host !== allowed) return refuse(host, port, 'another host');
      lookup(host, { all: true }, (err, list) => {
        const addrs = Array.isArray(list) ? list.map((x) => x.address) : [];
        if (err || !addrs.length) return refuse(host, port, 'no address');
        const bad = addrs.map(addressKind).find(Boolean);
        if (bad) return refuse(host, port, bad);
        if (events.length < 200) events.push({ host, port, refused: '' });
        const u = net.connect(443, addrs[0], () => {
          c.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          if (rest.length) u.write(rest);
          const count = (x) => { bytes += x.length; if (bytes > MAX_BYTES) { u.destroy(); c.destroy(); } };
          u.on('data', count);
          c.pipe(u); u.pipe(c);
        });
        u.setTimeout(TIME_LIMIT * 1000, () => u.destroy());
        u.on('error', () => c.destroy());
        c.on('close', () => u.destroy());
      });
    };
    c.on('data', onData);
  });
  return new Promise((resolve) => server.listen(sock, () => resolve(server)));
}

// Chrome on this machine: the runner's own, or one the workflow installed (WALL_CHROME).
function chromePath(env = process.env) {
  for (const p of [env.WALL_CHROME, '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser']) {
    if (p && fs.existsSync(p)) return p;
  }
  return null;
}
function available(env = process.env) {
  return spawnSync('bwrap', ['--version'], { encoding: 'utf8' }).status === 0 && Boolean(chromePath(env));
}

// Opens one link in the sandbox and returns { flags, seen }. dir: a folder for its run. The proxy allows exactly the
// link's own host. open: what Chrome opens, for the tests only (a data: page standing in for the link, no network).
async function runOne(dir, url, { env = process.env, lookup, open } = {}) {
  const label = String(url || '').slice(0, 120);
  let host = '';
  try { const u = new URL(url); if (u.protocol === 'https:' || u.protocol === 'http:') host = u.hostname.toLowerCase().replace(/^\[|\]$/g, ''); } catch { host = ''; }
  if (!host) return { flags: [('W51b link sandbox: could not be opened (not a web link): ' + label).slice(0, 240)], seen: [] };
  const chrome = chromePath(env);
  if (!chrome || spawnSync('bwrap', ['--version']).status !== 0) return { flags: [('W51b link sandbox: could not be opened (sandbox not installed): ' + label).slice(0, 240)], seen: [String(url).slice(0, 500)] };
  const work = fs.mkdtempSync(path.join(dir, 'link-'));
  const events = [];
  const server = await proxy(path.join(work, 'proxy.sock'), host, events, lookup ? { lookup } : {});
  // The inside script goes into the run's own folder: the sandbox hides /home, where the checkout is.
  fs.copyFileSync(path.join(__dirname, 'link-inner.js'), path.join(work, 'inner.js'));
  const args = ['--ro-bind', '/', '/', '--tmpfs', '/tmp', '--tmpfs', '/home', '--tmpfs', '/root', '--tmpfs', '/run', '--dev', '/dev', '--tmpfs', '/dev/shm', '--proc', '/proc',
    '--bind', work, '/tmp/w', '--chdir', '/tmp/w', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
    '--setenv', 'PATH', '/usr/local/bin:/usr/bin:/bin', '--setenv', 'HOME', '/home/x', process.execPath, '/tmp/w/inner.js', chrome, String(open || url)];
  const text = await new Promise((resolve) => {
    const p = spawn('timeout', ['--kill-after=3', String(TIME_LIMIT), 'bwrap', ...args], { stdio: ['ignore', 'pipe', 'ignore'] });
    let o = '';
    p.stdout.on('data', (d) => { if (o.length < 4 << 20) o += d.toString('utf8'); });
    p.on('close', () => resolve(o));
    p.on('error', () => resolve(''));
  });
  server.close();
  let log = null;
  try { log = JSON.parse(text); } catch { log = { ok: false, error: 'no answer from the sandbox' }; }
  return analyze(log, events, url);
}

// The link sandbox job (github-facts.yml): the links dog-github listed ([{ id, url }], at most MAX_LINKS), each opened
// here. Prints { id: { flags, seen } } and nothing else.
async function links(list, { dir, env = process.env } = {}) {
  const out = {};
  for (const x of (Array.isArray(list) ? list : []).slice(0, MAX_LINKS)) {
    if (!x || typeof x.id !== 'string' || !/^[0-9a-f-]{36}$/.test(x.id) || typeof x.url !== 'string' || x.url.length > 2000) continue;
    try { out[x.id] = await runOne(dir, x.url, { env }); } catch { out[x.id] = { flags: [('W51b link sandbox: could not be opened (run failed): ' + x.url).slice(0, 240)], seen: [x.url.slice(0, 500)] }; }
  }
  return out;
}

if (require.main === module) {
  let list = [];
  try { list = JSON.parse(process.env.WALL_LINKS_WANTED || '[]'); } catch { list = []; }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsx-'));
  links(list, { dir }).then((o) => process.stdout.write(JSON.stringify(o))).catch(() => process.stdout.write('{}'));
}

module.exports = { analyze, proxy, runOne, links, available, chromePath, siteOf, addressKind, nameKind, TIME_LIMIT, MAX_LINKS, EXEC, ARCHIVE, MINERS, HIDDEN };
