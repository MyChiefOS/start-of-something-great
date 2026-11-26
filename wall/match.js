// The firewall's attack checks without regular expressions (Aaron, Nov 25: "Rewrite without regex", after the
// scanner's ReDoS finding on #157). Every check is a single pass, or a bounded number of passes, over a capped string,
// so no input can make one slow (CWE-1333).
//
// 087 (Aaron, Nov 26: catch "permutations of that attack"): input is cleaned first (wall/normalize.js undoes stacked
// encodings, entities, look-alike letters, hidden characters, escapes), then each check runs on three views of it
// (comments as spaces, comments removed, and a shell view with quotes and $IFS undone). The checks match the shape of
// an attack, not one sample: a keyword pair with anything between, any shell command behind any separator, any tag
// with any handler, any Log4Shell lookup however nested.
'use strict';

const norm = require('./normalize');

const isWordChar = (c) => (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c === '_';
const isDigit = (c) => c >= '0' && c <= '9';
const isLetter = (c) => c >= 'a' && c <= 'z';
const skipSpace = (s, i) => { while (s[i] === ' ') i++; return i; };
function wordFrom(s, i) { let j = i; while (j < s.length && isWordChar(s[j])) j++; return s.slice(i, j); }

// Kept for callers that fold one string (083's interface): clean, then the spaced view.
function fold(input, max) { return norm.views(norm.clean(input, max)).spaced; }

// Every position where word w starts as a whole word.
function wordAt(s, w) {
  const at = [];
  let i = s.indexOf(w);
  while (i !== -1 && at.length < 200) {
    const before = i === 0 ? '' : s[i - 1];
    const after = s[i + w.length] || '';
    if (!isWordChar(before) && !isWordChar(after)) at.push(i);
    i = s.indexOf(w, i + 1);
  }
  return at;
}
const hasWord = (s, w) => wordAt(s, w).length > 0;

// ---- SQL injection ----
const SQL_TIME = ['sleep', 'benchmark', 'pg_sleep', 'randomblob', 'dbms_lock.sleep', 'dbms_pipe.receive_message'];
const SQL_STACK = ['drop', 'truncate', 'shutdown', 'exec', 'execute', 'insert', 'update', 'delete', 'alter', 'create', 'grant', 'declare', 'rename', 'replace', 'merge', 'call', 'copy', 'load_file'];
function sql(s) {
  // UNION [ALL|DISTINCT] SELECT ... FROM, or UNION SELECT with a column list of nulls or numbers (no FROM needed).
  for (const u of wordAt(s, 'union')) {
    let i = skipSpace(s, u + 5);
    while (s[i] === '(') i = skipSpace(s, i + 1);
    for (const m of ['all', 'distinct']) if (s.startsWith(m, i) && !isWordChar(s[i + m.length] || '')) i = skipSpace(s, i + m.length);
    while (s[i] === '(') i = skipSpace(s, i + 1);
    if (s.startsWith('select', i) && !isWordChar(s[i + 6] || '')) {
      const tail = s.slice(i + 6, i + 300);
      const amp = tail.indexOf('&');
      const t = amp === -1 ? tail : tail.slice(0, amp);
      if (hasWord(t, 'from') || hasWord(t, 'null') || t.trimStart().startsWith('1,') || t.includes('@@') || hasWord(t, 'version') || hasWord(t, 'user') || hasWord(t, 'database')
        || t.includes('concat(') || t.includes('group_concat') || t.includes('char(') || t.includes('0x')) return true;
    }
  }
  // A quote closing a value, then OR/AND/|| and a comparison that is always true: ' or 1=1, ') and 'a'='a, " or true,
  // ' or 2>1, ' || 1=1, ' or 'x' like 'x'.
  for (const q of ["'", '"', '`']) {
    let at = s.indexOf(q);
    let n = 0;
    while (at !== -1 && n++ < 200) {
      let i = at + 1;
      while (s[i] === ' ' || s[i] === ')' || s[i] === '(') i++;
      let w = wordFrom(s, i);
      if (!w && s.startsWith('||', i)) w = '||';
      if (!w && s.startsWith('&&', i)) w = '&&';
      if (['or', 'and', 'xor', '||', '&&', 'having', 'where'].includes(w)) {
        i += w.length;
        while (s[i] === ' ' || s[i] === '(' || s[i] === 'n' && s.startsWith('not ', i) && (i += 3)) i++;
        const rest = s.slice(i, i + 60);
        if (rest.startsWith('true') || rest.startsWith('1 ') || rest === '1' || rest.startsWith('1--') || rest.startsWith('1#')) return true;
        if (tautology(rest)) return true;
      }
      // A quote then a comment that ends the query: admin'-- , admin'#, admin'/*
      let k = at + 1; while (s[k] === ' ' || s[k] === ')') k++;
      if ((s.startsWith('--', k) || s[k] === '#' || s.startsWith(';--', k)) && at > 0 && isWordChar(s[at - 1])) return true;
      at = s.indexOf(q, at + 1);
    }
  }
  // The same after a closing bracket or a number (no quote needed): 1) || ('a'='a, 5 or 2>1, id=1 and 1=1, 1)(or true.
  const ops = [];
  for (const w of ['or', 'and', 'xor']) for (const at of wordAt(s, w)) ops.push([at, w.length]);
  for (const w of ['||', '&&']) { let at = s.indexOf(w); let k = 0; while (at !== -1 && k++ < 100) { ops.push([at, 2]); at = s.indexOf(w, at + 2); } }
  for (const [at, len] of ops.slice(0, 300)) {
    let b = at - 1; while (b >= 0 && (s[b] === ' ' || s[b] === '(')) b--;
    const prev = s[b] || '';
    if (prev === ')' || isDigit(prev) || prev === "'" || prev === '"') {
      let i = at + len;
      while (s[i] === ' ' || s[i] === '(') i++;
      if (s.startsWith('not ', i)) i = skipSpace(s, i + 4);
      const rest = s.slice(i, i + 60);
      if (rest.startsWith('true') || tautology(rest)) return true;
    }
  }
  // Stacked queries: ; then a statement keyword.
  let semi = s.indexOf(';'); let n = 0;
  while (semi !== -1 && n++ < 200) {
    let i = skipSpace(s, semi + 1);
    while (s[i] === '(') i = skipSpace(s, i + 1);
    const w = wordFrom(s, i);
    const after = s[i + w.length];
    if (SQL_STACK.includes(w) && (after === ' ' || after === '(' || after === ';' || after === undefined || after === '-' || after === '#' || after === '?' || after === '&')) {
      const tail = s.slice(i, i + 80);
      if (w !== 'update' && w !== 'delete' && w !== 'insert' && w !== 'create' && w !== 'replace' && w !== 'call' && w !== 'copy' && w !== 'rename') return true;
      if (hasWord(tail, 'set') || hasWord(tail, 'from') || hasWord(tail, 'into') || hasWord(tail, 'table') || hasWord(tail, 'user') || hasWord(tail, 'program')) return true;
    }
    semi = s.indexOf(';', semi + 1);
  }
  // Timing and file functions with an argument: sleep(5), pg_sleep (10), benchmark(1e6,...), waitfor delay '0:0:5'.
  for (const f of SQL_TIME) {
    let at = s.indexOf(f); let k = 0;
    while (at !== -1 && k++ < 100) {
      if (at === 0 || !isWordChar(s[at - 1])) {
        let i = skipSpace(s, at + f.length);
        if (s[i] === '(') { i = skipSpace(s, i + 1); if (isDigit(s[i] || '') || s[i] === "'" || s[i] === '(') return true; }
      }
      at = s.indexOf(f, at + 1);
    }
  }
  for (const at of wordAt(s, 'waitfor')) { const i = skipSpace(s, at + 7); if (s.startsWith('delay', i) || s.startsWith('time', i)) return true; }
  // Catalog reads and dangerous procedures.
  return ['information_schema', 'xp_cmdshell', 'sp_executesql', 'pg_catalog', 'sqlite_master', 'mysql.user', 'sys.objects', 'load_file', 'into outfile', 'into dumpfile', 'utl_http', 'dbms_xmlquery']
    .some((w) => (w.includes(' ') || w.includes('.') ? s.includes(w) : hasWord(s, w)));
}
// x=x, 'a'='a', 2>1, 1 like 1, 'x' in ('x'): two equal literals on either side of a comparison.
function tautology(rest) {
  let i = 0;
  const lit = () => {
    const q = rest[i];
    if (q === "'" || q === '"') {
      // The last literal may be left open on purpose (' or '1'='1): the application's own closing quote ends it.
      let e = rest.indexOf(q, i + 1); if (e === -1) { e = i + 1; while (e < rest.length && e - i <= 20 && !' &)"}],;#-?'.includes(rest[e])) e++; }
      if (e - i > 21) return null; const v = rest.slice(i + 1, e); i = Math.min(e + 1, rest.length); return v;
    }
    let j = i; while (j < rest.length && (isDigit(rest[j]) || rest[j] === '.')) j++;
    if (j === i) return null;
    const v = rest.slice(i, j); i = j; return v;
  };
  const a = lit(); if (a === null) return false;
  i = skipSpace(rest, i);
  let op = '';
  for (const o of ['==', '=', '<=>', '>=', '<=', '>', '<', 'like ', 'is ', 'in ']) if (rest.startsWith(o, i)) { op = o.trim(); i += o.length; break; }
  if (!op) return false;
  i = skipSpace(rest, i);
  if (rest[i] === '(') i = skipSpace(rest, i + 1);
  const b = lit(); if (b === null) return false;
  if (op === '>' || op === '<' || op === '>=' || op === '<=') return Number(a) !== Number(b) || op.includes('=');
  return a === b;
}

// ---- Cross-site scripting ----
const TAGS = ['script', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet', 'svg', 'math', 'img', 'image', 'body', 'video', 'audio', 'source', 'track', 'details',
  'marquee', 'input', 'form', 'button', 'select', 'textarea', 'keygen', 'isindex', 'link', 'meta', 'base', 'style', 'xss', 'a', 'div', 'span', 'table', 'td', 'animate', 'set', 'template', 'noscript', 'portal'];
// on<letters> = somewhere in t, as an attribute (after a space, a / or a quote).
function handlerIn(t) {
  let i = t.indexOf('on'); let n = 0;
  while (i !== -1 && n++ < 200) {
    const before = i === 0 ? ' ' : t[i - 1];
    if (!isWordChar(before) || before === '/') {
      let j = i + 2; let k = 0;
      while (isLetter(t[j] || '') && k < 30) { j++; k++; }
      if (k > 2 && t[skipSpace(t, j)] === '=') return true;
    }
    i = t.indexOf('on', i + 1);
  }
  return false;
}
// A script URL, with whitespace or controls inside the scheme removed (java\tscript:, jav&#x09;ascript:).
function scriptUrl(s) {
  const compact = s.split(' ').join('').split('\t').join('');
  for (const scheme of ['javascript:', 'vbscript:', 'livescript:', 'data:text/html', 'data:image/svg+xml', 'data:application/x-javascript']) {
    let at = compact.indexOf(scheme); let n = 0;
    while (at !== -1 && n++ < 50) {
      if (scheme.startsWith('data:')) return true;
      const tail = compact.slice(at + scheme.length, at + scheme.length + 120);
      // A call, an assignment or a template call anywhere in what follows: alert(1), alert`1`, top['al'+'ert'](1), x=1.
      if (tail.includes('(') || tail.includes('`') || tail.includes('=') || tail.includes('[')) return true;
      at = compact.indexOf(scheme, at + 1);
    }
  }
  return false;
}
function xss(s) {
  let lt = s.indexOf('<'); let n = 0;
  while (lt !== -1 && n++ < 400) {
    let i = skipSpace(s, lt + 1);
    if (s[i] === '/') i++;
    const tag = wordFrom(s, i);
    if (TAGS.includes(tag)) {
      const gt = s.indexOf('>', i);
      const inside = s.slice(i, gt === -1 ? i + 300 : Math.min(gt, i + 300));
      if (handlerIn(inside) || scriptUrl(inside) || inside.includes('srcdoc') || inside.includes('formaction') || inside.includes('expression(') || inside.includes('xlink:href')) return true;
      if (tag === 'script' || tag === 'iframe' || tag === 'object' || tag === 'embed' || tag === 'applet' || tag === 'base' || tag === 'portal') return true;
      if (tag === 'meta' && inside.includes('refresh')) return true;
    }
    lt = s.indexOf('<', lt + 1);
  }
  if (scriptUrl(s)) return true;
  // Template and expression injection that runs script: {{constructor.constructor('x')()}}, ${alert(1)} in templates.
  if (s.includes('{{') && (s.includes('constructor') || s.includes('__proto__') || s.includes('$eval') || s.includes('$on'))) return true;
  return false;
}

// ---- Path traversal ----
const SENSITIVE = ['/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/group', '/etc/issue', '/etc/sudoers', '/etc/crontab', '/proc/self', '/proc/version', '/proc/1/',
  'win.ini', 'boot.ini', 'system.ini', 'windows/system32', 'web.config', 'web-inf/web.xml', '/.ssh/', 'id_rsa', '/.aws/credentials', '/.bash_history', '/var/log/'];
function traversal(s) {
  const unified = s.split('\\').join('/');
  for (let p of unified.split('/')) {
    // A segment starts after the last delimiter in it ({"f":"../x, ?file=../x, path: ..): only the dots count.
    let cut = -1; for (const d of ['"', "'", '=', ':', ',', '(', '[', '{', '?', '&', ';']) cut = Math.max(cut, p.lastIndexOf(d, p.length - 1));
    if (cut !== -1 && p.slice(cut + 1).startsWith('..')) p = p.slice(cut + 1);
    // "..", "...", "..;", ". ." with spaces, ".%00." already decoded to "..\u0000"
    const t = p.split(' ').join('').split('\u0000').join('');
    if (t.length >= 2 && t.length <= 6 && t.startsWith('..') && [...t].every((c) => c === '.' || c === ';')) return true;
  }
  return SENSITIVE.some((f) => unified.includes(f));
}

// ---- Command injection ----
// Shell commands an attacker runs first: shells, downloaders, file readers, recon, interpreters, timing.
const COMMANDS = ['sh', 'bash', 'zsh', 'dash', 'ksh', 'csh', 'tcsh', 'fish', 'busybox', 'cmd', 'powershell', 'pwsh',
  'curl', 'wget', 'fetch', 'tftp', 'ftp', 'scp', 'nc', 'ncat', 'netcat', 'socat', 'telnet', 'ssh',
  'cat', 'tac', 'head', 'tail', 'more', 'less', 'nl', 'od', 'xxd', 'hexdump', 'strings', 'base64', 'type',
  'id', 'whoami', 'uname', 'hostname', 'ifconfig', 'ipconfig', 'netstat', 'ps', 'env', 'printenv', 'set', 'ls', 'dir', 'pwd', 'echo', 'getent', 'groups', 'w', 'who', 'last', 'systeminfo', 'tasklist', 'net', 'reg',
  'ping', 'nslookup', 'dig', 'host', 'traceroute', 'sleep', 'timeout',
  'python', 'python2', 'python3', 'perl', 'ruby', 'php', 'node', 'lua', 'java', 'awk', 'gawk', 'sed', 'xargs', 'find', 'chmod', 'chown', 'rm', 'mv', 'cp', 'touch', 'mkfifo', 'kill', 'crontab', 'certutil', 'bitsadmin', 'mshta', 'rundll32', 'regsvr32', 'wscript', 'cscript'];
const CMD = new Set(COMMANDS);
// Commands that are ordinary English words: after a separator they count only with an argument that looks like one.
const WORDY = new Set(['type', 'set', 'more', 'less', 'last', 'host', 'find', 'w', 'who', 'net', 'reg', 'echo', 'kill', 'touch', 'groups', 'timeout', 'fetch', 'node', 'java', 'head', 'tail', 'dir', 'ls', 'pwd', 'cp', 'mv', 'rm', 'id', 'env', 'ps', 'sleep', 'ping', 'cat', 'nl', 'od', 'sed', 'awk', 'set', 'sh']);
const BARE = new Set(['id', 'whoami', 'uname', 'hostname', 'ifconfig', 'ipconfig', 'netstat', 'printenv', 'systeminfo', 'tasklist', 'getent', 'groups', 'env', 'set', 'pwd', 'ls', 'dir', 'ps', 'reboot']);
// The command word at i: an optional path (/bin/, /usr/bin/, ./, c:\windows\system32\), then the word.
function commandAt(s, i) {
  i = skipSpace(s, i);
  let j = i;
  while (s[j] === '(' || s[j] === '{' || s[j] === '!') j = skipSpace(s, j + 1);
  // A path in front: take the last segment.
  let k = j; while (k < s.length && !(s[k] === ' ' || ';|&`)<>?#"\',{}'.includes(s[k])) && k - j < 80) k++;
  const token = s.slice(j, k);
  const last = token.slice(token.lastIndexOf('/') + 1);
  let w = last; const dot = w.lastIndexOf('.'); if (dot > 0 && ['exe', 'com', 'bat', 'cmd', 'ps1', 'sh', 'py', 'pl'].includes(w.slice(dot + 1))) w = w.slice(0, dot);
  if (!CMD.has(w)) return null;
  return { w, end: k, pathed: token.includes('/') };
}
function argLooksReal(s, k) {
  const i = skipSpace(s, k);
  const c = s[i] || '';
  if (!c || ';|&`)?#'.includes(c)) return true; // a bare command: `whoami`, ;id;, ;id?x=1
  return c === '-' || c === '/' || isDigit(c) || c === '.' || c === '$' || c === '~' || c === '<' || c === '>' || c === '|' || isWordChar(c) && s.slice(i, i + 40).includes('/') || s.slice(i, i + 6) === 'http:/' || s.slice(i, i + 7) === 'https:/';
}
function command(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    let start = -1; let strong = false;
    if (c === ';' || c === '|' || c === '&' || c === '`' || c === '\n') { start = i + 1; while (s[start] === '|' || s[start] === '&') start++; strong = c === '`'; }
    else if (c === '$' && s[i + 1] === '(') { start = i + 2; strong = true; }
    else if (c === '<' && s[i + 1] === '(') { start = i + 2; strong = true; } // process substitution <(cmd)
    else if ((c === '\'' || c === '"') && ';|&'.includes(s[skipSpace(s, i + 1)] || 'x')) { continue; }
    if (start < 0) continue;
    const cmd = commandAt(s, start);
    if (!cmd) continue;
    if (strong || cmd.pathed) return true;
    // An ordinary English word after "&" in a query string (&type=x) isn't a command: it needs "=" not to follow.
    if (s[cmd.end] === '=') continue;
    // "&&" never appears in a query string: only a single "&" gets the query-string reading below.
    if (WORDY.has(cmd.w) && c === '&' && s[i + 1] !== '&' && s[i - 1] !== '&') { const a = skipSpace(s, cmd.end); if (!(s[a] === '-' || s[a] === '/' || s.startsWith('http', a) || (['sleep', 'ping', 'timeout'].includes(cmd.w) && isDigit(s[a] || '')))) continue; }
    // A command with no argument at all counts only if it is one that does its harm alone (;id, |whoami); a bare shell
    // name or an English word (;dash, &w) doesn't.
    const a2 = skipSpace(s, cmd.end);
    if ((!s[a2] || ';|&`)?#'.includes(s[a2])) && !BARE.has(cmd.w)) continue;
    if (argLooksReal(s, cmd.end)) return true;
  }
  return false;
}

// ---- File inclusion and server-side request forgery ----
const SCHEMES = ['php://', 'expect://', 'phar://', 'zip://', 'glob://', 'data://', 'gopher://', 'dict://', 'ldap://', 'jar:', 'netdoc:', 'file://', 'file:/'];
const METADATA = ['169.254.169.254', '[fd00:ec2::254]', 'metadata.google.internal', '100.100.100.200', '169.254.170.2', 'metadata.azure.com'];
function inclusion(s) {
  const compact = s.split(' ').join('');
  if (SCHEMES.some((x) => compact.includes(x))) return true;
  return METADATA.some((x) => compact.includes(x));
}

// ---- Log4Shell-style lookups, however nested: ${${lower:j}${::-n}di:ldap:...}, ${jndi${env:x:-:}...} ----
function resolveLookups(s) {
  let t = s.slice(0, 4096);
  for (let round = 0; round < 20; round++) {
    // The innermost ${...}: replaced by what it evaluates to.
    const open = t.lastIndexOf('${');
    if (open === -1) break;
    const close = t.indexOf('}', open);
    if (close === -1) break;
    const body = t.slice(open + 2, close);
    let val;
    const dflt = body.indexOf(':-');
    if (body.startsWith('lower:') || body.startsWith('upper:')) val = body.slice(6).toLowerCase();
    else if (dflt !== -1) val = body.slice(dflt + 2);
    else if (body.startsWith('date:') || body.startsWith('sys:') || body.startsWith('env:') || body.startsWith('java:') || body.startsWith('main:') || body.startsWith('ctx:') || body.startsWith('base64:')) val = '\u0001' + body + '\u0001';
    else val = '\u0002' + body + '\u0002'; // a top-level lookup: jndi:ldap://...
    t = t.slice(0, open) + val + t.slice(close + 1);
  }
  return t;
}
function lookup(s) {
  if (!s.includes('${') && !s.includes('$%7b')) return false;
  const r = resolveLookups(s);
  for (const p of ['jndi:', 'jndi ']) {
    let at = r.indexOf(p);
    while (at !== -1) {
      const tail = r.slice(at + 5, at + 20);
      if (['ldap', 'ldaps', 'rmi', 'dns', 'iiop', 'corba', 'nds', 'nis', 'http', 'https'].some((x) => tail.startsWith(x))) return true;
      at = r.indexOf(p, at + 1);
    }
  }
  // Any lookup that reads secrets or the environment, nested or not.
  return r.includes('\u0001env:') || r.includes('\u0001sys:') || r.includes('\u0001java:') || r.includes('\u0001ctx:') || r.includes('\u0002jndi');
}

// ---- Server-side template injection: a template opener with code that reaches the system inside ----
const TEMPLATE_SINKS = ['__class__', '__globals__', '__builtins__', '__import__', '__mro__', '__subclasses__', '__init__', 'getruntime', 'processbuilder', 'popen', 'os.system',
  'system(', 'exec(', 'eval(', 'spawn(', 'spawnsync', 'execsync', 'child_process', 'require(', 'forname', 'java.lang', 'freemarker.template', 'subprocess', 'process.mainmodule',
  '.constructor.constructor', 'getclass', 'classloader', 'scriptengine', '`id`', 'io.popen', 'kernel.', 'file.read', 'open(', 'readlines'];
function template(s) {
  for (const [o, c] of [['{{', '}}'], ['${', '}'], ['<%', '%>'], ['#{', '}'], ['*{', '}']]) {
    let at = s.indexOf(o); let n = 0;
    while (at !== -1 && n++ < 50) {
      const e = s.indexOf(c, at + o.length);
      if (e === -1) break;
      const inner = s.slice(at + o.length, Math.min(e, at + 200));
      if (TEMPLATE_SINKS.some((k) => inner.includes(k))) return true;
      at = s.indexOf(o, at + 1);
    }
  }
  return false;
}

// Log4Shell first: its payload also holds a URL scheme (ldap://), and a body treats a lookup more strictly.
const STRONG = [['lookup', lookup], ['sql', sql], ['xss', xss], ['traversal', traversal], ['command', command], ['inclusion', inclusion], ['template', template],
  ['nullbyte', (s) => s.includes('\u0000')]];

// Which view each check reads: SQL is read with comments removed too (UN/**/ION); commands in the shell view.
// Comments used to break keywords apart (UN/**/ION, s/**/e/**/l/**/e/**/c/**/t): with comments removed, the words
// may run together, so UNION then SELECT is looked for as text, not as whole words. Only when the input had comments.
function splitKeywords(v) {
  if (v.joined === v.spaced) return false;
  const j = v.joined.split(' ').join('');
  let at = j.indexOf('union'); let n = 0;
  while (at !== -1 && n++ < 50) {
    const sel = j.indexOf('select', at + 5);
    if (sel !== -1 && sel - at < 40) return true;
    at = j.indexOf('union', at + 5);
  }
  for (const w of ['sleep(', 'benchmark(', 'waitfor', 'xp_cmdshell', 'information_schema', 'droptable', 'shutdown']) if (j.includes(w) && !v.spaced.includes(w)) return true;
  return false;
}
function attackIn(v) {
  for (const [kind, f] of STRONG) {
    if (kind === 'command') { if (f(v.shell)) return kind; continue; }
    if (f(v.spaced) || (kind === 'sql' && (f(v.joined) || splitKeywords(v)))) return kind;
  }
  return null;
}
// The first strong attack kind in raw input (cleaned here), or null.
// Read twice: with backslash escapes decoded (JSON, code) and without (Windows paths).
function attackRaw(input, max = norm.MAX) {
  const a = attackIn(norm.views(norm.clean(input, max)));
  if (a) return a;
  const s = String(input == null ? '' : input);
  const raw = norm.clean(s, max, false);
  return raw.includes('\\') ? attackIn(norm.views(raw)) : null;
}
// The first strong attack kind in an already folded string (083's interface).
function attack(s) { return attackIn({ spaced: s, joined: norm.squeeze(s), shell: s }); }

// Attack-like words (only flagged): what people might search for on a security site.
const WEAK_WORDS = ['union select', '<script', 'javascript:', 'onerror=', 'onload=', 'sleep(', 'benchmark(', 'file://', '| sh', '|sh', '| bash', '|bash', '${jndi', '../', 'drop table', 'or 1=1', '/etc/passwd', 'cmd.exe', 'xp_cmdshell', '{{'];
const weak = (s) => WEAK_WORDS.some((w) => s.includes(w));
function weakRaw(input, max = norm.MAX) { const v = norm.views(norm.clean(input, max)); return weak(v.spaced) || weak(v.joined); }

// Known attack scanners, by name in the user agent (whole words), and generic attack-tool words.
const SCANNER_NAMES = ['sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'zgrab2', 'nuclei', 'acunetix', 'wpscan', 'dirbuster', 'gobuster', 'ffuf', 'wfuzz', 'hydra',
  'netsparker', 'invicti', 'w3af', 'openvas', 'nessus', 'havij', 'jaeles', 'whatweb', 'feroxbuster', 'commix', 'xsstrike', 'arachni', 'skipfish', 'dirb', 'zmeu',
  'morfeus', 'paros', 'webinspect', 'appscan', 'burpsuite', 'owasp zap', 'zaproxy', 'metasploit', 'medusa', 'brutus',
  'fimap', 'joomscan', 'droopescan', 'cmsmap', 'afrog', 'interactsh', 'naabu', 'dalfox', 'ghauri', 'sqlninja', 'bbqsql'];
function scanner(ua) {
  const s = norm.views(norm.clean(String(ua || '').slice(0, 512))).spaced;
  return SCANNER_NAMES.some((n) => (n.includes(' ') ? s.includes(n) : hasWord(s, n)));
}

// Paths this site never serves that attackers probe for (WordPress, PHP, config and secret files, admin consoles,
// version-control folders). The site runs Node: no .php, .asp, .jsp or .cgi page exists, so any request for one is a
// probe, however it is named.
const PROBE_PARTS = ['/.env', '/.git/', '/.git', '/.svn/', '/.hg/', '/.bzr/', '/.ds_store', '/.htaccess', '/.htpasswd', '/.aws/', '/.ssh/', '/.docker', '/.kube/', '/.npmrc',
  '/wp-admin', '/wp-login', '/wp-content', '/wp-includes', '/wp-json/wp', '/xmlrpc', '/phpmyadmin', '/pma/', '/myadmin', '/adminer', '/phpinfo', '/cgi-bin/', '/server-status',
  '/server-info', '/actuator', '/jolokia', '/console/', '/manager/html', '/solr/', '/druid/', '/vendor/phpunit', '/boaform', '/hnap1', '/setup.cgi', '/shell', '/webshell',
  '/config.json', '/config.yml', '/backup', '/dump.sql', '/db.sql', '/database.sql', '/.vscode/', '/.idea/', '/owa/', '/ecp/', '/autodiscover', '/remote/login', '/global-protect',
  '/telescope', '/_profiler', '/elmah', '/trace.axd', '/web.config', '/id_rsa'];
const PROBE_EXT = ['php', 'php3', 'php5', 'phtml', 'asp', 'aspx', 'ashx', 'asmx', 'jsp', 'jspx', 'do', 'action', 'cgi', 'pl', 'cfm', 'sql', 'bak', 'old', 'swp', 'env', 'ini', 'log', 'conf', 'yml', 'yaml', 'pem', 'key'];
function probe(path) {
  const p = norm.views(norm.clean(String(path || '').slice(0, 2048))).joined.split('\\').join('/');
  if (p.startsWith('/.well-known/')) return false;
  if (PROBE_PARTS.some((x) => p.includes(x))) return true;
  const last = p.slice(p.lastIndexOf('/') + 1);
  const dot = last.lastIndexOf('.');
  return dot > 0 && PROBE_EXT.includes(last.slice(dot + 1).split(';')[0]);
}

module.exports = { fold, attack, attackRaw, attackIn, weak, weakRaw, scanner, probe, resolveLookups, STRONG, WEAK_WORDS, SCANNER_NAMES, COMMANDS, PROBE_PARTS };
