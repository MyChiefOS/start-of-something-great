// The firewall's attack checks without regular expressions (Aaron, Nov 25: "Rewrite without regex", after the
// scanner's ReDoS finding on #157). Every check is a single pass, or a bounded number of passes, over a capped string,
// so no input can make one slow (CWE-1333). Input is folded first: lower case, and runs of spaces, tabs, plus signs and
// SQL comments read as one space.
'use strict';

const isWordChar = (c) => (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c === '_';
const isDigit = (c) => c >= '0' && c <= '9';
const isLetter = (c) => c >= 'a' && c <= 'z';

// Lower case; whitespace, '+', and /* ... */ comments become single spaces.
function fold(input, max) {
  const s = String(input || '').slice(0, max).toLowerCase();
  let out = '';
  let space = false;
  for (let i = 0; i < s.length; i++) {
    let c = s[i];
    if (c === '/' && s[i + 1] === '*') {
      const end = s.indexOf('*/', i + 2);
      i = end === -1 ? s.length : end + 1;
      c = ' ';
    }
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v' || c === '+') {
      if (!space) out += ' ';
      space = true;
    } else {
      out += c;
      space = false;
    }
  }
  return out;
}

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
const skipSpace = (s, i) => { while (s[i] === ' ') i++; return i; };
// The word starting at i (letters, digits, underscores).
function wordFrom(s, i) { let j = i; while (j < s.length && isWordChar(s[j])) j++; return s.slice(i, j); }

// SQL injection.
function sql(s) {
  for (const u of wordAt(s, 'union')) {
    let i = skipSpace(s, u + 5);
    if (s.startsWith('all', i) && !isWordChar(s[i + 3] || '')) i = skipSpace(s, i + 3);
    if (s.startsWith('select', i) && !isWordChar(s[i + 6] || '')) {
      const tail = s.slice(i + 6, i + 206);
      const amp = tail.indexOf('&');
      if (hasWord(amp === -1 ? tail : tail.slice(0, amp), 'from')) return true;
    }
  }
  // ' or 1=1 / ') and '1'='1
  let q = s.indexOf("'");
  while (q !== -1) {
    let i = q + 1;
    while (s[i] === ' ' || s[i] === ')') i++;
    const w = wordFrom(s, i);
    if (w === 'or' || w === 'and') {
      i += w.length;
      if (s[i] === ' ' || s[i] === '(') {
        while (s[i] === ' ' || s[i] === '(') i++;
        if (s[i] === "'") i++;
        if (isDigit(s[i] || '')) {
          while (isDigit(s[i] || '')) i++;
          if (s[i] === "'") i++;
          i = skipSpace(s, i);
          if (s[i] === '=') {
            i = skipSpace(s, i + 1);
            if (s[i] === "'") i++;
            if (isDigit(s[i] || '')) return true;
          }
        }
      }
    }
    q = s.indexOf("'", q + 1);
  }
  // ; drop / truncate / shutdown / exec
  let semi = s.indexOf(';');
  while (semi !== -1) {
    const i = skipSpace(s, semi + 1);
    const w = wordFrom(s, i);
    if (['drop', 'truncate', 'shutdown', 'exec', 'execute'].includes(w) && s[i + w.length] === ' ') return true;
    semi = s.indexOf(';', semi + 1);
  }
  // sleep(5), benchmark(1000, ...), pg_sleep(5); waitfor delay '
  for (const f of ['sleep', 'benchmark', 'pg_sleep']) {
    for (const at of wordAt(s, f)) {
      let i = skipSpace(s, at + f.length);
      if (s[i] === '(') { i = skipSpace(s, i + 1); if (isDigit(s[i] || '')) return true; }
    }
  }
  for (const at of wordAt(s, 'waitfor')) {
    const i = skipSpace(s, at + 7);
    if (s.startsWith('delay', i) && s[skipSpace(s, i + 5)] === "'") return true;
  }
  return hasWord(s, 'information_schema') || hasWord(s, 'xp_cmdshell');
}

// Cross-site scripting: a tag with something that runs, or a javascript: call.
const TAGS = ['script', 'iframe', 'object', 'embed', 'svg', 'img'];
function handlerIn(t) {
  // on<letters>= somewhere in t
  let i = t.indexOf('on');
  while (i !== -1) {
    if (i === 0 || !isWordChar(t[i - 1])) {
      let j = i + 2; let n = 0;
      while (isLetter(t[j] || '') && n < 20) { j++; n++; }
      if (n > 0 && t[skipSpace(t, j)] === '=') return true;
    }
    i = t.indexOf('on', i + 1);
  }
  return false;
}
function xss(s) {
  let lt = s.indexOf('<');
  while (lt !== -1) {
    const i = skipSpace(s, lt + 1);
    const tag = wordFrom(s, i);
    if (TAGS.includes(tag) || tag === 'body') {
      const gt = s.indexOf('>', i);
      const inside = s.slice(i, gt === -1 ? i + 200 : Math.min(gt, i + 200));
      if (['img', 'svg', 'body', 'iframe'].includes(tag) && handlerIn(inside)) return true;
      if (TAGS.includes(tag) && gt !== -1 && gt - i <= 200) {
        const after = s.slice(gt + 1, gt + 201);
        if (after.includes('</script') || after.includes('< /script') || handlerIn(after) || after.includes('src=') || after.includes('src =')) return true;
      }
    }
    lt = s.indexOf('<', lt + 1);
  }
  for (const at of wordAt(s, 'javascript')) {
    let i = skipSpace(s, at + 10);
    if (s[i] !== ':') continue;
    i = skipSpace(s, i + 1);
    let j = i;
    while (j < s.length && (isWordChar(s[j]) || s[j] === '$' || s[j] === '.')) j++;
    if (j > i && s[skipSpace(s, j)] === '(') return true;
  }
  return false;
}

// Path traversal: a ".." path segment, or a well-known system file.
function traversal(s) {
  const parts = s.split('/').flatMap((p) => p.split('\\'));
  if (parts.some((p) => p === '..')) return true;
  return s.includes('/etc/passwd') || s.includes('/etc/shadow') || s.includes('/etc/hosts') || s.includes('win.ini') || s.includes('boot.ini');
}

// Command injection: ; | or ` then a shell command with an argument; $( then a command.
const COMMANDS = ['cat', 'curl', 'wget', 'bash', 'sh', 'nc', 'ncat', 'python', 'perl', 'powershell'];
function command(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === ';' || c === '|' || c === '`') {
      const j = skipSpace(s, i + 1);
      const w = wordFrom(s, j);
      if (COMMANDS.includes(w) && s[j + w.length] === ' ') {
        const k = skipSpace(s, j + w.length);
        const n = s[k] || '';
        if (isWordChar(n) || n === '-' || n === '/' || n === '.') return true;
      }
    } else if (c === '$' && s[i + 1] === '(') {
      const w = wordFrom(s, skipSpace(s, i + 2));
      if (['cat', 'curl', 'wget', 'id', 'whoami', 'uname', 'bash', 'sh'].includes(w)) return true;
    }
  }
  return false;
}

// File inclusion: dangerous URL schemes, or file:/// at system folders.
function inclusion(s) {
  return s.includes('php://') || s.includes('expect://') || s.includes('phar://')
    || s.includes('file:///etc') || s.includes('file:///proc') || s.includes('file:///windows');
}

// Log4Shell-style lookups: ${jndi: and the like.
function lookup(s) {
  let i = s.indexOf('${');
  while (i !== -1) {
    const j = skipSpace(s, i + 2);
    const w = wordFrom(s, j);
    if (['jndi', 'env', 'sys', 'java', 'lower', 'upper'].includes(w) && s[skipSpace(s, j + w.length)] === ':') return true;
    i = s.indexOf('${', i + 2);
  }
  return false;
}

const STRONG = [['sql', sql], ['xss', xss], ['traversal', traversal], ['command', command], ['inclusion', inclusion], ['lookup', lookup], ['nullbyte', (s) => s.includes('\u0000')]];

// The first strong attack kind in s, or null.
function attack(s) { for (const [kind, f] of STRONG) if (f(s)) return kind; return null; }

// Attack-like words (only flagged): what people might search for on a security site.
const WEAK_WORDS = ['union select', '<script', 'javascript:', 'onerror=', 'onload=', 'sleep(', 'benchmark(', 'file://', '| sh', '|sh', '| bash', '|bash'];
const weak = (s) => WEAK_WORDS.some((w) => s.includes(w));

// Known attack scanners, by name in the user agent (whole words).
const SCANNER_NAMES = ['sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'nuclei', 'acunetix', 'wpscan', 'dirbuster', 'gobuster', 'ffuf', 'wfuzz', 'hydra',
  'netsparker', 'w3af', 'openvas', 'nessus', 'havij', 'jaeles', 'whatweb', 'feroxbuster', 'commix', 'xsstrike'];
function scanner(ua) {
  const s = String(ua || '').slice(0, 512).toLowerCase();
  return SCANNER_NAMES.some((n) => hasWord(s, n));
}

module.exports = { fold, attack, weak, scanner, STRONG, WEAK_WORDS, SCANNER_NAMES };
