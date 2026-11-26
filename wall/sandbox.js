// The Agentic Wall's sandbox (088; Aaron, Nov 25: "open attachments in a sandbox to watch what they do", "Sandbox is
// fine"; Nov 26 plan, Phase 1 item 6). A pull request's runnable files (shell, JavaScript, Python, Perl, Ruby, PHP and
// Linux programs) are run in GitHub's own runner inside bubblewrap: no network (its own empty network namespace), the
// whole disk read-only, a fresh empty /tmp and home, no environment, its own process and user namespaces, killed after
// 10 seconds. strace records what each tries to do. Built into the Wall: no outside service, no account.
//
// The run happens in its own job of the facts workflow, which holds no identity token and no write permission: a file
// that broke out of the sandbox would find nothing to use. Its findings travel as a small JSON file that the facts job
// accepts only as W47 or W47b flags in the Wall's own words.
//
//   W47   block  the file tried to reach the network, start a shell or a downloader, or plant itself (cron, shell
//                startup files, systemd, ssh keys)
//   W47b  flag   something unusual (writing outside its own folders, reading secrets' usual places, many processes),
//                or the file could not be run
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const RUNNERS = { sh: ['bash'], bash: ['bash'], js: ['node'], mjs: ['node'], cjs: ['node'], py: ['python3'], pl: ['perl'], rb: ['ruby'], php: ['php'] };
const SHELLS = ['sh', 'bash', 'dash', 'zsh', 'ksh', 'csh', 'tcsh', 'fish', 'busybox'];
const FETCHERS = ['curl', 'wget', 'nc', 'ncat', 'netcat', 'socat', 'telnet', 'ftp', 'tftp', 'scp', 'ssh', 'openssl'];
const PLANT = ['/etc/cron', '/var/spool/cron', 'crontab', '/.bashrc', '/.profile', '/.bash_profile', '/.zshrc', '/etc/profile', '/etc/systemd', '/.config/systemd',
  '/.ssh/authorized_keys', '/etc/rc.local', '/etc/init.d', '/etc/ld.so.preload', '/.config/autostart'];
const SECRET_PLACES = ['/.ssh/', '/.aws/', '/.npmrc', '/.netrc', '/.git-credentials', '/.docker/config', '/etc/shadow', '/proc/self/environ', '/.config/gh/'];
const TIME_LIMIT = 10;
const REPO_API = 'https://api.github.com/repos/MyChiefOS/start-of-something-great';

// Which runner a file needs, from its name, its first line (#!) or its first bytes (an ELF program).
function runnerFor(name, bytes) {
  const b = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes || []);
  if (b.length >= 4 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return ['elf'];
  const ext = String(name || '').toLowerCase().split('.').pop();
  if (Object.prototype.hasOwnProperty.call(RUNNERS, ext)) return RUNNERS[ext];
  const first = b.subarray(0, 120).toString('latin1');
  if (first.startsWith('#!')) {
    const line = first.slice(2).split('\n')[0].trim().split(' ');
    const prog = (line[0].endsWith('/env') ? line[1] : line[0]) || '';
    const base = prog.slice(prog.lastIndexOf('/') + 1);
    if (SHELLS.includes(base)) return [base === 'busybox' ? 'sh' : base];
    if (base.startsWith('python')) return ['python3'];
    if (base === 'node' || base === 'perl' || base === 'ruby' || base === 'php') return [base];
  }
  return null;
}

// What strace's output (one line per call, -f) shows the program did. No regular expressions read it (as 083).
function analyze(trace, label) {
  const flags = [];
  const seen = new Set();
  const add = (code, why) => { const k = code + why; if (seen.has(k) || flags.length >= 5) return; seen.add(k); flags.push((code + ' sandbox: ' + why + ': ' + label).slice(0, 240)); };
  let procs = 0;
  for (const raw of String(trace || '').split('\n').slice(0, 200000)) {
    const at = raw.indexOf(' ');
    const line = at > 0 && raw.slice(0, at).split('').every((c) => c >= '0' && c <= '9') ? raw.slice(at + 1).trimStart() : raw.trimStart();
    const call = line.slice(0, line.indexOf('('));
    const args = line.slice(line.indexOf('(') + 1, 400);
    if ((call === 'connect' || call === 'sendto') && (args.includes('AF_INET') || args.includes('AF_INET6'))) add('W47', 'tried to reach the network');
    else if (call === 'bind' && (args.includes('AF_INET') || args.includes('AF_INET6'))) add('W47', 'tried to listen for connections');
    else if (call === 'execve') {
      procs++;
      const q = args.indexOf('"');
      const prog = q === -1 ? '' : args.slice(q + 1, args.indexOf('"', q + 1));
      const base = prog.slice(prog.lastIndexOf('/') + 1);
      if (procs > 1 && SHELLS.includes(base)) add('W47', 'started a shell (' + base + ')');
      if (FETCHERS.includes(base)) add('W47', 'started ' + base);
    } else if (call === 'openat' || call === 'open' || call === 'creat' || call === 'rename' || call === 'renameat' || call === 'symlink' || call === 'link') {
      const writes = call !== 'openat' && call !== 'open' ? true : args.includes('O_WRONLY') || args.includes('O_RDWR') || args.includes('O_CREAT');
      const q = args.indexOf('"');
      const p = q === -1 ? '' : args.slice(q + 1, args.indexOf('"', q + 1));
      if (writes && PLANT.some((x) => p.includes(x))) add('W47', 'tried to plant itself (' + p.slice(0, 60) + ')');
      else if (!writes && SECRET_PLACES.some((x) => p.includes(x))) add('W47b', 'read a place secrets are kept (' + p.slice(0, 60) + ')');
    } else if (call === 'ptrace' || call === 'process_vm_writev') add('W47', 'tried to control another process');
  }
  if (procs > 50) add('W47b', 'started ' + procs + ' processes');
  return flags;
}

// Runs one file in the sandbox and returns its flags. dir: an empty folder for the file.
function runOne(dir, name, bytes) {
  const label = String(name || 'file').slice(0, 120);
  const runner = runnerFor(name, bytes);
  if (!runner) return [];
  const safe = 'f' + (path.extname(String(name || '')).toLowerCase().replace(/[^a-z0-9.]/g, '').slice(0, 8) || '');
  const work = fs.mkdtempSync(path.join(dir, 'run-'));
  const file = path.join(work, safe);
  fs.writeFileSync(file, bytes, { mode: 0o755 });
  const cmd = runner[0] === 'elf' ? ['/tmp/w/' + safe] : [...runner, '/tmp/w/' + safe];
  const args = ['--ro-bind', '/', '/', '--tmpfs', '/tmp', '--tmpfs', '/home', '--tmpfs', '/root', '--tmpfs', '/run', '--dev', '/dev', '--proc', '/proc',
    '--bind', work, '/tmp/w', '--chdir', '/tmp/w', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv', '--setenv', 'PATH', '/usr/local/bin:/usr/bin:/bin', '--setenv', 'HOME', '/home/x',
    'strace', '-f', '-qq', '-e', 'trace=execve,connect,sendto,bind,open,openat,creat,rename,renameat,symlink,link,ptrace,process_vm_writev', '-o', '/tmp/w/trace.txt', '--', ...cmd];
  const r = spawnSync('timeout', ['--kill-after=2', String(TIME_LIMIT), 'bwrap', ...args], { encoding: 'utf8', timeout: (TIME_LIMIT + 5) * 1000, maxBuffer: 1 << 20 });
  let trace = '';
  try { trace = fs.readFileSync(path.join(work, 'trace.txt'), 'utf8').slice(0, 8 << 20); } catch { /* no trace */ }
  if (!trace) return [('W47b sandbox: could not run (' + String((r.error && r.error.code) || r.status || 'no trace').slice(0, 30) + '): ' + label).slice(0, 240)];
  return analyze(trace, label);
}

// Is the sandbox there (bubblewrap and strace on this machine)?
function available() {
  const a = spawnSync('bwrap', ['--version'], { encoding: 'utf8' });
  const b = spawnSync('strace', ['-V'], { encoding: 'utf8' });
  return a.status === 0 && b.status === 0;
}

// The sandbox job (github-facts.yml): the open pull requests pushed in the last 3 hours (at most 5), their changed files
// (at most 30 each, 2 MB each), each runnable one run here. Prints { 'number:filename': [flags] } and nothing else.
// get and getRaw are db/workjobs.js's GitHub readers, with the job's read-only token.
async function prs({ get, getRaw, now = Date.now(), dir }) {
  const out = {};
  const ok = available();
  const list = await get('/pulls?state=open&per_page=30&sort=updated&direction=desc').catch(() => null);
  const recent = (Array.isArray(list) ? list : []).filter((p) => p && Number.isSafeInteger(p.number) && Date.parse(p.updated_at) > now - 3 * 3600000).slice(0, 5);
  for (const p of recent) {
    const files = await get('/pulls/' + p.number + '/files?per_page=100').catch(() => null);
    let n = 0;
    for (const f of Array.isArray(files) ? files : []) {
      if (n >= 30 || !f || f.status === 'removed' || typeof f.contents_url !== 'string' || !f.contents_url.startsWith(REPO_API + '/contents/')) continue;
      const name = String(f.filename || '');
      // Only what could run: by name first, then by its first bytes.
      const ext = name.toLowerCase().split('.').pop();
      const maybe = Object.prototype.hasOwnProperty.call(RUNNERS, ext) || !name.includes('.') || ext === 'bin' || ext === 'elf' || ext === 'run';
      if (!maybe) continue;
      n++;
      let bytes = null;
      try { bytes = await getRaw(f.contents_url.slice(REPO_API.length)); } catch { bytes = null; }
      if (!bytes || bytes.length > 2 * 1024 * 1024 || !runnerFor(name, bytes)) continue;
      out[p.number + ':' + name] = ok ? runOne(dir, name, bytes) : [('W47b sandbox: could not run (sandbox not installed): ' + name).slice(0, 240)];
    }
  }
  return out;
}

if (require.main === module) {
  const w = require('../db/workjobs');
  const dir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'sbx-'));
  prs({ get: w.githubGet(process.env.GH_TOKEN || ''), getRaw: w.githubRaw(process.env.GH_TOKEN || ''), dir })
    .then((o) => process.stdout.write(JSON.stringify(o)))
    .catch(() => process.stdout.write('{}'));
}

module.exports = { runnerFor, analyze, runOne, available, prs, TIME_LIMIT, SHELLS, FETCHERS, PLANT };
