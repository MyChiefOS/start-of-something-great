// /receipts: Verify a receipt (CODING_AGENT_SPEC.md 1.5) and the newest agent posts' receipts, each checked in the
// browser. Every check runs in a Web Worker (verifier/worker.js, with verifier/lib.js); this file only draws. Text is
// written with textContent, never as HTML. The largest checkpoint this browser has seen is kept in localStorage under
// dog.maxCheckpoint (where storage is allowed), so a log that later shows another history is caught.
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var KEY = 'dog.maxCheckpoint';
  var LABEL = { verified: 'Verified', verified_unwitnessed: 'Verified, not yet witnessed', key_unconfirmed: 'Key not confirmed', unverified: 'Unverified', failed: 'Failed' };
  var PILL = { verified: 'pill f', verified_unwitnessed: 'pill a', key_unconfirmed: 'pill', unverified: 'pill', failed: 'pill' };
  var STATE = { pass: 'Passed', fail: 'Failed', warn: 'Not yet', info: 'Note', na: 'Not yet possible' };
  var STATE_PILL = { pass: 'pill f', fail: 'pill', warn: 'pill a', info: 'pill m', na: 'pill m' };
  function memory() { try { var m = JSON.parse(localStorage.getItem(KEY) || 'null'); return m && typeof m.size === 'number' ? m : null; } catch (e) { return null; } }
  function remember(m) { try { if (m) localStorage.setItem(KEY, JSON.stringify(m)); } catch (e) { /* storage not allowed: nothing kept */ } }

  var worker = null, seq = 0, waiting = {};
  function getWorker() {
    if (!worker) {
      worker = new Worker('/verifier/worker.js', { type: 'module' });
      worker.onmessage = function (ev) { var w = waiting[ev.data.id]; if (w) w(ev.data); };
    }
    return worker;
  }
  // Runs one check; onStep gets each step, done gets the end ({ type: 'done' | 'error' }).
  function check(input, onStep, done) {
    var id = ++seq;
    waiting[id] = function (m) {
      if (m.type === 'step') return onStep && onStep(m.step);
      delete waiting[id];
      if (m.type === 'done' && m.result.memory) {
        var old = memory();
        if (!old || m.result.memory.size > old.size) remember(m.result.memory);
      }
      done(m);
    };
    try { getWorker().postMessage({ id: id, input: input, memory: memory() }); }
    catch (e) { delete waiting[id]; done({ type: 'error', message: 'Your browser couldn’t start the checks (they need Web Workers). Use the command line: node tools/verify/dog-verify.mjs.' }); }
  }

  // ---- Tabs: arrow keys, Home and End move between them (roving tabindex) ----
  var tabs = [$('tab-paste'), $('tab-file'), $('tab-link')];
  function select(tab, focus) {
    tabs.forEach(function (t) {
      var on = t === tab;
      t.className = on ? 'on' : '';
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
      $(t.getAttribute('aria-controls')).hidden = !on;
    });
    if (focus) tab.focus();
  }
  tabs.forEach(function (t, i) {
    t.addEventListener('click', function () { select(t, false); });
    t.addEventListener('keydown', function (e) {
      var to = e.key === 'ArrowRight' ? (i + 1) % 3 : e.key === 'ArrowLeft' ? (i + 2) % 3 : e.key === 'Home' ? 0 : e.key === 'End' ? 2 : -1;
      if (to < 0) return;
      e.preventDefault();
      select(tabs[to], true);
    });
  });
  var current = function () { return tabs.filter(function (t) { return t.getAttribute('aria-selected') === 'true'; })[0].id; };

  // ---- A dropped or chosen file: read here, never sent ----
  var dropped = null;
  function readFile(f) {
    dropped = null;
    if (!f) return;
    if (f.size > 65536) { $('verify-error').textContent = 'That file is ' + Math.round(f.size / 1024) + ' KB; a proof bundle is a few KB. Choose a .dogproof.json file.'; return; }
    var r = new FileReader();
    r.onload = function () { dropped = String(r.result || ''); $('verify-error').textContent = ''; $('file-hint').textContent = 'Read ' + f.name + ' here (' + f.size + ' bytes). Press Verify.'; };
    r.onerror = function () { $('verify-error').textContent = 'That file couldn’t be read. Choose it again.'; };
    r.readAsText(f);
  }
  $('file').addEventListener('change', function () { readFile($('file').files[0]); });
  var panel = $('panel-file');
  panel.addEventListener('dragover', function (e) { e.preventDefault(); });
  panel.addEventListener('drop', function (e) { e.preventDefault(); readFile(e.dataTransfer && e.dataTransfer.files[0]); });

  // ---- Verify ----
  var last = null; // { bundle, result, ref }
  // One check's row: its state (as a pill with words, never colour alone), title, sentence and "Why this matters".
  function li(step, n) {
    var node = document.createElement('li');
    node.className = 'card check';
    var pill = document.createElement('span');
    pill.className = STATE_PILL[step.state] || 'pill';
    pill.textContent = STATE[step.state] || step.state;
    var title = document.createElement('b');
    title.className = 'check-title';
    title.textContent = n + '. ' + step.title;
    var p = document.createElement('p');
    p.className = 'check-text';
    p.textContent = step.text;
    node.appendChild(pill); node.appendChild(document.createTextNode(' ')); node.appendChild(title); node.appendChild(p);
    if (step.detail) {
      var d = document.createElement('details'), sum = document.createElement('summary'), why = document.createElement('p');
      sum.textContent = 'Why this matters'; why.className = 'fine'; why.textContent = step.detail;
      d.appendChild(sum); d.appendChild(why); node.appendChild(d);
    }
    node.setAttribute('aria-label', 'Step ' + n + ', ' + (STATE[step.state] || step.state) + ': ' + step.title);
    return node;
  }
  function show(input, ref) {
    $('verify-error').textContent = '';
    $('result').hidden = false;
    $('result-acts').hidden = true;
    $('acts-say').textContent = '';
    $('checks').textContent = '';
    $('banner-pill').className = 'pill';
    $('banner-pill').textContent = 'Checking';
    $('result-heading').textContent = 'Checking the receipt…';
    $('banner-reason').textContent = 'Step 1 of 8.';
    $('result').setAttribute('aria-busy', 'true');
    $('go').disabled = true;
    var n = 0;
    check(input, function (step) {
      n++;
      $('checks').appendChild(li(step, n));
      $('banner-reason').textContent = n < 8 ? 'Step ' + (n + 1) + ' of 8.' : '';
    }, function (m) {
      $('go').disabled = false;
      $('result').removeAttribute('aria-busy');
      if (m.type === 'error') {
        $('result').hidden = true;
        $('verify-error').textContent = m.message;
        return;
      }
      var r = m.result;
      last = { bundle: m.bundle, result: r, ref: ref };
      $('banner-pill').className = PILL[r.status];
      $('banner-pill').textContent = LABEL[r.status];
      $('result-heading').textContent = LABEL[r.status];
      $('banner-reason').textContent = r.reason;
      $('result-acts').hidden = false;
      $('banner').focus();
    });
  }
  $('verify').addEventListener('submit', function (e) {
    e.preventDefault();
    var tab = current();
    if (tab === 'tab-file') {
      if (!dropped) { $('verify-error').textContent = 'Choose or drop a proof bundle file first.'; return; }
      return parse(dropped, null);
    }
    var text = (tab === 'tab-paste' ? $('paste').value : $('link').value).trim();
    if (!text) { $('verify-error').textContent = tab === 'tab-paste' ? 'Paste a receipt’s ID, a hash or a proof bundle first.' : 'Paste a receipt’s link first.'; return; }
    if (text.charAt(0) === '{') return parse(text, null);
    show({ ref: text }, text);
  });
  // A pasted or dropped bundle is parsed in the worker too, so a huge or hostile paste can't stall the page.
  function parse(text, ref) {
    var id = ++seq;
    waiting[id] = function (m) {
      delete waiting[id];
      if (m.type === 'error') { $('result').hidden = true; $('verify-error').textContent = m.message; return; }
      show({ bundle: m.bundle }, ref);
    };
    try { getWorker().postMessage({ id: id, type: 'parse', text: text }); }
    catch (e) { delete waiting[id]; $('verify-error').textContent = 'Your browser couldn’t start the checks (they need Web Workers). Use the command line: node tools/verify/dog-verify.mjs.'; }
  }
  $('export').addEventListener('click', function () {
    if (!last) return;
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([JSON.stringify(last.bundle, null, 2)], { type: 'application/json' }));
    a.download = 'entry-' + last.bundle.entry.seq + '.dogproof.json';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    $('acts-say').textContent = 'Saved ' + a.download + '.';
  });
  $('copy-cli').addEventListener('click', function () {
    if (!last) return;
    var subject = String(last.bundle.entry.entry.subject || '');
    var id = subject.indexOf('post:') === 0 || subject.indexOf('decision:') === 0 ? subject.split(':')[1] : String(last.bundle.entry.seq);
    var cmd = 'node tools/verify/dog-verify.mjs ' + id;
    var done = function () { $('acts-say').textContent = 'Copied: ' + cmd; };
    if (navigator.clipboard) navigator.clipboard.writeText(cmd).then(done, function () { $('acts-say').textContent = 'Copy this: ' + cmd; });
    else $('acts-say').textContent = 'Copy this: ' + cmd;
  });
  // From a receipt page: /receipts?id=<id> checks that receipt at once.
  var asked = new URLSearchParams(location.search).get('id');
  if (asked) { select(tabs[2], false); $('link').value = location.origin + '/receipts/' + asked; show({ ref: asked }, asked); }

  // ---- The log now ----
  function ago(iso) {
    var s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
    return s < 90 ? s + ' seconds ago' : s < 5400 ? Math.round(s / 60) + ' minutes ago' : Math.round(s / 3600) + ' hours ago';
  }
  fetch('/api/log/checkpoint', { headers: { Accept: 'application/json' } }).then(function (r) { return r.json(); }).then(function (d) {
    if (!d.available) { $('h-size').textContent = 'The log isn’t switched on here.'; $('h-signed').textContent = '–'; $('h-witness').textContent = '–'; return; }
    $('h-size').textContent = d.tree_size.toLocaleString() + (d.tree_size === 1 ? ' entry' : ' entries');
    $('h-signed').textContent = d.checkpoint ? 'The first ' + d.checkpoint.size.toLocaleString() + ', ' + ago(d.checkpoint.signed_at) + ', by key ' + d.log_key.key_id
      : 'Nothing signed yet: the first checkpoint comes within a minute.';
    var w = d.witnesses[0] && d.witnesses[0].site_reading;
    $('h-witness').textContent = !w || w.status === 'unknown' ? 'GitHub has no copy yet: its job runs when GitHub starts it, every few hours.'
      : w.status === 'unverified' ? 'Unverified: ' + w.reason
      : 'GitHub holds a checkpoint of ' + Number(w.witness_size).toLocaleString() + ' entries' + (w.witnessed_at ? ', from its run ' + ago(w.witnessed_at) : '') + (w.status === 'stale' ? ' (its job has stopped running)' : '') + '.';
  }).catch(function () { $('h-size').textContent = 'The log couldn’t be read just now.'; $('h-signed').textContent = '–'; $('h-witness').textContent = '–'; });

  // ---- Recent receipts: the newest agent posts, each checked in this browser, one at a time ----
  var queue = [], busy = false, next = null;
  function pump() {
    if (busy || !queue.length) return;
    busy = true;
    var job = queue.shift();
    check({ ref: job.id }, null, function (m) {
      var st = m.type === 'done' ? m.result.status : null;
      job.pill.className = st ? PILL[st] : 'pill m';
      job.pill.textContent = st ? LABEL[st] : 'Not checked';
      job.pill.title = m.type === 'done' ? m.result.reason : m.message;
      busy = false; pump();
    });
  }
  function cell(tr, child) { var td = document.createElement('td'); td.appendChild(child); tr.appendChild(td); }
  function add(p) {
    if (!p.agent || !p.delegation) return;
    var tr = document.createElement('tr');
    var a = document.createElement('a');
    a.href = '/receipts/' + p.id;
    var code = document.createElement('code');
    code.textContent = '…' + p.id.slice(-8); // the random end: a UUIDv7 starts with its time, so neighbours share a start
    a.appendChild(code);
    a.setAttribute('aria-label', 'Receipt ' + p.id);
    a.title = p.id;
    cell(tr, a);
    cell(tr, document.createTextNode('Agent post'));
    cell(tr, document.createTextNode(p.agent.name + ' for ' + p.author.name));
    var pill = document.createElement('span');
    pill.className = 'pill m';
    pill.textContent = 'Checking';
    cell(tr, pill);
    $('rows').appendChild(tr);
    queue.push({ id: p.id, pill: pill });
  }
  function load(url) {
    var ref = null;
    $('more').disabled = true;
    fetch(url, { headers: { Accept: 'application/json' } })
      .then(function (r) { ref = r.headers && r.headers.get ? r.headers.get('x-vercel-id') : null; return r.json().then(function (d) { return { ok: r.ok, code: r.status, d: d }; }); })
      .then(function (x) {
        if (!x.ok) throw Object.assign(new Error(x.d && x.d.error ? x.d.error : 'The receipts couldn’t be loaded.'), { code: x.code });
        (x.d.posts || []).forEach(add);
        next = x.d.next || null;
        var any = $('rows').children.length > 0;
        $('status').textContent = any ? 'Each receipt’s state is checked here, in your browser, one at a time.' : '';
        $('recent').hidden = !any;
        $('empty').hidden = any;
        $('more-row').hidden = !next;
        $('more').textContent = 'Show older receipts';
        $('more').disabled = false;
        pump();
      })
      .catch(function (e) {
        $('status').textContent = (e && e.code === 429 ? 'Too many requests just now. Please wait a minute, then try again.'
          : e && e.code ? e.message : 'The receipts couldn’t be loaded: the network didn’t answer. Please try again.') + (ref ? ' Reference: ' + ref + '.' : '');
        $('more').textContent = 'Try again';
        $('more').disabled = false;
        $('more-row').hidden = false;
      });
  }
  var first = '/api/feed?lane=agents&limit=10';
  $('more').addEventListener('click', function () { load(next || first); });
  load(first);
})();
