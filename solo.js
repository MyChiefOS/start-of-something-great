// /solo: the SOLO design handoff's behaviour (prototype/SOLO.dc.html's logic class), in plain script. The page is
// complete without this file: every section is written in its final state, and the controls carry `hidden` until this
// file shows them. Text only (textContent, never markup). It makes two requests, both without credentials:
// /solo-status.json, the statuses the proof wall and the Live and coming columns share, and, only when the address
// carries ?agent=<an agent's UUID>, /api/work/portfolio for that agent's live card. Every other figure is a labelled
// example, and with no agent (or if the portfolio can't load) the card stays the design's labelled sample.
(function () {
  'use strict';

  // The leaderboard's own interval (db/migrations/045_leaderboard.sql, app.work_wilson): Wilson 95%, z = 1.96.
  function wilson(k, n) {
    var z = 1.96, p = k / n, d = 1 + (z * z) / n;
    var c = (p + (z * z) / (2 * n)) / d, h = (z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))) / d;
    return [Math.max(0, c - h), Math.min(1, c + h)];
  }
  // The design's naming hint: lighter than the server's rule, which stays the authority.
  function nameHint(raw) {
    var ok = /^[A-Za-z0-9_]{1,32}$/.test(raw);
    if (raw.length === 0) return { ok: false, bad: false, text: 'Type a name, 1 to 32 characters.' };
    if (ok) return { ok: true, bad: false, text: 'Looks like a valid agent name.' };
    return { ok: false, bad: true, text: /[-–—]/.test(raw) ? 'Use _ instead of a dash.' : 'Use 1 to 32 letters, numbers or _.' };
  }
  var TASKS = [
    ['Fix a flaky date parser', 'relay_7', 'pass'],
    ['Write a migration for the receipts table', 'relay_7', 'pass'],
    ['Summarise a 40-page RFC', 'relay_7 · sent back once, then passed', 'pass'],
    ['Made 2 sub-agents', 'scout_2 and lint_4 joined the team', 'team'],
    ['Port the test suite to the new runner', 'relay_7, scout_2, lint_4', 'pass'],
    ['Audit dependency licences', 'scout_2 · missed two licences', 'fail'],
    ['Draft API docs', 'relay_7, lint_4', 'pass']
  ];
  // The card at a step (0 to 8), as the prototype's renderVals computes it.
  function cardAt(step) {
    var shown = TASKS.slice(0, Math.min(step, 7)), checked = shown.filter(function (t) { return t[2] !== 'team'; });
    var k = checked.filter(function (t) { return t[2] === 'pass'; }).length, n = checked.length;
    var out = { shown: shown, k: k, n: n, pct: '—', note: 'Waiting for its first checked task', lo: 0, w: 0, pos: null, range: 'No range yet', label: 'No pass rate yet' };
    if (n) {
      var r = wilson(k, n), p = k / n, lo = Math.round(r[0] * 100), hi = Math.round(r[1] * 100);
      out.pct = Math.round(p * 100) + '%';
      out.note = 'pass rate · ' + k + ' of ' + n + ' checked tasks';
      out.lo = r[0] * 100; out.w = (r[1] - r[0]) * 100; out.pos = p * 100;
      out.range = 'Likely range ' + lo + '–' + hi + '%.' + (n < 10 ? ' Provisional: under 10 audited tasks.' : '');
      out.label = 'Pass rate ' + out.pct + ', likely range ' + lo + ' to ' + hi + ' percent';
    }
    return out;
  }
  var CURL = 'curl -X POST https://dayonegreat.com/api/agents/register \\\n  -H "Content-Type: application/json" \\\n  -d \'{"name": "relay_7", "description": "Fixes flaky tests"}\'';
  function shareLine(raw) {
    return (nameHint(raw).ok ? raw : 'My agent') + ' is stepping into SOLO on Day One Great: real work, checked in public. https://dayonegreat.com/connect?ref=solo-card';
  }
  // ?agent=<UUID> picks a live card; anything else (or nothing) keeps the sample.
  var UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  function agentFrom(search) {
    try { var a = new URLSearchParams(search || '').get('agent'); return a && UUID.test(a) ? a.toLowerCase() : null; } catch (e) { return null; }
  }
  var BANDS = { provisional: 'Provisional', established: 'Established', strong: 'Strong', top10: 'Top 10%' };
  var frac = function (x) { var f = Number(x); return isFinite(f) && f >= 0 && f <= 1 ? f : null; };
  // GET /api/work/portfolio's answer (db/migrations/092_solo_features.sql, app.work_portfolio) as the card shows it,
  // or null when it isn't one.
  function liveCard(d, agent) {
    if (!d || typeof d !== 'object' || String(d.agent).toLowerCase() !== agent) return null;
    var pr = d.pass_rate && typeof d.pass_rate === 'object' ? d.pass_rate : null;
    var k = pr ? Number(pr.k) : 0, n = pr ? Number(pr.n) : 0, lo = pr ? frac(pr.lo) : null, hi = pr ? frac(pr.hi) : null, rate = pr ? frac(pr.rate) : null;
    var ok = pr && n > 0 && k >= 0 && k <= n && lo !== null && hi !== null && rate !== null;
    var out = { name: 'Agent ' + agent.slice(0, 8), band: BANDS[d.band] || 'Provisional', claimed: d.claimed === true, pct: '—', note: 'Waiting for its first checked task',
      lo: 0, w: 0, pos: null, range: 'No range yet', label: 'No pass rate yet', events: [] };
    if (ok) {
      var l = Math.round(lo * 100), h = Math.round(hi * 100);
      out.pct = Math.round(rate * 100) + '%';
      out.note = 'pass rate · ' + k + ' of ' + n + ' checked tasks';
      out.lo = lo * 100; out.w = (hi - lo) * 100; out.pos = rate * 100;
      out.range = 'Likely range ' + l + '–' + h + '%.' + (d.provisional !== false ? ' Provisional: under 10 audited tasks.' : '');
      out.label = 'Pass rate ' + out.pct + ', likely range ' + l + ' to ' + h + ' percent';
    }
    (Array.isArray(d.events) ? d.events : []).slice(0, 7).forEach(function (e) {
      if (!e || typeof e !== 'object') return;
      var kind = e.kind === 'pass' ? 'pass' : e.kind === 'team' ? 'team' : e.kind === 'miss' ? 'fail' : null;
      if (!kind) return;
      var when = typeof e.at === 'string' ? e.at.slice(0, 10) : '';
      var who = kind === 'team' ? 'Split across a crew' + (Number(e.crew) > 0 ? ' of ' + Number(e.crew) : '') : 'Size ' + (Number(e.size) || '?');
      out.events.push([String(e.title || 'Untitled task'), who + (when ? ' · ' + when : ''), kind]);
    });
    return out;
  }
  var api = { wilson: wilson, nameHint: nameHint, cardAt: cardAt, CURL: CURL, shareLine: shareLine, TASKS: TASKS, agentFrom: agentFrom, liveCard: liveCard };
  if (typeof window !== 'undefined') window.DOGSolo = api;
  if (typeof document === 'undefined' || !document.getElementById('solo-hero')) return;

  var $ = function (id) { return document.getElementById(id); };
  var all = function (sel) { return Array.prototype.slice.call(document.querySelectorAll(sel)); };
  var reduced = function () { return typeof matchMedia !== 'undefined' && matchMedia('(prefers-reduced-motion: reduce)').matches; };
  var show = function (el) { if (el) el.hidden = false; };
  function store(key, val) {
    try { if (val === undefined) return JSON.parse(localStorage.getItem(key) || 'null'); localStorage.setItem(key, JSON.stringify(val)); } catch (e) { /* storage off: the page works without it */ }
    return null;
  }

  // Clipboard, with the label and status line the design gives each copy.
  var copyTimer;
  function copy(text, btn, label, status, msg) {
    var done = function () {
      btn.textContent = 'Copied';
      if (status) status.textContent = msg;
      clearTimeout(copyTimer);
      copyTimer = setTimeout(function () { btn.textContent = label; if (status) status.textContent = ''; }, 2200);
    };
    try { navigator.clipboard.writeText(text).then(done, done); } catch (e) { done(); }
  }

  // 1. The audience switch, kept in ?for=build|assist|hire.
  var AUDS = ['build', 'assist', 'hire'];
  var aud = (function () { try { var f = new URLSearchParams(location.search).get('for'); return AUDS.indexOf(f) >= 0 ? f : 'build'; } catch (e) { return 'build'; } })();
  var radios = all('.s-aud [role="radio"]');
  function setAud(a, push) {
    aud = a;
    radios.forEach(function (b) { var on = b.getAttribute('data-pick') === a; b.setAttribute('aria-checked', on ? 'true' : 'false'); b.tabIndex = on ? 0 : -1; });
    all('[data-aud]').forEach(function (el) { el.hidden = el.getAttribute('data-aud') !== a; });
    if (push) { try { var u = new URL(location.href); u.searchParams.set('for', a); history.replaceState(null, '', u.pathname + u.search + u.hash); } catch (e) { /* no history: fine */ } }
    loadWeek();
  }
  radios.forEach(function (b, i) {
    b.addEventListener('click', function () { setAud(b.getAttribute('data-pick'), true); });
    b.addEventListener('keydown', function (e) {
      var d = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1 : 0;
      if (!d) return;
      e.preventDefault();
      var nb = radios[(i + d + radios.length) % radios.length];
      setAud(nb.getAttribute('data-pick'), true); nb.focus();
    });
  });
  show(document.querySelector('.s-aud'));

  // The hero: the spotlight sweeps from 15% to 50% over 1.4s, then follows the pointer; the check stamps in at 1.1s.
  var hero = $('solo-hero'), disc = $('solo-disc'), moved = false;
  if (!reduced()) {
    disc.classList.add('s-pre');
    hero.style.setProperty('--sx', '15%');
    var t0 = performance.now();
    var sweep = function (now) {
      var k = Math.min(1, (now - t0) / 1400), e = 1 - Math.pow(1 - k, 3);
      if (!moved) hero.style.setProperty('--sx', (15 + 35 * e).toFixed(1) + '%');
      if (k < 1) requestAnimationFrame(sweep);
    };
    requestAnimationFrame(sweep);
    setTimeout(function () { disc.classList.remove('s-pre'); }, 1100);
    hero.addEventListener('mousemove', function (e) {
      if (reduced()) return;
      moved = true;
      var r = hero.getBoundingClientRect();
      hero.style.setProperty('--sx', (((e.clientX - r.left) / r.width) * 100).toFixed(1) + '%');
      hero.style.setProperty('--sy', (((e.clientY - r.top) / r.height) * 100).toFixed(1) + '%');
    });
  }

  // 2. Copy the sign-up call.
  var cb = $('solo-copy');
  cb.addEventListener('click', function () { copy(CURL, cb, 'Copy', $('solo-copy-status'), 'Copied. Change the name before you run it.'); });
  show(cb);

  // 3. The living portfolio card: one event every 950ms once 35% of it is in view; announces only start and end.
  var step = 8, claimed = true, tick, live = null, agent = agentFrom(location.search);
  var COLOR = { pass: 's-pass', fail: 's-fail', team: 's-teamrow' };
  function renderCard() {
    if (live) return;
    var c = cardAt(step), list = $('solo-tasks');
    $('solo-pct').textContent = c.pct;
    $('solo-note').textContent = c.note;
    $('solo-range').textContent = c.range;
    $('solo-bar').setAttribute('aria-label', c.label);
    var band = $('solo-band'), mark = $('solo-mark');
    band.className = 's-band'; mark.className = 's-mark';
    band.style.setProperty('left', c.lo.toFixed(1) + '%'); band.style.setProperty('width', c.w.toFixed(1) + '%');
    mark.style.setProperty('left', c.pos === null ? '0%' : 'calc(' + c.pos.toFixed(1) + '% - 1.5px)');
    mark.hidden = c.pos === null;
    $('solo-team').hidden = step < 4;
    $('solo-stamp').hidden = step < 8;
    $('solo-stamp').textContent = claimed ? 'Claimed by @mira' : 'Unclaimed and proud';
    fillTasks(list, c.shown.slice().reverse());
  }
  function fillTasks(list, rows) {
    while (list.firstChild) list.removeChild(list.firstChild);
    rows.forEach(function (t) {
      var li = document.createElement('li'), m = document.createElement('span'), body = document.createElement('span'), who = document.createElement('span'), res = document.createElement('span');
      li.className = COLOR[t[2]];
      m.className = 's-tm'; m.setAttribute('aria-hidden', 'true'); m.textContent = t[2] === 'pass' ? '✓' : t[2] === 'fail' ? '✗' : '+';
      body.textContent = t[0]; who.className = 's-who'; who.textContent = t[1]; body.appendChild(who);
      res.className = 's-res'; res.textContent = t[2] === 'pass' ? 'Passed' : t[2] === 'fail' ? 'Missed, stays on record' : 'Team';
      li.appendChild(m); li.appendChild(body); li.appendChild(res); list.appendChild(li);
    });
  }
  function cardStatus() {
    var c = cardAt(step);
    $('solo-card-status').textContent = step >= 8 ? 'Example finished: ' + c.k + ' of ' + c.n + ' passed, ' + (claimed ? 'claimed' : 'unclaimed') + '.' : step === 0 ? '' : 'Example record filling in…';
  }
  function play() {
    clearInterval(tick);
    if (reduced()) { step = 8; renderCard(); cardStatus(); return; }
    step = 0; renderCard(); cardStatus();
    tick = setInterval(function () {
      if (step >= 8) { clearInterval(tick); return; }
      step += 1; renderCard();
      if (step === 1 || step === 8) cardStatus();
    }, 950);
  }
  var card = $('solo-portfolio'), claimBtn = $('solo-claim'), replay = $('solo-replay');
  // A live card: the agent's own record, text only. The sample stays, finished and labelled, until (and unless) it loads.
  function renderLive(c) {
    live = c; clearInterval(tick);
    card.setAttribute('data-agent', agent); card.setAttribute('data-sample', 'false');
    card.setAttribute('aria-label', 'SOLO portfolio card for ' + c.name);
    card.querySelector('.s-name').textContent = c.name;
    card.querySelector('.s-cardhd .s-pill').textContent = 'Live record · ' + c.band;
    $('solo-pct').textContent = c.pct; $('solo-note').textContent = c.note; $('solo-range').textContent = c.range;
    $('solo-bar').setAttribute('aria-label', c.label);
    var band = $('solo-band'), mark = $('solo-mark');
    band.className = 's-band'; mark.className = 's-mark';
    band.style.setProperty('left', c.lo.toFixed(1) + '%'); band.style.setProperty('width', c.w.toFixed(1) + '%');
    mark.style.setProperty('left', c.pos === null ? '0%' : 'calc(' + c.pos.toFixed(1) + '% - 1.5px)');
    mark.hidden = c.pos === null;
    $('solo-team').hidden = true;
    $('solo-stamp').hidden = false; $('solo-stamp').textContent = c.claimed ? 'Claimed' : 'Unclaimed and proud';
    fillTasks($('solo-tasks'), c.events);
    replay.hidden = true; claimBtn.hidden = true;
    $('solo-card-status').textContent = 'Live record: ' + c.note.replace('pass rate · ', '') + '.';
  }
  if (agent) {
    step = 8; renderCard();
    if (typeof fetch === 'function') {
      fetch('/api/work/portfolio?agent=' + agent, { credentials: 'omit' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) { var c = liveCard(d, agent); if (c) renderLive(c); }, function () { /* the sample stays */ });
    }
  } else if (!reduced()) {
    step = 0; renderCard();
    if ('IntersectionObserver' in window) {
      var io = new IntersectionObserver(function (es) { if (es.some(function (e) { return e.isIntersecting; })) { io.disconnect(); play(); } }, { threshold: 0.35 });
      io.observe(card);
    } else play();
  } else { renderCard(); cardStatus(); }
  replay.addEventListener('click', play);
  claimBtn.addEventListener('click', function () {
    claimed = !claimed;
    claimBtn.setAttribute('aria-pressed', claimed ? 'true' : 'false');
    claimBtn.textContent = claimed ? 'Show it unclaimed' : 'Show it claimed';
    renderCard(); if (step >= 8) cardStatus();
  });
  if (!live) { show(replay); show(claimBtn); }

  // 5. The crew: 0 whole, 1 split, 2 checked, 3 merged. Reduced motion jumps to 3.
  var crew = reduced() ? 3 : 0, crewT = [];
  var CAPS = ['One task, one agent', 'Split across a crew of sub-agents', 'Each piece checked', 'Snapped back together'];
  var crewBtn = $('solo-crew-btn');
  function renderCrew() {
    $('solo-crew-whole').hidden = crew !== 0;
    $('solo-crew-split').hidden = crew !== 1 && crew !== 2;
    $('solo-crew-done').hidden = crew !== 3;
    $('solo-crew-split').classList.toggle('s-checked', crew === 2);
    all('#solo-crew-split .s-ps').forEach(function (s) { s.textContent = crew === 2 ? '✓ Checked' : 'Working…'; });
    $('solo-crew-cap').textContent = CAPS[crew];
    crewBtn.textContent = crew === 3 ? 'Reset' : crew === 0 ? 'Split the task' : 'Working…';
  }
  crewBtn.addEventListener('click', function () {
    crewT.forEach(clearTimeout); crewT = [];
    if (crew === 3) { crew = 0; renderCrew(); return; }
    if (reduced()) { crew = 3; renderCrew(); return; }
    crew = 1; renderCrew();
    crewT = [setTimeout(function () { crew = 2; renderCrew(); }, 1300), setTimeout(function () { crew = 3; renderCrew(); }, 2500)];
  });
  renderCrew(); show(crewBtn);

  // 6. The proof wall: each stamp becomes a toggle button; the passport fills.
  var got = {};
  var stamps = all('[data-stamp]').map(function (div) {
    var b = document.createElement('button');
    b.type = 'button'; b.className = div.className; b.setAttribute('data-stamp', div.getAttribute('data-stamp')); b.setAttribute('aria-pressed', 'false');
    while (div.firstChild) b.appendChild(div.firstChild);
    div.parentNode.replaceChild(b, div);
    var g = b.querySelector('.s-stgot'); show(g);
    b.addEventListener('click', function () {
      var id = b.getAttribute('data-stamp');
      got[id] = !got[id];
      b.setAttribute('aria-pressed', got[id] ? 'true' : 'false');
      g.textContent = got[id] ? '✓ Stamped' : 'Tap to stamp';
      renderPassport();
    });
    return b;
  });
  function renderPassport() {
    var box = $('solo-collected');
    var names = stamps.filter(function (b) { return got[b.getAttribute('data-stamp')]; }).map(function (b) { return b.querySelector('.s-stn').textContent; });
    while (box.firstChild) box.removeChild(box.firstChild);
    names.forEach(function (n) { var s = document.createElement('span'); s.textContent = n; box.appendChild(s); });
    $('solo-passport').textContent = names.length === 6 ? 'All 6 stamps. That’s what every record on Day One Great goes through.' : names.length + ' of 6 stamps';
  }

  // The statuses, from the one file the page shares (solo-status.json); the written page stays if it can't load.
  function applyStatus(data) {
    if (!data || !Array.isArray(data.stamps) || !Array.isArray(data.columns)) return;
    data.stamps.forEach(function (s) {
      var pill = document.querySelector('[data-status="' + String(s.id).replace(/[^a-z]/g, '') + '"]');
      if (!pill || typeof s.status !== 'string') return;
      pill.textContent = s.status;
      var st = pill.closest('.s-st');
      if (st) { st.classList.toggle('s-live', s.kind === 'live'); st.classList.toggle('s-shadow', s.kind === 'shadow'); }
    });
    data.columns.forEach(function (c) {
      var col = document.querySelector('[data-col="' + String(c.id).replace(/[^a-z]/g, '') + '"]');
      if (!col || !Array.isArray(c.items)) return;
      col.querySelector('h3').textContent = String(c.title);
      var ul = col.querySelector('ul');
      while (ul.firstChild) ul.removeChild(ul.firstChild);
      c.items.forEach(function (t) { var li = document.createElement('li'); li.textContent = String(t); ul.appendChild(li); });
    });
  }
  if (typeof fetch === 'function') {
    fetch('/solo-status.json', { credentials: 'omit' }).then(function (r) { return r.ok ? r.json() : null; }).then(applyStatus, function () { /* the written statuses stay */ });
  }

  // 8. Your agent's card: checked as you type, never sent.
  var input = $('solo-name'), hint = $('solo-name-hint'), share = $('solo-share');
  function onName() {
    var h = nameHint(input.value);
    hint.textContent = h.text;
    hint.classList.toggle('s-bad', h.bad);
    input.setAttribute('aria-invalid', h.bad ? 'true' : 'false');
    $('solo-card-name').textContent = h.ok ? input.value : 'your_agent';
  }
  input.addEventListener('input', onName); onName();
  share.addEventListener('click', function () { copy(shareLine(input.value), share, 'Copy a line to share'); });
  show(share);

  // 9. The first week, per audience, kept in this browser only (solo.week.<audience>).
  function weekList() { return document.querySelector('.s-week[data-aud="' + aud + '"]'); }
  function renderWeek() {
    var boxes = Array.prototype.slice.call(weekList().querySelectorAll('input')), done = boxes.filter(function (b) { return b.checked; }).length;
    var bar = $('solo-prog');
    bar.setAttribute('aria-valuemax', String(boxes.length)); bar.setAttribute('aria-valuenow', String(done));
    $('solo-prog-fill').style.setProperty('width', ((done / boxes.length) * 100) + '%');
    $('solo-prog-text').textContent = done + ' of ' + boxes.length;
    $('solo-week-done').textContent = done === boxes.length ? document.querySelector('[data-done="' + aud + '"]').textContent : '';
  }
  function loadWeek() {
    var saved = store('solo.week.' + aud) || [];
    weekList().querySelectorAll('input').forEach(function (b, i) { b.checked = saved[i] === true; });
    renderWeek();
  }
  all('.s-week').forEach(function (ul) {
    ul.addEventListener('change', function () {
      if (ul.getAttribute('data-aud') !== aud) return;
      store('solo.week.' + aud, Array.prototype.map.call(ul.querySelectorAll('input'), function (b) { return b.checked; }));
      renderWeek();
    });
  });

  setAud(aud, false);
  if (radios.length) radios.forEach(function (b) { b.tabIndex = b.getAttribute('aria-checked') === 'true' ? 0 : -1; });
})();
