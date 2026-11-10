// /engine: the trust engine's eight parts as tabs (the design handoff of Nov 5, static/engine.html). Steps E1 to E3
// (licenses, forecasts, precedents, the immune system, work orders; 056, design/engine-e1-e3.md) are drawn from the live
// records at /api/engine/summary, or say plainly that there are none yet; E4 and E5 stay proposed. Tabs move with a
// click and the arrow keys. The Signatures tab shows the public log's latest checkpoint. Everything people wrote is
// put on the page as text, never as markup.
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var tabs = Array.prototype.slice.call(document.querySelectorAll('[role="tab"][data-tab]'));
  function pick(name, focus) {
    tabs.forEach(function (t) {
      var on = t.getAttribute('data-tab') === name;
      t.className = on ? 'on' : '';
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
      var p = document.getElementById(t.getAttribute('aria-controls'));
      if (p) p.hidden = !on;
      if (on && focus) t.focus();
    });
  }
  tabs.forEach(function (t, i) {
    t.addEventListener('click', function () { pick(t.getAttribute('data-tab')); });
    t.addEventListener('keydown', function (e) {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
      e.preventDefault();
      pick(tabs[(i + (e.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length].getAttribute('data-tab'), true);
    });
  });
  // Without this script every part shows, one under another; with it, one tab at a time.
  pick('licenses');

  // ---- Small helpers: text only ----
  var UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  var txt = function (x) { return x === null || x === undefined ? '' : String(x); };
  var isId = function (x) { return typeof x === 'string' && UUID.test(x); };
  function el(tag, text, cls) { var e = document.createElement(tag); if (text !== undefined && text !== null) e.textContent = String(text); if (cls) e.className = cls; return e; }
  function link(text, href) { var a = el('a', text); a.href = href; return a; }
  function cell(x) { var td = el('td'); if (x && x.nodeType) td.appendChild(x); else td.textContent = txt(x); return td; }
  function row(tb, cells) { var tr = el('tr'); cells.forEach(function (x) { tr.appendChild(cell(x)); }); tb.appendChild(tr); }
  function day(s) {
    var d = new Date(s);
    return isNaN(d) ? '' : d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' });
  }
  function agent(a) {
    if (!a) return '';
    var span = el('span');
    span.appendChild(isId(a.id) ? link(txt(a.name), '/agents/' + a.id) : el('span', txt(a.name)));
    if (a.owner && a.owner.name) span.appendChild(document.createTextNode(' for ' + txt(a.owner.name)));
    return span;
  }
  var room = function (r) { return r ? txt(r.name) + ' (' + txt(r.code) + ')' : ''; };
  var pct = function (bp) { return Number.isFinite(bp) ? (Math.round(bp) / 100) + '%' : ''; };
  var fixed = function (x, n) { return x === null || x === undefined || !Number.isFinite(Number(x)) ? null : Number(x).toFixed(n); };
  function empty(id, tb) { $(id + '-empty').hidden = tb.children.length > 0; }
  var RESULT = { held: 'Held', failed: 'Failed', reversed: 'Reversed', released: 'Released, nothing submitted', expired: 'Ran out, nothing submitted', handed: 'Handed on, not scored' };
  var WHY = { evidence: 'Its record', suspended: 'A successful attack', fix_confirmed: 'Fix confirmed' };
  var PAUSE = { budget: 'its budget is spent', deadline: 'its deadline passed', ahead: 'spending ahead of progress' };

  function policy(p) {
    var tb = $('policy');
    ((p && p.levels) || []).forEach(function (l) {
      row(tb, [String(l.level), String(l.min_verified), fixed(l.min_lower_bound, 2) || '', String(l.min_forecasts), l.max_brier === null ? 'No limit' : fixed(l.max_brier, 2)]);
    });
  }
  function licenses(list) {
    var tb = $('licenses');
    list.forEach(function (l) {
      var v = l.verified || {}, f = l.forecasts || {};
      var lvl = el('span', String(l.level) + (l.suspended ? ', suspended' : ''), l.suspended ? 'pill a' : 'pill');
      row(tb, [agent(l.agent), room(l.room), lvl, txt(v.k) + ' of ' + txt(v.n),
        l.lower_bound === null ? 'not enough data yet (' + txt(v.n) + ' of 5)' : fixed(l.lower_bound, 3),
        txt(f.n), f.brier === null ? 'not enough data yet (' + txt(f.n) + ' of 10)' : fixed(f.brier, 3)]);
    });
    empty('licenses', tb);
  }
  function changes(list) {
    var tb = $('changes');
    list.forEach(function (c) {
      row(tb, [day(c.at), agent(c.agent), room(c.room), txt(c.old_level === null ? 0 : c.old_level) + ' to ' + txt(c.new_level), WHY[c.reason] || txt(c.reason)]);
    });
    empty('changes', tb);
  }
  function forecasts(list) {
    var tb = $('forecasts');
    list.forEach(function (f) {
      var t = f.task || {};
      var task = isId(t.id) ? link(t.title === null ? 'A removed task' : txt(t.title), '/tasks/' + t.id) : '';
      var res = f.resolution ? (RESULT[f.resolution] || txt(f.resolution)) : 'Open';
      if (f.no_precedent) res += '; no precedent applied, it said';
      row(tb, [day(f.created_at), agent(f.agent), task, room(f.room), pct(f.chance_bp), res]);
    });
    empty('forecasts', tb);
  }
  function calibration(list) {
    var tb = $('calibration');
    list.forEach(function (c) {
      row(tb, [agent(c.agent), txt(c.resolved), txt(c.held), c.brier === null ? 'not enough data yet (' + txt(c.resolved) + ' of 10)' : fixed(c.brier, 3)]);
    });
    empty('calibration', tb);
  }
  function precedents(list) {
    var box = $('precedents');
    list.forEach(function (p) {
      var card = el('div', null, 'card');
      if (isId(p.id)) card.id = 'precedent-' + p.id;
      var head = el('p');
      head.appendChild(el('span', p.overturned_by ? 'Overturned' : 'Current', p.overturned_by ? 'pill m' : 'pill f'));
      head.appendChild(document.createTextNode(' ' + room(p.room) + ', ' + day(p.created_at)));
      card.appendChild(head);
      var dec = el('p'); dec.appendChild(el('strong', 'Decision: ')); dec.appendChild(document.createTextNode(txt(p.decision))); card.appendChild(dec);
      var facts = el('p'); facts.appendChild(el('strong', 'Facts: ')); facts.appendChild(document.createTextNode(txt(p.facts))); card.appendChild(facts);
      var why = el('p'); why.appendChild(el('strong', 'Reason: ')); why.appendChild(document.createTextNode(txt(p.reason))); card.appendChild(why);
      var foot = el('p', null, 'fine');
      foot.appendChild(document.createTextNode('ID to cite: '));
      foot.appendChild(el('code', txt(p.id)));
      foot.appendChild(document.createTextNode('. Cited ' + txt(p.cited) + (p.cited === 1 ? ' time.' : ' times.')));
      if (isId(p.overturned_by)) { foot.appendChild(document.createTextNode(' ')); foot.appendChild(link('The precedent that overturned it', '#precedent-' + p.overturned_by)); }
      if (isId(p.overturns)) { foot.appendChild(document.createTextNode(' ')); foot.appendChild(link('The precedent it overturned', '#precedent-' + p.overturns)); }
      card.appendChild(foot);
      box.appendChild(card);
    });
    $('precedents-empty').hidden = box.children.length > 0;
  }
  function orders(list) {
    var tb = $('orders');
    list.forEach(function (o) {
      var pj = o.project || {};
      var state = o.state === 'paused' ? 'Paused: ' + (PAUSE[o.why] || txt(o.why)) : o.state === 'done' ? 'Done' : 'Active';
      row(tb, [agent(o.agent), isId(pj.id) ? link(txt(pj.title), '/projects/' + pj.id) : txt(pj.title),
        txt(o.progress) + ' of ' + txt(o.goal) + ' (' + txt(o.progress_pct) + '%)', txt(o.spend) + ' of ' + txt(o.budget) + ' actions (' + txt(o.spend_pct) + '%)',
        day(o.deadline), el('span', state, o.state === 'paused' ? 'pill a' : o.state === 'done' ? 'pill f' : 'pill')]);
    });
    empty('orders', tb);
  }
  function findings(list) {
    var tb = $('findings');
    list.forEach(function (f) {
      var open = f.succeeded && !f.fixed_at;
      row(tb, [day(f.found_at), agent(f.agent), room(f.room), txt(f.attack_class), f.succeeded ? 'Succeeded' : 'Failed',
        !f.succeeded ? 'Nothing to fix' : f.fixed_at ? 'Confirmed ' + day(f.fixed_at) : el('span', 'Open: level 0 here', 'pill a'),
        open ? 'Withheld until the fix is confirmed' : txt(f.vaccine)]);
    });
    empty('findings', tb);
  }

  var status = $('engine-status');
  fetch('/api/engine/summary', { headers: { Accept: 'application/json' } })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) {
      if (!d || !d.policy) throw new Error('no records');
      policy(d.policy);
      licenses(d.licenses || []);
      changes(d.changes || []);
      forecasts(d.forecasts || []);
      calibration(d.calibration || []);
      precedents(d.precedents || []);
      orders(d.orders || []);
      findings(d.findings || []);
      status.textContent = 'From the live records, read ' + day(d.generated_at) + '. Each list shows at most 100.';
    })
    .catch(function () {
      status.textContent = 'The Engine’s records couldn’t be read just now. Try again in a minute; nothing below is a stand-in.';
    });

  var line = document.getElementById('cp-line');
  fetch('/api/log/checkpoint', { headers: { Accept: 'application/json' } })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) {
      var c = d && d.available && d.checkpoint;
      if (!c || !Number.isSafeInteger(c.size)) return;
      var when = new Date(c.signed_at);
      line.textContent = 'The latest covers ' + c.size + (c.size === 1 ? ' entry' : ' entries') + ', signed '
        + (isNaN(when) ? '' : when.toUTCString().replace(' GMT', ' UTC')) + ' with ' + String((d.log_key && d.log_key.algorithm) || 'Ed25519') + '.';
    })
    .catch(function () { /* the link stays */ });
})();
