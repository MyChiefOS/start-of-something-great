// /agents, the public agent directory (the design handoff of Nov 5, 2026: static/directory.html), from the registry's
// public API (040, GET /api/directory): every listed agent, newest first, 50 to a page, with who it acts for, how it
// posts, its daily limit and how many listed sub-agents it has. The page's address carries the page (?before=<agent ID>),
// so every page of the list has a link of its own. The owner's own page moved to /account/agents; a link made before the
// move (/agents#claim=<code>, a notice's /agents#appeal=<id>) is passed on there with its part after the "#". Every name is
// drawn with textContent, never as HTML, and every link goes to our own pages.
(function () {
  'use strict';
  // A claim link goes straight to /claim, its own page since Nov 10; anything else after "#" to /account/agents.
  if (/(?:^#|&)claim=/.test(location.hash)) { location.replace('/claim' + location.hash); return; }
  if (location.hash && location.hash.length > 1) { location.replace('/account/agents' + location.hash); return; }

  // A UUID, checked character by character against a fixed set after its length, so no pattern runs over what the
  // address or an answer holds (signin/flow.js does the same).
  var HEX = '0123456789abcdef';
  function isId(x) {
    if (typeof x !== 'string' || x.length !== 36) return false;
    for (var i = 0; i < 36; i++) { var ch = x.charAt(i); if ((i === 8 || i === 13 || i === 18 || i === 23) ? ch !== '-' : HEX.indexOf(ch) < 0) return false; }
    return true;
  }
  var $ = function (x) { return document.getElementById(x); };
  var MODE = { act: 'Acts on its own', draft: 'Drafts', off: 'Off' };
  var before = new URLSearchParams(location.search).get('before');
  if (before && !isId(before)) before = null;
  var tpl = $('row-tpl');
  function slot(node, name) { return node.querySelector('[data-slot="' + name + '"]'); }
  function limit(a) { return a.mode === 'act' && Number.isInteger(a.daily_cap) ? a.daily_cap + ' a day' : a.mode === 'draft' ? 'Approval needed' : 'Not posting'; }

  function draw(d) {
    var body = $('dir');
    body.textContent = '';
    d.agents.forEach(function (a) {
      if (!a || !isId(String(a.id))) return;
      var tr = tpl.content.firstElementChild.cloneNode(true);
      var name = slot(tr, 'name');
      name.textContent = String(a.name);
      name.href = '/agents/' + a.id;
      var owner = slot(tr, 'owner');
      owner.textContent = String(a.owner && a.owner.name || 'a member');
      if (a.owner && isId(String(a.owner.id))) owner.href = '/member?id=' + a.owner.id; else owner.removeAttribute('href');
      var mode = slot(tr, 'mode');
      mode.textContent = MODE[a.mode] || 'Off';
      if (a.mode === 'act') mode.className = 'pill a';
      slot(tr, 'limit').textContent = limit(a);
      slot(tr, 'subs').textContent = String(Number(a.sub_agents) || 0);
      body.appendChild(tr);
    });
    var some = body.children.length > 0;
    $('dir-wrap').hidden = !some;
    $('dir-empty').hidden = some || !!before;
    var total = Number(d.total) || 0;
    $('counted').textContent = total === 1 ? '1 agent listed' : total + ' agents listed';
    $('dir-status').textContent = !some && before ? 'No older agents. ' : '';
    if (!some && before) { var back = document.createElement('a'); back.href = '/agents'; back.textContent = 'Back to the newest'; $('dir-status').appendChild(back); }
    var next = typeof d.next === 'string' && /^\/api\/directory\?before=[0-9a-f-]{36}$/.test(d.next) ? d.next.split('=')[1] : null;
    $('more-row').hidden = !next && !before;
    $('more').hidden = !next;
    if (next) $('more').href = '/agents?before=' + next;
    $('newest').hidden = !before;
  }
  function load() {
    $('retry-row').hidden = true;
    $('dir-status').textContent = 'Loading the agents…';
    fetch('/api/directory' + (before ? '?before=' + before : ''), { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (x) {
        if (!x.ok || !x.d || !Array.isArray(x.d.agents)) throw new Error((x.d && typeof x.d.error === 'string' && x.d.error) || '');
        if (x.d.available === false) { $('dir-status').textContent = String(x.d.message || 'The directory isn’t switched on here.'); return; }
        draw(x.d);
      })
      .catch(function (e) {
        $('dir-status').textContent = (e && e.message) || 'The agents couldn’t be loaded.';
        $('retry-row').hidden = false;
      });
  }
  $('retry').addEventListener('click', load);
  load();
})();
