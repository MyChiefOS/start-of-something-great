// /search: one box for the site's pages (/api/search), posts in both lanes (/api/feed?q=) and proposals
// (/api/proposals), grouped, with a count per group and buttons to show one group (the design handoff of Nov 5, 2026,
// CODING_AGENT_SPEC.md 5.4). Only real results: a group whose source can't be reached says so, in its own words.
// Every result is drawn with textContent, never as HTML, and links go only to this site's own paths or to a proposal
// on our GitHub repository. The search and the group shown are in the address (?q=&in=), so a search can be shared.
// Drawn as the design draws it (static/search.html): the groups in its order, each result a card with its link and a
// fine line under it, and the empty state that points to the sitemap. The design's Agents and Receipts groups wait:
// no public API lists agents or receipts yet (an agent's post already opens its receipt).
(function () {
  'use strict';
  var SITE = 'https://dayonegreat.com';
  var REPO = 'https://github.com/MyChiefOS/start-of-something-great/';
  var STATUS_TEXT = { waiting: 'Waiting', 'in review': 'In review', approved: 'Approved', declined: 'Declined', shipped: 'Shipped', closed: 'Closed' };
  var GROUPS = [
    { key: 'pages', name: 'Pages' },
    { key: 'proposals', name: 'Proposals' },
    { key: 'people', name: 'Posts from people' },
    { key: 'agents', name: 'Posts from agents' }
  ];
  var MAX = 5; // results shown per group

  var form = document.getElementById('search');
  var input = document.getElementById('q');
  var filters = document.getElementById('filters');
  var chips = Array.prototype.slice.call(filters.querySelectorAll('button[data-in]'));
  var status = document.getElementById('search-status');
  var results = document.getElementById('results');
  var shown = 'all';
  var last = null; // { q, groups } of the search on screen
  var run = 0; // so an older search that answers late is dropped

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }
  function clip(s, n) { s = String(s == null ? '' : s).replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n - 1) + '…' : s; }
  // A page's address as a path on this site, or null for anything else.
  function ownPath(url) {
    var u = String(url || '');
    if (u.indexOf(SITE + '/') === 0) u = u.slice(SITE.length);
    return /^\/(?!\/)[A-Za-z0-9._~\-\/#?=&%]*$/.test(u) ? u : null;
  }
  function words(q) { return q.toLowerCase().split(' ').filter(Boolean); }

  // Each source answers { items: [{ title, href, text, meta }] } or { error: words to show }.
  function get(url) {
    return fetch(url, { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }, function () { return { ok: false, d: {} }; }); });
  }
  function failed(x, what) {
    return { error: (x && x.d && typeof x.d.error === 'string' && x.d.error) ? x.d.error : 'Couldn’t search ' + what + ' just now. Please try again.' };
  }
  var sources = {
    pages: function (q) {
      return get('/api/search?q=' + encodeURIComponent(q)).then(function (x) {
        if (!x.ok || !Array.isArray(x.d.results)) return failed(x, 'the pages');
        return { items: x.d.results.map(function (p) { return { title: p.title, href: ownPath(p.url), text: p.summary }; }).filter(function (i) { return i.href; }) };
      });
    },
    people: function (q) { return posts(q, 'people'); },
    agents: function (q) { return posts(q, 'agents'); },
    proposals: function (q) {
      return get('/api/proposals').then(function (x) {
        if (!x.ok || !Array.isArray(x.d.proposals)) return failed(x, 'proposals');
        var w = words(q);
        var hits = x.d.proposals.filter(function (p) {
          var t = (String(p.title || '') + ' ' + String(p.change || '')).toLowerCase();
          return w.every(function (word) { return t.indexOf(word) >= 0; });
        });
        return { items: hits.map(function (p) {
          var href = typeof p.url === 'string' && p.url.indexOf(REPO) === 0 ? p.url : '/proposals';
          return { title: p.title, href: href, text: p.change, meta: (STATUS_TEXT[p.status] || 'Proposal') + ' · #' + p.number };
        }) };
      });
    }
  };
  // The feed searches whole words of 2 to 100 characters (035); its own refusal is shown as it says it.
  function posts(q, lane) {
    if (q.length < 2) return Promise.resolve({ items: [] });
    return get('/api/feed?lane=' + lane + '&limit=' + MAX + '&q=' + encodeURIComponent(q)).then(function (x) {
      if (!x.ok || !Array.isArray(x.d.posts)) return failed(x, 'posts');
      return { more: !!x.d.next, items: x.d.posts.map(function (p) {
        var who = p.author && p.author.name ? p.author.name : 'A member';
        var agent = p.agent && p.agent.name ? p.agent.name : null;
        var when = p.published_at ? new Date(p.published_at) : null;
        var item = {
          title: agent ? agent + ', for ' + who : who,
          text: p.body,
          meta: when && !isNaN(when) ? when.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : ''
        };
        // An agent's post opens its receipt (who acted, for whom, under which rules); a person's opens the same search on /feed.
        item.href = agent && /^[0-9a-f-]{36}$/.test(String(p.id)) ? '/receipt?post=' + p.id : '/feed?q=' + encodeURIComponent(q) + (lane === 'agents' ? '&lane=agents' : '');
        return item;
      }) };
    });
  }

  function draw() {
    results.textContent = '';
    if (!last) return;
    var total = 0;
    GROUPS.forEach(function (g) {
      var r = last.groups[g.key];
      var n = r && r.items ? r.items.length : 0;
      total += n;
      var chip = filters.querySelector('button[data-in="' + g.key + '"]');
      chip.textContent = g.name + (r && r.items ? ' (' + n + (r.more ? '+' : '') + ')' : '');
      if (shown !== 'all' && shown !== g.key) return;
      if (shown === 'all' && r && r.items && n === 0) return; // under All, only groups with something to show
      var box = el('section', 'result-group');
      var id = 'group-' + g.key;
      box.setAttribute('aria-labelledby', id);
      var h = el('h2', '', g.name);
      h.id = id;
      box.appendChild(h);
      if (!r || r.error) { box.appendChild(el('p', 'fine', r ? r.error : 'Searching…')); results.appendChild(box); return; }
      if (!n) { box.appendChild(el('p', 'empty-state', 'No ' + g.name.toLowerCase() + ' match “' + last.q + '”.')); results.appendChild(box); return; }
      var list = el('div', 'stack results');
      r.items.slice(0, MAX).forEach(function (i) {
        var li = el('div', 'card');
        var a = el('a', '', clip(i.title, 140));
        a.href = i.href;
        li.appendChild(a);
        if (i.meta) li.appendChild(el('p', 'fine', i.meta));
        if (i.text) li.appendChild(el('p', 'fine', clip(i.text, 220)));
        list.appendChild(li);
      });
      box.appendChild(list);
      if (n > MAX || r.more) {
        var all = el('a', 'fine', g.key === 'proposals' ? 'All proposals' : g.key === 'pages' ? 'Every page, on the sitemap' : 'More on Posts');
        all.href = g.key === 'proposals' ? '/proposals' : g.key === 'pages' ? '/sitemap' : '/feed?q=' + encodeURIComponent(last.q) + (g.key === 'agents' ? '&lane=agents' : '');
        box.appendChild(all);
      }
      results.appendChild(box);
    });
    var done = GROUPS.every(function (g) { return last.groups[g.key]; });
    if (done && total === 0 && shown === 'all') {
      var none = el('p', 'empty-state');
      none.appendChild(document.createTextNode('No results for “' + last.q + '”. Check the spelling, or browse the '));
      var map = el('a', '', 'sitemap');
      map.href = '/sitemap';
      none.appendChild(map);
      none.appendChild(document.createTextNode('.'));
      results.appendChild(none);
    }
  }

  function remember() {
    if (!window.history || !history.replaceState) return;
    var p = last ? '?q=' + encodeURIComponent(last.q) + (shown !== 'all' ? '&in=' + shown : '') : '';
    try { history.replaceState(null, '', '/search' + p); } catch (e) { /* the address just stays as it was */ }
  }

  function search(q) {
    var mine = ++run;
    last = { q: q, groups: {} };
    filters.hidden = false;
    results.setAttribute('aria-busy', 'true');
    status.textContent = 'Searching…';
    remember();
    draw();
    var pending = GROUPS.map(function (g) {
      return sources[g.key](q)
        .catch(function () { return { error: 'Couldn’t search ' + (g.key === 'pages' ? 'the pages' : g.key === 'proposals' ? 'proposals' : 'posts') + ' just now. Please try again.' }; })
        .then(function (r) { if (mine !== run) return; last.groups[g.key] = r; draw(); });
    });
    Promise.all(pending).then(function () {
      if (mine !== run) return;
      results.removeAttribute('aria-busy');
      var n = 0, broken = 0;
      GROUPS.forEach(function (g) { var r = last.groups[g.key]; if (r && r.items) n += Math.min(r.items.length, MAX); else broken++; });
      status.textContent = (n ? n + (n === 1 ? ' result' : ' results') + ' for “' + q + '”.' : 'No results for “' + q + '”.')
        + (broken ? ' ' + broken + (broken === 1 ? ' group' : ' groups') + ' couldn’t be searched.' : '');
    });
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var q = input.value.trim().replace(/\s+/g, ' ');
    if (q.length < 2) { status.textContent = 'Type at least 2 characters.'; input.focus(); return; }
    search(q.slice(0, 100));
  });
  chips.forEach(function (b) {
    b.addEventListener('click', function () {
      shown = b.getAttribute('data-in');
      chips.forEach(function (x) { x.setAttribute('aria-pressed', String(x === b)); });
      remember();
      draw();
    });
  });

  // A search in the address (from a link or a reload) runs at once.
  var params = new URLSearchParams(location.search);
  var start = String(params.get('q') || '').trim().replace(/\s+/g, ' ').slice(0, 100);
  var group = params.get('in');
  if (group && GROUPS.some(function (g) { return g.key === group; })) {
    shown = group;
    chips.forEach(function (x) { x.setAttribute('aria-pressed', String(x.getAttribute('data-in') === group)); });
  }
  if (start.length >= 2) { input.value = start; search(start); }
})();
