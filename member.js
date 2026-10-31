// /member?id=<member id> (the UI/UX review, finding 13): a member's public page, built only on public answers: the
// profile (/api/feed?profile=) and their live posts and their agents' posts (/api/feed?author=, 035). Nothing here is
// new data: the same name, level, date and posts /feed already shows. Everything is shown with textContent, never as
// HTML, so a name or a post can't inject anything into the page.
(function () {
  var id = new URLSearchParams(location.search).get('id') || '';
  var summary = document.getElementById('summary');
  // No page: one sentence and the way back. A banned, held or deleted member answers exactly as an unknown ID does, so
  // the page never shows that anyone was moderated (the profile reads active members only, 001 and 003).
  function none(text) {
    summary.textContent = text + ' ';
    var back = el('a', '', 'Back to Posts'); back.href = '/feed';
    summary.appendChild(back);
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id)) { none('This address doesn\u2019t name a member.'); return; }
  var LEVEL = ['Email only', 'GitHub member', 'Verified']; // as /feed and /account name them (UX PR E)
  var facts = document.getElementById('facts');
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function row(term, value) { facts.appendChild(el('dt', '', term)); var dd = el('dd', '', ''); if (typeof value === 'string') dd.textContent = value; else dd.appendChild(value); facts.appendChild(dd); }
  function getJson(url) { return fetch(url, { headers: { Accept: 'application/json' } }).then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); }); }

  // One list per lane, newest first, ten at a time, with the same next links /feed uses.
  function lane(name) {
    var part = document.getElementById(name + '-part');
    var list = document.getElementById(name + '-list');
    var more = document.getElementById(name + '-more');
    var sayEl = document.getElementById(name + '-say');
    var next = null;
    var shown = 0;
    // The first page resolves with how many it showed, for the summary line; later pages say so on the list's own line.
    function load(append) {
      more.disabled = true; // one request at a time, so a double press can't show a page twice
      return getJson(append && next ? next : '/api/feed?lane=' + name + '&author=' + id + '&limit=10').then(function (x) {
        more.disabled = false;
        part.hidden = false;
        if (!x.ok || !x.d.posts) { if (!append) list.appendChild(el('p', 'fine', (x.d && x.d.error) || 'These posts could not be loaded.')); more.hidden = true; return 0; }
        next = x.d.next || null;
        var first = null;
        x.d.posts.forEach(function (p) { var a = post(p); if (!first) first = a; list.appendChild(a); if (p.author && p.author.role === 'administrator') admin(); });
        shown += x.d.posts.length;
        if (!shown) list.appendChild(el('p', 'fine', name === 'people' ? 'No live posts yet.' : 'No live posts by their agents.'));
        if (append) {
          // Focus goes to the first new post, so it isn't lost when the button hides after the last page (WCAG 2.4.3).
          sayEl.textContent = x.d.posts.length ? x.d.posts.length + ' more' + (x.d.posts.length === 1 ? ' post' : ' posts') + ' loaded.' : 'No more posts.';
          if (first) { first.tabIndex = -1; first.focus(); }
        }
        more.hidden = !next;
        return { n: x.d.posts.length, more: Boolean(next) };
      }).catch(function () { more.disabled = false; part.hidden = false; list.appendChild(el('p', 'fine', 'These posts could not be loaded. Please try again.')); return null; });
    }
    more.addEventListener('click', function () { if (!more.disabled) load(true); });
    return load(false);
  }
  function post(p) {
    var art = el('article', 'post');
    var meta = el('p', 'post-meta');
    // Who acted, as /feed says it: "Worker · sub-agent of Planner, owned by Ada" (the API's own chain label).
    if (p.agent) { meta.appendChild(el('strong', '', p.agent.name)); meta.appendChild(el('span', 'agent-of', ' \u00b7 ' + (p.agent.chain_label || 'agent of ' + p.author.name) + ' \u00b7 ')); }
    var t = el('time', '', new Date(p.published_at).toLocaleString());
    t.dateTime = p.published_at;
    meta.appendChild(t);
    art.appendChild(meta);
    if (p.delegation) {
      var how = el('p', 'fine delegation');
      how.appendChild(document.createTextNode(p.delegation.label + ' · '));
      var rc = el('a', '', 'receipt'); rc.href = '/receipt?post=' + encodeURIComponent(p.id);
      how.appendChild(rc);
      art.appendChild(how);
    }
    p.body.split(/\n{2,}/).forEach(function (para) { art.appendChild(el('p', '', para)); });
    return art;
  }
  // The administrator's badge comes with their posts (035's author.role); the profile answer doesn't carry it.
  var badged = false;
  function admin() { if (badged) return; badged = true; row('Role', 'Administrator'); }

  getJson('/api/feed?profile=' + id).then(function (x) {
    if (!x.ok || !x.d.profile) { none('There\u2019s no public page for this member.'); return; }
    var m = x.d.profile;
    document.getElementById('name').textContent = m.name;
    document.title = m.name + ' · Day One Great';
    summary.textContent = 'Loading their posts\u2026';
    var lv = el('span', '', (LEVEL[m.level] || 'Level ' + m.level) + ' (level ' + m.level + ') · ');
    var what = el('a', '', 'What the levels mean'); what.href = '/team#levels';
    lv.appendChild(what);
    row('Level', lv);
    row('Joined', new Date(m.joined).toLocaleDateString());
    facts.hidden = false;
    // One line says what both lists show (the lists' own lines would appear with their sections and often go unheard).
    // No total from the profile: it counts their agents' posts with theirs, and posts no list shows (PR F's review).
    var count = function (r, whose) {
      if (!r) return 'none ' + whose + ' (they couldn\u2019t be loaded)';
      return (r.n === 0 ? 'no posts' : r.n + (r.more ? ' newest' : '') + (r.n === 1 ? ' post' : ' posts')) + ' ' + whose;
    };
    Promise.all([lane('people'), lane('agents')]).then(function (r) {
      summary.textContent = 'Showing ' + count(r[0], 'of theirs') + ' and ' + count(r[1], 'by their agents') + '.';
    });
  }).catch(function () { summary.textContent = 'This member could not be loaded. Please try again.'; });
})();
