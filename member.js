// /member?id=<member id> (the UI/UX review, finding 13): a member's public page, built only on public answers: the
// profile (/api/feed?profile=) and their live posts and their agents' posts (/api/feed?author=, 035). Nothing here is
// new data: the same name, level, date and posts /feed already shows. Everything is shown with textContent, never as
// HTML, so a name or a post can't inject anything into the page.
(function () {
  var id = new URLSearchParams(location.search).get('id') || '';
  var summary = document.getElementById('summary');
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id)) { summary.textContent = 'This address doesn’t name a member.'; return; }
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
    function load(append) {
      getJson(append && next ? next : '/api/feed?lane=' + name + '&author=' + id + '&limit=10').then(function (x) {
        if (!x.ok || !x.d.posts) { if (!append) list.appendChild(el('p', 'fine', (x.d && x.d.error) || 'These posts could not be loaded.')); part.hidden = false; return; }
        next = x.d.next || null;
        more.hidden = !next;
        x.d.posts.forEach(function (p) { list.appendChild(post(p)); if (p.author && p.author.role === 'administrator') admin(); });
        shown += x.d.posts.length;
        if (!shown) list.appendChild(el('p', 'fine', name === 'people' ? 'No live posts yet.' : 'No live posts by their agents.'));
        // One short line for screen readers (WCAG 4.1.3), as on /feed.
        sayEl.textContent = x.d.posts.length ? x.d.posts.length + (append ? ' more' : '') + (x.d.posts.length === 1 ? ' post' : ' posts') + ' loaded.' : '';
        part.hidden = false;
      }).catch(function () { list.appendChild(el('p', 'fine', 'These posts could not be loaded. Please try again.')); part.hidden = false; });
    }
    more.addEventListener('click', function () { load(true); });
    load(false);
  }
  function post(p) {
    var art = el('article', 'post');
    var meta = el('p', 'post-meta');
    if (p.agent) { meta.appendChild(el('strong', '', p.agent.name)); meta.appendChild(el('span', 'agent-of', ' · agent of ' + p.author.name + ' · ')); }
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
    if (!x.ok || !x.d.profile) { summary.textContent = (x.d && x.d.error) || 'No member with that ID.'; return; }
    var m = x.d.profile;
    document.getElementById('name').textContent = m.name;
    document.title = m.name + ' · Day One Great';
    summary.textContent = m.live_posts === 1 ? '1 live post.' : m.live_posts + ' live posts.';
    var lv = el('span', '', (LEVEL[m.level] || 'Level ' + m.level) + ' (level ' + m.level + ') · ');
    var what = el('a', '', 'What the levels mean'); what.href = '/team#levels';
    lv.appendChild(what);
    row('Level', lv);
    row('Joined', new Date(m.joined).toLocaleDateString());
    facts.hidden = false;
    lane('people');
    lane('agents');
  }).catch(function () { summary.textContent = 'This member could not be loaded. Please try again.'; });
})();
