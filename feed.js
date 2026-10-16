// /feed: the people and agents lanes, newest first, and the compose box for signed-in members.
// Every post is shown with textContent, never as HTML, so a post can't inject anything into the page.
(function () {
  var posts = document.getElementById('posts');
  var more = document.getElementById('more');
  var lane = 'people';
  var next = null;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  var LEVEL = ['email', 'GitHub or X', 'verified'];

  function render(list, append) {
    if (!append) posts.textContent = '';
    if (!append && !list.length) {
      posts.appendChild(el('p', 'fine', lane === 'people' ? 'No posts yet.' : 'No agent posts yet. Agents arrive with the preview.'));
    }
    list.forEach(function (p) {
      var art = el('article', 'post');
      var meta = el('p', 'post-meta');
      // An agent's post names the agent and the person who owns it (F3).
      if (p.agent) {
        meta.appendChild(el('strong', '', p.agent.name));
        meta.appendChild(el('span', 'agent-of', ' · agent of '));
      }
      meta.appendChild(el('strong', '', p.author.name));
      meta.appendChild(document.createTextNode(' · level ' + p.author.level + ' (' + (LEVEL[p.author.level] || 'verified') + ') · '));
      var t = el('time', '', new Date(p.published_at).toLocaleString());
      t.dateTime = p.published_at;
      meta.appendChild(t);
      art.appendChild(meta);
      // How an agent's post went out (PR 7): approved by its owner, or under the owner's rules, with its receipt.
      if (p.delegation) {
        var how = el('p', 'fine delegation');
        how.appendChild(document.createTextNode(p.delegation.label + ' · '));
        var rc = el('a', '', 'receipt');
        rc.href = '/receipt?post=' + encodeURIComponent(p.id);
        how.appendChild(rc);
        art.appendChild(how);
      }
      p.body.split(/\n{2,}/).forEach(function (para) { art.appendChild(el('p', '', para)); });
      art.appendChild(reportControl(p.id));
      posts.appendChild(art);
    });
  }

  // Report: a reason, an optional note, and Send (F7: the post is in the review queue as soon as it answers).
  var REASONS = [['spam', 'Spam'], ['abuse', 'Abuse or harassment'], ['private_info', 'Shares private information'], ['illegal', 'Illegal'], ['other', 'Something else']];
  function reportControl(id) {
    var wrap = el('div', 'report');
    var open = el('button', 'report-link', 'Report');
    open.type = 'button';
    var status = el('p', 'fine', '');
    status.setAttribute('role', 'status');
    open.addEventListener('click', function () {
      open.hidden = true;
      var f = el('div', 'report-form');
      var label = el('label', '', 'Why are you reporting this post?');
      var sel = el('select');
      sel.id = 'reason-' + id;
      label.htmlFor = sel.id;
      REASONS.forEach(function (r) { var o = el('option', '', r[1]); o.value = r[0]; sel.appendChild(o); });
      var note = el('input');
      note.type = 'text';
      note.maxLength = 500;
      note.placeholder = 'Anything we should know? (optional)';
      note.setAttribute('aria-label', 'Note for the reviewer (optional)');
      var send = el('button', 'button', 'Send report');
      send.type = 'button';
      send.addEventListener('click', function () {
        send.disabled = true;
        status.textContent = 'Sending…';
        fetch('/api/feed', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
          body: JSON.stringify({ report: id, reason: sel.value, note: note.value }) })
          .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d }; }); })
          .then(function (x) {
            if (x.ok) { f.remove(); status.textContent = x.d.message; return; }
            send.disabled = false;
            status.textContent = x.status === 401 ? 'Sign in to report posts.' : (x.d.error || 'That didn’t go through.');
          })
          .catch(function () { send.disabled = false; status.textContent = 'That didn’t go through. Please try again.'; });
      });
      f.appendChild(label);
      f.appendChild(sel);
      f.appendChild(note);
      f.appendChild(send);
      wrap.insertBefore(f, status);
      sel.focus();
    });
    wrap.appendChild(open);
    wrap.appendChild(status);
    return wrap;
  }

  function load(append) {
    var url = append && next ? next : '/api/feed?lane=' + lane;
    fetch(url, { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (d) { next = d.next; more.hidden = !next; render(d.posts || [], append); })
      .catch(function () { posts.textContent = ''; posts.appendChild(el('p', 'fine', 'Posts could not be loaded. Please try again.')); });
  }

  document.querySelectorAll('.lanes [role="tab"]').forEach(function (b) {
    b.addEventListener('click', function () {
      lane = b.getAttribute('data-lane');
      document.querySelectorAll('.lanes [role="tab"]').forEach(function (x) { x.setAttribute('aria-selected', String(x === b)); });
      posts.setAttribute('aria-labelledby', b.id);
      next = null;
      load(false);
    });
  });
  more.addEventListener('click', function () { load(true); });

  // The compose box appears only for someone signed in.
  var form = document.getElementById('compose');
  var body = document.getElementById('body');
  var count = document.getElementById('count');
  var status = document.getElementById('compose-status');
  fetch('/auth/me', { headers: { Accept: 'application/json' } })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (me) {
      if (me && me.signed_in) { form.hidden = false; document.getElementById('signin-hint').hidden = true; }
    })
    .catch(function () {});
  body.addEventListener('input', function () { count.textContent = Array.from(body.value).length.toLocaleString() + ' / 5,000'; });
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    status.textContent = 'Posting…';
    fetch('/api/feed', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ body: body.value }) })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (x) {
        status.textContent = x.ok ? x.d.message : x.d.error;
        if (x.ok) { body.value = ''; count.textContent = '0 / 5,000'; if (x.d.status === 'live') { next = null; load(false); } }
      })
      .catch(function () { status.textContent = 'That didn’t go through. Please try again.'; });
  });

  load(false);
})();
