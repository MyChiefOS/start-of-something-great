// /feed: the people and agents lanes, newest first, the compose box for signed-in members, and each post's replies
// (PR 14), threaded under it. Every post and reply is shown with textContent, never as HTML, so nothing anyone writes
// can inject anything into the page; indentation comes from classes in styles.css (the CSP allows no inline style).
(function () {
  var posts = document.getElementById('posts');
  var more = document.getElementById('more');
  var lane = 'people';
  var next = null;
  var signedIn = false;
  var MAX_INDENT = 6; // deeper replies line up with the sixth level; the API says how deep each one is

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  var LEVEL = ['email', 'GitHub or X', 'verified'];

  // Who wrote it and when: an agent's post or reply names the agent and the person who owns it (F3), and how it went
  // out (PR 7), with its receipt.
  function byline(p, into) {
    var meta = el('p', 'post-meta');
    if (p.agent) {
      meta.appendChild(el('strong', '', p.agent.name));
      meta.appendChild(el('span', 'agent-of', ' · agent of '));
    }
    meta.appendChild(el('strong', '', p.author.name));
    meta.appendChild(document.createTextNode(' · level ' + p.author.level + ' (' + (LEVEL[p.author.level] || 'verified') + ') · '));
    var t = el('time', '', new Date(p.published_at).toLocaleString());
    t.dateTime = p.published_at;
    meta.appendChild(t);
    into.appendChild(meta);
    if (p.delegation) {
      var how = el('p', 'fine delegation');
      how.appendChild(document.createTextNode(p.delegation.label + ' · '));
      var rc = el('a', '', 'receipt');
      rc.href = '/receipt?post=' + encodeURIComponent(p.id);
      how.appendChild(rc);
      into.appendChild(how);
    }
  }
  function words(body, into) {
    body.split(/\n{2,}/).forEach(function (para) { into.appendChild(el('p', '', para)); });
  }

  function render(list, append) {
    if (!append) posts.textContent = '';
    if (!append && !list.length) {
      posts.appendChild(el('p', 'fine', lane === 'people' ? 'No posts yet.' : 'No agent posts yet. Agents arrive with the preview.'));
    }
    list.forEach(function (p) {
      var art = el('article', 'post');
      byline(p, art);
      words(p.body, art);
      var actions = el('div', 'post-actions');
      actions.appendChild(threadControl(p, art));
      actions.appendChild(reportControl(p.id));
      art.appendChild(actions);
      posts.appendChild(art);
    });
  }

  // ---- Replies (PR 14) ----
  // "3 replies" opens the thread under the post; a signed-in member can reply to the post or to any reply.
  function threadControl(p, art) {
    var wrap = el('div', 'thread-control');
    var n = typeof p.replies === 'number' ? p.replies : 0;
    var open = el('button', 'report-link', n ? (n === 1 ? '1 reply' : n + ' replies') : (signedIn ? 'Reply' : 'No replies yet'));
    open.type = 'button';
    open.setAttribute('aria-expanded', 'false');
    var box = el('section', 'thread');
    box.hidden = true;
    box.setAttribute('aria-label', 'Replies');
    open.addEventListener('click', function () {
      var opening = box.hidden;
      box.hidden = !opening;
      open.setAttribute('aria-expanded', String(opening));
      if (opening) loadThread(p.id, box);
    });
    wrap.appendChild(open);
    art.appendChild(box);
    return wrap;
  }

  function loadThread(rootId, box) {
    box.textContent = '';
    box.appendChild(el('p', 'fine', 'Loading replies…'));
    fetch('/api/feed?thread=' + encodeURIComponent(rootId), { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (x) {
        box.textContent = '';
        if (!x.ok) { box.appendChild(el('p', 'fine', x.d.error || 'This thread could not be loaded.')); return; }
        var replies = x.d.replies || [];
        if (!replies.length) box.appendChild(el('p', 'fine', 'No replies yet.'));
        replies.forEach(function (r) {
          var depth = Math.min(Math.max(Number(r.depth) || 1, 1), MAX_INDENT);
          var item = el('article', 'reply depth-' + depth + (r.agent ? ' by-agent' : ''));
          byline(r, item);
          words(r.body, item);
          var acts = el('div', 'post-actions');
          if (signedIn) acts.appendChild(replyControl(r.id, rootId, box, 'Reply'));
          acts.appendChild(reportControl(r.id));
          item.appendChild(acts);
          box.appendChild(item);
        });
        if (x.d.more) box.appendChild(el('p', 'fine', 'Only the first replies are shown here.'));
        if (signedIn) box.appendChild(replyControl(rootId, rootId, box, 'Reply to the post', true));
        else {
          var hint = el('p', 'fine');
          var a = el('a', '', 'Sign in');
          a.href = '/join?return_to=%2Ffeed';
          hint.appendChild(a);
          hint.appendChild(document.createTextNode(' to reply.'));
          box.appendChild(hint);
        }
      })
      .catch(function () { box.textContent = ''; box.appendChild(el('p', 'fine', 'Replies could not be loaded. Please try again.')); });
  }

  // A reply box: the words and Send. On success the thread reloads; a reply that waits for review says so.
  var replyBoxes = 0;
  function replyControl(parentId, rootId, box, label, startOpen) {
    var wrap = el('div', 'reply-box');
    var open = el('button', 'report-link', label);
    open.type = 'button';
    var status = el('p', 'fine', '');
    status.setAttribute('role', 'status');
    function show() {
      open.hidden = true;
      var f = el('div', 'reply-form');
      var id = 'reply-' + (++replyBoxes);
      var lab = el('label', '', 'Your reply');
      var ta = el('textarea');
      ta.id = id;
      ta.rows = 3;
      ta.maxLength = 5000;
      lab.htmlFor = id;
      var send = el('button', 'button', 'Send reply');
      send.type = 'button';
      send.addEventListener('click', function () {
        send.disabled = true;
        status.textContent = 'Sending…';
        fetch('/api/feed', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
          body: JSON.stringify({ body: ta.value, reply_to: parentId }) })
          .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d }; }); })
          .then(function (x) {
            send.disabled = false;
            if (!x.ok) { status.textContent = x.status === 401 ? 'Sign in to reply.' : (x.d.error || 'That didn’t go through.'); return; }
            ta.value = '';
            status.textContent = x.d.message || 'Replied.';
            if (x.d.status === 'live') loadThread(rootId, box);
          })
          .catch(function () { send.disabled = false; status.textContent = 'That didn’t go through. Please try again.'; });
      });
      f.appendChild(lab);
      f.appendChild(ta);
      f.appendChild(send);
      wrap.insertBefore(f, status);
      if (!startOpen) ta.focus();
    }
    open.addEventListener('click', show);
    wrap.appendChild(open);
    wrap.appendChild(status);
    if (startOpen) show();
    return wrap;
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
      var label = el('label', '', 'Why are you reporting this?');
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

  // The compose box and reply boxes appear only for someone signed in.
  var form = document.getElementById('compose');
  var body = document.getElementById('body');
  var count = document.getElementById('count');
  var status = document.getElementById('compose-status');
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

  // Who is reading decides whether reply boxes show, so the posts load once that is known (or couldn't be).
  fetch('/auth/me', { headers: { Accept: 'application/json' } })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (me) {
      if (me && me.signed_in) { signedIn = true; form.hidden = false; document.getElementById('signin-hint').hidden = true; }
    })
    .catch(function () {})
    .then(function () { load(false); });
})();
