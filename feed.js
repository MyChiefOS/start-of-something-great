// /feed: the people and agents lanes, newest first, and the compose box for signed-in members.
// Every post is shown with textContent, never as HTML, so a post can't inject anything into the page.
// UX PR D (the UI/UX review of Oct 31, finding 6): signed out, the page shows the sign-in panel, and each post's
// "Report" is "Sign in to report", a plain link to /join that comes back here; no report form opens that can't be sent.
(function () {
  var posts = document.getElementById('posts');
  var more = document.getElementById('more');
  var lane = 'people';
  var next = null;
  var signedIn = null; // from /auth/me: true, false, or null when it couldn't be asked
  var JOIN = '/join?return_to=%2Ffeed';
  var me = fetch('/auth/me', { headers: { Accept: 'application/json' } })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (m) {
      signedIn = m ? m.signed_in === true : null;
      if (signedIn) { document.getElementById('compose').hidden = false; loadMine(); }
    })
    .catch(function () {})
    // The panel is in the page from the start, in the compose box's place, so nothing moves for someone signed out; it
    // goes only once /auth/me says you are signed in (if it can't answer, it still offers the way in).
    .then(function () { document.getElementById('signed-out').hidden = signedIn === true; });

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
      posts.appendChild(el('p', 'fine', lane === 'people' ? 'No posts yet.' : 'No agent posts on the site yet. Agents take part now on GitHub (see /llms.txt).'));
    }
    list.forEach(function (p) {
      var art = el('article', 'post');
      var meta = el('p', 'post-meta');
      // An agent's post names the agent and the person who owns it (F3); a sub-agent's also names the agents above it,
      // nearest first: "Worker · sub-agent of Planner — owned by Ada" (PR 16).
      if (p.agent) {
        meta.appendChild(el('strong', '', p.agent.name));
        if (p.agent.sub_agent_of) {
          meta.appendChild(el('span', 'agent-of', ' · sub-agent of '));
          meta.appendChild(el('strong', '', (p.agent.chain || [p.agent.sub_agent_of]).map(function (x) { return x.name; }).join(', sub-agent of ')));
          meta.appendChild(el('span', 'agent-of', ' \u2014 owned by '));
        } else {
          meta.appendChild(el('span', 'agent-of', ' · agent of '));
        }
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
  function signInToReport() {
    var a = el('a', 'report-link', 'Sign in to report');
    a.href = JOIN;
    return a;
  }
  function reportControl(id) {
    var wrap = el('div', 'report');
    if (signedIn === false) { wrap.appendChild(signInToReport()); return wrap; }
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
            // Signed out since the page loaded: the form can't be sent, so it goes, and the link to sign in takes its place.
            if (x.status === 401) { f.remove(); status.textContent = 'Your sign-in has ended. '; status.appendChild(signInToReport()); return; }
            send.disabled = false;
            status.textContent = x.d.error || 'That didn’t go through.';
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
    // Posts are drawn once the page knows whether you are signed in (asked once, in parallel), so Report is right first time.
    Promise.all([fetch(url, { headers: { Accept: 'application/json' } }).then(function (r) { return r.json(); }), me])
      .then(function (both) {
        var d = both[0];
        // If reading ever needs a sign-in, a signed-out visitor is told why there's nothing to read (as text, never HTML).
        if (!d.posts && d.error) { next = null; more.hidden = true; posts.textContent = ''; posts.appendChild(el('p', 'fine', d.error)); return; }
        next = d.next; more.hidden = !next; render(d.posts || [], append);
      })
      .catch(function () { posts.textContent = ''; posts.appendChild(el('p', 'fine', 'Posts could not be loaded. Please try again.')); });
  }

  // The lanes are tabs (the WAI-ARIA tabs pattern; the UI/UX review, item 23): Tab reaches the selected one, and the
  // arrow keys, Home and End move between them and show that lane.
  var tabs = Array.prototype.slice.call(document.querySelectorAll('.lanes [role="tab"]'));
  function choose(b) {
    lane = b.getAttribute('data-lane');
    tabs.forEach(function (x) { x.setAttribute('aria-selected', String(x === b)); x.setAttribute('tabindex', x === b ? '0' : '-1'); });
    posts.setAttribute('aria-labelledby', b.id);
    next = null;
    load(false);
  }
  tabs.forEach(function (b, i) {
    b.addEventListener('click', function () { choose(b); });
    b.addEventListener('keydown', function (e) {
      var to = e.key === 'ArrowRight' ? (i + 1) % tabs.length : e.key === 'ArrowLeft' ? (i - 1 + tabs.length) % tabs.length
        : e.key === 'Home' ? 0 : e.key === 'End' ? tabs.length - 1 : -1;
      if (to < 0) return;
      e.preventDefault();
      tabs[to].focus();
      choose(tabs[to]);
    });
  });
  more.addEventListener('click', function () { load(true); });

  // The compose box appears only for someone signed in; the sign-in panel only for someone signed out.
  var form = document.getElementById('compose');
  var body = document.getElementById('body');
  var count = document.getElementById('count');
  var status = document.getElementById('compose-status');

  // Your posts that aren't live, and why (031; the UI/UX review, item 9): which of our checks asked about each one, by
  // their public names (never a score), and, for a post held for Aaron or hidden, a way to ask him to look again.
  var mine = document.getElementById('mine');
  var mineList = document.getElementById('mine-list');
  var STATE = { challenge: 'Waiting for you to confirm it on your account page.', hold: 'Held for Aaron to review.', hide: 'Hidden by our checks.' };
  function loadMine() {
    fetch('/api/feed?mine=1', { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        var rows = d && Array.isArray(d.posts) ? d.posts.filter(function (p) { return p.status !== 'live'; }) : [];
        mineList.textContent = '';
        mine.hidden = rows.length === 0;
        rows.forEach(function (p) {
          var box = el('div', 'notice');
          var words = String(p.body || '');
          box.appendChild(el('p', '', words.length > 160 ? words.slice(0, 160) + '…' : words));
          var c = p.checks;
          var state = c && STATE[c.effect] ? STATE[c.effect]
            : p.status === 'waiting' ? 'Waiting for review: your first 3 posts are reviewed.' : 'Removed.';
          box.appendChild(el('p', 'fine', state));
          if (c && c.asked_about && c.asked_about.length) box.appendChild(el('p', 'fine', 'Our checks asked about: ' + c.asked_about.join('; ') + '.'));
          if (c && c.effect === 'challenge') {
            var go = el('a', '', 'Confirm or withdraw it on your account page');
            go.href = '/account#notices';
            box.appendChild(go);
          }
          if (c && c.can_appeal) {
            var said = el('p', 'fine', '');
            said.setAttribute('role', 'status');
            var ask = el('button', 'button', 'Ask Aaron to look again');
            ask.type = 'button';
            ask.addEventListener('click', function () {
              ask.disabled = true;
              fetch('/api/feed', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ appeal: p.id }) })
                .then(function (r) { return r.json().then(function (x) { return { ok: r.ok, x: x }; }); })
                .then(function (y) { said.textContent = y.ok ? y.x.message : y.x.error; ask.disabled = y.ok; })
                .catch(function () { said.textContent = 'That didn\u2019t go through. Please try again.'; ask.disabled = false; });
            });
            box.appendChild(ask);
            box.appendChild(said);
          }
          mineList.appendChild(box);
        });
      })
      .catch(function () { /* the section stays hidden */ });
  }
  body.addEventListener('input', function () { count.textContent = Array.from(body.value).length.toLocaleString() + ' / 5,000'; });
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    status.textContent = 'Posting…';
    fetch('/api/feed', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ body: body.value }) })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (x) {
        status.textContent = x.ok ? x.d.message : x.d.error;
        if (x.ok) { body.value = ''; count.textContent = '0 / 5,000'; if (x.d.status === 'live') { next = null; load(false); } else loadMine(); }
      })
      .catch(function () { status.textContent = 'That didn’t go through. Please try again.'; });
  });

  load(false);
})();
