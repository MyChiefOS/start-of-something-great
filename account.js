// /account (PR 8): your name, how you sign in, signing out, and deleting your account (F8). PR 15: unlinking a
// sign-in method, with a form per method (never the last one; the server checks that the session is fresh).
// The forms post to /auth/... themselves; this only fills in the page and shows what happened. Text is set with
// textContent, never as HTML.
(function () {
  var msg = document.getElementById('message');
  // A deletion JEVs flagged as high risk (PR 12; Aaron, Oct 16, 2026). Nothing is deleted until Aaron decides.
  var REVIEW = 'Your account was flagged as high risk by our automatic checks (JEVs), so it hasn’t been deleted. Aaron will review it '
    + 'and decide. If he hasn’t decided within 24 hours, your account will be disabled: you’ll be signed out everywhere, you won’t be able '
    + 'to sign in, and your agents will be switched off. Nothing is deleted until he decides.';
  var q = new URLSearchParams(location.search);
  var NOTES = {
    'saved=name': 'Saved. New posts show your new name.',
    'error=name': 'A name needs 1 to 80 characters on one line.',
    'error=confirm': 'Nothing was deleted: type DELETE, in capitals, to confirm.',
    'error=admin': 'The administrator can’t delete their own account here.',
    'error=fresh': 'Nothing was deleted: to delete your account, sign in again first, then delete it within 10 minutes.',
    'error=gone': 'That account can’t be deleted right now: it isn’t active.',
    'error=review': REVIEW,
    'saved=unlinked': 'Unlinked. That method no longer signs in to your account, and every other session of yours was signed out. Anything its sessions linked is unlinked, agent keys made from them are revoked, and agents they let act on their own draft for your approval again: your notices say exactly what changed.',
    'error=busy': 'Nothing was changed: something else was changing your account at the same moment. Please try again.',
    'error=fresh_method': 'Nothing was changed: to link or unlink a sign-in method, sign in again first, then do it within 10 minutes.',
    'error=last_method': 'Nothing was changed: that is the only way you sign in. Link another method first.',
    'error=unlink': 'Nothing was changed: that sign-in method isn’t yours or is already gone.',
    'error=senior': 'Nothing was changed: from this session you can remove only a method added after the one you signed in with. To remove an older one, sign in with your oldest method first.',
    'error=link': 'That sign-in method wasn’t linked: the sign-in was cancelled, took too long, or didn’t start from this page. Please try again from here.',
    'error=taken_method': 'That sign-in method wasn’t linked: it already belongs to another account.',
  };
  var note = q.get('saved') ? NOTES['saved=' + q.get('saved')] : q.get('error') ? NOTES['error=' + q.get('error')] : null;
  var PROVIDER = { github: 'GitHub', x: 'X', email: 'email', linkedin: 'LinkedIn' };

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  fetch('/auth/account', { headers: { Accept: 'application/json' } })
    .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
    .then(function (x) {
      if (!x.ok || !x.d.signed_in) {
        msg.textContent = 'Sign in to see your account.';
        var a = el('a', '', 'Sign in');
        a.href = '/join?return_to=%2Faccount';
        msg.after(a);
        return;
      }
      var d = x.d;
      msg.textContent = note || 'Signed in as ' + d.display_name + '.';
      if (q.get('error') === 'fresh' || q.get('error') === 'fresh_method' || q.get('error') === 'senior') {
        var again = el('a', '', 'Sign in again');
        again.href = '/join?return_to=%2Faccount';
        msg.after(again);
      }
      document.getElementById('who').textContent = 'Level ' + d.trust_level + ' · joined ' + new Date(d.joined).toLocaleDateString() + ' · member ID ' + d.member_id;
      var list = document.getElementById('signins');
      d.sign_ins.forEach(function (s) {
        var li = el('li', '', 'Signs in with ' + (PROVIDER[s.provider] || s.provider) + ' (level ' + s.level + ')');
        // An Unlink form for each method while there is more than one: a plain same-site POST. /account is served
        // form-action 'self' (vercel.json; guarded by test/security.test.js, which also covers forms built here).
        if (d.sign_ins.length > 1 && s.id) {
          var f = el('form', 'inline-form');
          f.method = 'post';
          f.action = '/auth/account/unlink';
          var hid = el('input');
          hid.type = 'hidden'; hid.name = 'id'; hid.value = s.id;
          var b = el('button', 'button', 'Unlink');
          b.type = 'submit';
          f.appendChild(hid);
          f.appendChild(b);
          li.appendChild(document.createTextNode(' '));
          li.appendChild(f);
        }
        list.appendChild(li);
      });
      // PR 15: a button to add each provider not linked yet. It is a plain link from this page (a link must start
      // from our own pages), and comes back here.
      var have = d.sign_ins.map(function (s) { return s.provider; });
      var add = document.getElementById('add-methods');
      ['github', 'x'].forEach(function (p) {
        if (have.indexOf(p) >= 0) return;
        var a = el('a', 'button', 'Add ' + PROVIDER[p]);
        a.href = '/auth/' + p + '/start?link=1&return_to=%2Faccount';
        add.appendChild(a);
        add.appendChild(document.createTextNode(' '));
      });
      add.hidden = !add.childNodes.length;
      document.getElementById('name').value = d.display_name;
      document.getElementById('sessions').textContent = d.sessions + (d.sessions === 1 ? ' session open' : ' sessions open');
      if (d.deletion_review) {
        msg.textContent = REVIEW + ' Flagged ' + new Date(d.deletion_review.since).toLocaleString() + '; disabled from '
          + new Date(d.deletion_review.disables_at).toLocaleString() + ' unless Aaron decides first.';
        document.getElementById('delete-part').hidden = true;
      }
      if (d.is_admin) { document.getElementById('delete-part').hidden = true; document.getElementById('admin-note').hidden = false; }
      document.getElementById('details').hidden = false;
      loadNotices();
    })
    .catch(function () { msg.textContent = 'Your account could not be loaded. Please try again.'; });

  // ---- Notices (PR 13): every notice lands here, in-app only ----
  // One tap answers a notice right here, through the same APIs the agents page and the feed use, from this signed-in
  // session: approve or decline a draft's exact words (the SHA-256 of the text shown here goes with the approval, R16),
  // keep an agent acting on its own (R33), or confirm or withdraw a post JEVs is holding for you.
  var summary = document.getElementById('notices-summary');
  var noticeList = document.getElementById('notice-list');
  var readAll = document.getElementById('read-all');

  function postJson(url, body) {
    return fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().then(function (x) { return { ok: r.ok, status: r.status, d: x }; }); });
  }
  function getJson(url) {
    return fetch(url, { headers: { Accept: 'application/json' } }).then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; });
  }
  // The hex SHA-256 of a text, as UTF-8: what the server compares with the words it stored.
  function sha256(text) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)).then(function (buf) {
      return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
    });
  }
  function button(label, cls, act) {
    var b = el('button', 'button' + (cls ? ' ' + cls : ''), label);
    b.type = 'button';
    b.addEventListener('click', function () { b.disabled = true; act(b); });
    return b;
  }
  // What a one-tap answer says back, then the inbox again.
  function answered(out, x) {
    out.textContent = x.d.message || x.d.error || (x.ok ? 'Done.' : 'That didn’t go through. Please try again.');
    // PR 15: keeping an agent acting on its own needs a fresh sign-in; offer one.
    // It comes back to this page (the API's own link returns to /agents).
    if (!x.ok && x.d.reauth) { var again = el('a', '', 'Sign in again'); again.href = '/join?return_to=%2Faccount'; out.appendChild(document.createTextNode(' ')); out.appendChild(again); }
    if (x.ok) setTimeout(loadNotices, 1200);
  }

  // The words, shown exactly as written, and the buttons that answer this notice.
  function oneTap(n, ctx) {
    var box = el('div', 'one-tap');
    var out = el('p', 'fine', '');
    out.setAttribute('role', 'status');
    if (n.kind === 'draft_waiting' && n.subject && n.subject.kind === 'draft') {
      var d = ctx.activity && ctx.activity.inbox.find(function (x) { return x.id === n.subject.id; });
      if (!d) return null;
      var words = el('blockquote', 'draft-words', d.body);
      box.appendChild(words);
      box.appendChild(button('Approve these words', 'primary', function (b) {
        sha256(words.textContent).then(function (h) { return postJson('/api/agents/approve', { draft: d.id, hash: h }); })
          .then(function (x) { answered(out, x); b.disabled = x.ok; });
      }));
      box.appendChild(document.createTextNode(' '));
      box.appendChild(button('Decline', '', function (b) { postJson('/api/agents/decline', { draft: d.id }).then(function (x) { answered(out, x); b.disabled = x.ok; }); }));
    } else if (n.kind === 'act_reconfirm' && n.subject && n.subject.kind === 'agent') {
      var a = ctx.activity && ctx.activity.agents.find(function (x) { return x.id === n.subject.id; });
      if (!a || !a.acting_alone || !a.rules) return null;
      box.appendChild(button('Keep it acting on its own', 'primary', function (b) {
        postJson('/api/agents/reconfirm', { agent: a.id, version: a.rules.version }).then(function (x) { answered(out, x); b.disabled = x.ok; });
      }));
    } else if (n.kind === 'challenge' && n.subject && n.subject.kind === 'challenge') {
      var c = ctx.challenges && ctx.challenges.find(function (x) { return x.id === n.subject.id; });
      if (!c || !c.subject || c.subject.kind !== 'post') return null;
      if (c.body) box.appendChild(el('blockquote', 'draft-words', c.body));
      box.appendChild(button('Confirm: post it', 'primary', function (b) { postJson('/api/feed', { challenge: c.id, answer: 'confirm' }).then(function (x) { answered(out, x); b.disabled = x.ok; }); }));
      box.appendChild(document.createTextNode(' '));
      box.appendChild(button('Withdraw it', '', function (b) { postJson('/api/feed', { challenge: c.id, answer: 'decline' }).then(function (x) { answered(out, x); b.disabled = x.ok; }); }));
    } else {
      return null;
    }
    box.appendChild(out);
    return box;
  }

  function renderNotices(d, ctx) {
    noticeList.textContent = '';
    summary.textContent = d.notices.length ? (d.unread ? d.unread + ' unread' : 'All read') : 'No notices yet. When something needs you, it shows up here first.';
    readAll.hidden = !d.unread;
    d.notices.forEach(function (n) {
      var card = el('article', 'post notice' + (n.read ? ' decided' : ''));
      var meta = el('p', 'post-meta');
      meta.appendChild(el('strong', '', n.title));
      meta.appendChild(document.createTextNode(' · ' + new Date(n.created_at).toLocaleString() + (n.read ? '' : ' · new') + (n.for_admins ? ' · for administrators' : '')));
      card.appendChild(meta);
      if (n.body) card.appendChild(el('p', '', n.body));
      var tap = oneTap(n, ctx);
      if (tap) card.appendChild(tap);
      var row = el('p', 'fine');
      // Links are paths on this site only (the database refuses anything else); checked again here before use.
      if (n.link && /^\/(?!\/)/.test(n.link)) { var a = el('a', '', 'Open'); a.href = n.link; row.appendChild(a); row.appendChild(document.createTextNode(' ')); }
      if (!n.read) {
        row.appendChild(button('Mark read', '', function (b) {
          postJson('/api/notify/read', { ids: [n.id] }).then(function (x) { if (x.ok) loadNotices(); else b.disabled = false; });
        }));
      }
      card.appendChild(row);
      noticeList.appendChild(card);
    });
  }
  function loadNotices() {
    fetch('/api/notify', { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.json().then(function (x) { return { ok: r.ok, d: x }; }); })
      .then(function (x) {
        if (!x.ok) { summary.textContent = x.d.error || 'Your notices could not be loaded.'; return; }
        // What the one-tap answers need, fetched only when a notice asks for it.
        var kinds = x.d.notices.map(function (n) { return n.kind; });
        var needActivity = kinds.indexOf('draft_waiting') >= 0 || kinds.indexOf('act_reconfirm') >= 0;
        var needChallenges = kinds.indexOf('challenge') >= 0;
        return Promise.all([needActivity ? getJson('/api/agents/activity') : null, needChallenges ? getJson('/api/feed?challenges=1') : null])
          .then(function (r) { renderNotices(x.d, { activity: r[0], challenges: r[1] && r[1].challenges }); });
      })
      .catch(function () { summary.textContent = 'Your notices could not be loaded. Please try again.'; });
  }
  readAll.addEventListener('click', function () { readAll.disabled = true; postJson('/api/notify/read', { all: true }).then(function () { readAll.disabled = false; loadNotices(); }); });
})();
