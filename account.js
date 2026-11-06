// /account (PR 8): your name, how you sign in, signing out, and deleting your account (F8). PR 15: unlinking a
// sign-in method, with a form per method (never the last one; the server checks that the session is fresh).
// The forms post to /auth/... themselves; this only fills in the page and shows what happened. Text is set with
// textContent, never as HTML.
// The design handoff of Nov 5, 2026 (static/account.html): "Signed in as <name> · <level>" under the heading, and each
// notice as a card with a pill naming its kind, its words, and its answers in one row of equal buttons
// (CODING_AGENT_SPEC.md 2.2: Approve and Reject with equal weight). The administrator's pages moved to /admin/review and
// /admin/controls; notices written before the move are opened at the new address.
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
    // 037: the PIN and the browsers.
    'saved=pin': 'Your PIN is changed. Use the new one in every browser from now on.',
    'saved=browser_removed': 'Removed. That browser no longer signs in with your PIN; it needs your key file and PIN, or a new code.',
    'error=pin_wrong': 'Nothing was changed: that isn’t your PIN now.',
    'error=pin_weak': 'Nothing was changed: please choose a PIN that’s harder to guess (not one digit repeated, a run like 123456, or a short pattern repeated).',
    'error=pin_again': 'Nothing was changed: the two new PINs weren’t the same.',
    'error=pin_none': 'You don’t have a PIN yet: you set one at your next sign-in.',
    'error=browser': 'Nothing was removed: that browser isn’t on your account any more.',
  };
  var note = q.get('saved') ? NOTES['saved=' + q.get('saved')] : q.get('error') ? NOTES['error=' + q.get('error')] : null;
  // How many tries are left before this session is signed out, after a wrong current PIN (a number only).
  if (q.get('error') === 'pin_wrong' && /^[0-9]$/.test(q.get('left') || '')) note += ' ' + q.get('left') + (q.get('left') === '1' ? ' try is' : ' tries are') + ' left before this session is signed out.';
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
      // Signed out (UX PR D, the UI/UX review of Oct 31, finding 6): the sign-in panel, and nothing else.
      if (!x.ok || !x.d.signed_in) {
        msg.hidden = true;
        document.getElementById('signed-out').hidden = false;
        return;
      }
      var d = x.d;
      var level = { 0: 'Email only', 1: 'GitHub member', 2: 'Verified' }[d.trust_level] || 'Level ' + d.trust_level;
      msg.textContent = note || 'Signed in as ' + d.display_name + ' \u00b7 ' + level;
      if (q.get('error') === 'fresh' || q.get('error') === 'fresh_method' || q.get('error') === 'senior') {
        var again = el('a', '', 'Sign in again');
        again.href = '/join?return_to=%2Faccount';
        msg.after(again);
      }
      // The level's name, as /feed shows it, with what it means (PR E's review, finding 3).
      var whoLine = document.getElementById('who');
      whoLine.textContent = level + ' (level ' + d.trust_level + ') · joined '
        + new Date(d.joined).toLocaleDateString() + ' · member ID ' + d.member_id + ' · ';
      var levels = el('a', '', 'What the levels mean'); levels.href = '/team#levels';
      whoLine.appendChild(levels);
      var list = document.getElementById('signins');
      d.sign_ins.forEach(function (s) {
        // The method only: its own strength number isn't the account's level, and showing both confused (PR E's review).
        var li = el('li', '', 'Signs in with ' + (PROVIDER[s.provider] || s.provider));
        // An Unlink form for each method while there is more than one: a plain same-site POST. /account is served
        // form-action 'self' (vercel.json; guarded by test/security.test.js, which also covers forms built here).
        if (d.sign_ins.length > 1 && s.id) {
          var f = el('form', 'inline-form');
          f.method = 'post';
          f.action = '/auth/account/unlink';
          var hid = el('input');
          hid.type = 'hidden'; hid.name = 'id'; hid.value = s.id;
          var b = el('button', 'btn s', 'Unlink');
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
        var a = el('a', 'btn s', 'Add ' + PROVIDER[p]);
        a.href = '/auth/' + p + '/start?link=1&return_to=%2Faccount';
        add.appendChild(a);
        add.appendChild(document.createTextNode(' '));
      });
      add.hidden = !add.childNodes.length;
      showMethods(d);
      document.getElementById('name').value = d.display_name;
      document.getElementById('sessions').textContent = d.sessions + (d.sessions === 1 ? ' session open' : ' sessions open');
      if (d.deletion_review) {
        msg.textContent = REVIEW + ' Flagged ' + new Date(d.deletion_review.since).toLocaleString() + '; disabled from '
          + new Date(d.deletion_review.disables_at).toLocaleString() + ' unless Aaron decides first.';
        document.getElementById('delete-part').hidden = true;
      }
      if (d.is_admin) {
        document.getElementById('delete-part').hidden = true; document.getElementById('admin-note').hidden = false;
        // The administrator's own pages, linked only for the administrator (the UI/UX review, item 8: they were
        // linked from nowhere). Each page checks again: a link alone opens nothing.
        document.getElementById('go-review').hidden = false; document.getElementById('go-controls').hidden = false;
      }
      document.getElementById('details').hidden = false;
      goToHash();
      loadNotices();
    })
    .catch(function () { msg.textContent = 'Your account could not be loaded. Please try again.'; });

  // 037: your browsers (this one marked, each with Remove), your PIN (set when, and a form to change it) and your key
  // file. This browser is the one whose key ID its IndexedDB keeps (join.js); nothing else is read from it.
  var day = function (t) { return t ? new Date(t).toLocaleDateString() : null; };
  function thisBrowser() {
    return new Promise(function (ok) {
      try {
        if (!window.indexedDB) { ok(null); return; }
        var open = indexedDB.open('dog-signin', 1);
        open.onupgradeneeded = function () { open.result.createObjectStore('keys'); };
        open.onerror = function () { ok(null); };
        open.onsuccess = function () {
          try {
            var r = open.result.transaction('keys', 'readonly').objectStore('keys').get('signin');
            r.onsuccess = function () { ok(r.result && typeof r.result.keyId === 'string' ? r.result.keyId : null); };
            r.onerror = function () { ok(null); };
          } catch (e) { ok(null); }
        };
      } catch (e) { ok(null); }
    });
  }
  function forgetThisBrowser() {
    try {
      var open = indexedDB.open('dog-signin', 1);
      open.onsuccess = function () { try { open.result.transaction('keys', 'readwrite').objectStore('keys').delete('signin'); } catch (e) { /* nothing kept */ } };
    } catch (e) { /* nothing kept */ }
  }
  function showMethods(d) {
    var pinState = document.getElementById('pin-state');
    pinState.textContent = d.pin ? 'Set ' + day(d.pin.set_at) + '. It is never shown or stored as you typed it.'
      : 'You don’t have a PIN yet: you’ll set one at your next sign-in, with a code or with your key file.';
    document.getElementById('pin-form').hidden = !d.pin;
    var kf = document.getElementById('key-file-state');
    kf.textContent = d.key_file ? 'Chosen ' + day(d.key_file.created_at) + (d.key_file.used_at ? ', last used ' + day(d.key_file.used_at) : '')
      + '. It is your backup for a new browser, with your PIN. To use another file, get a new code on /join and choose it there.'
      : 'None now (it was cancelled, or you signed out everywhere). Get a new code on /join and choose a key file to have one again.';
    var list = document.getElementById('browser-list');
    var browsers = d.browsers || [];
    thisBrowser().then(function (mine) {
      if (!browsers.length) { list.appendChild(el('li', '', 'None yet: your next sign-in adds this browser.')); return; }
      browsers.forEach(function (b) {
        var here = b.id === mine;
        var li = el('li', '', b.label + (here ? ' (this browser)' : '') + ': added ' + day(b.added) + (b.used ? ', last signed in ' + day(b.used) : ''));
        var f = el('form', 'inline-form');
        f.method = 'post';
        f.action = '/auth/account/browser/remove';
        var hid = el('input');
        hid.type = 'hidden'; hid.name = 'id'; hid.value = b.id;
        var btn = el('button', 'btn s', 'Remove');
        btn.type = 'submit';
        // Removing this browser forgets its key here too, so the join page doesn't offer a PIN it can't use.
        if (here) f.addEventListener('submit', forgetThisBrowser);
        f.appendChild(hid);
        f.appendChild(btn);
        li.appendChild(document.createTextNode(' '));
        li.appendChild(f);
        list.appendChild(li);
      });
    });
  }

  // The page's parts are hidden until your account loads, so the browser can't jump to /account#notices or #name on
  // its own: once they show, go there (the UI/UX review, finding 11). #name, linked from the welcome on /feed, also
  // puts the cursor in the field. Only this page's own ids are looked up.
  function goToHash() {
    var id = location.hash.slice(1);
    if (!/^[a-z-]+$/.test(id)) return;
    var target = document.getElementById(id);
    if (!target || target.closest('#details') === null) return;
    // A field goes to the middle of the screen with its label; a section to the top.
    if (target.scrollIntoView) target.scrollIntoView(id === 'name' ? { block: 'center' } : undefined);
    if (id === 'name') target.focus({ preventScroll: true });
  }

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
  // Every answer on a notice is the same small button: no answer is drawn as the one to pick (2.2, equal weight).
  function button(label, cls, act) {
    var b = el('button', 'btn s' + (cls ? ' ' + cls : ''), label);
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

  // Back to drafting, as the 90-day clock itself would do (011, app.act_expire): every "acts on its own" becomes
  // "drafts", the daily limit stays. Lowering needs no fresh sign-in (api/agents.js, POST rules).
  var DRAFT = function (m) { return m === 'act' ? 'draft' : m; };

  // The words, shown exactly as written, and the buttons that answer this notice, in one row (the design's .acts).
  function oneTap(n, ctx) {
    var box = el('div', 'one-tap');
    var acts = el('div', 'acts');
    var out = el('p', 'fine', '');
    out.setAttribute('role', 'status');
    if (n.kind === 'draft_waiting' && n.subject && n.subject.kind === 'draft') {
      var d = ctx.activity && ctx.activity.inbox.find(function (x) { return x.id === n.subject.id; });
      if (!d) return null;
      var words = el('blockquote', 'draft-words', d.body);
      box.appendChild(words);
      acts.appendChild(button('Approve and post', '', function (b) {
        sha256(words.textContent).then(function (h) { return postJson('/api/agents/approve', { draft: d.id, hash: h }); })
          .then(function (x) { answered(out, x); b.disabled = x.ok; });
      }));
      acts.appendChild(button('Reject', '', function (b) { postJson('/api/agents/decline', { draft: d.id }).then(function (x) { answered(out, x); b.disabled = x.ok; }); }));
    } else if (n.kind === 'act_reconfirm' && n.subject && n.subject.kind === 'agent') {
      var a = ctx.activity && ctx.activity.agents.find(function (x) { return x.id === n.subject.id; });
      if (!a || !a.acting_alone || !a.rules) return null;
      acts.appendChild(button('Keep acting', '', function (b) {
        postJson('/api/agents/reconfirm', { agent: a.id, version: a.rules.version }).then(function (x) { answered(out, x); b.disabled = x.ok; });
      }));
      acts.appendChild(button('Back to drafts', '', function (b) {
        postJson('/api/agents/rules', { agent: a.id, post: DRAFT(a.rules.post), reply: DRAFT(a.rules.reply), report: DRAFT(a.rules.report), daily_cap: a.rules.daily_cap })
          .then(function (x) {
            if (x.ok) x.d.message = 'Back to drafts: its posts wait for your approval on Your agents.';
            answered(out, x); b.disabled = x.ok;
          });
      }));
    } else if (n.kind === 'challenge' && n.subject && n.subject.kind === 'challenge') {
      var c = ctx.challenges && ctx.challenges.find(function (x) { return x.id === n.subject.id; });
      if (!c || !c.subject || c.subject.kind !== 'post') return null;
      if (c.body) box.appendChild(el('blockquote', 'draft-words', c.body));
      // Which checks asked, by name: on Your posts (the UI/UX review, item 9).
      var why = el('a', 'fine', 'Why was it held? See Your posts');
      why.href = '/feed#mine';
      box.appendChild(why);
      acts.appendChild(button('Confirm: post it', '', function (b) { postJson('/api/feed', { challenge: c.id, answer: 'confirm' }).then(function (x) { answered(out, x); b.disabled = x.ok; }); }));
      acts.appendChild(button('Withdraw it', '', function (b) { postJson('/api/feed', { challenge: c.id, answer: 'decline' }).then(function (x) { answered(out, x); b.disabled = x.ok; }); }));
    } else {
      return null;
    }
    box.appendChild(acts);
    box.appendChild(out);
    return box;
  }

  // The pill on each card names the notice's kind in the design's words; one that needs an answer has the amber edge.
  var KIND = { draft_waiting: 'Draft waiting', act_reconfirm: '90-day check', challenge: 'Held post', signin_keyfile: 'Sign-in',
    signin_linked: 'Sign-in', signin_unlinked: 'Sign-in', signin_pin: 'Sign-in', signin_browser: 'Sign-in', alert: 'Alert' };
  var ASKS = { draft_waiting: true, act_reconfirm: true, challenge: true, alert: true };
  // Notices keep the address they were written with, and the database still writes the old ones (011 to 034): /review
  // and /controls moved to /admin/review and /admin/controls on Nov 5, so the link opens the new address, "#" part kept;
  // a sign-in link that came back to /agents (011's challenge notice) comes back to /account/agents.
  function moved(link) {
    return link.replace(/^\/(review|controls)(?=$|[#?])/, '/admin/$1')
      .replace(/^(\/join\?return_to=)%2Fagents(?=$|[&#]|%23|%3F)/, '$1%2Faccount%2Fagents')
      .replace(/^(\/join\?return_to=)%2F(review|controls)(?=$|[&#]|%23|%3F)/, '$1%2Fadmin%2F$2');
  }

  function renderNotices(d, ctx) {
    noticeList.textContent = '';
    summary.textContent = d.notices.length ? (d.unread ? d.unread + ' unread' : 'All read') : 'No notices yet. When something needs you, it shows up here first.';
    readAll.hidden = !d.unread;
    d.notices.forEach(function (n) {
      var card = el('article', 'card notice-card' + (n.read ? ' decided' : ''));
      card.appendChild(el('span', 'pill ' + (ASKS[n.kind] && !n.read ? 'a' : 'm'), KIND[n.kind] || 'Notice'));
      var title = el('p', 'notice-title');
      title.appendChild(el('strong', '', n.title));
      card.appendChild(title);
      if (n.body) card.appendChild(el('p', '', n.body));
      var tap = oneTap(n, ctx);
      if (tap) card.appendChild(tap);
      var row = el('p', 'fine notice-meta', new Date(n.created_at).toLocaleString() + (n.read ? '' : ' · new') + (n.for_admins ? ' · for administrators' : '') + ' ');
      // Links are paths on this site only (the database refuses anything else); checked again here before use.
      // Notices written before Nov 5 link to /agents, now the public agent list; an owner's agents page is /account/agents.
      if (n.link && /^\/(?![/\\])/.test(n.link)) { var a = el('a', '', 'Open'); a.href = moved(n.link.replace(/^\/agents(?=$|[#?])/, '/account/agents')); row.appendChild(a); row.appendChild(document.createTextNode(' ')); }
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
          .then(function (r) {
            renderNotices(x.d, { activity: r[0], challenges: r[1] && r[1].challenges });
            // Notices above the name field push it down; browsers without scroll anchoring (Safari before 27) don't
            // follow it, so go there again (PR E's review, finding 4).
            if (location.hash === '#name') goToHash();
          });
      })
      .catch(function () { summary.textContent = 'Your notices could not be loaded. Please try again.'; });
  }
  readAll.addEventListener('click', function () { readAll.disabled = true; postJson('/api/notify/read', { all: true }).then(function () { readAll.disabled = false; loadNotices(); }); });
})();
