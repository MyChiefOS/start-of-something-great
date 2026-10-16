// /account (PR 8): your name, how you sign in, signing out, and deleting your account (F8).
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
    'error=review': REVIEW
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
      if (q.get('error') === 'fresh') {
        var again = el('a', '', 'Sign in again');
        again.href = '/join?return_to=%2Faccount';
        msg.after(again);
      }
      document.getElementById('who').textContent = 'Level ' + d.trust_level + ' · joined ' + new Date(d.joined).toLocaleDateString() + ' · member ID ' + d.member_id;
      var list = document.getElementById('signins');
      d.sign_ins.forEach(function (s) { list.appendChild(el('li', '', 'Signs in with ' + (PROVIDER[s.provider] || s.provider) + ' (level ' + s.level + ')')); });
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

  // ---- Notices (PR 13): the inbox every notice lands in first, and the optional email copies ----
  var summary = document.getElementById('notices-summary');
  var noticeList = document.getElementById('notice-list');
  var readAll = document.getElementById('read-all');
  var emailState = document.getElementById('email-state');
  var emailForm = document.getElementById('email-form');
  var quietForm = document.getElementById('quiet-form');
  var emailActions = document.getElementById('email-actions');
  var toggle = document.getElementById('copies-toggle');
  var zone = (function () { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'America/Los_Angeles'; } catch (e) { return 'America/Los_Angeles'; } })();

  function notifyPost(path, body) {
    return fetch('/api/notify/' + path, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().then(function (x) { return { ok: r.ok, status: r.status, d: x }; }); });
  }
  function hours(select, value) {
    select.textContent = '';
    for (var h = 0; h < 24; h++) {
      var o = el('option', '', (h < 10 ? '0' : '') + h + ':00');
      o.value = String(h);
      if (h === value) o.selected = true;
      select.appendChild(o);
    }
  }
  function renderNotices(d) {
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
      var row = el('p', 'fine');
      if (n.link) { var a = el('a', '', 'Open'); a.href = n.link; row.appendChild(a); row.appendChild(document.createTextNode(' ')); }
      if (!n.read) {
        var mark = el('button', 'button', 'Mark read');
        mark.type = 'button';
        mark.addEventListener('click', function () {
          mark.disabled = true;
          notifyPost('read', { ids: [n.id] }).then(function (x) { if (x.ok) loadNotices(); else mark.disabled = false; });
        });
        row.appendChild(mark);
      }
      card.appendChild(row);
      noticeList.appendChild(card);
    });
    var e = d.email;
    emailForm.hidden = !e.offered;
    quietForm.hidden = !e.address;
    emailActions.hidden = !e.address;
    if (!e.offered && !e.address) { emailState.textContent = 'Email copies aren’t switched on yet. Everything arrives here.'; return; }
    if (!e.address) { emailState.textContent = 'No email copies: add an address to get them.'; return; }
    var STATE = { pending: 'waiting for your confirmation (check your email)', active: 'on', off: 'off', suppressed: 'stopped: emails to this address bounced or were marked as spam. Add another address to start again.' };
    emailState.textContent = 'Copies to ' + e.address + ': ' + (STATE[e.status] || e.status) + '.';
    hours(document.getElementById('quiet-start'), e.quiet_start);
    hours(document.getElementById('quiet-end'), e.quiet_end);
    document.getElementById('quiet-zone').textContent = '(' + e.time_zone + ')';
    toggle.hidden = !(e.status === 'active' || (e.status === 'off' && e.confirmed));
    toggle.textContent = e.status === 'active' ? 'Pause email copies' : 'Turn email copies back on';
  }
  function loadNotices() {
    fetch('/api/notify', { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.json().then(function (x) { return { ok: r.ok, d: x }; }); })
      .then(function (x) { if (x.ok) renderNotices(x.d); else summary.textContent = x.d.error || 'Your notices could not be loaded.'; })
      .catch(function () { summary.textContent = 'Your notices could not be loaded. Please try again.'; });
  }
  readAll.addEventListener('click', function () { readAll.disabled = true; notifyPost('read', { all: true }).then(function () { readAll.disabled = false; loadNotices(); }); });
  emailForm.addEventListener('submit', function (ev) {
    ev.preventDefault();
    notifyPost('email', { address: document.getElementById('email-address').value, time_zone: zone }).then(function (x) {
      emailState.textContent = x.ok ? x.d.message : x.d.error;
      if (x.ok) { document.getElementById('email-address').value = ''; loadNotices(); }
    });
  });
  quietForm.addEventListener('submit', function (ev) {
    ev.preventDefault();
    notifyPost('settings', { quiet_start: Number(document.getElementById('quiet-start').value), quiet_end: Number(document.getElementById('quiet-end').value), time_zone: zone })
      .then(function (x) { emailState.textContent = x.ok ? 'Quiet hours saved.' : x.d.error; if (x.ok) loadNotices(); });
  });
  toggle.addEventListener('click', function () {
    notifyPost('email', { copies: toggle.textContent.indexOf('Pause') === 0 ? 'off' : 'on' }).then(function (x) { if (!x.ok) emailState.textContent = x.d.error; loadNotices(); });
  });
  var armed = false;
  document.getElementById('email-remove').addEventListener('click', function (ev) {
    if (!armed) { armed = true; ev.target.textContent = 'Tap again to remove'; return; }
    notifyPost('email', { remove: true }).then(function (x) { emailState.textContent = x.ok ? x.d.message : x.d.error; armed = false; ev.target.textContent = 'Remove my address'; loadNotices(); });
  });
})();
