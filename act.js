// /act: what a link from one of our emails does, shown first; a button does it (R16, R33, confirming an address,
// unsubscribing). The token is after "#", so it never reaches our server or its logs when the page opens, and a mail
// scanner that opens the link changes nothing. It is kept in this tab while the person signs in (sessionStorage).
// Approving sends the SHA-256 of the very words shown on this page. Text is set with textContent, never as HTML.
(function () {
  var msg = document.getElementById('message');
  var heading = document.getElementById('heading');
  var detail = document.getElementById('detail');
  var what = document.getElementById('what');
  var words = document.getElementById('words');
  var go = document.getElementById('go');
  var result = document.getElementById('result');
  var STORE = 'dog_act';
  var KINDS = ['approve', 'keep', 'confirm', 'unsub'];

  function remember(v) { try { if (v) sessionStorage.setItem(STORE, v); else sessionStorage.removeItem(STORE); } catch (e) { /* storage off */ } }
  function recalled() { try { return sessionStorage.getItem(STORE); } catch (e) { return null; } }
  function sha256(text) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)).then(function (buf) {
      return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
    });
  }
  function post(path, body) {
    return fetch('/api/notify/' + path, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d }; }); });
  }
  function signIn() {
    msg.textContent = 'Sign in first, with the account this email was sent to. This page will remember the link.';
    var a = document.createElement('a');
    a.href = '/join?return_to=%2Fact';
    a.textContent = 'Sign in';
    msg.after(a);
  }
  function finish(x, done) {
    go.hidden = true;
    result.textContent = x.ok ? (x.d.message || done) : (x.d.error || 'That didn’t go through.');
    if (x.ok) remember(null);
  }

  var m = /^#(approve|keep|confirm|unsub)=([A-Za-z0-9_.-]{43,140})$/.exec(location.hash);
  var saved = m ? m[1] + '=' + m[2] : recalled();
  if (m) { remember(saved); history.replaceState(null, '', '/act'); }
  var parts = saved ? saved.split('=') : [];
  var kind = KINDS.indexOf(parts[0]) >= 0 ? parts[0] : null;
  var value = parts[1] || '';
  if (!kind) { msg.textContent = 'This link is incomplete. Open it again from the email.'; return; }

  if (kind === 'unsub') {
    var bits = value.split('.');
    heading.textContent = 'Stop email copies';
    msg.textContent = '';
    what.textContent = 'Stop sending copies of your Day One Great notices to your email? Your notices stay in your inbox on the site.';
    go.textContent = 'Stop email copies';
    go.hidden = false;
    detail.hidden = false;
    go.addEventListener('click', function () {
      go.disabled = true;
      post('unsubscribe', { c: bits[0], s: bits[1] }).then(function (x) { finish(x, 'Done.'); });
    });
    return;
  }

  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) { msg.textContent = 'This link is incomplete. Open it again from the email.'; return; }
  post('link', { t: value, preview: true }).then(function (x) {
    if (x.status === 401) return signIn();
    if (!x.ok) { msg.textContent = x.d.error || 'This link can’t be used.'; remember(null); return; }
    var d = x.d;
    msg.textContent = '';
    detail.hidden = false;
    if (d.purpose === 'approve_draft') {
      heading.textContent = 'Approve a draft';
      if (d.draft.status !== 'pending') { msg.textContent = 'That draft has already been decided.'; detail.hidden = true; remember(null); return; }
      what.textContent = d.draft.agent + ' wrote this, word for word. Approve posts exactly these words under your name, marked "approved".';
      words.textContent = d.draft.body;
      words.hidden = false;
      go.textContent = 'Approve';
      go.hidden = false;
      go.addEventListener('click', function () {
        go.disabled = true;
        sha256(words.textContent).then(function (h) { return post('link', { t: value, hash: h }); }).then(function (r) { finish(r, 'Approved and posted.'); });
      });
    } else if (d.purpose === 'keep_acting') {
      heading.textContent = 'Keep it acting on its own';
      what.textContent = d.agent.name + ' acts on its own under your rules (version ' + d.rules.version + ', at most ' + d.rules.daily_cap
        + ' actions a day). Keep it that way for another 90 days? If you don’t, it goes back to drafting for your approval; nothing is switched off.';
      go.textContent = 'Keep acting on its own';
      go.hidden = false;
      go.addEventListener('click', function () { go.disabled = true; post('link', { t: value }).then(function (r) { finish(r, 'Kept.'); }); });
    } else {
      heading.textContent = 'Confirm email copies';
      what.textContent = 'Send copies of your Day One Great notices to the address this email came to? At most one email an hour, never in your quiet hours.';
      go.textContent = 'Confirm';
      go.hidden = false;
      go.addEventListener('click', function () { go.disabled = true; post('link', { t: value }).then(function (r) { finish(r, 'Confirmed.'); }); });
    }
  }).catch(function () { msg.textContent = 'This link could not be checked. Please try again.'; });
})();
