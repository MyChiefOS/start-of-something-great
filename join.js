// Shows the result of a sign-in step on /join (the address says which), without any inline script.
(function () {
  var q = new URLSearchParams(location.search);
  var text = {
    sent: 'Check your email for a sign-in link. It works once, for 15 minutes.',
    cancelled: 'Sign-in was cancelled.',
    expired: 'That sign-in took too long or was already used. Please start again.',
    provider: 'We couldn’t confirm your account with that provider. Please try again.',
    unavailable: 'Sign-in isn’t available for this account right now.',
    taken: 'That account is already linked to a different member.',
    slow: 'Too many tries in a short time. Please wait a few minutes.',
    email: 'That doesn’t look like an email address.',
    signin: 'Please sign in first.',
    email_off: 'Sign-in by email isn\u2019t switched on yet. Please use GitHub or X for now.',
    deleted: 'Your account and everything about it has been deleted. You\u2019re welcome back any time.',
    fast: 'That was quick! Please press the button once more.',
    linked: 'Linked. To keep your account safe, adding a sign-in method signs you out everywhere, here too. Sign in again with any of your sign-in methods.',
    preview: 'New accounts on the site itself aren\u2019t open yet. You can join now with GitHub on this page.',
    sent_preview: 'If this address already has an account, a sign-in link is on its way. It works once, for 15 minutes.',
    disabled: 'This account is disabled while a request to delete it is reviewed. Nothing has been deleted. If it\u2019s restored, you can sign in again.',
    region: 'Day One Great isn\u2019t offered to people who live in the EU, the EEA, the UK or Switzerland, so we can\u2019t sign you up. '
      + 'If this address already has an account, we\u2019ve sent it a sign-in link; you\u2019ll be asked to confirm where you live before you\u2019re signed in.'
  };
  var key = q.get('sent') === '1' ? 'sent' : q.get('sent') === 'region' ? 'region' : q.get('sent') === 'preview' ? 'sent_preview' : q.get('deleted') === '1' ? 'deleted' : q.get('linked') === '1' ? 'linked' : q.get('error');
  var el = document.getElementById('message');
  if (el && key && text[key]) { el.textContent = text[key]; el.hidden = false; }
})();

// After signing in with GitHub or X, go back to the page that sent you here (for example /review). The server
// checks the path again (signin/http.js returnPath): only a path on this site is ever followed.
(function () {
  var rt = new URLSearchParams(location.search).get('return_to');
  if (!rt || !/^\/(?![/\\])[A-Za-z0-9\-._~/?=&%]*$/.test(rt) || rt.length > 200) return;
  document.querySelectorAll('a[href="/auth/github/start"], a[href="/auth/x/start"]').forEach(function (a) {
    a.setAttribute('href', a.getAttribute('href') + '?return_to=' + encodeURIComponent(rt));
  });
})();

// The email form's sealed time stamp (a bot check, PR 12): fetched when the page opens, so a form sent within a second
// of opening is turned back. People never notice; scripts that post the form straight away are refused.
(function () {
  var f = document.querySelector('form.email-signin input[name="ft"]');
  if (!f || !window.fetch) return;
  fetch('/auth/form', { credentials: 'same-origin', cache: 'no-store' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) { if (d && typeof d.token === 'string') f.value = d.token; })
    .catch(function () { /* the form still works; the server says if the stamp is missing */ });
})();

// Sign in with giscus (Aaron, Oct 28, 2026). Shown only when sign-in is switched on (/auth/me answers). giscus keeps the
// person's sign-in in this page's storage ("giscus-session"); this sends it to /auth/giscus, which asks giscus and GitHub
// who it is and signs that GitHub account in. Nothing is posted, and the session isn't kept anywhere else.
(function () {
  var box = document.getElementById('giscus-signin');
  if (!box || !window.fetch) return;
  var status = document.getElementById('giscus-status');
  var ask = document.getElementById('giscus-region');
  var say = function (t) { status.textContent = t; };
  var words = {
    giscus: 'We couldn\u2019t confirm your giscus sign-in. Sign in again in the comment box below, then press Sign in.',
    slow: 'Too many tries in a short time. Please wait a few minutes.',
    disabled: 'This account is disabled while a request to delete it is reviewed.',
    unavailable: 'Sign-in isn\u2019t available for this account right now.',
    expired: 'Please reload this page and try again.'
  };
  fetch('/auth/me', { credentials: 'same-origin', cache: 'no-store' }).then(function (r) {
    if (r.ok) box.hidden = false;
  }).catch(function () { /* sign-in stays hidden */ });
  function session() {
    try {
      var raw = localStorage.getItem('giscus-session');
      var s = raw ? JSON.parse(raw) : '';
      return typeof s === 'string' ? s : '';
    } catch (e) { return ''; }
  }
  var busy = false;
  function go(confirm) {
    if (busy) return;
    var s = session();
    if (!s) { say('First sign in with GitHub in the comment box below. Then press Sign in.'); return; }
    busy = true;
    say('Signing you in\u2026');
    var rt = new URLSearchParams(location.search).get('return_to') || '';
    var body = { session: s };
    if (rt) body.return_to = rt;
    if (confirm) body.confirm = '1';
    fetch('/auth/giscus', { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body).toString() })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.signed_in) { say('Signed in. Taking you on\u2026'); location.href = d.go || '/feed'; return; }
        if (d.region) {
          document.getElementById('giscus-region-text').textContent = 'You appear to be in ' + d.region + '. Day One Great isn\u2019t offered to people who live in the EU, the EEA, the UK or Switzerland. If you\u2019re a member who lives elsewhere (for example, you\u2019re travelling), you can continue.';
          ask.hidden = false;
          say('');
          return;
        }
        if (d.declined) { say('Day One Great isn\u2019t offered where you live, so we can\u2019t sign you up.'); return; }
        say(words[d.error] || words.unavailable);
      })
      .catch(function () { say('Couldn\u2019t reach the site just now. Please try again.'); })
      .then(function () { busy = false; });
  }
  document.getElementById('giscus-go').addEventListener('click', function () { go(false); });
  document.getElementById('giscus-region-yes').addEventListener('click', function () { ask.hidden = true; go(true); });
})();
