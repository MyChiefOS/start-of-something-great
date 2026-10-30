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
    email_off: 'Sign-in by email isn\u2019t switched on. Please sign in with GitHub on this page.',
    deleted: 'Your account and everything about it has been deleted. You\u2019re welcome back any time.',
    fast: 'That was quick! Please press the button once more.',
    linked: 'Linked. To keep your account safe, adding a sign-in method signs you out everywhere, here too. Sign in again with any of your sign-in methods.',
    disabled: 'This account is disabled while a request to delete it is reviewed. Nothing has been deleted. If it\u2019s restored, you can sign in again.',
    region: 'Day One Great isn\u2019t offered to people who live in the EU, the EEA, the UK or Switzerland, so we can\u2019t sign you up. '
      + 'If this address already has an account, we\u2019ve sent it a sign-in link; you\u2019ll be asked to confirm where you live before you\u2019re signed in.'
  };
  var key = q.get('sent') === '1' ? 'sent' : q.get('sent') === 'region' ? 'region' : q.get('deleted') === '1' ? 'deleted' : q.get('linked') === '1' ? 'linked' : q.get('error');
  var el = document.getElementById('message');
  // Only the messages above, never a built-in name like "constructor" (the review of the sign-in fix, finding 2).
  if (el && key && Object.prototype.hasOwnProperty.call(text, key)) { el.textContent = text[key]; el.hidden = false; }
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

// Signing in with a code posted through giscus (023; Aaron, Oct 28, 2026). Shown only when sign-in is switched on
// (/auth/me answers). The code comes from /auth/code/start; this page then asks /auth/code/finish every 2 seconds, one
// request at a time, until the JEVs gate has seen the code posted below and the server signs this browser in. From a
// declined region the page asks where the person lives before any code is made.
(function () {
  var box = document.getElementById('code-signin');
  if (!box || !window.fetch) return;
  var status = document.getElementById('code-status');
  var show = document.getElementById('code-show');
  var ask = document.getElementById('code-region');
  var say = function (t) { status.textContent = t; };
  var post = function (path, body) {
    return fetch(path, { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body || {}).toString() })
      .then(function (r) { return r.json(); });
  };
  // Shown only to someone signed out: a member already signed in who got a new code would replace their key file
  // (the review of the sign-in fix, finding 1). /auth/me answers 200 either way, and 503 while sign-in is off.
  fetch('/auth/me', { credentials: 'same-origin', cache: 'no-store' }).then(function (r) {
    return r.ok ? r.json() : null;
  }).then(function (d) {
    if (!d) return;
    if (d.signed_in === false) { box.hidden = false; return; }
    if (d.signed_in === true) {
      var m = document.getElementById('message');
      if (m && m.hidden) { m.textContent = 'You\u2019re signed in. Your posts are on Posts (/feed) and your settings on your account page (/account).'; m.hidden = false; }
    }
  }).catch(function () { /* sign-in stays hidden */ });

  // The page that sent the person here (return_to), sent with the sign-in; the server checks it again (signin/http.js
  // returnPath) and otherwise goes to the feed.
  var back = new URLSearchParams(location.search).get('return_to');
  if (!back || back.length > 200 || !/^\/(?![/\\])[A-Za-z0-9\-._~/?=&%]*$/.test(back)) back = null;
  var timer = null, deadline = null, busy = false, started = 0, confirmed = false, askedAt = 'start';
  function stop() {
    if (timer) { clearInterval(timer); timer = null; }
    if (deadline) { clearTimeout(deadline); deadline = null; }
  }
  function expired() { stop(); show.hidden = true; say('That code has expired or was used. Get a new one.'); }
  function check() {
    if (busy) return; // one request at a time, so two answers can't race (the CSO's review, finding 5)
    busy = true;
    var fb = confirmed ? { confirm: '1' } : {};
    if (back) fb.return_to = back;
    post('/auth/code/finish', fb).then(function (d) {
      if (!timer) return;
      if (d.signed_in) { stop(); say('Signed in. Taking you on\u2026'); location.href = d.go || '/'; return; }
      // The region can look different by the time the code is used (a network that changed while travelling): ask
      // then, and carry on with the same code once they confirm (the CSO's re-check, N1).
      if (d.region) { clearInterval(timer); timer = null; askRegion(d.region, 'finish'); return; }
      if (d.declined) { stop(); show.hidden = true; say('Day One Great isn\u2019t offered where you live, so we can\u2019t sign you up.'); return; }
      if (d.refused) { stop(); show.hidden = true; say(d.refused === 'disabled' ? 'This account is disabled while a request to delete it is reviewed.' : 'Sign-in isn\u2019t available for this account right now.'); return; }
      if (d.expired) { expired(); return; }
      var secs = Math.round((Date.now() - started) / 1000);
      say('Waiting for your post to reach us through GitHub\u2026 ' + secs + ' s. This usually takes 10 to 20 seconds.');
    }).catch(function () { say('Couldn\u2019t reach the site just now. Still trying\u2026'); })
      .then(function () { busy = false; });
  }
  function askRegion(name, at) {
    askedAt = at;
    document.getElementById('code-region-text').textContent = 'You appear to be in ' + name + '. Day One Great isn\u2019t offered to people who live in the EU, the EEA, the UK or Switzerland, and new sign-ups from there are declined. If you\u2019re already a member and live elsewhere (for example, you\u2019re travelling), you can continue. By continuing, you confirm that you live outside these regions and are using your account lawfully and in line with our terms.';
    ask.hidden = false;
    say('');
  }
  // The key file's SHA-256, made here: the file itself never leaves this device (Aaron, Oct 28).
  function fileHash() {
    var input = document.getElementById('code-file');
    var f = input && input.files && input.files[0];
    if (!f) return Promise.resolve('');
    if (f.size > 100 * 1024 * 1024) return Promise.reject(new Error('big'));
    return f.arrayBuffer().then(function (buf) { return crypto.subtle.digest('SHA-256', buf); }).then(function (d) {
      return Array.prototype.map.call(new Uint8Array(d), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
    });
  }
  function keyFileSignIn() {
    var login = (document.getElementById('code-login').value || '').trim();
    if (!login) { say('Type your GitHub username first.'); return; }
    say('Checking your key file\u2026');
    fileHash().then(function (h) {
      if (!h) { say('Choose your key file first.'); return null; }
      var body = { login: login, file: h };
      if (confirmed) body.confirm = '1';
      if (back) body.return_to = back;
      return post('/auth/key', body);
    }).then(function (d) {
      if (!d) return;
      if (d.signed_in) { say('Signed in. Taking you on\u2026'); location.href = d.go || '/'; return; }
      if (d.region) { askRegion(d.region, 'key'); return; }
      if (d.declined) { say('Day One Great isn\u2019t offered where you live, so we can\u2019t sign you up.'); return; }
      if (d.refused) { say(d.refused === 'disabled' ? 'This account is disabled while a request to delete it is reviewed.' : 'Sign-in isn\u2019t available for this account right now.'); return; }
      say(d.error || 'Couldn\u2019t sign you in. Please try again.');
    }).catch(function (e) { say(e && e.message === 'big' ? 'That file is over 100 MB. Choose a smaller one.' : 'Couldn\u2019t read that file or reach the site. Please try again.'); });
  }
  function getCode() {
    say('Getting a code\u2026');
    var login = (document.getElementById('code-login').value || '').trim();
    if (!login) { say('Type your GitHub username first.'); return; }
    fileHash().then(function (h) {
      if (!h) { say('Choose your key file first.'); return null; }
      var body = { login: login, file: h };
      if (confirmed) body.confirm = '1';
      return post('/auth/code/start', body);
    }).then(function (d) {
      if (!d) return;
      if (d.region) { askRegion(d.region, 'start'); return; }
      if (!d.code) { say(d.error || 'Couldn\u2019t get a code. Please try again.'); return; }
      document.getElementById('code-value').textContent = d.code;
      show.hidden = false;
      say('Post exactly this code in the box below. This page signs you in once GitHub tells us.');
      started = Date.now();
      stop();
      timer = setInterval(check, 2000);
      deadline = setTimeout(expired, (d.expires_in || 600) * 1000);
    }).catch(function (e) { say(e && e.message === 'big' ? 'That file is over 100 MB. Choose a smaller one.' : 'Couldn\u2019t get a code. Please try again.'); });
  }
  document.getElementById('code-region-yes').addEventListener('click', function () {
    confirmed = true;
    ask.hidden = true;
    if (askedAt === 'finish' && deadline) { timer = setInterval(check, 2000); check(); } else if (askedAt === 'key') keyFileSignIn(); else getCode();
  });
  document.getElementById('code-get').addEventListener('click', getCode);
  document.getElementById('key-signin').addEventListener('click', keyFileSignIn);
  document.getElementById('code-copy').addEventListener('click', function () {
    var text = document.getElementById('code-value').textContent;
    if (navigator.clipboard) navigator.clipboard.writeText(text).catch(function () {});
  });
})();
