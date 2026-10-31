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
//
// Signing in to the comment box (giscus) sends this whole tab to GitHub and back to a freshly loaded /join (its "Sign
// in" link targets the top window). So the waiting code is kept in this tab's sessionStorage until it is used or
// expires, and a reloaded page shows it again and keeps waiting (the sign-in simulation, Oct 30: 5 of 10 people got a
// code, signed in to the box, and came back to a page that had forgotten it; posting it then signed nobody in).
(function () {
  var box = document.getElementById('code-signin');
  if (!box || !window.fetch) return;
  var status = document.getElementById('code-status');
  var show = document.getElementById('code-show');
  var ask = document.getElementById('code-region');
  var fields = document.getElementById('signin-fields');
  var getBtn = document.getElementById('code-get');
  var newBtn = document.getElementById('code-new');
  var keyBtn = document.getElementById('key-signin');
  var copyBtn = document.getElementById('code-copy');
  var copyLine = document.getElementById('code-copied');
  var helloHead = document.getElementById('hello-head');
  var postHere = document.getElementById('post-here');
  var fieldSet = document.getElementById('field-set');
  var signinAs = document.getElementById('signin-as');
  var loginBox = document.getElementById('code-login');
  // The live region is written only when something changes, never with a ticking count (the UI/UX review of Oct 31,
  // finding 7; WCAG 2.2, 4.1.3): a person's own action always gets its answer, and the wait for the code is announced
  // once per state (waiting, a problem, signed in, expired). The seconds go in #code-wait, which screen readers skip.
  var said = null;
  var say = function (t, state) {
    if (state && state === said) return;
    said = state || null;
    status.textContent = t;
  };
  var post = function (path, body) {
    return fetch(path, { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body || {}).toString() })
      .then(function (r) { return r.json(); });
  };
  // Which way in the person chose: "new" (first time, or a new key file: get a code) or "back" (the key file alone).
  // Only the choice is kept, in this tab (sessionStorage); never a name, a username or a file. The username shown on
  // the folded line (asLogin) lives only in this page, so it is gone after a reload.
  var PATH = 'dog-path', path = null, ranOut = false, codeShown = false, editing = false, asLogin = '';
  function layout() {
    var chosen = path === 'new' || path === 'back';
    // While a code shows, the fields fold to one line, the username and "Change", so the code step starts high on the
    // page (the design review of PR A, fix 1). "Change" opens them again, to get a code for another name or file.
    var compact = codeShown && path === 'new' && !editing;
    fields.hidden = !chosen;
    if (fieldSet) fieldSet.hidden = compact;
    if (signinAs) signinAs.hidden = !compact;
    getBtn.hidden = path !== 'new' || ranOut || compact;
    document.getElementById('code-again').hidden = path !== 'new' || !ranOut;
    keyBtn.hidden = path !== 'back';
    document.getElementById('back-help').hidden = path !== 'back';
    show.hidden = !(codeShown && path === 'new');
    // While a code shows, the comment box sits right under it (finding 1): the "Say hello" heading above the box steps
    // aside for "Post your code here", which heading navigation finds (fix 7), and the code's own step says the post is
    // public.
    if (helloHead) helloHead.hidden = !show.hidden;
    if (postHere) {
      postHere.hidden = show.hidden;
      var hello = document.getElementById('say-hello');
      if (hello) hello.setAttribute('aria-labelledby', show.hidden ? 'hello-title' : 'post-here');
    }
    document.getElementById('path-new').setAttribute('aria-pressed', String(path === 'new'));
    document.getElementById('path-back').setAttribute('aria-pressed', String(path === 'back'));
  }
  function choose(p) {
    path = p;
    if (p === 'back') ranOutMark(null);
    try { sessionStorage.setItem(PATH, p); } catch (e) { /* not kept: no storage */ }
    layout();
  }
  document.getElementById('path-new').addEventListener('click', function () { choose('new'); });
  document.getElementById('path-back').addEventListener('click', function () { choose('back'); });
  document.getElementById('code-change').addEventListener('click', function () {
    editing = true;
    layout();
    if (loginBox.focus) loginBox.focus();
  });
  // Shown only to someone signed out: a member already signed in who got a new code would replace their key file
  // (the review of the sign-in fix, finding 1). /auth/me answers 200 either way, and 503 while sign-in is off.
  fetch('/auth/me', { credentials: 'same-origin', cache: 'no-store' }).then(function (r) {
    return r.ok ? r.json() : null;
  }).then(function (d) {
    if (!d) return;
    if (d.signed_in === false) { box.hidden = false; restore(); resume(); return; }
    forget(); ranOutMark(null); // signed in already: a kept code has nothing left to do
    if (d.signed_in === true) {
      var m = document.getElementById('message');
      if (m && m.hidden) { m.textContent = 'You\u2019re signed in. Your posts are on Posts (/feed) and your settings on your account page (/account).'; m.hidden = false; }
    }
  }).catch(function () { /* sign-in stays hidden */ });
  function restore() {
    var p = null;
    try { p = sessionStorage.getItem(PATH); } catch (e) { p = null; }
    if (p === 'new' || p === 'back') { path = p; layout(); }
  }

  // The page that sent the person here (return_to), sent with the sign-in; the server checks it again (signin/http.js
  // returnPath) and otherwise goes to the feed.
  var back = new URLSearchParams(location.search).get('return_to');
  if (!back || back.length > 200 || !/^\/(?![/\\])[A-Za-z0-9\-._~/?=&%]*$/.test(back)) back = null;
  var timer = null, deadline = null, clock = null, busy = false, started = 0, until = 0, confirmed = false, askedAt = 'start';
  function stop() {
    if (timer) { clearInterval(timer); timer = null; }
    if (deadline) { clearTimeout(deadline); deadline = null; }
    if (clock) { clearInterval(clock); clock = null; }
    document.getElementById('code-wait').textContent = '';
  }
  // A code that ran out while waiting: hidden so nobody posts it, with "Get a new code" in its place (finding 1), and
  // focus moves there, so a keyboard or screen-reader user isn't left on a control that has gone (fix 3).
  var RAN_OUT = { expired: 'That code has run out. Get a new code to try again.',
    gone: 'That code has expired or was used. Get a new code to try again.' };
  function ranOutNow(why) {
    stop(); forget(); ranOutMark(why); codeShown = false; editing = false; ranOut = true; layout(); say(RAN_OUT[why], 'expired');
    if (newBtn.focus) newBtn.focus();
  }
  function expired() { ranOutNow('expired'); }
  // What the server says when the code is unknown to this browser: it ran out, or was already used.
  function gone() { ranOutNow('gone'); }
  // The code this tab is waiting for, kept only here (sessionStorage: this tab, this site) and only until it signs in,
  // expires or is replaced. It is worth nothing elsewhere: it works only with this browser's own code cookie.
  var KEEP = 'dog-code';
  function forget() { try { sessionStorage.removeItem(KEEP); } catch (e) { /* nothing kept */ } }
  // After a sign-in with a code (a first sign-in, or a new key file), /feed (where a sign-in lands unless it was sent from another page) greets you once in this tab with three next
  // steps (the UI/UX review, finding 10). Only a yes is kept: no ID, no name. The key-file sign-in doesn't set it.
  function welcome() { try { sessionStorage.setItem('dog-welcome', '1'); } catch (e) { /* no greeting: no storage */ } }
  function keep(code, until) { try { sessionStorage.setItem(KEEP, JSON.stringify({ code: code, until: until })); } catch (e) { /* not kept: no storage */ } }
  // That a code ran out, kept in this tab only (no code, no name), so a person who comes back from GitHub after it ran
  // out is told so, with "Get a new code" ready, instead of a page that seems to have forgotten them (the simulation, fix 5).
  var GONE = 'dog-ran-out';
  function ranOutMark(why) { try { if (why) sessionStorage.setItem(GONE, why); else sessionStorage.removeItem(GONE); } catch (e) { /* not kept */ } }
  // Focus on one control, and the part of the panel that matters on the screen: scrolled only if its top or its last
  // control is off the screen, so nothing moves when it already fits.
  function place(target, top, end) {
    if (target && target.focus) { try { target.focus({ preventScroll: true }); } catch (e) { target.focus(); } }
    if (!top || !end || !top.getBoundingClientRect || !top.scrollIntoView) return;
    var a = top.getBoundingClientRect(), b = end.getBoundingClientRect();
    if (a.top < 0 || b.bottom > window.innerHeight) top.scrollIntoView({ block: 'start' });
  }
  // After a reload the browser puts the old scroll position back, sometimes after this script has run; so the page
  // places itself, and again once loaded (measured: 3 of 6 reloads at 1280 px left Copy below the screen).
  function placeOnLoad(fn) {
    try { if (window.history && 'scrollRestoration' in history) history.scrollRestoration = 'manual'; } catch (e) { /* the check on load still runs */ }
    fn();
    if (document.readyState && document.readyState !== 'complete' && window.addEventListener) window.addEventListener('load', fn, { once: true });
  }
  // The code step in view, with focus on its heading (fix 1; the simulation, fix 3): from the "Signing in as" line when
  // the name is known (right after Get), else from the status line, which says what to do next (after a reload the name
  // isn't known: it isn't kept).
  function bring() {
    var line = status.parentNode;
    place(document.getElementById('code-title'), asLogin && signinAs && !signinAs.hidden ? signinAs : line, copyBtn);
  }
  // The time left and the seconds waited, drawn once a second where screen readers don't go (finding 7). The time left
  // counts down to the same moment the page stops waiting: what the server gave (expires_in, at most 10 minutes).
  function tick() {
    var left = Math.max(0, Math.round((until - Date.now()) / 1000));
    document.getElementById('code-time').textContent = 'Expires in ' + Math.floor(left / 60) + ':' + ('0' + (left % 60)).slice(-2);
    // No time is promised: nothing measures how long GitHub takes to pass a post on (the design review, fix 4).
    if (timer) document.getElementById('code-wait').textContent = Math.round((Date.now() - started) / 1000) + ' s so far. This page keeps checking and signs you in once GitHub passes your post on.';
  }
  function wait(code, u) {
    document.getElementById('code-value').textContent = code;
    copyBtn.textContent = 'Copy';
    copyLine.textContent = '';
    ranOutMark(null);
    path = 'new'; codeShown = true; ranOut = false; editing = false;
    var t = document.getElementById('signin-as-text');
    t.textContent = asLogin ? 'Signing in as ' + asLogin : 'Signing in with the code below';
    layout();
    started = Date.now();
    until = u;
    stop();
    timer = setInterval(check, 2000);
    deadline = setTimeout(expired, Math.max(0, u - Date.now()));
    clock = setInterval(tick, 1000);
    tick();
  }
  // Back from GitHub (or any reload in this tab). A kept code shows again, in view, with focus on its step; Copy is
  // asked for again, as GitHub may have used the clipboard meanwhile, for a password for example (the simulation,
  // fix 3). A code that ran out meanwhile is said to have run out, with "Get a new code" ready (fix 5). The username and
  // key file aren't kept, so the username field takes focus: both are needed again.
  function resume() {
    var k = null, was = null;
    try { k = JSON.parse(sessionStorage.getItem(KEEP) || 'null'); } catch (e) { k = null; }
    try { was = sessionStorage.getItem(GONE); } catch (e) { was = null; }
    var shaped = k && typeof k.code === 'string' && /^DOG-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/.test(k.code) &&
      typeof k.until === 'number' && k.until - Date.now() <= 600000;
    if (shaped && !(k.until > Date.now())) was = 'expired';
    if (!shaped || !(k.until > Date.now())) {
      forget();
      if (was === 'expired' || was === 'gone') {
        ranOutMark(was);
        path = 'new'; ranOut = true; codeShown = false; layout();
        say(was === 'gone' ? 'Your last code expired or was used. Type your username, choose your key file again and press \u201cGet a new code\u201d.'
          : 'Your code ran out. Type your username, choose your key file again and press \u201cGet a new code\u201d.', 'expired');
        // The fields at the top of the screen, so the username (focused), this message and "Get a new code" all show.
        placeOnLoad(function () { place(loginBox, fields, newBtn); });
      }
      return;
    }
    asLogin = '';
    wait(k.code, k.until);
    say('Your code is still here. Press Copy again, then paste it below.', 'waiting');
    placeOnLoad(bring);
    check();
  }
  function check() {
    if (busy) return; // one request at a time, so two answers can't race (the CSO's review, finding 5)
    busy = true;
    var fb = confirmed ? { confirm: '1' } : {};
    if (back) fb.return_to = back;
    post('/auth/code/finish', fb).then(function (d) {
      if (!timer) return;
      if (d.signed_in) { stop(); forget(); ranOutMark(null); if (d.go === '/feed') welcome(); say('Signed in. Taking you on\u2026', 'signed_in'); location.href = d.go || '/'; return; }
      // The region can look different by the time the code is used (a network that changed while travelling): ask
      // then, and carry on with the same code once they confirm (the CSO's re-check, N1).
      if (d.region) { clearInterval(timer); timer = null; document.getElementById('code-wait').textContent = ''; askRegion(d.region, 'finish'); return; }
      if (d.declined) { stop(); forget(); codeShown = false; layout(); say('Day One Great isn\u2019t offered where you live, so we can\u2019t sign you up.', 'declined'); return; }
      if (d.refused) { stop(); forget(); codeShown = false; layout(); say(d.refused === 'disabled' ? 'This account is disabled while a request to delete it is reviewed.' : 'Sign-in isn\u2019t available for this account right now.', 'refused'); return; }
      if (d.expired) { gone(); return; }
      say('Waiting for your post in the box below. Press Copy and paste the code there, if you haven\u2019t yet.', 'waiting');
    }).catch(function () { say('Couldn\u2019t reach the site just now. Still trying\u2026', 'problem'); })
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
    if (!login) { say('Type your GitHub username first.'); if (loginBox.focus) loginBox.focus(); return; }
    fileHash().then(function (h) {
      if (!h) { say('Choose your key file first.'); var f = document.getElementById('code-file'); if (f.focus) f.focus(); return null; }
      var body = { login: login, file: h };
      if (confirmed) body.confirm = '1';
      return post('/auth/code/start', body);
    }).then(function (d) {
      if (!d) return;
      if (d.region) { askRegion(d.region, 'start'); return; }
      if (!d.code) { say(d.error || 'Couldn\u2019t get a code. Please try again.'); return; }
      var until = Date.now() + Math.min(d.expires_in || 600, 600) * 1000;
      keep(d.code, until);
      asLogin = login;
      wait(d.code, until);
      // Short, so Copy is on the first screen after the tap; the GitHub round trip is in the step's first hint.
      say('Waiting for your post.', 'waiting');
      bring();
    }).catch(function (e) { say(e && e.message === 'big' ? 'That file is over 100 MB. Choose a smaller one.' : 'Couldn\u2019t get a code. Please try again.'); });
  }
  document.getElementById('code-region-yes').addEventListener('click', function () {
    confirmed = true;
    ask.hidden = true;
    if (askedAt === 'finish' && deadline) { timer = setInterval(check, 2000); check(); } else if (askedAt === 'key') keyFileSignIn(); else getCode();
  });
  getBtn.addEventListener('click', getCode);
  newBtn.addEventListener('click', getCode);
  keyBtn.addEventListener('click', keyFileSignIn);
  // Copy puts the code on a line of its own, with an empty line above and below it, which is how the gate reads a code
  // posted on purpose (core.mjs signinCodes). Pasted after "Hi" or into a sentence, it still stands alone (the sign-in
  // simulation, Oct 30: 5 of 10 posts put the code in a sentence, after "code:", in backticks or with no empty line).
  // It shows "Copied" when the browser took it; if the browser refuses, the code is selected instead and the page
  // says so (the UI/UX review, finding 1: it used to fail without a word). Either answer goes in its own line under the
  // code, which the waiting checks never write, so it stays until the next Copy or the next code (the design review,
  // fix 2: in the shared status line it was overwritten by "Waiting…" within 2 seconds).
  var copied = null;
  copyBtn.addEventListener('click', function () {
    var code = document.getElementById('code-value');
    copyLine.textContent = '';
    var done = function () {
      copyBtn.textContent = 'Copied';
      copyLine.textContent = 'Copied. Paste it in the box below.';
      if (copied) clearTimeout(copied);
      copied = setTimeout(function () { copyBtn.textContent = 'Copy'; copied = null; }, 4000);
    };
    var refused = function () {
      try {
        var r = document.createRange();
        r.selectNodeContents(code);
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(r);
      } catch (e) { /* the code is still there to select by hand */ }
      copyLine.textContent = 'This browser didn\u2019t let the page copy, so the code is selected: copy it yourself, then paste it on a line of its own, with an empty line above and below it.';
      if (copyLine.getBoundingClientRect && copyLine.scrollIntoView && copyLine.getBoundingClientRect().bottom > window.innerHeight) copyLine.scrollIntoView({ block: 'nearest' });
    };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText('\n\n' + code.textContent + '\n\n').then(done, refused);
    else refused();
  });
})();
