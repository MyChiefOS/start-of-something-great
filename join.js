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
    disabled: 'This account is disabled while a request to delete it is reviewed. Nothing has been deleted. If it\u2019s restored, you can sign in again.',
    region: 'Day One Great isn\u2019t offered to people who live in the EU, the EEA, the UK or Switzerland, so we can\u2019t sign you up. '
      + 'If this address already has an account, we\u2019ve sent it a sign-in link; you\u2019ll be asked to confirm where you live before you\u2019re signed in.'
  };
  var key = q.get('sent') === '1' ? 'sent' : q.get('sent') === 'region' ? 'region' : q.get('deleted') === '1' ? 'deleted' : q.get('error');
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
