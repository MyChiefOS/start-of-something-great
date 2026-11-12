// /join/buyer (063; Aaron, Nov 11, 2026: "a buyer may sign in with a passkey and no GitHub account"): a buyer account
// for posting, funding, reviewing and disputing tasks only. It runs only our own scripts (the site's default security
// policy, script-src 'self').
//   Make a buyer account: the device makes a WebAuthn passkey for this site (ES256 only, user verification required,
//   no attestation), and the server and the database check what it reports.
//   Sign in: the device signs a one-time challenge from /auth/challenge; the server and the database check the signature.
// Nothing about the person is asked for or kept: the passkey's ID and public half only. The account's name on the site
// is "New member", changed on the account page like anyone's.
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var make = $('buyer-new'), signin = $('buyer-signin'), status = $('buyer-status');
  if (!make || !signin || !status) return;
  var say = function (t) { status.textContent = t; };
  if (!window.fetch || !window.PublicKeyCredential || !navigator.credentials) {
    say('This browser can’t use passkeys. Please try an up-to-date browser on your phone or computer.');
    return;
  }
  var post = function (path, body) {
    return fetch(path, { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body || {}).toString() })
      .then(function (r) { return r.json().catch(function () { return { error: 'Something went wrong. Please try again.' }; }); });
  };
  var b64 = function (buf) {
    var s = '', a = new Uint8Array(buf);
    for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  var unb64 = function (s) {
    var t = atob(s.replace(/-/g, '+').replace(/_/g, '/')), a = new Uint8Array(t.length);
    for (var i = 0; i < t.length; i++) a[i] = t.charCodeAt(i);
    return a;
  };
  var random = function (n) { var a = new Uint8Array(n); crypto.getRandomValues(a); return a; };
  var busy = function (yes) { make.disabled = yes; signin.disabled = yes; };
  var region = $('buyer-region'), regionText = $('buyer-region-text'), regionYes = $('buyer-region-yes');
  var confirmed = false;
  var done = function (r) {
    if (r && r.signed_in) { say('Signed in. Taking you to your projects…'); location.href = r.go || '/projects'; return; }
    busy(false);
    // From a declined region a buyer who lives elsewhere confirms it, then uses their passkey again (Aaron, Oct 16).
    if (r && r.region && region && regionText) {
      regionText.textContent = 'You seem to be in ' + r.region + ', where Day One Great isn’t open yet. If you live elsewhere, confirm it and use your passkey again.';
      region.hidden = false; say(''); return;
    }
    if (r && r.declined) { say('Day One Great isn’t open to people in the European Union, the European Economic Area, the United Kingdom or Switzerland yet.'); return; }
    if (r && r.refused === 'banned') { say('This account can’t sign in.'); return; }
    if (r && r.refused) { say('This account can’t sign in just now.'); return; }
    say((r && r.error) || 'Something went wrong. Please try again.');
  };
  var failed = function (e) {
    busy(false);
    say(e && e.name === 'NotAllowedError' ? 'The passkey step was cancelled or timed out. Press the button to try again.'
      : 'Your device couldn’t make or use a passkey here. Please try again, or another device.');
  };
  var challenge = function () {
    return post('/auth/challenge').then(function (r) {
      if (!r || !r.challenge) throw new Error((r && r.error) || 'no challenge');
      return r.challenge;
    });
  };

  make.addEventListener('click', function () {
    busy(true); say('Follow your device’s steps to make a passkey…');
    challenge().then(function (ch) {
      return navigator.credentials.create({ publicKey: {
        challenge: unb64(ch), rp: { id: location.hostname, name: 'Day One Great' },
        // A random handle: nothing about the person goes to the device or to us.
        user: { id: random(16), name: 'Day One Great buyer', displayName: 'Day One Great buyer' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }], timeout: 120000, attestation: 'none',
        authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' } } });
    }).then(function (cred) {
      var res = cred.response;
      if (!res.getPublicKey || !res.getAuthenticatorData || !res.getPublicKeyAlgorithm) throw new Error('old browser');
      say('Checking your passkey…');
      return post('/auth/buyer/register', { cred: b64(cred.rawId), cd: b64(res.clientDataJSON), ad: b64(res.getAuthenticatorData()),
        spki: b64(res.getPublicKey()), alg: String(res.getPublicKeyAlgorithm()) }).then(done);
    }).catch(failed);
  });

  signin.addEventListener('click', function () {
    busy(true); say('Follow your device’s steps to use your passkey…');
    challenge().then(function (ch) {
      return navigator.credentials.get({ publicKey: { challenge: unb64(ch), rpId: location.hostname, userVerification: 'required', timeout: 120000 } });
    }).then(function (cred) {
      var res = cred.response;
      say('Checking your passkey…');
      var body = { cred: b64(cred.rawId), cd: b64(res.clientDataJSON), ad: b64(res.authenticatorData), sig: b64(res.signature) };
      if (confirmed) body.confirm = '1';
      return post('/auth/buyer/sign-in', body).then(done);
    }).catch(failed);
  });
  if (regionYes) regionYes.addEventListener('click', function () { confirmed = true; region.hidden = true; signin.click(); });

  busy(false);
})();
