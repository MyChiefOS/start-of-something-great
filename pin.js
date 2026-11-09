// /join/pin (037; Aaron, Nov 5, 2026: "Yes, PIN on its own page"): the one page where the PIN is typed and this browser's
// sign-in key is made and used. It runs only our own scripts (the site's default security policy, script-src 'self'):
// the comment box (giscus.app's script) that takes the code runs on /join, never here (the review of 037, M1).
//   Lane 3, this browser again: its key and the PIN.
//   Lane 2, a new browser: the username, the key file and the PIN (a first PIN is typed twice).
//   Lane 1's last step (?step=set): the code posted on /join was claimed; a new PIN, typed twice, and this browser's key.
// The key is an ECDSA P-256 pair made with Web Crypto, its private half non-extractable, kept in this site's IndexedDB;
// only the public half goes to the server. Each try signs a one-time challenge with this site's address. The PIN is
// read from its field when it is sent, then the field is cleared; it is never kept anywhere in the browser.
(function () {
  var q = new URLSearchParams(location.search);
  var $ = function (id) { return document.getElementById(id); };
  var card = $('pin-signin-card');
  if (!card || !window.fetch) return;
  var status = $('code-status');
  var say = function (t) { status.textContent = t; };
  var show = function (id, yes) { var e = $(id); if (e) e.hidden = !yes; };
  var post = function (path, body) {
    return fetch(path, { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body || {}).toString() })
      .then(function (r) { return r.json(); });
  };
  // Where to go after signing in: the page that sent the person to /join (the server checks it again, signin/http.js).
  var back = q.get('return_to');
  if (!back || back.length > 200 || !/^\/(?![/\\])[A-Za-z0-9\-._~/?=&%]*$/.test(back)) back = null;
  var toJoin = function () { location.href = '/join?other=1' + (back ? '&return_to=' + encodeURIComponent(back) : ''); };

  // ---- This browser's sign-in key ----
  var DB = 'dog-signin', STORE = 'keys';
  var FLAG = 'dog-signin-key';
  function idb(mode, fn) {
    return new Promise(function (ok) {
      try {
        if (!window.indexedDB) { ok(null); return; }
        var open = window.indexedDB.open(DB, 1);
        open.onupgradeneeded = function () { open.result.createObjectStore(STORE); };
        open.onerror = function () { ok(null); };
        open.onsuccess = function () {
          try {
            var tx = open.result.transaction(STORE, mode);
            var r = fn(tx.objectStore(STORE));
            tx.oncomplete = function () { ok(r && 'result' in r ? r.result : true); };
            tx.onerror = function () { ok(null); };
          } catch (e) { ok(null); }
        };
      } catch (e) { ok(null); }
    });
  }
  // /join reads only this flag (never the key) to send a returning browser here first.
  var flag = function (on) { try { if (on) localStorage.setItem(FLAG, '1'); else localStorage.removeItem(FLAG); } catch (e) { /* only a shortcut */ } };
  function keyGet() {
    return idb('readonly', function (st) { return st.get('signin'); }).then(function (k) {
      return k && typeof k.keyId === 'string' && k.privateKey ? k : null;
    });
  }
  var keyPut = function (k) { flag(true); return idb('readwrite', function (st) { st.put(k, 'signin'); }); };
  var keyDrop = function () { flag(false); return idb('readwrite', function (st) { st.delete('signin'); }); };
  // The short name this browser gives itself, from two fixed lists (signin/session.js holds the same): never the
  // browser's full details. The order matters (Edge says Chrome too; an iPhone says Mac OS X).
  var BROWSERS = [['Edg/', 'Edge'], ['OPR/', 'Opera'], ['SamsungBrowser', 'Samsung Internet'], ['Firefox/', 'Firefox'], ['Chrome/', 'Chrome'], ['Safari/', 'Safari']];
  var DEVICES = [['iPhone', 'iPhone'], ['iPad', 'iPad'], ['Android', 'Android'], ['CrOS', 'ChromeOS'], ['Windows', 'Windows'], ['Mac OS X', 'macOS'], ['Linux', 'Linux']];
  function label() {
    var ua = (window.navigator && navigator.userAgent) || '';
    var pick = function (list, none) { for (var i = 0; i < list.length; i++) if (ua.indexOf(list[i][0]) >= 0) return list[i][1]; return none; };
    return pick(BROWSERS, 'A browser') + ' on ' + pick(DEVICES, 'a device');
  }
  var b64 = function (buf) {
    var s = ''; var a = new Uint8Array(buf);
    for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  // A new key pair; the private half can never be exported.
  function makeKey() {
    return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']).then(function (pair) {
      return crypto.subtle.exportKey('raw', pair.publicKey).then(function (raw) { return { privateKey: pair.privateKey, pub: b64(raw) }; });
    });
  }
  // A one-time challenge from the server, signed with this site's address (what app.signin_message builds).
  function prove(privateKey) {
    return post('/auth/challenge').then(function (d) {
      if (!d || typeof d.challenge !== 'string') throw new Error(d && d.error ? d.error : 'challenge');
      var msg = new TextEncoder().encode('dayonegreat-signin-v1\n' + location.origin + '\n' + d.challenge);
      return crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, msg).then(function (sig) {
        return { challenge: d.challenge, sig: b64(sig) };
      });
    });
  }
  var canKey = function () { return Boolean(window.crypto && crypto.subtle && window.TextEncoder && window.btoa); };
  var NO_KEY = 'This browser can’t make a sign-in key (it needs Web Crypto). Please use an up-to-date browser.';
  var readPin = function (input) { var v = input ? String(input.value || '').trim() : ''; if (input) input.value = ''; return v; };
  // A PIN anyone would try first, refused here as the server refuses it (app.pin_weak), so people are told why.
  function weak(p) {
    var up = true, down = true;
    for (var i = 0; i < 5; i++) {
      if ((+p[i + 1] - +p[i] + 10) % 10 !== 1) up = false;
      if ((+p[i] - +p[i + 1] + 10) % 10 !== 1) down = false;
    }
    return up || down || p === Array(7).join(p[0]) || p === p.slice(0, 2) + p.slice(0, 2) + p.slice(0, 2) || p === p.slice(0, 3) + p.slice(0, 3)
      || ['112233', '123321', '159753', '147258', '147852', '258456', '789456', '102030', '159357', '753951', '852456', '000123'].indexOf(p) >= 0;
  }
  var WEAK = 'Please choose a PIN that’s harder to guess: not one digit repeated, a run like 123456, or a short pattern repeated.';
  // After a sign-in with a code, /feed greets the person once in this tab (join.js's welcome); the code kept for the
  // GitHub round trip has nothing left to do.
  function signed(d, fresh) {
    try { sessionStorage.removeItem('dog-code'); sessionStorage.removeItem('dog-ran-out'); if (fresh && d.go === '/feed') sessionStorage.setItem('dog-welcome', '1'); } catch (e) { /* nothing kept */ }
    say('Signed in. Taking you on…');
    location.href = d.go || '/';
  }
  function refusedSay(d) {
    if (d.declined) { say('Day One Great isn’t offered where you live, so we can’t sign you up.'); return true; }
    if (d.refused) { say(d.refused === 'disabled' ? 'This account is disabled while a request to delete it is reviewed.' : d.refused === 'locked' ? 'Signing in to this account is locked for 15 minutes, after 3 failed attempts. Browsers already signed in stay signed in. Please try again later.' : 'Sign-in isn’t available for this account right now.'); return true; }
    return false;
  }
  // The region question: a member travelling where we don't sign people up confirms where they live, once per try.
  var confirmed = false, askedAt = null, pending = '', pendingAgain = '';
  function askRegion(name, at) {
    askedAt = at;
    $('code-region-text').textContent = 'You appear to be in ' + name + '. Day One Great isn’t offered to people who live in the EU, the EEA, the UK or Switzerland, and new sign-ups from there are declined. If you’re already a member and live elsewhere (for example, you’re travelling), you can continue. By continuing, you confirm that you live outside these regions and are using your account lawfully and in line with our terms.';
    show('code-region', true);
    say('');
  }

  var mode = null; // 'browser' (lane 3), 'file' (lane 2) or 'set' (lane 1's last step)
  function layout() {
    show('pin-lane', mode === 'browser');
    show('file-lane', mode === 'file');
    show('pin-set', mode === 'set');
    show('paths', mode !== 'set');
  }

  // Lane 3: this browser again, its key and the PIN.
  function pinSignIn() {
    var pin = pending || readPin($('pin-now'));
    pending = '';
    if (!/^[0-9]{6}$/.test(pin)) { say('Type your six-digit PIN.'); $('pin-now').focus(); return; }
    say('Signing in…');
    keyGet().then(function (k) {
      if (!k) { flag(false); mode = 'file'; layout(); say('This browser no longer has its sign-in key. Sign in with your key file and PIN, or get a new code.'); return null; }
      return prove(k.privateKey).then(function (p) {
        var body = { key_id: k.keyId, pin: pin, challenge: p.challenge, sig: p.sig };
        if (confirmed) body.confirm = '1';
        if (back) body.return_to = back;
        return post('/auth/browser', body);
      });
    }).then(function (d) {
      if (!d) return;
      if (d.signed_in) { signed(d, false); return; }
      if (d.region) { pending = pin; askRegion(d.region, 'browser'); return; }
      if (d.no_key || d.cancelled) {
        keyDrop(); mode = 'file'; layout();
        say(d.error || 'This browser’s sign-in key isn’t on your account any more. Sign in with your key file and PIN, or with a new code.');
        return;
      }
      if (refusedSay(d)) return;
      say(d.error || 'Couldn’t sign you in. Please try again.');
      $('pin-now').focus();
    }).catch(function () { say('Couldn’t reach the site just now. Please try again.'); });
  }

  // The key file's SHA-256, made here: the file itself never leaves this device.
  function fileHash() {
    var input = $('code-file');
    var f = input && input.files && input.files[0];
    if (!f) return Promise.resolve('');
    if (f.size > 100 * 1024 * 1024) return Promise.reject(new Error('big'));
    return f.arrayBuffer().then(function (buf) { return crypto.subtle.digest('SHA-256', buf); }).then(function (d) {
      return Array.prototype.map.call(new Uint8Array(d), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
    });
  }
  // Lane 2: the key file and the PIN, on a new browser. This browser gets its key.
  function keyFileSignIn() {
    var login = ($('code-login').value || '').trim();
    if (!login) { say('Type your GitHub username first.'); $('code-login').focus(); return; }
    var pin = pending || readPin($('key-pin'));
    var again = pendingAgain || readPin($('key-pin-again'));
    pending = ''; pendingAgain = '';
    if (!/^[0-9]{6}$/.test(pin)) { say('Type your six-digit PIN.'); $('key-pin').focus(); return; }
    if (!canKey()) { say(NO_KEY); return; }
    say('Checking your key file…');
    var made = null;
    fileHash().then(function (h) {
      if (!h) { say('Choose your key file first.'); return null; }
      return makeKey().then(function (k) { made = k; return prove(k.privateKey); }).then(function (p) {
        var body = { login: login, file: h, pin: pin, pub: made.pub, label: label(), challenge: p.challenge, sig: p.sig };
        if (again) body.pin_again = again;
        if (confirmed) body.confirm = '1';
        if (back) body.return_to = back;
        return post('/auth/key', body);
      });
    }).then(function (d) {
      if (!d) return;
      if (d.signed_in) { keyPut({ keyId: d.key_id, privateKey: made.privateKey }).then(function () { signed(d, false); }); return; }
      if (d.region) { pending = pin; pendingAgain = again; askRegion(d.region, 'key'); return; }
      // A first PIN (an account from before PINs) is typed twice: the second field shows.
      if (d.confirm_pin) { show('key-pin-again-field', true); say(d.error); $('key-pin').focus(); return; }
      if (refusedSay(d)) return;
      say(d.error || 'Couldn’t sign you in. Please try again.');
    }).catch(function (e) { say(e && e.message === 'big' ? 'That file is over 100 MB. Choose a smaller one.' : 'Couldn’t read that file or reach the site. Please try again.'); });
  }

  // Lane 1's last step: the code posted on /join was claimed; a new PIN and this browser's key.
  function setStep() {
    mode = 'set'; layout();
    post('/auth/code/finish', confirmed ? { confirm: '1' } : {}).then(function (d) {
      if (d.region) { askRegion(d.region, 'set-check'); return; }
      if (!d.claimed) {
        say(d.expired ? 'That code has run out or was already used. Get a new code on the join page.' : 'Your code hasn’t been claimed yet. Go back to the join page and post it.');
        mode = keyFlag ? 'browser' : 'file'; layout();
        return;
      }
      // When the account already has a PIN and other browsers, they can go in the same step (on by default).
      if (d.has_pin && d.browsers > 0) { $('pin-others-count').textContent = String(d.browsers); show('pin-remove-others-field', true); }
      say('Your post was found. Now set your PIN to finish signing in.');
      var t = $('pin-set-title'); if (t && t.focus) t.focus();
    }).catch(function () { say('Couldn’t reach the site just now. Please reload this page.'); });
  }
  function savePin() {
    var a = pending || readPin($('pin-new')), b2 = pendingAgain || readPin($('pin-again'));
    pending = ''; pendingAgain = '';
    if (!/^[0-9]{6}$/.test(a)) { say('Your PIN is six digits.'); $('pin-new').focus(); return; }
    if (a !== b2) { say('The two PINs aren’t the same. Please type it twice again.'); $('pin-new').focus(); return; }
    if (weak(a)) { say(WEAK); $('pin-new').focus(); return; }
    if (!canKey()) { say(NO_KEY); return; }
    say('Signing in…');
    var made = null;
    var others = $('pin-remove-others-field');
    var remove = others && !others.hidden && $('pin-remove-others').checked;
    makeKey().then(function (k) { made = k; return prove(k.privateKey); }).then(function (p) {
      var body = { pin: a, pub: made.pub, label: label(), challenge: p.challenge, sig: p.sig };
      if (remove) body.remove_others = '1';
      if (confirmed) body.confirm = '1';
      if (back) body.return_to = back;
      return post('/auth/code/finish', body);
    }).then(function (d) {
      if (d.signed_in) { keyPut({ keyId: d.key_id, privateKey: made.privateKey }).then(function () { signed(d, true); }); return; }
      if (d.region) { pending = a; pendingAgain = b2; askRegion(d.region, 'set'); return; }
      if (d.expired) { say('That code has run out or was already used. Get a new code on the join page.'); return; }
      if (refusedSay(d)) return;
      say(d.error || 'Couldn’t sign you in. Please try again.');
      $('pin-new').focus();
    }).catch(function () { say('Couldn’t reach the site just now. Please try again.'); });
  }

  $('path-new').addEventListener('click', toJoin);
  $('path-back').addEventListener('click', function () { mode = 'file'; layout(); $('code-login').focus(); });
  $('pin-signin').addEventListener('click', pinSignIn);
  $('pin-other').addEventListener('click', function () { mode = 'file'; layout(); $('code-login').focus(); });
  $('key-signin').addEventListener('click', keyFileSignIn);
  $('pin-save').addEventListener('click', savePin);
  $('code-region-yes').addEventListener('click', function () {
    confirmed = true; show('code-region', false);
    if (askedAt === 'browser') pinSignIn(); else if (askedAt === 'key') keyFileSignIn(); else if (askedAt === 'set') savePin(); else setStep();
  });
  // Enter in a PIN field presses its button.
  [['pin-now', pinSignIn], ['key-pin', keyFileSignIn], ['key-pin-again', keyFileSignIn], ['pin-again', savePin]].forEach(function (x) {
    $(x[0]).addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); x[1](); } });
  });

  var keyFlag = false;
  // Shown only to someone signed out (/auth/me answers 503 while sign-in is off).
  fetch('/auth/me', { credentials: 'same-origin', cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : null; }).then(function (d) {
    if (!d) return;
    if (d.signed_in === true) {
      var m = $('message'); m.textContent = 'You’re signed in. Your posts are on Posts (/feed) and your settings on your account page (/account).'; m.hidden = false;
      return;
    }
    card.hidden = false;
    return keyGet().then(function (k) {
      keyFlag = Boolean(k);
      flag(keyFlag);
      if (q.get('step') === 'set') { setStep(); return; }
      mode = keyFlag && q.get('lane') !== 'file' ? 'browser' : 'file';
      layout();
      var first = $(mode === 'browser' ? 'pin-now' : 'code-login');
      if (first && first.focus) first.focus();
    });
  }).catch(function () { /* the card stays hidden */ });
})();
