// Passkeys in the browser (PR 17): adding one, and confirming it's you with one before a risky step (D5). Plain
// JavaScript with no outside code, loaded from our own site (the pages' CSP allows script-src 'self' only).
// The server checks everything (signature, origin, RP ID, user verification, a single-use 2-minute challenge bound to
// this session); this only carries the browser's answer there.
//   dogPasskey.supported()        whether this browser can use passkeys
//   dogPasskey.enrol(label)       adds a passkey (needs a sign-in in the last 10 minutes)
//   dogPasskey.stepUp()           confirms with a passkey; risky steps are open for 5 minutes
//   dogPasskey.postJson(url, b)   a JSON POST that, if the server asks for a passkey check, does one and tries once more
(function () {
  function b64uToBuf(s) {
    var b = atob(String(s).replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((String(s).length + 3) % 4));
    var u = new Uint8Array(b.length);
    for (var i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
    return u.buffer;
  }
  function bufToB64u(buf) {
    var u = new Uint8Array(buf), s = '';
    for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function post(url, body) {
    return fetch(url, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body || {}) })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, status: r.status, d: d }; }); });
  }
  function supported() {
    return Boolean(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create && navigator.credentials.get);
  }
  // What the browser said, in the JSON shape the server reads.
  function serialize(cred, kind) {
    var r = cred.response, out = { id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type, clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      authenticatorAttachment: cred.authenticatorAttachment || undefined, response: { clientDataJSON: bufToB64u(r.clientDataJSON) } };
    if (kind === 'create') {
      out.response.attestationObject = bufToB64u(r.attestationObject);
      out.response.transports = r.getTransports ? r.getTransports() : [];
    } else {
      out.response.authenticatorData = bufToB64u(r.authenticatorData);
      out.response.signature = bufToB64u(r.signature);
      if (r.userHandle) out.response.userHandle = bufToB64u(r.userHandle);
    }
    return out;
  }
  function failed(e) {
    // The person cancelled, or the device couldn't: say so plainly, without the browser's own wording.
    var cancelled = e && (e.name === 'NotAllowedError' || e.name === 'AbortError');
    return { ok: false, status: 0, d: { error: cancelled ? 'The passkey request was cancelled or timed out. Nothing changed.' : 'This device couldn’t use a passkey here. Nothing changed.' } };
  }

  function enrol(label) {
    if (!supported()) return Promise.resolve({ ok: false, status: 0, d: { error: 'This browser can’t use passkeys. Try another browser or device.' } });
    return post('/auth/passkey/enrol/options').then(function (o) {
      if (!o.ok) return o;
      var p = o.d.options;
      p.challenge = b64uToBuf(p.challenge);
      p.user.id = b64uToBuf(p.user.id);
      p.excludeCredentials = (p.excludeCredentials || []).map(function (c) { return { type: c.type, id: b64uToBuf(c.id), transports: c.transports }; });
      return navigator.credentials.create({ publicKey: p })
        .then(function (cred) { return post('/auth/passkey/enrol/finish', { response: serialize(cred, 'create'), label: label || 'Passkey' }); }, failed);
    });
  }

  function stepUp() {
    if (!supported()) return Promise.resolve({ ok: false, status: 0, d: { error: 'This browser can’t use passkeys. Try another browser or device.' } });
    return post('/auth/passkey/assert/options').then(function (o) {
      if (!o.ok) return o;
      var p = o.d.options;
      p.challenge = b64uToBuf(p.challenge);
      p.allowCredentials = (p.allowCredentials || []).map(function (c) { return { type: c.type, id: b64uToBuf(c.id), transports: c.transports }; });
      return navigator.credentials.get({ publicKey: p })
        .then(function (cred) { return post('/auth/passkey/assert/finish', { response: serialize(cred, 'get') }); }, failed);
    });
  }

  // A JSON POST; when the answer is "confirm with your passkey first", it does so (one tap) and tries once more. A member
  // without a passkey, or in recovery, gets the server's answer back as it is, with the link to add one.
  function postJson(url, body) {
    return post(url, body).then(function (x) {
      var s = x.d && x.d.step_up;
      if (x.status !== 403 || !s || !s.has_passkey || s.recovery_until) return x;
      return stepUp().then(function (u) { return u.ok ? post(url, body) : u; });
    });
  }

  window.dogPasskey = { supported: supported, enrol: enrol, stepUp: stepUp, postJson: postJson };
})();
