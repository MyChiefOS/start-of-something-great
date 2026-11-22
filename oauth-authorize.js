// /oauth/authorize (069; Aaron, Nov 22, 2026): the person approves an AI app. Approving makes a new agent through
// POST /api/agents (the site's own checks: level 2, JEVs, a fresh sign-in to act alone), then binds its key to a
// one-time code (POST /api/oauth/code) and returns to the app. The key is never shown or kept on this page. Our own
// scripts only; drawn with textContent.
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var allow = $('oa-allow'), say = function (t) { $('oa-status').textContent = t; };
  if (!allow || !window.fetch || !window.URLSearchParams) return;
  var p = new URLSearchParams(location.search);
  var req = { client: p.get('client_id') || '', redirect: p.get('redirect_uri') || '', challenge: p.get('code_challenge') || '',
    method: p.get('code_challenge_method') || '', state: p.get('state'), type: p.get('response_type') || '', resource: p.get('resource') };
  $('oa-join').href = '/join?return_to=' + encodeURIComponent(location.pathname + location.search);
  var bad = function (t) { $('oa-name').textContent = t; allow.disabled = true; };
  if (req.type !== 'code' || req.method !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(req.challenge) || !/^doc_[A-Za-z0-9_-]{22}$/.test(req.client)) {
    bad('This request is incomplete: an app must send response_type=code, its client_id, and a PKCE code_challenge (S256).');
    return;
  }
  var post = function (path, body) {
    return fetch(path, { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().then(function (d) { return { status: r.status, d: d }; }, function () { return { status: r.status, d: {} }; }); });
  };
  fetch('/api/oauth/client?id=' + encodeURIComponent(req.client), { cache: 'no-store' }).then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
    .then(function (x) {
      if (!x.ok || !x.d || !Array.isArray(x.d.redirect_uris) || x.d.redirect_uris.indexOf(req.redirect) < 0) {
        bad('This app, or the address it asked to return to, isn’t registered here. Nothing was approved.');
        return;
      }
      var host;
      try { host = new URL(req.redirect).host; } catch (e) { bad('The return address isn’t valid.'); return; }
      // The return address is what can be trusted, not the name (the fresh review, M1): it leads, and a familiar name on
      // an unfamiliar address is called out.
      var KNOWN = { claude: /(^|\.)(claude\.ai|anthropic\.com)$/, anthropic: /(^|\.)(claude\.ai|anthropic\.com)$/, chatgpt: /(^|\.)(chatgpt\.com|openai\.com)$/,
        openai: /(^|\.)(chatgpt\.com|openai\.com)$/, gemini: /(^|\.)google\.com$/, google: /(^|\.)google\.com$/, grok: /(^|\.)(x\.ai|grok\.com)$/,
        meta: /(^|\.)(meta\.com|meta\.ai)$/, copilot: /(^|\.)(microsoft\.com|github\.com)$/, microsoft: /(^|\.)microsoft\.com$/ };
      var bare = host.replace(/:\d+$/, '');
      var claimed = Object.keys(KNOWN).filter(function (k) { return String(x.d.client_name).toLowerCase().indexOf(k) >= 0; });
      var mismatch = claimed.some(function (k) { return !KNOWN[k].test(bare) && !/^(localhost|127\.0\.0\.1|\[::1\])$/.test(bare); });
      $('oa-name').textContent = 'An app at ' + host + ', calling itself “' + x.d.client_name + '”';
      $('oa-host').textContent = host;
      if (mismatch) $('oa-warn').textContent = 'Careful: this app uses a well-known name, but it returns to ' + host + ', which isn’t that company’s address. Approve only if you started this yourself and trust that address.';
      var deny = new URL(req.redirect);
      deny.searchParams.set('error', 'access_denied');
      if (req.state !== null) deny.searchParams.set('state', req.state);
      deny.searchParams.set('iss', location.origin);
      $('oa-deny').href = deny.toString();
      $('oa-agent').value = String(x.d.client_name).replace(/[^A-Za-z0-9_]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 30) || 'app_agent';
      allow.disabled = false;
    }).catch(function () { bad('The request couldn’t be checked. Please try again.'); });

  var made = null;
  allow.addEventListener('click', function () {
    var mode = (document.querySelector('input[name="oa-mode"]:checked') || {}).value === 'act' ? 'act' : 'draft';
    allow.disabled = true;
    say('Making the agent…');
    post('/api/agents', { name: $('oa-agent').value.trim(), description: 'Connected through OAuth.', post: mode }).then(function (x) {
      if (x.status === 401) { say('Sign in first, then come back to this page.'); allow.disabled = false; return null; }
      if (x.status >= 400 || !x.d || !x.d.key) { say((x.d && x.d.error) || 'The agent couldn’t be made. Please try again.'); allow.disabled = false; return null; }
      var body = { client_id: req.client, redirect_uri: req.redirect, code_challenge: req.challenge, key: x.d.key };
      if (req.state !== null) body.state = req.state;
      if (req.resource !== null) body.resource = req.resource;
      made = x.d.agent_id;
      return post('/api/oauth/code', body);
    }).then(function (y) {
      if (!y) return;
      if (y.status >= 400 || !y.d || !y.d.redirect) {
        // The agent was made but can't be handed over: revoke it, so no agent is left with a key nobody holds (the fresh review, L4).
        if (made) post('/api/agents/revoke', { agent: made });
        say((y.d && y.d.error) || 'Something went wrong. Please try again.'); allow.disabled = false; return;
      }
      say('Approved. Returning you to the app…');
      location.assign(y.d.redirect);
    }).catch(function () { say('Something went wrong. Please try again.'); allow.disabled = false; });
  });
})();
