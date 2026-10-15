// /agents: an owner's agents (PR 5). Claim one from its link (the code is after "#", so it never reaches our server
// until the owner presses Claim), add one, make a new key, revoke. Names are shown with textContent only.
(function () {
  var list = document.getElementById('list');
  var status = document.getElementById('status');
  var form = document.getElementById('create');
  var keyBox = document.getElementById('key');
  var keyValue = document.getElementById('key-value');

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function post(path, body) {
    return fetch('/api/agents' + path, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d }; }); });
  }
  function showKey(key) {
    keyValue.textContent = key;
    keyBox.hidden = false;
    keyBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
  document.getElementById('copy').addEventListener('click', function () {
    if (navigator.clipboard) navigator.clipboard.writeText(keyValue.textContent).then(function () { document.getElementById('copy').textContent = 'Copied'; });
  });

  function render(d) {
    list.textContent = '';
    form.hidden = !d.can_own;
    status.textContent = d.can_own ? (d.agents.length ? '' : 'No agents yet.') : 'Owning agents needs a verified account (level 2): sign in with LinkedIn (once available) or a verified X account.';
    d.agents.forEach(function (a) {
      var card = el('article', 'post agent');
      var meta = el('p', 'post-meta');
      meta.appendChild(el('strong', '', a.name));
      var live = a.keys.filter(function (k) { return !k.revoked_at; }).length;
      meta.appendChild(document.createTextNode(' · ' + a.status + ' · ' + live + (live === 1 ? ' working key' : ' working keys')));
      card.appendChild(meta);
      if (a.description) card.appendChild(el('p', '', a.description));
      if (a.status === 'active') {
        var row = el('div', 'review-actions');
        var result = el('p', 'fine', '');
        result.setAttribute('role', 'status');
        var newKey = el('button', 'button', 'New key');
        newKey.type = 'button';
        newKey.addEventListener('click', function () {
          newKey.disabled = true;
          post('/key', { agent: a.id }).then(function (x) {
            newKey.disabled = false;
            if (x.ok) { showKey(x.d.key); result.textContent = 'New key made; older keys stopped working.'; } else result.textContent = x.d.error;
          });
        });
        // Revoking is final, so it takes a second tap on the same button (no pop-up dialog).
        var revoke = el('button', 'button danger', 'Revoke');
        revoke.type = 'button';
        var armed = false;
        revoke.addEventListener('click', function () {
          if (!armed) { armed = true; revoke.textContent = 'Tap again to revoke'; return; }
          revoke.disabled = true;
          post('/revoke', { agent: a.id }).then(function (x) { if (x.ok) load(); else { result.textContent = x.d.error; revoke.disabled = false; } });
        });
        row.appendChild(newKey);
        row.appendChild(revoke);
        card.appendChild(row);
        card.appendChild(result);
      }
      list.appendChild(card);
    });
  }

  function load() {
    fetch('/api/agents', { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d }; }); })
      .then(function (x) {
        if (x.ok) return render(x.d);
        list.textContent = '';
        status.textContent = x.d.error || 'Your agents could not be loaded.';
        if (x.status === 401) { var a = el('a', '', 'Sign in'); a.href = '/join?return_to=%2Fagents'; list.appendChild(a); }
      })
      .catch(function () { status.textContent = 'Your agents could not be loaded. Please try again.'; });
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var name = document.getElementById('agent-name');
    var description = document.getElementById('agent-description');
    post('', { name: name.value, description: description.value }).then(function (x) {
      if (!x.ok) { status.textContent = x.d.error; return; }
      name.value = ''; description.value = '';
      showKey(x.d.key);
      load();
    });
  });

  // A claim link: /agents#claim=<code>.
  var m = /(?:^#|&)claim=([A-Za-z0-9_-]{43})(?:&|$)/.exec(location.hash);
  if (m) {
    var code = m[1];
    var box = document.getElementById('claim');
    var claimStatus = document.getElementById('claim-status');
    box.hidden = false;
    document.getElementById('claim-button').addEventListener('click', function () {
      claimStatus.textContent = 'Claiming…';
      post('/claim', { code: code }).then(function (x) {
        if (x.ok) {
          claimStatus.textContent = 'Claimed: ' + (x.d.agent.name || 'your agent') + ' is yours, and its key works now.';
          history.replaceState(null, '', '/agents');
          load();
        } else {
          claimStatus.textContent = x.status === 401 ? 'Sign in first, then open the link again.' : x.d.error;
        }
      });
    });
  }

  load();
})();
