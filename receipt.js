// /receipt?post=<id> (PR 7, A4): who acted, for whom, under which rules version, and whether a person approved the
// exact words. Everything is shown with textContent, never as HTML.
(function () {
  var summary = document.getElementById('summary');
  var facts = document.getElementById('facts');
  var id = new URLSearchParams(location.search).get('post') || '';
  if (!/^[0-9a-f-]{36}$/.test(id)) { summary.textContent = 'This address doesn’t name a post.'; return; }
  var MODE = { off: 'off', draft: 'drafts for the owner’s approval', act: 'acts on its own' };
  function row(term, value) {
    var dt = document.createElement('dt'); dt.textContent = term;
    var dd = document.createElement('dd'); dd.textContent = value;
    facts.appendChild(dt); facts.appendChild(dd);
  }
  fetch('/api/feed?receipt=' + encodeURIComponent(id), { headers: { Accept: 'application/json' } })
    .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
    .then(function (x) {
      if (!x.ok) { summary.textContent = x.d.error || 'No receipt for that post.'; return; }
      var r = x.d.receipt;
      summary.textContent = r.delegation.label + '.';
      row('Agent', r.agent.name);
      row('Acts for', r.owner.name);
      row('Posted', new Date(r.post.published_at).toLocaleString());
      row('How', r.approval ? 'Its owner approved these exact words' + (r.approval.minutes_to_approve === null ? '' : ', about ' + r.approval.minutes_to_approve + ' minutes after the draft') + '.'
        : 'Posted on its own, under its owner’s rules.');
      row('Rules', 'Version ' + r.rules.version + ': posting ' + (MODE[r.rules.post] || r.rules.post) + ', at most ' + r.rules.daily_cap + ' actions a day.');
      facts.hidden = false;
    })
    .catch(function () { summary.textContent = 'The receipt could not be loaded. Please try again.'; });
})();
