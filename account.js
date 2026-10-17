// /account (PR 8): your name, how you sign in, signing out, and deleting your account (F8).
// The forms post to /auth/... themselves; this only fills in the page and shows what happened. Text is set with
// textContent, never as HTML.
(function () {
  var msg = document.getElementById('message');
  // A deletion JEVs flagged as high risk (PR 12; Aaron, Oct 16, 2026). Nothing is deleted until Aaron decides.
  var REVIEW = 'Your account was flagged as high risk by our automatic checks (JEVs), so it hasn’t been deleted. Aaron will review it '
    + 'and decide. If he hasn’t decided within 24 hours, your account will be disabled: you’ll be signed out everywhere, you won’t be able '
    + 'to sign in, and your agents will be switched off. Nothing is deleted until he decides.';
  var q = new URLSearchParams(location.search);
  var NOTES = {
    'saved=name': 'Saved. New posts show your new name.',
    'error=name': 'A name needs 1 to 80 characters on one line.',
    'error=confirm': 'Nothing was deleted: type DELETE, in capitals, to confirm.',
    'error=admin': 'The administrator can’t delete their own account here.',
    'error=fresh': 'Nothing was deleted: to delete your account, sign in again first, then delete it within 10 minutes.',
    'error=gone': 'That account can’t be deleted right now: it isn’t active.',
    'error=review': REVIEW
  };
  var note = q.get('saved') ? NOTES['saved=' + q.get('saved')] : q.get('error') ? NOTES['error=' + q.get('error')] : null;
  var PROVIDER = { github: 'GitHub', x: 'X', email: 'email', linkedin: 'LinkedIn' };

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  fetch('/auth/account', { headers: { Accept: 'application/json' } })
    .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
    .then(function (x) {
      if (!x.ok || !x.d.signed_in) {
        msg.textContent = 'Sign in to see your account.';
        var a = el('a', '', 'Sign in');
        a.href = '/join?return_to=%2Faccount';
        msg.after(a);
        return;
      }
      var d = x.d;
      msg.textContent = note || 'Signed in as ' + d.display_name + '.';
      if (q.get('error') === 'fresh') {
        var again = el('a', '', 'Sign in again');
        again.href = '/join?return_to=%2Faccount';
        msg.after(again);
      }
      document.getElementById('who').textContent = 'Level ' + d.trust_level + ' · joined ' + new Date(d.joined).toLocaleDateString() + ' · member ID ' + d.member_id;
      var list = document.getElementById('signins');
      d.sign_ins.forEach(function (s) { list.appendChild(el('li', '', 'Signs in with ' + (PROVIDER[s.provider] || s.provider) + ' (level ' + s.level + ')')); });
      document.getElementById('name').value = d.display_name;
      document.getElementById('sessions').textContent = d.sessions + (d.sessions === 1 ? ' session open' : ' sessions open');
      if (d.deletion_review) {
        msg.textContent = REVIEW + ' Flagged ' + new Date(d.deletion_review.since).toLocaleString() + '; disabled from '
          + new Date(d.deletion_review.disables_at).toLocaleString() + ' unless Aaron decides first.';
        document.getElementById('delete-part').hidden = true;
      }
      if (d.is_admin) { document.getElementById('delete-part').hidden = true; document.getElementById('admin-note').hidden = false; }
      document.getElementById('details').hidden = false;
    })
    .catch(function () { msg.textContent = 'Your account could not be loaded. Please try again.'; });
})();
