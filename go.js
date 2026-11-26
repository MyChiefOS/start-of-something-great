// /go (088; Aaron, Nov 25: "check links again when someone clicks them"): an outside link from a post is checked
// against the security wiki's threat lists at the moment of the click (/api/work/link), then followed, or stopped with
// a warning (W49). The link travels in the address as ?u=, is never put into the page as markup, and only http and
// https links are followed.
(function () {
  'use strict';
  var status = document.getElementById('go-status');
  var shown = document.getElementById('go-url');
  var acts = document.getElementById('go-acts');
  var on = document.getElementById('go-on');
  var u = new URLSearchParams(location.search).get('u') || '';
  var ok = /^https?:\/\/[^\s/?#]+/i.test(u) && u.length <= 2000;
  if (!ok) { status.textContent = 'That isn’t a web link this page can follow.'; return; }
  shown.textContent = u; shown.hidden = false;
  fetch('/api/work/link?u=' + encodeURIComponent(u), { headers: { accept: 'application/json' } })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (b) {
      var d = b && (b.data || b);
      if (d && d.verdict === 'ok') { status.textContent = 'This link is clear. Opening it…'; location.replace(u); return; }
      if (d && d.verdict === 'blocked') { status.textContent = 'Stopped: ' + d.why; acts.hidden = false; on.hidden = true; return; }
      if (d && d.verdict === 'warn') { status.textContent = 'Careful: ' + d.why; on.href = u; acts.hidden = false; return; }
      status.textContent = 'The link couldn’t be checked just now. You can still go on, at your own risk.'; on.href = u; acts.hidden = false;
    })
    .catch(function () { status.textContent = 'The link couldn’t be checked just now. You can still go on, at your own risk.'; on.href = u; acts.hidden = false; });
})();
