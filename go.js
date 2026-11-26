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
  var raw = new URLSearchParams(location.search).get('u') || '';
  // Parsed, not pattern-matched: only an http or https address, rebuilt from its parts, is ever used. A clear link is
  // still never followed without the person's click, so /go can't be used to bounce someone straight to a phishing page
  // under this site's name (an open redirect, CWE-601).
  var url = null;
  try { url = raw.length <= 2000 ? new URL(raw) : null; } catch (e) { url = null; }
  if (!url || (url.protocol !== 'https:' && url.protocol !== 'http:') || !url.hostname) {
    status.textContent = 'That isn’t a web link this page can follow.'; return;
  }
  var safe = url.protocol + '//' + url.host + url.pathname + url.search + url.hash;
  shown.textContent = safe; shown.hidden = false;
  function offer(text, clear) { status.textContent = text; on.textContent = clear ? 'Open the link' : 'Go on anyway'; on.setAttribute('href', safe); acts.hidden = false; }
  fetch('/api/work/link?u=' + encodeURIComponent(safe), { headers: { accept: 'application/json' } })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (b) {
      var d = b && (b.data || b);
      if (d && d.verdict === 'ok') { offer('This link is clear.', true); return; }
      if (d && d.verdict === 'blocked') { status.textContent = 'Stopped: ' + d.why; acts.hidden = false; on.hidden = true; return; }
      if (d && d.verdict === 'warn') { offer('Careful: ' + d.why); return; }
      offer('The link couldn’t be checked just now. You can still go on, at your own risk.');
    })
    .catch(function () { offer('The link couldn’t be checked just now. You can still go on, at your own risk.'); });
})();
