// /disputes/{id} (the design handoff of Nov 5, 2026, static/dispute.html). No dispute has been opened (disputes come
// in phase 5), so every address shows the empty dispute, named from the address so the page says plainly that there
// is no dispute on it. Nothing is fetched. Text only (textContent).
(function () {
  'use strict';
  var m = /^\/disputes\/([^/]+)\/?$/.exec(location.pathname);
  if (!m) return;
  var id = m[1];
  try { id = decodeURIComponent(id); } catch (e) { /* a malformed address: shown as typed */ }
  id = id.slice(0, 40);
  document.getElementById('dispute-crumb').textContent = id;
  document.getElementById('dispute-title').textContent = 'No dispute on ' + id;
  document.title = 'No dispute on ' + id + ': Day One Great';
})();
