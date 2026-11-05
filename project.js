// /projects/{id} (the design handoff of Nov 5, 2026, static/project.html). One project is real so far: this site,
// project "day-one-great" (Aaron's phase 6 decision: the first data is the project's own work). Its latest change is
// read live from our own /api/changes (the newest commit on main, from GitHub) into the card the design draws as the
// latest submission. Any other ID shows the not-found state. Text only (textContent); links only to the repository.
(function () {
  'use strict';
  var ID = 'day-one-great';
  var REPO = 'https://github.com/MyChiefOS/start-of-something-great/commit/';
  var m = /^\/projects\/([^/]+)\/?$/.exec(location.pathname);
  var id = m ? m[1] : (/^\/project\/?$/.test(location.pathname) ? ID : null);
  if (m) { try { id = decodeURIComponent(id); } catch (e) { /* a malformed address: shown as typed */ } }

  if (id !== ID) {
    var found = document.getElementById('project-found');
    var missing = document.getElementById('project-missing');
    found.hidden = true;
    missing.hidden = false;
    document.getElementById('project-title').textContent = 'Project not found';
    document.getElementById('project-crumb').textContent = 'Not found';
    if (id) document.getElementById('project-missing-text').textContent = 'There is no project with the ID ' + id.slice(0, 80) + '.';
    document.title = 'Project not found: Day One Great';
    return;
  }

  var meta = document.getElementById('latest-meta');
  var text = document.getElementById('latest-text');

  function ago(iso) {
    var t = Date.parse(iso);
    if (isNaN(t)) return '';
    var min = Math.max(0, Math.round((Date.now() - t) / 60000));
    if (min < 60) return min + ' min ago';
    if (min < 48 * 60) return Math.round(min / 60) + 'h ago';
    return new Date(t).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' });
  }

  fetch('/api/changes?limit=1', { headers: { Accept: 'application/json' } })
    .then(function (r) { if (!r.ok) throw new Error(String(r.status)); return r.json(); })
    .then(function (d) {
      var c = d && d.changes && d.changes[0];
      if (!c || typeof c.summary !== 'string') return;
      meta.textContent = 'Latest change · ' + (c.author || 'unknown author') + (c.date ? ' · ' + ago(c.date) : '');
      text.textContent = '';
      if (typeof c.url === 'string' && c.url.indexOf(REPO) === 0) {
        var a = document.createElement('a');
        a.href = c.url;
        a.textContent = c.summary;
        text.appendChild(a);
      } else {
        text.textContent = c.summary;
      }
    })
    .catch(function () {
      meta.textContent = 'Latest change · not loaded';
      text.textContent = '';
      text.appendChild(document.createTextNode('GitHub didn’t answer just now; reload to try again, or '));
      var a = document.createElement('a');
      a.href = 'https://github.com/MyChiefOS/start-of-something-great/commits/main';
      a.textContent = 'see every change on GitHub';
      text.appendChild(a);
      text.appendChild(document.createTextNode('.'));
    });
})();
