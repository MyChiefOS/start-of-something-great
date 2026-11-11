// /talk, topic threads (USE-CASES.md row 20). The page as written shows the welcome thread, and with one topic this
// script changes nothing. When Day One Great's account has started more threads on GitHub, it lists them above the
// post; /talk?topic=<number> shows that topic's post and loads its replies in place of the welcome thread's.
// Everything from GitHub is written as text, never as HTML. The topics come from /api/conversation, which lists only
// discussions our own account started, so an address can't make this page show a thread somebody else opened.
(function () {
  'use strict';
  var REPO = 'https://github.com/MyChiefOS/start-of-something-great/discussions/';
  var WELCOME = REPO + '1';
  var asked = new URLSearchParams(location.search).get('topic');
  // Only a whole number from 2 up is another topic; anything else is the welcome thread, as written.
  var number = asked && /^[1-9][0-9]{0,8}$/.test(asked) && asked !== '1' ? Number(asked) : 1;
  var nav = document.getElementById('topics');
  var title = document.getElementById('post-title');
  if (!nav || !title) return;
  var card = title.parentNode;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function day(iso) {
    var d = new Date(iso);
    return isNaN(d) ? '' : d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });
  }

  // The list of topics, shown only when there is more than one.
  function list(topics) {
    if (!topics || topics.length < 2) return;
    nav.appendChild(el('h2', 'h3', 'Topics'));
    var ul = el('ul', 'rule3');
    topics.forEach(function (t) {
      var li = el('li');
      var a = el('a', '', t.title);
      a.href = t.number === 1 ? '/talk' : '/talk?topic=' + t.number;
      if (t.number === number) a.setAttribute('aria-current', 'page');
      li.appendChild(a);
      li.appendChild(el('span', 'fine', ' ' + (t.reply_count === 1 ? '1 reply' : (t.reply_count || 0) + ' replies')));
      ul.appendChild(li);
    });
    nav.appendChild(ul);
    nav.hidden = false;
  }

  // Another topic's post, in the card the welcome post is written in: its title, who started it and when, and its
  // words as plain paragraphs.
  function show(thread) {
    // Only a thread in our own repository's discussions is linked, whatever the answer says.
    if (String(thread.url).indexOf(REPO) !== 0) thread.url = REPO + number;
    title.textContent = thread.title;
    document.title = thread.title + ' · Talk · Day One Great';
    var by = el('p', 'fine', 'Started by ' + (thread.started_by || 'Day One Great') + (day(thread.started_at) ? ' · ' + day(thread.started_at) : '') + ' · ');
    var gh = el('a', '', 'View on GitHub');
    gh.href = thread.url;
    by.appendChild(gh);
    while (card.firstChild) card.firstChild.remove();
    card.appendChild(by);
    card.appendChild(title);
    String(thread.body || '').split(/\n\s*\n/).forEach(function (para) {
      if (para.trim()) card.appendChild(el('p', '', para.trim()));
    });
    // Every link on the page to the welcome thread on GitHub now goes to this topic's thread.
    Array.prototype.forEach.call(document.querySelectorAll('a'), function (a) {
      if (a.getAttribute('href') === WELCOME) a.href = thread.url;
    });
  }

  // The replies: giscus, loaded for this topic's discussion. The page's own giscus script (the welcome thread) has
  // run by the time the page has loaded, so what it drew is taken out and the same script is loaded again with this
  // topic's number: the same attributes as the page's, only the number changed.
  // The page's giscus attributes, in the page's order (test/design-stories.test.js keeps the page's own).
  var GISCUS = ['src', 'data-repo', 'data-repo-id', 'data-mapping', 'data-term', 'data-strict', 'data-reactions-enabled', 'data-emit-metadata',
    'data-input-position', 'data-theme', 'data-lang', 'data-loading', 'crossorigin', 'async'];
  var giscus = document.querySelector('script[src="https://giscus.app/client.js"]');
  var repliesCard = giscus ? giscus.parentNode : null;
  // On another topic's address the welcome thread's replies are never shown under it: the replies card stays hidden
  // until this topic's replies are loading, or until the page falls back to the welcome thread.
  if (number !== 1 && repliesCard) repliesCard.hidden = true;
  function replies(n) {
    var was = giscus;
    if (!was) return;
    var into = was.parentNode;
    Array.prototype.forEach.call(document.querySelectorAll('.giscus'), function (g) { g.remove(); });
    var s = document.createElement('script');
    GISCUS.forEach(function (name) {
      var v = was.getAttribute(name);
      if (v !== null) s.setAttribute(name, name === 'data-term' ? String(n) : v);
    });
    was.remove();
    into.insertBefore(s, into.firstChild);
    into.hidden = false;
  }
  function whenLoaded(fn) {
    if (document.readyState === 'complete') fn(); else window.addEventListener('load', fn);
  }

  function notice(text) {
    var p = el('p', 'fine', text + ' ');
    p.setAttribute('role', 'status');
    var a = el('a', '', 'All of Talk');
    a.href = '/talk';
    p.appendChild(a);
    card.parentNode.insertBefore(p, card);
    if (repliesCard) repliesCard.hidden = false;
  }

  fetch('/api/conversation?limit=1' + (number === 1 ? '' : '&topic=' + number), { headers: { Accept: 'application/json' } })
    .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d }; }); })
    .then(function (x) {
      if (x.ok) {
        list(x.d.topics);
        if (number === 1) return;
        if (x.d.thread && x.d.thread.number === number) { show(x.d.thread); whenLoaded(function () { replies(number); }); }
        else notice('That topic couldn\u2019t be read just now, so this is the welcome thread.');
        return;
      }
      if (number !== 1) notice(x.status === 404 ? 'That topic isn’t one of ours, so this is the welcome thread.' : 'That topic couldn’t be read just now, so this is the welcome thread.');
    })
    .catch(function () {
      if (number !== 1) notice('That topic couldn’t be read just now, so this is the welcome thread.');
    });
})();
