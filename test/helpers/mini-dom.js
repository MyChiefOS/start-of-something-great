// A small stand-in DOM for running a page's real <main> and script without a browser, copied from
// test/ux-signed-out.test.js (UX PR D) with three additions: removeAttribute, a ?query for location.search, and a
// record of every address fetched, every history.replaceState and every location.replace (a hash can be given too). Not a test file itself (test/*.test.js only).
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const read = (p) => fs.readFileSync(path.join(__dirname, '..', '..', p), 'utf8');

// ---- A small DOM: enough of one for these pages' scripts, built from the page's own <main> ----
const VOID = new Set(['input', 'br', 'img', 'meta', 'link', 'hr', 'source', 'wbr']);
class El {
  constructor(tag, doc) {
    this.tagName = tag.toUpperCase(); this.ownerDocument = doc; this.children = []; this.attrs = {}; this.parentNode = null;
    this.hidden = false; this.disabled = false; this.open = false; this.value = ''; this.className = ''; this.on = {}; this._text = '';
    this.classList = { add: (c) => { this.className = (this.className + ' ' + c).trim(); } };
  }
  get id() { return this.attrs.id || ''; } set id(v) { this.attrs.id = String(v); }
  get href() { return this.attrs.href; } set href(v) { this.attrs.href = String(v); }
  get type() { return this.attrs.type; } set type(v) { this.attrs.type = String(v); }
  get textContent() { return this.tagName === '#TEXT' ? this._text : this._text + this.children.map((c) => c.textContent).join(''); }
  set textContent(v) { this.children.forEach((c) => { c.parentNode = null; }); this.children = []; this._text = String(v); }
  get firstChild() { return this.children[0] || null; }
  get childNodes() { return this.children; } // /account counts its Add buttons this way (test/design-app.test.js)
  get options() { return this.children.filter((c) => c.tagName === 'OPTION'); }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'hidden') this.hidden = true; }
  removeAttribute(k) { delete this.attrs[k]; }
  getAttribute(k) { return Object.hasOwn(this.attrs, k) ? this.attrs[k] : null; }
  appendChild(n) { if (n.parentNode) n.remove(); n.parentNode = this; this.children.push(n); return n; }
  insertBefore(n, ref) { if (n.parentNode) n.remove(); n.parentNode = this; const i = ref ? this.children.indexOf(ref) : -1; this.children.splice(i < 0 ? this.children.length : i, 0, n); return n; }
  after(n) { const p = this.parentNode; if (n.parentNode) n.remove(); n.parentNode = p; p.children.splice(p.children.indexOf(this) + 1, 0, n); }
  remove() { if (!this.parentNode) return; const s = this.parentNode.children; s.splice(s.indexOf(this), 1); this.parentNode = null; }
  addEventListener(t, f) { (this.on[t] = this.on[t] || []).push(f); }
  // Runs the listeners in order, as a browser does; stopImmediatePropagation stops the rest.
  click() { this.dispatch('click'); }
  dispatch(type) {
    let stopped = false;
    const ev = { type, target: this, preventDefault() {}, stopImmediatePropagation() { stopped = true; } };
    for (const f of (this.on[type] || []).slice()) { if (stopped) break; f(ev); }
  }
  remove_(i) { this.options[i].remove(); }
  focus() { this.ownerDocument.focused = this; }
  scrollIntoView() {}
  reset() {}
  all() { return this.children.flatMap((c) => [c, ...c.all()]); }
  // Selectors these scripts use: tag, .class, tag.class, #id, [attr], [attr="v"], tag[attr], and "A B" (descendant).
  matches(sel) {
    const m = /^([a-z0-9]*)(?:#([\w-]+))?(?:\.([\w-]+))?(?:\[([\w-]+)(?:="([^"]*)")?\])?$/i.exec(sel);
    if (!m) throw new Error('selector not supported here: ' + sel);
    return (!m[1] || this.tagName === m[1].toUpperCase()) && (!m[2] || this.id === m[2])
      && (!m[3] || this.className.split(/\s+/).includes(m[3])) && (!m[4] || Object.hasOwn(this.attrs, m[4]))
      && (m[5] === undefined || this.attrs[m[4]] === m[5]);
  }
  querySelectorAll(sel) {
    const parts = sel.trim().split(/\s+/);
    let found = this.all().filter((e) => e.matches(parts[0]));
    for (const p of parts.slice(1)) found = found.flatMap((e) => e.all().filter((x) => x.matches(p)));
    return [...new Set(found)];
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  // Shown: neither it nor anything above it is hidden, and no closed <details> stands between (its summary aside).
  shown() {
    for (let e = this, child = null; e; child = e, e = e.parentNode) {
      if (e.hidden) return false;
      if (e.tagName === 'DETAILS' && !e.open && child && child.tagName !== 'SUMMARY') return false;
    }
    return true;
  }
}
// select.remove(i) removes an option; any other element's remove() removes itself.
const baseRemove = El.prototype.remove;
El.prototype.remove = function (i) { if (this.tagName === 'SELECT' && typeof i === 'number') return this.remove_(i); return baseRemove.call(this); };

function parseMain(html, doc) {
  const src = html.slice(html.indexOf('<main'), html.indexOf('</main>') + 7);
  const root = new El('#root', doc);
  const stack = [root];
  const re = /<!--[\s\S]*?-->|<\/([a-z0-9]+)\s*>|<([a-z0-9]+)((?:\s+[^\s=>]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*\/?>|([^<]+)/gi;
  let m;
  while ((m = re.exec(src))) {
    const top = stack[stack.length - 1];
    if (m[1]) { while (stack.length > 1 && stack.pop().tagName !== m[1].toUpperCase()); continue; }
    if (m[2]) {
      const e = new El(m[2], doc);
      const ar = /([^\s=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
      let a;
      while ((a = ar.exec(m[3] || ''))) {
        const v = a[2] ?? a[3] ?? a[4] ?? '';
        e.attrs[a[1]] = v;
        if (a[1] === 'class') e.className = v;
        if (a[1] === 'hidden') e.hidden = true;
        if (a[1] === 'open') e.open = true;
      }
      top.appendChild(e);
      if (!VOID.has(m[2].toLowerCase())) stack.push(e);
      continue;
    }
    if (m[4] && m[4].trim()) { const t = new El('#text', doc); t._text = m[4].replace(/\s+/g, ' '); top.appendChild(t); }
  }
  return root.children[0];
}

// Loads a page: its <main>, then its script, with fetch answered by answers(url, init) -> [status, body].
function page(file, script, answers, search, hash) {
  const doc = { focused: null };
  const main = parseMain(read(file), doc);
  const sent = [];
  const timers = [];
  const asked = [];
  const replaced = [];
  const history = [];
  Object.assign(doc, {
    getElementById: (id) => main.all().find((e) => e.id === id) || (main.id === id ? main : null),
    createElement: (t) => new El(t, doc),
    createTextNode: (t) => { const n = new El('#text', doc); n._text = String(t); return n; },
    querySelectorAll: (s) => main.querySelectorAll(s),
    querySelector: (s) => main.querySelector(s)
  });
  const sandbox = {
    document: doc, location: { hash: hash || '', search: search || '', pathname: '/' + file.replace(/\.html$/, ''), replace: (u) => { replaced.push(u); } },
    history: { replaceState: (s, t, url) => { history.push(url); } }, sessionStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    navigator: {}, URLSearchParams, Promise, JSON, Date, Math, Array, Object, String, Number, Boolean, encodeURIComponent,
    setTimeout: (f, ms) => { timers.push({ f, ms }); return timers.length; }, clearTimeout: (n) => { if (timers[n - 1]) timers[n - 1].f = null; },
    fetch: (url, init) => {
      asked.push(url);
      if (init && init.method && init.method !== 'GET') sent.push({ url, body: JSON.parse(init.body) });
      const [status, body] = answers(url, init);
      return Promise.resolve({ ok: status >= 200 && status < 300, status, json: () => Promise.resolve(body) });
    }
  };
  sandbox.window = sandbox;
  vm.runInNewContext(read(script), sandbox);
  return { main, doc, sent, timers, asked, history, replaced, $: doc.getElementById };
}
const settle = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r)); };

module.exports = { El, parseMain, page, settle };
