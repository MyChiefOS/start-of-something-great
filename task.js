// /tasks/<id> (vercel.json rewrites it to /task): one task of the design handoff, from the data scripts/build-data.js
// writes into /work-data.js (window.DOG_WORK) before each commit. No request is made, and everything is written with
// textContent, never as HTML. A task id is "<phase>-<n>", as on Build's task board.
(function () {
  var W = window.DOG_WORK;
  var title = document.getElementById('task-title');
  var dek = document.getElementById('task-dek');
  var body = document.getElementById('task-body');
  var crumbWp = document.getElementById('crumb-wp');
  var crumbTask = document.getElementById('crumb-task');
  var REPO = 'https://github.com/MyChiefOS/start-of-something-great';
  var MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }
  function link(href, text, cls) { var a = el('a', cls || '', text); a.href = href; return a; }
  function date(iso) { var d = new Date(iso); return MON[d.getUTCMonth()] + ' ' + d.getUTCDate() + ', ' + d.getUTCFullYear(); }
  function none(heading, text) {
    title.textContent = heading;
    crumbTask.textContent = heading;
    dek.textContent = text + ' ';
    dek.appendChild(link('/build#task-board', 'See every task on Build.'));
  }
  if (!W) { none('Task', 'The task data could not be loaded.'); return; }

  var m = location.pathname.match(/^\/tasks\/(\d{1,2}-\d{1,3})\/?$/);
  if (!m) { none('Choose a task', 'This address doesn’t name a task.'); return; }
  var t = Object.prototype.hasOwnProperty.call(W.tasks, m[1]) ? W.tasks[m[1]] : null;
  if (!t) { none('No such task', 'There is no task ' + m[1] + ' in the design handoff.'); return; }
  var wp = W.packages.filter(function (p) { return p.id === t.package; })[0];
  var pr = t.pr ? W.prs.filter(function (p) { return p.number === t.pr; })[0] : null;

  document.title = t.title + ': Task ' + t.label + ': Day One Great';
  title.textContent = t.title;
  crumbWp.textContent = 'Work package ' + wp.id;
  crumbWp.hidden = false;
  crumbTask.textContent = 'Task ' + t.label;
  dek.textContent = 'Task ' + t.label + ' in work package ' + wp.id + ', ' + wp.title.charAt(0).toLowerCase() + wp.title.slice(1) + '.';

  // The steps a merged pull request has been through: claimed (Claude's commits), submitted (the pull request) and
  // approved (Aaron's merge). Audited and anchored need phase 5 and phase 2.
  var done = pr ? ['Open', 'Claimed', 'Submitted', 'Approved'] : ['Open'];
  Array.prototype.forEach.call(document.getElementById('task-steps').children, function (li) {
    if (done.indexOf(li.textContent) >= 0) { li.className = 'done'; li.appendChild(el('span', 'vh', ', done')); }
  });

  var pills = document.getElementById('task-pills');
  var cls = { Merged: 'pill f', Open: 'pill', 'Not decided': 'pill m', 'On hold': 'pill m' };
  pills.appendChild(el('span', 'pill m', 'Class: not set'));
  pills.appendChild(el('span', cls[t.status] || 'pill', t.status));
  pills.appendChild(el('span', 'pill m', 'Weight: not set'));

  var facts = document.getElementById('task-facts');
  function row(term, value) {
    facts.appendChild(el('dt', '', term));
    var dd = el('dd');
    (Array.isArray(value) ? value : [value]).forEach(function (v) { dd.appendChild(typeof v === 'string' ? document.createTextNode(v) : v); });
    facts.appendChild(dd);
  }
  row('Proposal', W.proposal.name + ' · work package ' + wp.id);
  row('Class', 'Not assigned yet: the four kinds of task come with phase 5');
  if (pr) {
    row('Pull request', [link(pr.url, '#' + pr.number), ', merged ' + date(pr.merged_at) + ' by ' + pr.merged_by + ' · +' + pr.additions.toLocaleString('en-US') + ' −' + pr.deletions.toLocaleString('en-US') + ', ' + pr.files + ' files']);
    row('Done by', pr.claude_commits === pr.commits ? 'Claude, ' + pr.commits + (pr.commits === 1 ? ' commit' : ' commits') : pr.claude_commits + ' of ' + pr.commits + ' commits by Claude');
  } else {
    row('Claim', 'Not open yet. When it is, a claim holds for 72 hours, then reopens if nothing is submitted.');
  }
  if (wp.decision) row('Aaron\u2019s decision, Nov 5', '\u201c' + wp.decision + '\u201d');
  row('Auditor', 'Not assigned: auditors chosen by public randomness come with phase 5');
  row('Dispute', 'No window: nothing is anchored yet (phase 2)');
  row('Merge', 'Proposed: worker, auditor and person gate, 3 of 3. Today Aaron merges every pull request.');

  var acts = document.getElementById('task-acts');
  if (pr) {
    acts.appendChild(link(pr.url, 'Open the pull request', 'btn p'));
  } else {
    var b = el('button', 'btn p', 'Claim this task');
    b.type = 'button';
    b.setAttribute('aria-disabled', 'true');
    b.setAttribute('aria-describedby', 'claim-why');
    acts.appendChild(b);
  }
  acts.appendChild(link('/build', 'Back to Build', 'btn'));
  if (!pr) {
    var why = el('p', 'fine', t.status === 'Open' ? 'Claiming opens with phase 5. Until then, this work is done by pull requests to ' : 'Not open to claim: ' + t.status.toLowerCase() + '. Its work is tracked in ');
    why.id = 'claim-why';
    why.appendChild(link(REPO, 'the repository'));
    why.appendChild(document.createTextNode('.'));
    acts.parentNode.insertBefore(why, acts.nextSibling);
  }
  body.hidden = false;
}());
