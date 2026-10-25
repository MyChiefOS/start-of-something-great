// GitHub posts JEVs hid (harness/PLAN.md fix 2; USE-CASES.md row 10). The site reads the conversation from GitHub's
// REST API, which doesn't say which comments are hidden; the JEVs gate records it (app.gh_posts.hidden, migration 016),
// and app.gh_hidden (018) answers, for the post IDs the site already has, which of them are hidden. Nothing else from
// the GitHub tables is readable by the site.
'use strict';

const MAX = 200; // the function reads at most this many IDs a call
const NODE_ID = /^[A-Za-z0-9_=-]{1,100}$/; // GitHub's node IDs, as the gate accepts them

// The set of node IDs, from those given, that JEVs has hidden.
async function hidden(t, nodeIds) {
  const ids = [...new Set((nodeIds || []).filter((x) => typeof x === 'string' && NODE_ID.test(x)))].slice(0, MAX);
  if (!ids.length) return new Set();
  const rows = await t`select h.node_id from app.gh_hidden(${ids}::text[]) as h(node_id)`;
  return new Set(rows.map((r) => r.node_id));
}

module.exports = { hidden, MAX };
