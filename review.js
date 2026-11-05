// /review moved to /admin/review on Nov 5, 2026 (the design handoff, CODING_AGENT_SPEC.md section 6), as /agents moved
// to /account/agents. An old link, a bookmark, or a notice the database wrote before the move keeps working: it is
// passed on with its query and its part after "#". Only our own path is ever followed.
(function () {
  'use strict';
  location.replace('/admin/review' + location.search + location.hash);
})();
