// Writing to the audit log (S7, G4). Call it inside the same transaction as the change it records, so the change
// and its record succeed or fail together. Who acted is filled in by the database from the transaction's actor,
// and its policy refuses a row in anyone else's name.
'use strict';

const v = require('./validate');

const ACTION = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$/;
const KIND = /^[a-z][a-z_]*$/;

async function record(t, { action, subjectKind = null, subjectId = null, detail = {} }) {
  const a = v.text('action', action, { max: 64, pattern: ACTION });
  const k = subjectKind === null ? null : v.text('subjectKind', subjectKind, { max: 32, pattern: KIND });
  const id = subjectId === null ? null : v.uuid('subjectId', subjectId);
  // 2 KB here; the database allows 4 KB because Postgres writes JSON out with extra spaces.
  const d = v.object('detail', detail, { maxBytes: 2048 });
  // Nothing is returned: only Aaron may read the log, and "insert ... returning" counts as reading.
  await t`insert into app.audit_log (action, subject_kind, subject_id, detail) values (${a}, ${k}, ${id}, ${t.json(d)})`;
}

module.exports = { record };
