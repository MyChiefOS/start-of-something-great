// Members. Sign-in (PR 2) will call create(); everything here checks its inputs first (S8) and leaves the
// decision about who may see or change a row to the database's policies (S1, S3).
'use strict';

const v = require('./validate');
const audit = require('./audit');

const name = (s) => v.text('displayName', s, { max: 80 });

async function create(t, { displayName }) {
  const n = name(displayName);
  const [m] = await t`insert into app.members (display_name) values (${n}) returning id, created_at, display_name, trust_level, status`;
  await audit.record(t, { action: 'member.created', subjectKind: 'member', subjectId: m.id });
  return m;
}

// Returns null when the row doesn't exist or the actor isn't allowed to see it; callers can't tell which.
async function get(t, id) {
  const [m] = await t`select id, created_at, display_name, trust_level, status from app.members where id = ${v.uuid('id', id)}`;
  return m || null;
}

async function rename(t, id, displayName) {
  const n = name(displayName);
  const rows = await t`update app.members set display_name = ${n} where id = ${v.uuid('id', id)} returning id`;
  if (rows.length) await audit.record(t, { action: 'member.renamed', subjectKind: 'member', subjectId: rows[0].id });
  return rows.length === 1;
}

async function setTrustLevel(t, id, level) {
  const l = v.int('trustLevel', level, { min: 0, max: 3 });
  const rows = await t`update app.members set trust_level = ${l} where id = ${v.uuid('id', id)} returning id`;
  if (rows.length) await audit.record(t, { action: 'member.trust_level_set', subjectKind: 'member', subjectId: rows[0].id, detail: { level: l } });
  return rows.length === 1;
}

module.exports = { create, get, rename, setTrustLevel };
