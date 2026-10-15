// Input checks for everything that goes into the database (S8). Every value is checked for type and size before a
// query runs, and the database has matching limits as a second line. Errors name the field, never echo the value,
// so a rejected input can't put someone's private text into our logs.
'use strict';

class ValidationError extends Error {
  constructor(field, problem) {
    super(field + ' ' + problem);
    this.name = 'ValidationError';
    this.field = field;
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
// Control characters (C0 and C1) other than tab and newline have no place in names or posts. Single-line text
// also refuses tab and newlines. Invisible characters that reorder or hide text (bidirectional overrides and
// isolates, zero-width space, word joiner, byte-order mark) are refused everywhere; the joiners emoji and some
// scripts need (U+200C, U+200D) are allowed.
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/;
const LINE_BREAK = /[\t\n\r\u2028\u2029]/;
const HIDDEN = /[\u200b\u200e\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/;
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

// Text: normalized to NFC, trimmed, and limited in characters (Unicode code points, as Postgres counts them).
function text(field, value, { min = 1, max, pattern, multiline = false } = {}) {
  if (!Number.isInteger(max) || max < 1) throw new Error('text() needs a max for ' + field);
  if (typeof value !== 'string') throw new ValidationError(field, 'must be text');
  // Checked before normalizing so a huge input costs nothing to reject.
  if (value.length > max * 4) throw new ValidationError(field, 'is too long');
  if (LONE_SURROGATE.test(value)) throw new ValidationError(field, 'is not valid text');
  const s = value.normalize('NFC').trim();
  if (CONTROL.test(s) || (!multiline && LINE_BREAK.test(s))) throw new ValidationError(field, 'contains control characters');
  if (HIDDEN.test(s)) throw new ValidationError(field, 'contains invisible formatting characters');
  const n = [...s].length;
  if (n < min) throw new ValidationError(field, min === 1 ? 'is required' : 'is too short');
  if (n > max) throw new ValidationError(field, 'is too long');
  if (pattern && !pattern.test(s)) throw new ValidationError(field, 'is not in the expected format');
  return s;
}

function uuid(field, value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw new ValidationError(field, 'must be an ID');
  return value;
}

function int(field, value, { min, max }) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new ValidationError(field, 'must be a whole number from ' + min + ' to ' + max);
  }
  return value;
}

function oneOf(field, value, allowed) {
  if (!allowed.includes(value)) throw new ValidationError(field, 'must be one of ' + allowed.join(', '));
  return value;
}

// A small JSON object, limited by its size in bytes once written out.
function object(field, value, { maxBytes }) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new ValidationError(field, 'must be an object');
  }
  let s;
  try { s = JSON.stringify(value); } catch { throw new ValidationError(field, 'must be plain data'); }
  if (typeof s !== 'string') throw new ValidationError(field, 'must be plain data');
  // Postgres can't store the NUL character in JSON, so it's refused here rather than failing in the database.
  if (s.includes('\\u0000')) throw new ValidationError(field, 'contains control characters');
  if (Buffer.byteLength(s, 'utf8') > maxBytes) throw new ValidationError(field, 'is too large');
  return JSON.parse(s);
}

module.exports = { ValidationError, text, uuid, int, oneOf, object };
