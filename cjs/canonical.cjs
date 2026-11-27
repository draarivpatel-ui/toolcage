// Canonical JSON, bounded measurement, immutable copies and audit hashing.

const { createHash } = require('node:crypto');

function stableStringify(value) {
  const seen = new WeakSet();
  return stringifyValue(value, seen);
}

function stringifyValue(value, seen) {
  if (value === null) return 'null';
  const type = typeof value;
  if (type === 'string') return JSON.stringify(value);
  if (type === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('non-finite number cannot be canonicalized');
    return Object.is(value, -0) ? '0' : String(value);
  }
  if (type === 'boolean') return value ? 'true' : 'false';
  if (type !== 'object') throw new TypeError(type + ' values cannot be canonicalized');
  if (seen.has(value)) throw new TypeError('cyclic value cannot be canonicalized');
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return '[' + value.map((entry) => stringifyValue(entry, seen)).join(',') + ']';
    }
    const parts = [];
    for (const key of Object.keys(value).sort()) {
      const entry = value[key];
      if (entry === undefined) throw new TypeError('undefined values cannot be canonicalized');
      parts.push(JSON.stringify(key) + ':' + stringifyValue(entry, seen));
    }
    return '{' + parts.join(',') + '}';
  } finally {
    seen.delete(value);
  }
}

function sha256Text(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function canonicalHash(value) {
  return sha256Text(stableStringify(value));
}

function utf8Bytes(value) {
  return Buffer.byteLength(value, 'utf8');
}

function measuredJsonBytes(value) {
  return utf8Bytes(stableStringify(value));
}

function maxDepthOf(value) {
  const seen = new WeakSet();
  function visit(node, depth) {
    if (node === null || typeof node !== 'object') return depth;
    if (seen.has(node)) throw new TypeError('cyclic value has no finite depth');
    seen.add(node);
    try {
      let best = depth;
      if (Array.isArray(node)) {
        for (const entry of node) best = Math.max(best, visit(entry, depth + 1));
      } else {
        for (const key of Object.keys(node)) best = Math.max(best, visit(node[key], depth + 1));
      }
      return best;
    } finally {
      seen.delete(node);
    }
  }
  return visit(value, 0);
}

function deepImmutableCopy(value) {
  if (Array.isArray(value)) return Object.freeze(value.map((entry) => deepImmutableCopy(entry)));
  if (value !== null && typeof value === 'object') {
    const output = {};
    for (const key of Object.keys(value)) output[key] = deepImmutableCopy(value[key]);
    return Object.freeze(output);
  }
  return value;
}

function redactForDisplay(value) {
  if (Array.isArray(value)) return value.map((entry) => redactForDisplay(entry));
  if (value !== null && typeof value === 'object') {
    const output = {};
    for (const key of Object.keys(value)) output[key] = redactForDisplay(value[key]);
    return output;
  }
  return value;
}

exports.stableStringify = stableStringify;
exports.sha256Text = sha256Text;
exports.canonicalHash = canonicalHash;
exports.utf8Bytes = utf8Bytes;
exports.measuredJsonBytes = measuredJsonBytes;
exports.maxDepthOf = maxDepthOf;
exports.deepImmutableCopy = deepImmutableCopy;
exports.redactForDisplay = redactForDisplay;
