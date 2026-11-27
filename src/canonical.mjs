// Canonical JSON, bounded measurement, immutable copies and audit hashing.

import { createHash } from 'node:crypto';

export const MAX_JSON_GRAPH_DEPTH = 128;

function graphError(reason) {
  if (reason === 'cyclic') return new TypeError('cyclic value cannot be canonicalized');
  if (reason === 'shared') return new TypeError('shared object references cannot be canonicalized safely');
  return new TypeError(`json value exceeds maximum safe structural depth ${MAX_JSON_GRAPH_DEPTH}`);
}

export function analyzeJsonGraph(value, maximumDepth = MAX_JSON_GRAPH_DEPTH) {
  const seen = new WeakSet();
  const active = new WeakSet();
  let depth = 0;
  const stack = [{ node: value, depth: 0, enter: true }];
  while (stack.length > 0) {
    const frame = stack.pop();
    const node = frame.node;
    if (node === null || typeof node !== 'object') {
      if (frame.depth > maximumDepth) return { ok: false, reason: 'depth', depth: frame.depth };
      depth = Math.max(depth, frame.depth);
      continue;
    }
    if (!frame.enter) {
      active.delete(node);
      continue;
    }
    if (active.has(node)) return { ok: false, reason: 'cyclic', depth: frame.depth };
    if (seen.has(node)) return { ok: false, reason: 'shared', depth: frame.depth };
    if (frame.depth > maximumDepth) return { ok: false, reason: 'depth', depth: frame.depth };
    seen.add(node);
    active.add(node);
    depth = Math.max(depth, frame.depth);
    stack.push({ node, depth: frame.depth, enter: false });
    for (const key of Object.keys(node)) {
      const descriptor = Object.getOwnPropertyDescriptor(node, key);
      if (descriptor && Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
        stack.push({ node: descriptor.value, depth: frame.depth + 1, enter: true });
      }
    }
  }
  return { ok: true, depth };
}

function assertSafeGraph(value) {
  const graph = analyzeJsonGraph(value);
  if (!graph.ok) throw graphError(graph.reason);
  return graph;
}

function ownDataValue(value, key) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor) throw new TypeError('sparse arrays cannot be canonicalized');
  if (typeof descriptor.get === 'function' || typeof descriptor.set === 'function') {
    throw new TypeError('accessor properties cannot be canonicalized');
  }
  return descriptor.value;
}

export function stableStringify(value) {
  assertSafeGraph(value);
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
      const entries = [];
      for (let index = 0; index < value.length; index += 1) {
        entries.push(stringifyValue(ownDataValue(value, String(index)), seen));
      }
      return '[' + entries.join(',') + ']';
    }
    const parts = [];
    for (const key of Object.keys(value).sort()) {
      const entry = ownDataValue(value, key);
      if (entry === undefined) throw new TypeError('undefined values cannot be canonicalized');
      parts.push(JSON.stringify(key) + ':' + stringifyValue(entry, seen));
    }
    return '{' + parts.join(',') + '}';
  } finally {
    seen.delete(value);
  }
}

export function sha256Text(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export function canonicalHash(value) {
  return sha256Text(stableStringify(value));
}

export function utf8Bytes(value) {
  return Buffer.byteLength(value, 'utf8');
}

export function measuredJsonBytes(value) {
  return utf8Bytes(stableStringify(value));
}

export function maxDepthOf(value) {
  return assertSafeGraph(value).depth;
}

export function deepImmutableCopy(value) {
  if (Array.isArray(value)) return Object.freeze(value.map((entry) => deepImmutableCopy(entry)));
  if (value !== null && typeof value === 'object') {
    const output = {};
    for (const key of Object.keys(value)) output[key] = deepImmutableCopy(value[key]);
    return Object.freeze(output);
  }
  return value;
}

export function redactForDisplay(value) {
  if (Array.isArray(value)) return value.map((entry) => redactForDisplay(entry));
  if (value !== null && typeof value === 'object') {
    const output = {};
    for (const key of Object.keys(value)) output[key] = redactForDisplay(value[key]);
    return output;
  }
  return value;
}
