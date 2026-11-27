// Tamper-evident append-only audit trail.

const { canonicalHash, deepImmutableCopy, sha256Text, stableStringify } = require('./canonical.cjs');

const GENESIS = '0'.repeat(64);

function primitiveDetails(details) {
  if (!details || typeof details !== 'object') return {};
  const output = {};
  for (const key of Object.keys(details).sort()) {
    const value = details[key];
    if (value === undefined) continue;
    if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) output[key] = value;
    else if (Array.isArray(value) && value.every((entry) => entry === null || ['string', 'number', 'boolean'].includes(typeof entry))) output[key] = value.slice();
  }
  return output;
}

class AuditTrail {
  constructor(options) {
    const opts = options && typeof options === 'object' ? options : {};
    this._now = typeof opts.now === 'function' ? opts.now : () => Date.now();
    this._entries = [];
  }

  append(event, fields) {
    const source = fields && typeof fields === 'object' ? fields : {};
    const sequence = this._entries.length;
    const previousHash = sequence === 0 ? GENESIS : this._entries[sequence - 1].hash;
    const body = {
      sequence,
      timestamp: new Date(this._now()).toISOString(),
      event: String(event),
      tool: typeof source.tool === 'string' ? source.tool : null,
      decision: typeof source.decision === 'string' ? source.decision : null,
      inputHash: typeof source.inputHash === 'string' ? source.inputHash : null,
      bytes: Number.isInteger(source.bytes) ? source.bytes : 0,
      durationMs: Number.isFinite(source.durationMs) ? Math.max(0, source.durationMs) : 0,
      details: primitiveDetails(source.details),
      previousHash,
    };
    body.hash = sha256Text(stableStringify(body));
    const frozen = deepImmutableCopy(body);
    this._entries.push(frozen);
    return frozen;
  }

  entries() {
    return Object.freeze(this._entries.slice());
  }

  verify() {
    let previous = GENESIS;
    for (let index = 0; index < this._entries.length; index += 1) {
      const entry = this._entries[index];
      if (entry.sequence !== index || entry.previousHash !== previous) return false;
      const copy = {};
      for (const key of Object.keys(entry).sort()) if (key !== 'hash') copy[key] = entry[key];
      if (sha256Text(stableStringify(copy)) !== entry.hash) return false;
      previous = entry.hash;
    }
    return true;
  }

  digest() {
    if (this._entries.length === 0) return GENESIS;
    return this._entries[this._entries.length - 1].hash;
  }

  statistics() {
    const counts = {};
    let bytes = 0;
    for (const entry of this._entries) {
      counts[entry.event] = (counts[entry.event] || 0) + 1;
      bytes += entry.bytes;
    }
    return deepImmutableCopy({ entries: this._entries.length, bytes, events: counts, digest: this.digest() });
  }
}

Object.defineProperty(exports, "AUDIT_GENESIS_HASH", { enumerable: true, get: () => GENESIS });

exports.AUDIT_GENESIS_HASH = GENESIS;
exports.AuditTrail = AuditTrail;
