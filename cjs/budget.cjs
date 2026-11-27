// Capability budgets, sliding windows and duplicate-call loop detection.

function prune(values, cutoff) {
  while (values.length > 0 && values[0] <= cutoff) values.shift();
}

function denial(code, message) {
  return { ok: false, code, message };
}

class CapabilityBudget {
  constructor(config, options) {
    this.config = {
      maxCalls: 1000,
      maxBytes: 1048576,
      windowMs: 60000,
      windowMaxCalls: 120,
      duplicateWindowMs: 10000,
      maxDuplicates: 4,
      ...(config || {}),
    };
    const opts = options && typeof options === 'object' ? options : {};
    this._now = typeof opts.now === 'function' ? opts.now : () => Date.now();
    this.calls = 0;
    this.bytes = 0;
    this.sessionTimes = [];
    this.toolCalls = new Map();
    this.toolTimes = new Map();
    this.duplicates = new Map();
  }

  _toolStats(name) {
    if (!this.toolCalls.has(name)) this.toolCalls.set(name, 0);
    if (!this.toolTimes.has(name)) this.toolTimes.set(name, []);
    return { calls: this.toolCalls.get(name), times: this.toolTimes.get(name) };
  }

  admit(toolName, toolPolicy, inputHash, inputBytes) {
    const now = this._now();
    const cfg = this.config;
    prune(this.sessionTimes, now - cfg.windowMs);
    const stats = this._toolStats(toolName);
    const rate = toolPolicy && toolPolicy.rateLimit ? toolPolicy.rateLimit : null;
    if (rate) prune(stats.times, now - rate.windowMs);
    if (this.calls >= cfg.maxCalls) return denial('SESSION_CALL_LIMIT', 'session call budget exhausted');
    if (toolPolicy && Number.isInteger(toolPolicy.maxCalls) && stats.calls >= toolPolicy.maxCalls) return denial('TOOL_CALL_LIMIT', 'per-tool call budget exhausted');
    if (this.sessionTimes.length >= cfg.windowMaxCalls) return denial('RATE_LIMIT', 'session sliding-window rate limit exceeded');
    if (rate && stats.times.length >= rate.maxCalls) return denial('RATE_LIMIT', 'tool sliding-window rate limit exceeded');
    if (this.bytes + inputBytes > cfg.maxBytes) return denial('BYTE_BUDGET', 'cumulative byte budget exhausted');

    const duplicateKey = toolName + ':' + inputHash;
    if (!this.duplicates.has(duplicateKey)) this.duplicates.set(duplicateKey, []);
    const duplicateTimes = this.duplicates.get(duplicateKey);
    prune(duplicateTimes, now - cfg.duplicateWindowMs);
    if (duplicateTimes.length >= cfg.maxDuplicates) return denial('DUPLICATE_CALL_LOOP', 'identical tool call loop detected');

    this.calls += 1;
    this.bytes += inputBytes;
    this.sessionTimes.push(now);
    this.toolCalls.set(toolName, stats.calls + 1);
    if (rate) stats.times.push(now);
    duplicateTimes.push(now);
    return { ok: true, admittedAt: now, inputBytes, inputHash, toolName };
  }

  complete(toolName, outputBytes) {
    this.bytes += Math.max(0, outputBytes | 0);
    if (this.bytes > this.config.maxBytes) {
      return denial('BYTE_BUDGET', 'cumulative byte budget exhausted by tool output');
    }
    return { ok: true };
  }

  snapshot() {
    const perTool = {};
    for (const [name, count] of this.toolCalls.entries()) perTool[name] = count;
    return Object.freeze({
      calls: this.calls,
      bytes: this.bytes,
      remainingCalls: Math.max(0, this.config.maxCalls - this.calls),
      remainingBytes: Math.max(0, this.config.maxBytes - this.bytes),
      perTool: Object.freeze(perTool),
    });
  }
}

exports.CapabilityBudget = CapabilityBudget;
