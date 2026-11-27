// Runtime firewall that combines policy validation, budgets, audit and sanitization.

const { AuditTrail } = require('./audit.cjs');
const { CapabilityBudget } = require('./budget.cjs');
const { canonicalHash, stableStringify } = require('./canonical.cjs');
const { normalizePolicy } = require('./policy.cjs');
const { sanitizeToolResult } = require('./sanitizer.cjs');
const { inspectToolArguments, validateToolArguments } = require('./schema.cjs');

const TOOL_NAME_RE = /^[A-Za-z0-9_.:-]{1,128}$/u;

function publicErrors(errors) {
  return errors.map((entry) => Object.freeze({ code: entry.code, message: entry.message, path: entry.path }));
}

function failure(code, message, extra) {
  return { ok: false, error: Object.freeze({ code, message }), ...(extra || {}) };
}

class ToolCage {
  constructor(policy, options) {
    const opts = options && typeof options === 'object' ? options : {};
    this.policy = normalizePolicy(policy);
    this.audit = new AuditTrail({ now: opts.now });
    this.budget = new CapabilityBudget(this.policy.budget, { now: opts.now });
    this._now = typeof opts.now === 'function' ? opts.now : () => Date.now();
  }

  resolveTool(toolName) {
    if (typeof toolName !== 'string' || !TOOL_NAME_RE.test(toolName)) {
      return { allowed: false, code: 'TOOL_NAME_INVALID', message: 'tool name is invalid' };
    }
    if (this.policy.deniedTools.includes(toolName)) {
      return { allowed: false, code: 'TOOL_DENIED', message: 'tool is denied by policy' };
    }
    if (this.policy.allowedTools.length > 0 && !this.policy.allowedTools.includes(toolName)) {
      return { allowed: false, code: 'TOOL_NOT_ALLOWLISTED', message: 'tool is not on the allowlist' };
    }
    const spec = this.policy.tools[toolName];
    if (!spec) {
      if (this.policy.allowUnknownTools !== true) {
        return { allowed: false, code: 'TOOL_NOT_ALLOWLISTED', message: 'tool is not declared by policy' };
      }
      return { allowed: true, spec: null, unknown: true };
    }
    if (spec.enabled !== true) return { allowed: false, code: 'TOOL_DISABLED', message: 'tool is disabled by policy' };
    return { allowed: true, spec, unknown: false };
  }

  validateCall(toolName, args) {
    const resolution = this.resolveTool(toolName);
    if (!resolution.allowed) return failure(resolution.code, resolution.message);
    if (resolution.unknown) {
      const inspected = inspectToolArguments(args);
      if (!inspected.ok) return { ok: false, errors: publicErrors(inspected.errors) };
      return { ok: true, tool: toolName, normalizedArguments: JSON.parse(stableStringify(args)), bytes: inspected.bytes, depth: inspected.depth, unknownTool: true };
    }
    const validated = validateToolArguments(args, resolution.spec);
    if (!validated.ok) return { ok: false, errors: publicErrors(validated.errors), bytes: validated.bytes || 0, depth: validated.depth || 0 };
    return {
      ok: true,
      tool: toolName,
      normalizedArguments: validated.normalizedArguments,
      bytes: validated.bytes,
      depth: validated.depth,
      unknownTool: false,
    };
  }

  async execute(toolName, args, handler) {
    const started = this._now();
    if (typeof handler !== 'function') {
      const entry = this.audit.append('execution_rejected', { tool: String(toolName || ''), decision: 'deny', details: { reason: 'handler_missing' } });
      return { ...failure('HANDLER_MISSING', 'execute requires a tool handler function'), auditHash: entry.hash };
    }
    const resolution = this.resolveTool(toolName);
    if (!resolution.allowed) {
      const entry = this.audit.append('policy_denied', { tool: String(toolName || ''), decision: 'deny', details: { code: resolution.code } });
      return { ...failure(resolution.code, resolution.message), auditHash: entry.hash };
    }
    const validated = resolution.unknown
      ? (() => {
        const inspected = inspectToolArguments(args);
        return inspected.ok ? { ok: true, normalizedArguments: JSON.parse(stableStringify(args)), bytes: inspected.bytes, depth: inspected.depth } : { ok: false, errors: inspected.errors };
      })()
      : validateToolArguments(args, resolution.spec);
    if (!validated.ok) {
      const entry = this.audit.append('validation_failed', {
        tool: toolName,
        decision: 'deny',
        bytes: validated.bytes || 0,
        details: { firstCode: validated.errors[0] ? validated.errors[0].code : 'INVALID', errorCount: validated.errors.length },
      });
      return { ok: false, errors: publicErrors(validated.errors), auditHash: entry.hash };
    }
    const normalized = validated.normalizedArguments;
    const inputHash = canonicalHash(normalized);
    const admission = this.budget.admit(toolName, resolution.spec || {}, inputHash, validated.bytes);
    if (!admission.ok) {
      const entry = this.audit.append('budget_denied', {
        tool: toolName,
        decision: 'deny',
        inputHash,
        bytes: validated.bytes,
        details: { code: admission.code },
      });
      return { ...failure(admission.code, admission.message), auditHash: entry.hash };
    }

    let raw;
    try {
      raw = await handler(normalized, Object.freeze({ toolName, policy: this.policy, inputHash }));
    } catch (caught) {
      const entry = this.audit.append('tool_error', {
        tool: toolName,
        decision: 'error',
        inputHash,
        bytes: validated.bytes,
        durationMs: this._now() - started,
        details: { errorName: caught && caught.name ? String(caught.name) : 'Error' },
      });
      return { ...failure('TOOL_ERROR', 'tool handler failed'), auditHash: entry.hash };
    }

    const sanitizerOptions = { ...(this.policy.sanitizer || {}), ...((resolution.spec && resolution.spec.result) || {}) };
    const sanitized = sanitizeToolResult(raw, sanitizerOptions);
    const completion = this.budget.complete(toolName, sanitized.bytes || 0);
    if (!completion.ok) {
      const entry = this.audit.append('budget_denied', {
        tool: toolName,
        decision: 'deny',
        inputHash,
        bytes: validated.bytes + (sanitized.bytes || 0),
        durationMs: this._now() - started,
        details: { code: completion.code, phase: 'output' },
      });
      return { ...failure(completion.code, completion.message), auditHash: entry.hash };
    }
    if (!sanitized.ok) {
      const entry = this.audit.append('result_blocked', {
        tool: toolName,
        decision: 'deny',
        inputHash,
        bytes: validated.bytes + (sanitized.bytes || 0),
        durationMs: this._now() - started,
        details: { findingCount: sanitized.findings.length, action: sanitized.action },
      });
      return { ...failure('RESULT_BLOCKED', 'tool result was blocked by the output sanitizer'), findings: sanitized.findings, auditHash: entry.hash };
    }
    const entry = this.audit.append('call_completed', {
      tool: toolName,
      decision: sanitized.action === 'sanitized' ? 'sanitize' : 'allow',
      inputHash,
      bytes: validated.bytes + sanitized.bytes,
      durationMs: this._now() - started,
      details: { findingCount: sanitized.findings.length, action: sanitized.action, redactions: sanitized.redactedSecrets, hiddenRemoved: sanitized.removedHidden },
    });
    return {
      ok: true,
      value: sanitized.value,
      action: sanitized.action,
      findings: sanitized.findings,
      bytes: validated.bytes + sanitized.bytes,
      inputHash,
      auditHash: entry.hash,
    };
  }

  wrapTool(toolName, handler) {
    return async (args) => this.execute(toolName, args, handler);
  }

  wrapTools(handlers) {
    if (!handlers || typeof handlers !== 'object') throw new TypeError('handlers must be an object');
    const output = {};
    for (const [name, handler] of Object.entries(handlers)) output[name] = this.wrapTool(name, handler);
    return Object.freeze(output);
  }

  sanitizeResult(value, toolName) {
    const spec = typeof toolName === 'string' && this.policy.tools[toolName] ? this.policy.tools[toolName] : null;
    return sanitizeToolResult(value, { ...(this.policy.sanitizer || {}), ...((spec && spec.result) || {}) });
  }

  auditEntries() {
    return this.audit.entries();
  }

  verifyAudit() {
    return this.audit.verify();
  }

  auditDigest() {
    return this.audit.digest();
  }

  budgetSnapshot() {
    return this.budget.snapshot();
  }
}

function createFirewall(policy, options) {
  return new ToolCage(policy, options);
}

function wrapTool(policy, toolName, handler, options) {
  return createFirewall(policy, options).wrapTool(toolName, handler);
}

exports.ToolCage = ToolCage;
exports.createFirewall = createFirewall;
exports.wrapTool = wrapTool;
