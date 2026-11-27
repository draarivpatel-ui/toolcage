// Sanitize untrusted tool output before it is returned to a model.

const { analyzeJsonGraph, measuredJsonBytes } = require('./canonical.cjs');

const REDACTED_SECRET = '[REDACTED_SECRET]';
const REDACTED_BLOCK = '[REDACTED_PRIVATE_KEY_BLOCK]';

const SECRET_ASSIGNMENT_RE = /\b(api[_\s-]?key|access[_\s-]?token|refresh[_\s-]?token|session[_\s-]?token|client[_\s-]?secret|secret|password|passwd|private[_\s-]?key|auth[_\s-]?token)(\s*[:=]\s*)(["']?)([^\s"',\]}]{8,})\3/giu;
const BEARER_RE = /\b(bearer\s+)([A-Za-z0-9._~+/=-]{12,})\b/giu;
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu;
const PRIVATE_KEY_RE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{20,4096}?-----END [A-Z0-9 ]*PRIVATE KEY-----/gu;
const URL_AUTH_RE = /\b([a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:)([^/\s@]{4,})(@)/giu;

const INSTRUCTION_PATTERNS = [
  ['INSTRUCTION_OVERRIDE', /\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|directions|messages)\b/iu],
  ['INSTRUCTION_OVERRIDE', /\bdisregard\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|directions|messages)\b/iu],
  ['INSTRUCTION_OVERRIDE', /\bforget\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|directions|messages)\b/iu],
  ['PROMPT_EXFILTRATION', /\b(?:reveal|print|show|repeat|disclose)\s+(?:your|the)\s+(?:system|developer|hidden)\s+(?:prompt|instructions|message)\b/iu],
  ['SECRET_EXFILTRATION', /\b(?:exfiltrate|steal|send|leak)\s+(?:all\s+)?(?:secrets|credentials|tokens|api\s+keys|passwords)\b/iu],
  ['QUIET_EXFILTRATION', /\bdo\s+not\s+(?:tell|inform|warn)\s+the\s+user\b/iu],
  ['SAFETY_BYPASS', /\b(?:bypass|override|disable)\s+(?:the\s+)?(?:safety|security)\s+(?:policy|policies|controls|guardrails)\b/iu],
  ['TOOL_HIJACK', /\b(?:call|invoke|execute|run)\s+(?:the\s+)?[a-z0-9_.:-]{1,80}(?:\s+tool)?\s+(?:with|using)\b/iu],
  ['TOOL_HIJACK', /\buse\s+the\s+tool\s+(?:to\s+)?(?:delete|exfiltrate|send|upload|modify)\b/iu],
];

const DEFAULT_SENSITIVE_KEYS = new Set([
  'password', 'passwd', 'secret', 'token', 'apikey', 'authorization', 'auth', 'credential',
  'credentials', 'privatekey', 'clientsecret', 'accesstoken', 'refreshtoken', 'sessiontoken',
  'cookie', 'setcookie', 'session', 'secretkey', 'signingkey', 'encryptionkey',
]);
const DANGEROUS_RESULT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function normalizeKey(key) {
  return key.toLowerCase().replace(/[\s_.-]+/gu, '');
}

function isHiddenCodepoint(cp) {
  return (cp >= 0x202a && cp <= 0x202e)
    || (cp >= 0x2066 && cp <= 0x2069)
    || (cp >= 0x200b && cp <= 0x200f)
    || (cp >= 0x2060 && cp <= 0x2064)
    || cp === 0x180e
    || cp === 0x061c
    || cp === 0xfeff
    || cp === 0x00ad
    || (cp >= 0xe0000 && cp <= 0xe007f)
    || (cp >= 0x0000 && cp <= 0x0008)
    || cp === 0x000b
    || cp === 0x000c
    || (cp >= 0x000e && cp <= 0x001f)
    || (cp >= 0x007f && cp <= 0x009f);
}

function stripHidden(value) {
  let output = '';
  let count = 0;
  for (const ch of value) {
    const cp = ch.codePointAt(0);
    if (isHiddenCodepoint(cp)) count += 1;
    else output += ch;
  }
  return { text: output, count };
}

function safeCustomPattern(pattern) {
  if (typeof pattern !== 'string' || pattern.length === 0 || pattern.length > 256) return null;
  if (/\([^)]*[+*][^)]*\)[+*]/u.test(pattern)) return null;
  try {
    return new RegExp(pattern, 'giu');
  } catch {
    return null;
  }
}

function redactSecretsInString(input, customPatterns) {
  let text = input;
  let count = 0;
  const patterns = [];
  text = text.replace(PRIVATE_KEY_RE, () => { count += 1; return REDACTED_BLOCK; });
  text = text.replace(SECRET_ASSIGNMENT_RE, (match, key, separator, quote) => {
    count += 1;
    return key + separator + quote + REDACTED_SECRET + quote;
  });
  text = text.replace(BEARER_RE, (match, prefix) => {
    count += 1;
    return prefix + REDACTED_SECRET;
  });
  text = text.replace(JWT_RE, () => { count += 1; return REDACTED_SECRET; });
  text = text.replace(URL_AUTH_RE, (match, prefix, secret, at) => {
    count += 1;
    return prefix + REDACTED_SECRET + at;
  });
  for (const source of customPatterns || []) {
    const regex = safeCustomPattern(source);
    if (regex === null) {
      patterns.push({ code: 'CUSTOM_PATTERN_REJECTED' });
      continue;
    }
    text = text.replace(regex, () => { count += 1; return REDACTED_SECRET; });
  }
  return { text, count, rejectedCustomPatterns: patterns.length };
}

function instructionFindings(text, path) {
  const findings = [];
  for (const [code, regex] of INSTRUCTION_PATTERNS) {
    regex.lastIndex = 0;
    if (regex.test(text)) findings.push({ code, path, message: 'high-confidence prompt-injection marker detected' });
  }
  return findings;
}

function jsonTypeSupported(value) {
  if (value === null) return true;
  const type = typeof value;
  if (type === 'string' || type === 'boolean') return true;
  return type === 'number' && Number.isFinite(value);
}


function inspectResultStructure(value) {
  const seen = new WeakSet();
  let depth = 0;
  function visit(node, current) {
    depth = Math.max(depth, current);
    if (jsonTypeSupported(node)) return true;
    if (node === null || typeof node !== 'object') return false;
    if (seen.has(node)) return false;
    if (Array.isArray(node)) {
      seen.add(node);
      for (let index = 0; index < node.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(node, String(index));
        if (!descriptor || typeof descriptor.get === 'function' || typeof descriptor.set === 'function') {
          seen.delete(node);
          return false;
        }
        if (!visit(descriptor.value, current + 1)) {
          seen.delete(node);
          return false;
        }
      }
      for (const key of Object.getOwnPropertyNames(node)) {
        if (!/^(?:\d+|length)$/u.test(key)) {
          seen.delete(node);
          return false;
        }
      }
      seen.delete(node);
      return true;
    }
    const proto = Object.getPrototypeOf(node);
    if (proto !== Object.prototype && proto !== null) return false;
    seen.add(node);
    for (const key of Object.getOwnPropertyNames(node)) {
      const descriptor = Object.getOwnPropertyDescriptor(node, key);
      if (!descriptor || typeof descriptor.get === 'function' || typeof descriptor.set === 'function') {
        seen.delete(node);
        return false;
      }
      if (!visit(descriptor.value, current + 1)) {
        seen.delete(node);
        return false;
      }
    }
    seen.delete(node);
    return true;
  }
  if (!visit(value, 0)) return { ok: false, depth };
  return { ok: true, depth };
}

function sanitizeToolResult(result, options) {
  const opts = {
    maxBytes: 65536,
    maxDepth: 12,
    blockOnInstruction: true,
    redactSecrets: true,
    removeHiddenUnicode: true,
    sensitiveKeys: [],
    customSecretPatterns: [],
    ...(options || {}),
  };
  const findings = [];
  let removedHidden = 0;
  let redactedSecrets = 0;
  let unsupported = false;
  let unsafeKeys = false;

  const graph = analyzeJsonGraph(result);
  if (!graph.ok) {
    if (graph.reason === 'depth') findings.push({ code: 'RESULT_TOO_DEEP', path: '$', message: 'result exceeds the maximum safe structural depth' });
    else findings.push({ code: 'RESULT_NOT_JSON', path: '$', message: graph.reason === 'shared' ? 'shared object references are not valid JSON results' : 'cyclic result value' });
    return { action: 'blocked', ok: false, value: null, findings, removedHidden, redactedSecrets, bytes: 0 };
  }
  const structure = inspectResultStructure(result);
  let inputBytes = -1;
  const inputDepth = graph.depth;
  if (structure.ok) {
    try {
      inputBytes = measuredJsonBytes(result);
    } catch {
      inputBytes = -1;
    }
  }
  if (!structure.ok || inputBytes < 0) {
    findings.push({ code: 'RESULT_NOT_JSON', path: '$', message: 'result must be finite JSON-compatible data' });
    return { action: 'blocked', ok: false, value: null, findings, removedHidden, redactedSecrets, bytes: 0 };
  }
  if (inputBytes > opts.maxBytes) {
    findings.push({ code: 'RESULT_TOO_LARGE', path: '$', message: `result exceeds ${opts.maxBytes} bytes` });
    return { action: 'blocked', ok: false, value: null, findings, removedHidden, redactedSecrets, bytes: inputBytes };
  }
  if (inputDepth > opts.maxDepth) {
    findings.push({ code: 'RESULT_TOO_DEEP', path: '$', message: `result exceeds depth ${opts.maxDepth}` });
    return { action: 'blocked', ok: false, value: null, findings, removedHidden, redactedSecrets, bytes: inputBytes };
  }

  const sensitive = new Set(DEFAULT_SENSITIVE_KEYS);
  for (const key of opts.sensitiveKeys || []) if (typeof key === 'string') sensitive.add(normalizeKey(key));

  function sanitizeString(value, path) {
    let text = value;
    let changed = false;
    if (opts.removeHiddenUnicode !== false) {
      const stripped = stripHidden(text);
      if (stripped.count > 0) {
        removedHidden += stripped.count;
        findings.push({ code: 'HIDDEN_UNICODE_REMOVED', path, message: 'hidden or bidirectional control characters removed' });
        text = stripped.text;
        changed = true;
      }
    }
    if (opts.redactSecrets !== false) {
      const redacted = redactSecretsInString(text, opts.customSecretPatterns);
      if (redacted.rejectedCustomPatterns > 0) findings.push({ code: 'CUSTOM_PATTERN_REJECTED', path, message: 'unsafe custom secret pattern rejected' });
      if (redacted.count > 0) {
        redactedSecrets += redacted.count;
        findings.push({ code: 'SECRET_REDACTED', path, message: 'secret-like material redacted' });
        text = redacted.text;
        changed = true;
      }
    }
    const injection = instructionFindings(text, path);
    findings.push(...injection);
    return { text, changed, injection: injection.length > 0 };
  }

  function visit(value, path, seen) {
    if (jsonTypeSupported(value)) {
      if (typeof value !== 'string') return { value, changed: false, blocked: false };
      const output = sanitizeString(value, path);
      return { value: output.text, changed: output.changed, blocked: output.injection && opts.blockOnInstruction !== false };
    }
    if (value === undefined || typeof value === 'number' || typeof value !== 'object') {
      unsupported = true;
      findings.push({ code: 'RESULT_NOT_JSON', path, message: 'unsupported result value type' });
      return { value: null, changed: true, blocked: true };
    }
    if (seen.has(value)) {
      unsupported = true;
      findings.push({ code: 'RESULT_NOT_JSON', path, message: 'cyclic result value' });
      return { value: null, changed: true, blocked: true };
    }
    seen.add(value);
    try {
      if (Array.isArray(value)) {
        let changed = false;
        let blocked = false;
        const array = [];
        for (let index = 0; index < value.length; index += 1) {
          const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
          const child = visit(descriptor ? descriptor.value : undefined, `${path}[${index}]`, seen);
          array.push(child.value);
          changed = changed || child.changed;
          blocked = blocked || child.blocked;
        }
        return { value: array, changed, blocked };
      }
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        unsupported = true;
        findings.push({ code: 'RESULT_NOT_JSON', path, message: 'non-plain object result' });
        return { value: null, changed: true, blocked: true };
      }
      let changed = false;
      let blocked = false;
      const object = {};
      for (const key of Object.keys(value)) {
        const childPath = `${path}.${key}`;
        if (DANGEROUS_RESULT_KEYS.has(key.toLowerCase())) {
          unsafeKeys = true;
          findings.push({ code: 'UNSAFE_RESULT_KEY', path: childPath, message: 'result key is unsafe for structured consumers' });
          blocked = true;
          continue;
        }
        if (sensitive.has(normalizeKey(key))) {
          object[key] = REDACTED_SECRET;
          redactedSecrets += 1;
          findings.push({ code: 'SECRET_REDACTED', path: childPath, message: 'sensitive structured field redacted' });
          changed = true;
          continue;
        }
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        const child = visit(descriptor ? descriptor.value : undefined, childPath, seen);
        object[key] = child.value;
        changed = changed || child.changed;
        blocked = blocked || child.blocked;
      }
      return { value: object, changed, blocked };
    } finally {
      seen.delete(value);
    }
  }

  const visited = visit(result, '$', new WeakSet());
  if (visited.blocked) {
    const code = unsupported || unsafeKeys ? 'UNSAFE_RESULT_STRUCTURE' : 'PROMPT_INJECTION_DETECTED';
    findings.push({ code, path: '$', message: 'tool result blocked before model exposure' });
    return { action: 'blocked', ok: false, value: null, findings, removedHidden, redactedSecrets, bytes: inputBytes };
  }
  let outputBytes = inputBytes;
  try {
    outputBytes = measuredJsonBytes(visited.value);
  } catch {
    outputBytes = inputBytes;
  }
  if (outputBytes > opts.maxBytes) {
    findings.push({ code: 'RESULT_TOO_LARGE', path: '$', message: `sanitized result exceeds ${opts.maxBytes} bytes` });
    return { action: 'blocked', ok: false, value: null, findings, removedHidden, redactedSecrets, bytes: outputBytes };
  }
  const action = visited.changed ? 'sanitized' : 'allow';
  return { action, ok: true, value: visited.value, findings, removedHidden, redactedSecrets, bytes: outputBytes };
}

function resultLooksDangerous(result) {
  const sanitized = sanitizeToolResult(result, { redactSecrets: false, removeHiddenUnicode: false });
  return sanitized.action === 'blocked';
}

exports.REDACTED_SECRET = REDACTED_SECRET;
exports.REDACTED_BLOCK = REDACTED_BLOCK;
exports.sanitizeToolResult = sanitizeToolResult;
exports.resultLooksDangerous = resultLooksDangerous;
