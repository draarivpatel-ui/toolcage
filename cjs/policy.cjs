// Policy validation, normalization and static audit.

const { deepImmutableCopy } = require('./canonical.cjs');
const { PARAM_TYPES } = require('./schema.cjs');

const TOP_LEVEL_KEYS = new Set(['version', 'tools', 'allowedTools', 'deniedTools', 'allowUnknownTools', 'budget', 'sanitizer', 'metadata']);
const TOOL_KEYS = new Set(['description', 'enabled', 'parameters', 'maxCalls', 'rateLimit', 'maxBytes', 'maxDepth', 'result', 'metadata']);
const PARAM_KEYS = new Set([
  'type', 'required', 'nullable', 'enum', 'minLength', 'maxLength', 'maxBytes', 'pattern',
  'min', 'max', 'multipleOf', 'properties', 'additionalProperties', 'items', 'minItems', 'maxItems',
  'uniqueItems', 'maxProperties', 'maxDepth', 'allowAbsolute', 'allowParentTraversal',
  'allowUnicodeNormalizationBypass', 'allowShellOperators', 'allowPrivateNetworks', 'allowSingleLabelHostnames',
  'allowedSchemes', 'allowedPorts', 'hostPolicy', 'metadata',
]);
const BUDGET_KEYS = new Set(['maxCalls', 'maxBytes', 'windowMs', 'windowMaxCalls', 'duplicateWindowMs', 'maxDuplicates']);
const RATE_KEYS = new Set(['windowMs', 'maxCalls']);
const RESULT_KEYS = new Set(['maxBytes', 'maxDepth', 'blockOnInstruction', 'redactSecrets', 'removeHiddenUnicode', 'sensitiveKeys', 'customSecretPatterns']);
const TOOL_NAME_RE = /^[A-Za-z0-9_.:-]{1,128}$/u;

function isPlain(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function issue(kind, code, message, path) {
  return { kind, code, message, path };
}

function checkUnknownKeys(object, allowed, kind, path, errors) {
  for (const key of Object.keys(object)) {
    if (!allowed.has(key)) errors.push(issue(kind, 'POLICY_UNKNOWN_KEY', `unknown policy key ${key}`, `${path}.${key}`));
  }
}

function positiveInteger(value) {
  return Number.isInteger(value) && value >= 0;
}

function validateRateLimit(value, path, errors) {
  if (value === undefined) return;
  if (!isPlain(value)) {
    errors.push(issue('error', 'POLICY_RATE_INVALID', 'rateLimit must be an object', path));
    return;
  }
  checkUnknownKeys(value, RATE_KEYS, 'error', path, errors);
  if (!positiveInteger(value.maxCalls) || value.maxCalls < 1) errors.push(issue('error', 'POLICY_RATE_INVALID', 'rateLimit.maxCalls must be a positive integer', `${path}.maxCalls`));
  if (!positiveInteger(value.windowMs) || value.windowMs < 1) errors.push(issue('error', 'POLICY_RATE_INVALID', 'rateLimit.windowMs must be a positive integer', `${path}.windowMs`));
}

function validateHostPolicy(value, path, errors) {
  if (value === undefined) return;
  if (!isPlain(value)) {
    errors.push(issue('error', 'POLICY_HOST_INVALID', 'hostPolicy must be an object', path));
    return;
  }
  for (const key of Object.keys(value)) {
    if (key !== 'allow' && key !== 'deny') errors.push(issue('error', 'POLICY_UNKNOWN_KEY', `unknown hostPolicy key ${key}`, `${path}.${key}`));
  }
  for (const key of ['allow', 'deny']) {
    if (value[key] !== undefined && (!Array.isArray(value[key]) || value[key].some((entry) => typeof entry !== 'string'))) {
      errors.push(issue('error', 'POLICY_HOST_INVALID', `hostPolicy.${key} must be an array of strings`, `${path}.${key}`));
    }
  }
}

function validateParamSpec(spec, path, errors, warnings, depth) {
  if (!isPlain(spec)) {
    errors.push(issue('error', 'POLICY_PARAM_INVALID', 'parameter specification must be an object', path));
    return;
  }
  checkUnknownKeys(spec, PARAM_KEYS, 'error', path, errors);
  if (!PARAM_TYPES.has(spec.type)) {
    errors.push(issue('error', 'POLICY_PARAM_TYPE', `unsupported parameter type ${String(spec.type)}`, `${path}.type`));
  }
  if (spec.pattern !== undefined) {
    if (typeof spec.pattern !== 'string' || spec.pattern.length === 0 || spec.pattern.length > 512) {
      errors.push(issue('error', 'POLICY_PATTERN_INVALID', 'pattern must be a string of 1 to 512 characters', `${path}.pattern`));
    } else {
      try { new RegExp(spec.pattern, 'u'); } catch { errors.push(issue('error', 'POLICY_PATTERN_INVALID', 'pattern does not compile', `${path}.pattern`)); }
    }
  }
  for (const key of ['minLength', 'maxLength', 'maxBytes', 'minItems', 'maxItems', 'maxProperties', 'maxDepth']) {
    if (spec[key] !== undefined && (!Number.isInteger(spec[key]) || spec[key] < 0)) errors.push(issue('error', 'POLICY_NUMBER_INVALID', `${key} must be a nonnegative integer`, `${path}.${key}`));
  }
  for (const key of ['min', 'max', 'multipleOf']) {
    if (spec[key] !== undefined && (typeof spec[key] !== 'number' || !Number.isFinite(spec[key]))) errors.push(issue('error', 'POLICY_NUMBER_INVALID', `${key} must be finite`, `${path}.${key}`));
  }
  if (typeof spec.minLength === 'number' && typeof spec.maxLength === 'number' && spec.minLength > spec.maxLength) errors.push(issue('error', 'POLICY_RANGE_INVALID', 'minLength exceeds maxLength', path));
  if (typeof spec.min === 'number' && typeof spec.max === 'number' && spec.min > spec.max) errors.push(issue('error', 'POLICY_RANGE_INVALID', 'min exceeds max', path));
  if (typeof spec.minItems === 'number' && typeof spec.maxItems === 'number' && spec.minItems > spec.maxItems) errors.push(issue('error', 'POLICY_RANGE_INVALID', 'minItems exceeds maxItems', path));
  if (spec.type === 'object') {
    if (spec.properties !== undefined) {
      if (!isPlain(spec.properties)) errors.push(issue('error', 'POLICY_PROPERTIES_INVALID', 'properties must be an object', `${path}.properties`));
      else if (depth < 16) {
        for (const key of Object.keys(spec.properties)) validateParamSpec(spec.properties[key], `${path}.properties.${key}`, errors, warnings, depth + 1);
      }
    }
    if (spec.additionalProperties === true) warnings.push(issue('warning', 'POLICY_OPEN_OBJECT', 'object allows additional nested properties', `${path}.additionalProperties`));
  }
  if (spec.type === 'array' && spec.items !== undefined) validateParamSpec(spec.items, `${path}.items`, errors, warnings, depth + 1);
  if (spec.type === 'path') {
    if (spec.allowAbsolute === true) warnings.push(issue('warning', 'POLICY_ABSOLUTE_PATH', 'path parameter allows absolute paths', `${path}.allowAbsolute`));
    if (spec.allowParentTraversal === true) warnings.push(issue('warning', 'POLICY_PARENT_TRAVERSAL', 'path parameter allows parent traversal', `${path}.allowParentTraversal`));
  }
  if (spec.type === 'url') {
    if (spec.allowPrivateNetworks === true) warnings.push(issue('warning', 'POLICY_PRIVATE_NETWORK', 'URL parameter allows private network targets', `${path}.allowPrivateNetworks`));
    if (spec.allowSingleLabelHostnames === true) warnings.push(issue('warning', 'POLICY_SINGLE_LABEL_HOSTNAMES', 'URL parameter allows bare single-label hostnames', `${path}.allowSingleLabelHostnames`));
    if (spec.allowedSchemes !== undefined && (!Array.isArray(spec.allowedSchemes) || spec.allowedSchemes.some((entry) => typeof entry !== 'string'))) errors.push(issue('error', 'POLICY_SCHEME_INVALID', 'allowedSchemes must be an array of strings', `${path}.allowedSchemes`));
    if (spec.allowedPorts !== undefined && spec.allowedPorts !== 'any' && spec.allowedPorts !== 'default-only' && (!Array.isArray(spec.allowedPorts) || spec.allowedPorts.some((entry) => !Number.isInteger(entry) || entry < 1 || entry > 65535))) errors.push(issue('error', 'POLICY_PORT_INVALID', 'allowedPorts must be default-only, any, or an array of valid ports', `${path}.allowedPorts`));
    validateHostPolicy(spec.hostPolicy, `${path}.hostPolicy`, errors);
  }
  if (spec.type === 'command' && spec.allowShellOperators === true) warnings.push(issue('warning', 'POLICY_SHELL_OPERATORS', 'command parameter allows shell operators', `${path}.allowShellOperators`));
}

function validateBudget(budget, path, errors) {
  if (budget === undefined) return;
  if (!isPlain(budget)) {
    errors.push(issue('error', 'POLICY_BUDGET_INVALID', 'budget must be an object', path));
    return;
  }
  checkUnknownKeys(budget, BUDGET_KEYS, 'error', path, errors);
  for (const key of Object.keys(budget)) {
    if (!positiveInteger(budget[key]) || budget[key] < 1) errors.push(issue('error', 'POLICY_BUDGET_INVALID', `budget.${key} must be a positive integer`, `${path}.${key}`));
  }
}

function validateResultPolicy(result, path, errors) {
  if (result === undefined) return;
  if (!isPlain(result)) {
    errors.push(issue('error', 'POLICY_RESULT_INVALID', 'result policy must be an object', path));
    return;
  }
  checkUnknownKeys(result, RESULT_KEYS, 'error', path, errors);
  if (result.maxBytes !== undefined && (!Number.isInteger(result.maxBytes) || result.maxBytes < 1)) errors.push(issue('error', 'POLICY_RESULT_INVALID', 'result.maxBytes must be positive', `${path}.maxBytes`));
  if (result.maxDepth !== undefined && (!Number.isInteger(result.maxDepth) || result.maxDepth < 0)) errors.push(issue('error', 'POLICY_RESULT_INVALID', 'result.maxDepth must be nonnegative', `${path}.maxDepth`));
  if (result.sensitiveKeys !== undefined && (!Array.isArray(result.sensitiveKeys) || result.sensitiveKeys.some((entry) => typeof entry !== 'string'))) errors.push(issue('error', 'POLICY_RESULT_INVALID', 'result.sensitiveKeys must be a string array', `${path}.sensitiveKeys`));
  if (result.customSecretPatterns !== undefined && (!Array.isArray(result.customSecretPatterns) || result.customSecretPatterns.some((entry) => typeof entry !== 'string'))) errors.push(issue('error', 'POLICY_RESULT_INVALID', 'result.customSecretPatterns must be a string array', `${path}.customSecretPatterns`));
}

function auditPolicy(policy) {
  const errors = [];
  const warnings = [];
  if (!isPlain(policy)) {
    errors.push(issue('error', 'POLICY_NOT_OBJECT', 'policy must be a plain object', '$'));
    return { ok: false, errors, warnings, summary: { tools: 0, parameters: 0, errors: 1, warnings: 0 } };
  }
  checkUnknownKeys(policy, TOP_LEVEL_KEYS, 'error', '$', errors);
  if (policy.version !== undefined && policy.version !== 1) errors.push(issue('error', 'POLICY_VERSION', 'policy version must be 1', '$.version'));
  for (const key of ['allowedTools', 'deniedTools']) {
    if (policy[key] !== undefined && (!Array.isArray(policy[key]) || policy[key].some((entry) => typeof entry !== 'string' || !TOOL_NAME_RE.test(entry)))) errors.push(issue('error', 'POLICY_TOOL_LIST_INVALID', `${key} must contain valid tool names`, `$.${key}`));
  }
  if (policy.allowUnknownTools === true) warnings.push(issue('warning', 'POLICY_UNKNOWN_TOOLS_OPEN', 'unknown tools are allowed', '$.allowUnknownTools'));
  validateBudget(policy.budget, '$.budget', errors);
  validateResultPolicy(policy.sanitizer, '$.sanitizer', errors);
  if (!isPlain(policy.tools)) {
    errors.push(issue('error', 'POLICY_TOOLS_INVALID', 'tools must be an object', '$.tools'));
  } else {
    for (const [name, tool] of Object.entries(policy.tools)) {
      const path = `$.tools.${name}`;
      if (!TOOL_NAME_RE.test(name)) errors.push(issue('error', 'POLICY_TOOL_NAME_INVALID', 'tool name contains unsafe characters', path));
      if (!isPlain(tool)) {
        errors.push(issue('error', 'POLICY_TOOL_INVALID', 'tool policy must be an object', path));
        continue;
      }
      checkUnknownKeys(tool, TOOL_KEYS, 'error', path, errors);
      if (tool.enabled !== undefined && typeof tool.enabled !== 'boolean') errors.push(issue('error', 'POLICY_TOOL_INVALID', 'enabled must be boolean', `${path}.enabled`));
      if (tool.maxCalls !== undefined && (!Number.isInteger(tool.maxCalls) || tool.maxCalls < 1)) errors.push(issue('error', 'POLICY_BUDGET_INVALID', 'maxCalls must be positive', `${path}.maxCalls`));
      validateRateLimit(tool.rateLimit, `${path}.rateLimit`, errors);
      if (tool.maxBytes !== undefined && (!Number.isInteger(tool.maxBytes) || tool.maxBytes < 1)) errors.push(issue('error', 'POLICY_BUDGET_INVALID', 'maxBytes must be positive', `${path}.maxBytes`));
      if (tool.maxDepth !== undefined && (!Number.isInteger(tool.maxDepth) || tool.maxDepth < 0)) errors.push(issue('error', 'POLICY_BUDGET_INVALID', 'maxDepth must be nonnegative', `${path}.maxDepth`));
      validateResultPolicy(tool.result, `${path}.result`, errors);
      if (tool.parameters !== undefined) {
        if (!isPlain(tool.parameters)) errors.push(issue('error', 'POLICY_PARAMETERS_INVALID', 'parameters must be an object', `${path}.parameters`));
        else for (const key of Object.keys(tool.parameters)) validateParamSpec(tool.parameters[key], `${path}.parameters.${key}`, errors, warnings, 0);
      }
      if (tool.enabled !== false && policy.allowUnknownTools !== true && (!isPlain(tool.parameters) || Object.keys(tool.parameters).length === 0)) {
        warnings.push(issue('warning', 'POLICY_TOOL_HAS_NO_PARAMETERS', 'enabled tool declares no parameters', `${path}.parameters`));
      }
    }
  }
  const toolCount = isPlain(policy.tools) ? Object.keys(policy.tools).length : 0;
  let parameterCount = 0;
  if (isPlain(policy.tools)) {
    for (const tool of Object.values(policy.tools)) {
      if (isPlain(tool) && isPlain(tool.parameters)) parameterCount += Object.keys(tool.parameters).length;
    }
  }
  return {
    ok: errors.length === 0,
    errors,
    warnings,
    summary: { tools: toolCount, parameters: parameterCount, errors: errors.length, warnings: warnings.length },
  };
}

function normalizePolicy(policy) {
  const audit = auditPolicy(policy);
  if (!audit.ok) {
    const first = audit.errors[0];
    const error = new Error(`invalid tool policy: ${first.code} at ${first.path}`);
    error.code = 'INVALID_POLICY';
    error.audit = deepImmutableCopy(audit);
    throw error;
  }
  const copy = JSON.parse(JSON.stringify(policy));
  copy.version = 1;
  copy.allowUnknownTools = copy.allowUnknownTools === true;
  copy.allowedTools = Array.isArray(copy.allowedTools) ? Array.from(new Set(copy.allowedTools)) : [];
  copy.deniedTools = Array.isArray(copy.deniedTools) ? Array.from(new Set(copy.deniedTools)) : [];
  copy.budget = {
    maxCalls: 1000,
    maxBytes: 1048576,
    windowMs: 60000,
    windowMaxCalls: 120,
    duplicateWindowMs: 10000,
    maxDuplicates: 4,
    ...(copy.budget || {}),
  };
  copy.sanitizer = {
    maxBytes: 65536,
    maxDepth: 12,
    blockOnInstruction: true,
    redactSecrets: true,
    removeHiddenUnicode: true,
    ...(copy.sanitizer || {}),
  };
  copy.tools = copy.tools || {};
  for (const tool of Object.values(copy.tools)) {
    tool.enabled = tool.enabled !== false;
    if (tool.rateLimit) {
      tool.rateLimit = { windowMs: 1000, maxCalls: 5, ...tool.rateLimit };
    }
  }
  return deepImmutableCopy(copy);
}

exports.auditPolicy = auditPolicy;
exports.normalizePolicy = normalizePolicy;
