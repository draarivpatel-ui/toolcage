// Strict JSON-schema-like validation for agent tool arguments.

import { failure } from './errors.mjs';
import { guardValueByKind } from './guards.mjs';
import { measuredJsonBytes, maxDepthOf, stableStringify, utf8Bytes } from './canonical.mjs';

export const PARAM_TYPES = new Set([
  'any', 'string', 'number', 'integer', 'boolean', 'object', 'array', 'path', 'url', 'command', 'null',
]);

const DEFAULT_MAX_DEPTH = 12;
const DEFAULT_MAX_BYTES = 16384;
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function error(errors, code, message, path) {
  errors.push(failure(code, message, path));
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function scanJsonLike(value, path, errors, seen) {
  if (value === null) return;
  const type = typeof value;
  if (type === 'string' || type === 'boolean') return;
  if (type === 'number') {
    if (!Number.isFinite(value)) error(errors, 'NON_FINITE_NUMBER', 'numbers must be finite', path);
    return;
  }
  if (type !== 'object') {
    error(errors, 'UNSUPPORTED_JSON_TYPE', `${type} values are not valid tool arguments`, path);
    return;
  }
  if (seen.has(value)) {
    error(errors, 'CYCLIC_ARGUMENT', 'cyclic values are not valid tool arguments', path);
    return;
  }
  if (!Array.isArray(value) && !isPlainObject(value)) {
    error(errors, 'NON_PLAIN_OBJECT', 'only plain objects and arrays are valid tool arguments', path);
    return;
  }
  seen.add(value);
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (descriptor && (typeof descriptor.get === 'function' || typeof descriptor.set === 'function')) {
        error(errors, 'GETTER_REJECTED', 'accessor properties are not valid tool arguments', `${path}[${index}]`);
        continue;
      }
      scanJsonLike(value[index], `${path}[${index}]`, errors, seen);
    }
    for (const key of Object.getOwnPropertyNames(value)) {
      if (!/^(?:\d+|length)$/u.test(key)) error(errors, 'UNEXPECTED_ARRAY_PROPERTY', 'arrays must not carry extra properties', `${path}.${key}`);
    }
  } else {
    for (const key of Object.getOwnPropertyNames(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor && (typeof descriptor.get === 'function' || typeof descriptor.set === 'function')) {
        error(errors, 'GETTER_REJECTED', 'accessor properties are not valid tool arguments', `${path}.${key}`);
        continue;
      }
      if (DANGEROUS_KEYS.has(key.toLowerCase())) {
        error(errors, 'PROTOTYPE_POLLUTION_KEY', 'object key can mutate or confuse object prototypes', `${path}.${key}`);
        continue;
      }
      scanJsonLike(descriptor ? descriptor.value : value[key], `${path}.${key}`, errors, seen);
    }
  }
  for (const symbol of Object.getOwnPropertySymbols(value)) {
    error(errors, 'SYMBOL_KEY_REJECTED', 'symbol keys are not valid tool arguments', `${path}[${String(symbol)}]`);
  }
  seen.delete(value);
}

export function inspectToolArguments(args) {
  const errors = [];
  if (!isPlainObject(args)) {
    error(errors, 'ARGUMENTS_NOT_OBJECT', 'tool arguments must be a plain object', '$');
    return { ok: false, errors };
  }
  scanJsonLike(args, '$', errors, new WeakSet());
  if (errors.length > 0) return { ok: false, errors };
  let bytes = 0;
  let depth = 0;
  try {
    bytes = measuredJsonBytes(args);
    depth = Math.max(0, maxDepthOf(args) - 1);
  } catch (caught) {
    error(errors, 'MEASUREMENT_FAILED', caught instanceof Error ? caught.message : 'argument measurement failed', '$');
    return { ok: false, errors };
  }
  return { ok: true, errors: [], bytes, depth };
}

function lengthOf(text) {
  return Array.from(text).length;
}

function compilePattern(pattern) {
  if (typeof pattern !== 'string' || pattern.length === 0 || pattern.length > 512) return null;
  try {
    return new RegExp(pattern, 'u');
  } catch {
    return null;
  }
}

function enumContains(options, value) {
  if (!Array.isArray(options)) return false;
  let canonical;
  try {
    canonical = stableStringify(value);
  } catch {
    return false;
  }
  return options.some((option) => {
    try {
      return stableStringify(option) === canonical;
    } catch {
      return false;
    }
  });
}

function validateString(value, spec, path, errors) {
  if (typeof value !== 'string') {
    error(errors, 'TYPE_MISMATCH', `expected ${spec.type}`, path);
    return;
  }
  if (Number.isInteger(spec.minLength) && lengthOf(value) < spec.minLength) error(errors, 'STRING_TOO_SHORT', `string is shorter than ${spec.minLength} characters`, path);
  if (Number.isInteger(spec.maxLength) && lengthOf(value) > spec.maxLength) error(errors, 'STRING_TOO_LONG', `string is longer than ${spec.maxLength} characters`, path);
  if (Number.isInteger(spec.maxBytes) && utf8Bytes(value) > spec.maxBytes) error(errors, 'STRING_TOO_LARGE', `string is larger than ${spec.maxBytes} bytes`, path);
  if (spec.pattern !== undefined) {
    const regex = compilePattern(spec.pattern);
    if (regex === null) error(errors, 'INVALID_POLICY_PATTERN', 'parameter regular expression is invalid', path);
    else if (!regex.test(value)) error(errors, 'PATTERN_MISMATCH', 'string does not match the required pattern', path);
  }
}

function validateNumber(value, spec, path, errors, integer) {
  if (typeof value !== 'number' || !Number.isFinite(value) || (integer && !Number.isSafeInteger(value))) {
    error(errors, 'TYPE_MISMATCH', `expected ${integer ? 'integer' : 'number'}`, path);
    return;
  }
  if (typeof spec.min === 'number' && value < spec.min) error(errors, 'NUMBER_TOO_SMALL', `number is below minimum ${spec.min}`, path);
  if (typeof spec.max === 'number' && value > spec.max) error(errors, 'NUMBER_TOO_LARGE', `number is above maximum ${spec.max}`, path);
  if (typeof spec.multipleOf === 'number' && spec.multipleOf > 0) {
    const quotient = value / spec.multipleOf;
    if (Math.abs(quotient - Math.round(quotient)) > 1e-10) error(errors, 'NUMBER_MULTIPLE_MISMATCH', `number is not a multiple of ${spec.multipleOf}`, path);
  }
}

function validateArray(value, spec, path, errors, depth) {
  if (!Array.isArray(value)) {
    error(errors, 'TYPE_MISMATCH', 'expected array', path);
    return;
  }
  if (Number.isInteger(spec.minItems) && value.length < spec.minItems) error(errors, 'ARRAY_TOO_SHORT', `array has fewer than ${spec.minItems} items`, path);
  if (Number.isInteger(spec.maxItems) && value.length > spec.maxItems) error(errors, 'ARRAY_TOO_LONG', `array has more than ${spec.maxItems} items`, path);
  if (spec.uniqueItems === true) {
    const seen = new Set();
    for (const entry of value) {
      let key;
      try { key = stableStringify(entry); } catch { key = '<unmeasurable>'; }
      if (seen.has(key)) {
        error(errors, 'ARRAY_ITEMS_NOT_UNIQUE', 'array items must be unique', path);
        break;
      }
      seen.add(key);
    }
  }
  if (spec.items && typeof spec.items === 'object') {
    for (let index = 0; index < value.length; index += 1) validateValue(value[index], spec.items, `${path}[${index}]`, errors, depth + 1);
  }
}

function validateObject(value, spec, path, errors, depth) {
  if (!isPlainObject(value)) {
    error(errors, 'TYPE_MISMATCH', 'expected object', path);
    return;
  }
  const properties = spec.properties && typeof spec.properties === 'object' ? spec.properties : {};
  const keys = Object.keys(value);
  if (Number.isInteger(spec.maxProperties) && keys.length > spec.maxProperties) error(errors, 'OBJECT_TOO_MANY_PROPERTIES', `object has more than ${spec.maxProperties} properties`, path);
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(properties, key)) {
      if (spec.additionalProperties !== true) error(errors, 'UNKNOWN_ARGUMENT_KEY', `unknown object key ${key}`, `${path}.${key}`);
      continue;
    }
    validateValue(value[key], properties[key], `${path}.${key}`, errors, depth + 1);
  }
  for (const key of Object.keys(properties)) {
    const child = properties[key];
    if (child && child.required === true && !Object.prototype.hasOwnProperty.call(value, key)) {
      error(errors, 'REQUIRED_ARGUMENT_MISSING', `required object key ${key} is missing`, `${path}.${key}`);
    }
  }
}

function validateValue(value, spec, path, errors, depth) {
  if (!spec || typeof spec !== 'object') {
    error(errors, 'INVALID_POLICY', 'parameter specification must be an object', path);
    return;
  }
  if (spec.enum !== undefined && !enumContains(spec.enum, value)) {
    error(errors, 'ENUM_MISMATCH', 'value is not one of the allowed values', path);
    return;
  }
  if (value === null) {
    if (spec.enum !== undefined || spec.type === 'null' || spec.nullable === true) return;
    error(errors, 'TYPE_MISMATCH', `expected ${spec.type}`, path);
    return;
  }
  if (Number.isInteger(spec.maxDepth) && depth > spec.maxDepth) {
    error(errors, 'DEPTH_EXCEEDED', `value exceeds maximum depth ${spec.maxDepth}`, path);
    return;
  }
  switch (spec.type) {
    case 'any':
      break;
    case 'string':
    case 'path':
    case 'url':
    case 'command':
      validateString(value, spec, path, errors);
      if (typeof value === 'string') {
        for (const item of guardValueByKind(value, spec, path)) errors.push(item);
      }
      break;
    case 'number':
      validateNumber(value, spec, path, errors, false);
      break;
    case 'integer':
      validateNumber(value, spec, path, errors, true);
      break;
    case 'boolean':
      if (typeof value !== 'boolean') error(errors, 'TYPE_MISMATCH', 'expected boolean', path);
      break;
    case 'array':
      validateArray(value, spec, path, errors, depth);
      break;
    case 'object':
      validateObject(value, spec, path, errors, depth);
      break;
    case 'null':
      error(errors, 'TYPE_MISMATCH', 'expected null', path);
      break;
    default:
      error(errors, 'INVALID_POLICY_TYPE', `unknown parameter type ${String(spec.type)}`, path);
  }
}

function cloneJson(value) {
  if (Array.isArray(value)) return value.map((entry) => cloneJson(entry));
  if (value !== null && typeof value === 'object') {
    const output = {};
    for (const key of Object.keys(value)) output[key] = cloneJson(value[key]);
    return output;
  }
  return value;
}

export function validateToolArguments(args, toolSpec) {
  const inspected = inspectToolArguments(args);
  if (!inspected.ok) return { ok: false, errors: inspected.errors };
  const errors = [];
  const parameters = toolSpec && typeof toolSpec.parameters === 'object' && toolSpec.parameters !== null ? toolSpec.parameters : {};
  const maxDepth = Number.isInteger(toolSpec.maxDepth) ? toolSpec.maxDepth : DEFAULT_MAX_DEPTH;
  const maxBytes = Number.isInteger(toolSpec.maxBytes) ? toolSpec.maxBytes : DEFAULT_MAX_BYTES;
  if (inspected.depth > maxDepth) error(errors, 'DEPTH_EXCEEDED', `arguments exceed maximum depth ${maxDepth}`, '$');
  if (inspected.bytes > maxBytes) error(errors, 'ARGUMENTS_TOO_LARGE', `arguments exceed maximum size ${maxBytes} bytes`, '$');
  for (const key of Object.keys(args)) {
    if (!Object.prototype.hasOwnProperty.call(parameters, key)) error(errors, 'UNKNOWN_ARGUMENT_KEY', `unknown argument key ${key}`, `$.${key}`);
  }
  for (const key of Object.keys(parameters)) {
    const spec = parameters[key];
    const present = Object.prototype.hasOwnProperty.call(args, key);
    if (!present && spec && spec.required === true) {
      error(errors, 'REQUIRED_ARGUMENT_MISSING', `required argument ${key} is missing`, `$.${key}`);
      continue;
    }
    if (present) validateValue(args[key], spec, `$.${key}`, errors, 1);
  }
  if (errors.length > 0) return { ok: false, errors, bytes: inspected.bytes, depth: inspected.depth };
  return {
    ok: true,
    errors: [],
    normalizedArguments: cloneJson(args),
    bytes: inspected.bytes,
    depth: inspected.depth,
  };
}
