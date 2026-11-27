import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inspectToolArguments, validateToolArguments } from '../src/index.mjs';
import { expectFailureCode, makeDepth } from './helpers.mjs';

function spec(parameters, extra) {
  return { parameters, ...(extra || {}) };
}

function validate(args, parameters, extra) {
  return validateToolArguments(args, spec(parameters, extra));
}

const validPrimitiveCases = [
  ['string', 'hello'],
  ['string', ''],
  ['number', 0],
  ['number', -12.5],
  ['integer', 0],
  ['integer', -9007199254740991],
  ['boolean', true],
  ['boolean', false],
  ['path', 'safe/file.txt'],
  ['url', 'https://example.com/a'],
  ['command', 'git status'],
  ['any', 'text'],
  ['any', 42],
  ['any', false],
  ['null', null],
];

for (const [type, value] of validPrimitiveCases) {
  test(`schema accepts valid ${type}`, () => {
    const result = validate({ value }, { value: { type, required: true } });
    assert.equal(result.ok, true, JSON.stringify(result.errors));
    assert.deepEqual(result.normalizedArguments.value, value);
  });
}

const invalidPrimitiveCases = [
  ['string', 1],
  ['string', true],
  ['number', '1'],
  ['number', Number.NaN],
  ['number', Number.POSITIVE_INFINITY],
  ['integer', 1.5],
  ['integer', Number.MAX_SAFE_INTEGER + 1],
  ['boolean', 'true'],
  ['boolean', 1],
  ['path', 12],
  ['url', false],
  ['command', []],
  ['null', 'null'],
];

for (const [type, value] of invalidPrimitiveCases) {
  test(`schema rejects invalid ${type}`, () => {
    const result = validate({ value }, { value: { type, required: true } });
    assert.equal(result.ok, false);
    assert.ok(result.errors.length > 0);
  });
}

const numericCases = [];
for (let value = 0; value <= 10; value += 1) numericCases.push([`in range ${value}`, value, true]);
for (const value of [-10, -1, 11, 100]) numericCases.push([`out of range ${value}`, value, false]);
for (const [name, value, ok] of numericCases) {
  test(`integer range ${name}`, () => {
    const result = validate({ value }, { value: { type: 'integer', min: 0, max: 10 } });
    assert.equal(result.ok, ok, JSON.stringify(result.errors));
    if (!ok) expectFailureCode(result, value < 0 ? 'NUMBER_TOO_SMALL' : 'NUMBER_TOO_LARGE');
  });
}

const multiples = [2, 4, 10, -6];
for (const value of multiples) {
  test(`integer accepts multiple ${value}`, () => {
    assert.equal(validate({ value }, { value: { type: 'integer', multipleOf: 2 } }).ok, true);
  });
}
for (const value of [1, 3, 5, 7, 9, 11, -3]) {
  test(`integer rejects nonmultiple ${value}`, () => {
    expectFailureCode(validate({ value }, { value: { type: 'integer', multipleOf: 2 } }), 'NUMBER_MULTIPLE_MISMATCH');
  });
}

const stringLengthCases = [
  ['empty within minimum zero', '', 0, 3, true],
  ['one within minimum zero', 'a', 0, 3, true],
  ['three at maximum', 'abc', 0, 3, true],
  ['four above maximum', 'abcd', 0, 3, false],
  ['one below minimum two', 'a', 2, 4, false],
  ['two at minimum two', 'ab', 2, 4, true],
  ['unicode count', 'a\u20acb', 2, 3, true],
  ['unicode above count', 'a\u20acb\u20ac', 2, 3, false],
];
for (const [name, value, minLength, maxLength, ok] of stringLengthCases) {
  test(`string length ${name}`, () => {
    const result = validate({ value }, { value: { type: 'string', minLength, maxLength } });
    assert.equal(result.ok, ok, JSON.stringify(result.errors));
  });
}

for (const [name, pattern, value, ok] of [
  ['lowercase accepted', '^[a-z]+$', 'abc', true],
  ['lowercase rejects uppercase', '^[a-z]+$', 'Abc', false],
  ['digits accepted', '^\\d{2,4}$', '123', true],
  ['digits reject letters', '^\\d{2,4}$', '12a', false],
  ['unicode flag accepted', '^[\\p{L}]+$', 'caf\u00e9', true],
  ['anchor middle rejected', '^ok$', 'nook', false],
]) {
  test(`string pattern ${name}`, () => {
    assert.equal(validate({ value }, { value: { type: 'string', pattern } }).ok, ok);
  });
}

for (const [name, enumValues, value, ok] of [
  ['string member', ['a', 'b'], 'a', true],
  ['string nonmember', ['a', 'b'], 'c', false],
  ['number member', [1, 2], 2, true],
  ['boolean member', [true], true, true],
  ['null member nullable', [null], null, true],
  ['object member', [{ a: 1 }], { a: 1 }, true],
  ['object key order member', [{ a: 1, b: 2 }], { b: 2, a: 1 }, true],
  ['array member', [[1, 2]], [1, 2], true],
  ['array order differs', [[1, 2]], [2, 1], false],
]) {
  test(`enum ${name}`, () => {
    assert.equal(validate({ value }, { value: { type: 'any', enum: enumValues } }).ok, ok);
  });
}

for (const [name, value, minItems, maxItems, ok] of [
  ['empty allowed', [], 0, 2, true],
  ['one allowed', [1], 1, 2, true],
  ['two at maximum', [1, 2], 1, 2, true],
  ['three above maximum', [1, 2, 3], 1, 2, false],
  ['zero below minimum', [], 1, 2, false],
]) {
  test(`array length ${name}`, () => {
    assert.equal(validate({ value }, { value: { type: 'array', minItems, maxItems } }).ok, ok);
  });
}

for (const [name, value, ok] of [
  ['unique primitives', [1, 2, 3], true],
  ['duplicate number', [1, 2, 1], false],
  ['unique objects', [{ a: 1 }, { a: 2 }], true],
  ['duplicate object key order', [{ a: 1, b: 2 }, { b: 2, a: 1 }], false],
  ['duplicate array', [[1], [1]], false],
  ['null and false unique', [null, false], true],
]) {
  test(`array uniqueness ${name}`, () => {
    assert.equal(validate({ value }, { value: { type: 'array', uniqueItems: true } }).ok, ok);
  });
}

for (const [name, value, itemSpec, ok, code] of [
  ['integer items valid', [1, 2, 3], { type: 'integer' }, true, null],
  ['integer item invalid', [1, 'x'], { type: 'integer' }, false, 'TYPE_MISMATCH'],
  ['nested object valid', [{ name: 'a' }], { type: 'object', properties: { name: { type: 'string', required: true } } }, true, null],
  ['nested object missing', [{}], { type: 'object', properties: { name: { type: 'string', required: true } } }, false, 'REQUIRED_ARGUMENT_MISSING'],
  ['nested object unknown', [{ name: 'a', extra: 1 }], { type: 'object', properties: { name: { type: 'string' } } }, false, 'UNKNOWN_ARGUMENT_KEY'],
]) {
  test(`array item schema ${name}`, () => {
    const result = validate({ value }, { value: { type: 'array', items: itemSpec } });
    assert.equal(result.ok, ok, JSON.stringify(result.errors));
    if (!ok) expectFailureCode(result, code);
  });
}

for (const [name, value, objectSpec, ok, code] of [
  ['empty object valid', {}, { type: 'object', properties: {} }, true, null],
  ['known property valid', { name: 'x' }, { type: 'object', properties: { name: { type: 'string' } } }, true, null],
  ['unknown property rejected', { extra: 1 }, { type: 'object', properties: {} }, false, 'UNKNOWN_ARGUMENT_KEY'],
  ['additional property allowed', { extra: 1 }, { type: 'object', additionalProperties: true }, true, null],
  ['required property missing', {}, { type: 'object', properties: { name: { type: 'string', required: true } } }, false, 'REQUIRED_ARGUMENT_MISSING'],
  ['too many properties', { a: 1, b: 2 }, { type: 'object', additionalProperties: true, maxProperties: 1 }, false, 'OBJECT_TOO_MANY_PROPERTIES'],
]) {
  test(`object schema ${name}`, () => {
    const result = validate({ value }, { value: objectSpec });
    assert.equal(result.ok, ok, JSON.stringify(result.errors));
    if (!ok) expectFailureCode(result, code);
  });
}

test('top-level unknown key is rejected fail closed', () => {
  expectFailureCode(validate({ known: 'x', extra: 1 }, { known: { type: 'string' } }), 'UNKNOWN_ARGUMENT_KEY');
});

test('missing required key is rejected', () => {
  expectFailureCode(validate({}, { known: { type: 'string', required: true } }), 'REQUIRED_ARGUMENT_MISSING');
});

test('optional key may be absent', () => {
  assert.equal(validate({}, { known: { type: 'string' } }).ok, true);
});

test('null is rejected when nullable is false', () => {
  expectFailureCode(validate({ value: null }, { value: { type: 'string' } }), 'TYPE_MISMATCH');
});

test('null is accepted when nullable is true', () => {
  assert.equal(validate({ value: null }, { value: { type: 'string', nullable: true } }).ok, true);
});

for (const key of ['__proto__', 'constructor', 'prototype']) {
  test(`prototype pollution key ${key} is rejected`, () => {
    const input = JSON.parse(`{"${key}":1}`);
    expectFailureCode(inspectToolArguments(input), 'PROTOTYPE_POLLUTION_KEY');
  });
}

test('object getter is rejected without being invoked', () => {
  let invoked = false;
  const input = {};
  Object.defineProperty(input, 'evil', { enumerable: true, get() { invoked = true; return 1; } });
  expectFailureCode(inspectToolArguments(input), 'GETTER_REJECTED');
  assert.equal(invoked, false);
});

test('array getter is rejected without being invoked', () => {
  let invoked = false;
  const input = { items: [] };
  Object.defineProperty(input.items, '0', { enumerable: true, get() { invoked = true; return 1; } });
  expectFailureCode(inspectToolArguments(input), 'GETTER_REJECTED');
  assert.equal(invoked, false);
});

test('cyclic object is rejected', () => {
  const input = {};
  input.self = input;
  expectFailureCode(inspectToolArguments(input), 'CYCLIC_ARGUMENT');
});

test('cyclic array is rejected', () => {
  const input = { items: [] };
  input.items.push(input.items);
  expectFailureCode(inspectToolArguments(input), 'CYCLIC_ARGUMENT');
});

for (const [name, value] of [
  ['undefined', undefined],
  ['function', () => 1],
  ['symbol', Symbol('x')],
  ['bigint', 1n],
]) {
  test(`unsupported ${name} argument is rejected`, () => {
    expectFailureCode(inspectToolArguments({ value }), 'UNSUPPORTED_JSON_TYPE');
  });
}

for (const value of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
  test('nonfinite number argument is rejected', () => {
    expectFailureCode(inspectToolArguments({ value }), 'NON_FINITE_NUMBER');
  });
}

test('class instance object is rejected', () => {
  class Example {}
  expectFailureCode(inspectToolArguments({ value: new Example() }), 'NON_PLAIN_OBJECT');
});

test('date object is rejected', () => {
  expectFailureCode(inspectToolArguments({ value: new Date(0) }), 'NON_PLAIN_OBJECT');
});

test('null-prototype object is accepted as plain JSON object', () => {
  const input = Object.create(null);
  input.value = 1;
  assert.equal(inspectToolArguments(input).ok, true);
});

test('symbol key is rejected', () => {
  const input = {};
  input[Symbol('x')] = 1;
  expectFailureCode(inspectToolArguments(input), 'SYMBOL_KEY_REJECTED');
});

test('array extra property is rejected', () => {
  const input = { items: [1] };
  input.items.extra = 2;
  expectFailureCode(inspectToolArguments(input), 'UNEXPECTED_ARRAY_PROPERTY');
});

for (const depth of [0, 1, 4, 8, 12]) {
  test(`argument depth ${depth} within default`, () => {
    assert.equal(validate({ value: makeDepth('x', depth) }, { value: { type: 'any' } }).ok, true);
  });
}

for (const depth of [13, 14, 20]) {
  test(`argument depth ${depth} exceeds default`, () => {
    expectFailureCode(validate({ value: makeDepth('x', depth) }, { value: { type: 'any' } }), 'DEPTH_EXCEEDED');
  });
}

for (const [limit, depth, ok] of [[0, 0, true], [1, 1, true], [1, 2, false], [4, 3, true], [4, 5, false]]) {
  test(`configured depth limit ${limit} with depth ${depth}`, () => {
    assert.equal(validate({ value: makeDepth('x', depth) }, { value: { type: 'any' } }, { maxDepth: limit }).ok, ok);
  });
}

for (const [limit, size, ok] of [[10, 4, false], [20, 4, true], [30, 4, true], [1000, 200, true], [40, 200, false]]) {
  test(`argument byte budget ${limit} with repeated size ${size}`, () => {
    const result = validate({ value: 'x'.repeat(size) }, { value: { type: 'string' } }, { maxBytes: limit });
    assert.equal(result.ok, ok, JSON.stringify(result.errors));
  });
}

test('normalized arguments are a detached copy', () => {
  const input = { value: { nested: 'x' } };
  const result = validate(input, { value: { type: 'object', additionalProperties: true } });
  assert.equal(result.ok, true);
  input.value.nested = 'changed';
  assert.equal(result.normalizedArguments.value.nested, 'x');
});

test('measured byte count and depth are reported', () => {
  const result = validate({ value: 'x' }, { value: { type: 'string' } });
  assert.equal(result.ok, true);
  assert.ok(result.bytes > 0);
  assert.equal(result.depth, 0);
});

test('invalid parameter type is a validation failure', () => {
  expectFailureCode(validate({ value: 1 }, { value: { type: 'mystery' } }), 'INVALID_POLICY_TYPE');
});

test('invalid regex policy is reported without throwing', () => {
  expectFailureCode(validate({ value: 'x' }, { value: { type: 'string', pattern: '[' } }), 'INVALID_POLICY_PATTERN');
});

for (const [path, ok] of [
  ['plain.txt', true],
  ['nested/plain.txt', true],
  ['./nested/plain.txt', true],
  ['nested/../plain.txt', false],
  ['..', false],
  ['../plain.txt', false],
]) {
  test(`schema delegates path guard ${path}`, () => {
    assert.equal(validate({ value: path }, { value: { type: 'path' } }).ok, ok);
  });
}
