import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { validateToolArguments } from '../src/index.mjs';

const FUZZ_SEED = 20261127;
const NUM_RUNS = 80;
const safeChars = 'abcdefghijklmnopqrstuvwxyz0123456789';
const safeWord = fc.array(fc.constantFrom(...safeChars), { minLength: 1, maxLength: 12 }).map((chars) => chars.join(''));
const safePath = fc.array(safeWord, { minLength: 1, maxLength: 5 }).map((segments) => segments.join('/'));
const safeCommand = fc.array(safeWord, { minLength: 1, maxLength: 5 }).map((words) => words.join(' '));
const traversalPayloads = Object.freeze(['../', '..%2f', '%2e%2e/', '%252e%252e%252f', '..../']);
const commandPayloads = Object.freeze([';', '&&', '||', '$(id)', '`id`', '|', '>']);

function validatePath(path) {
  return validateToolArguments({ path }, { parameters: { path: { type: 'path', required: true, maxLength: 1024 } } });
}

function validateCommand(command) {
  return validateToolArguments({ command }, { parameters: { command: { type: 'command', required: true, maxLength: 1024 } } });
}

test('fuzz invariant: generated relative safe paths are accepted', () => {
  let cases = 0;
  fc.assert(fc.property(safePath, (path) => {
    cases += 1;
    assert.ok(path.length > 0);
    const result = validatePath(path);
    assert.equal(result.ok, true, JSON.stringify(result.errors));
    assert.equal(result.normalizedArguments.path, path);
  }), { seed: FUZZ_SEED, numRuns: NUM_RUNS });
  assert.equal(cases, NUM_RUNS);
});

test('fuzz invariant: generated traversal path inclusions are rejected', () => {
  let cases = 0;
  fc.assert(fc.property(safePath, safePath, fc.constantFrom(...traversalPayloads), (prefix, suffix, payload) => {
    cases += 1;
    const path = prefix + '/' + payload + suffix;
    assert.equal(path.includes(payload), true);
    const result = validatePath(path);
    assert.equal(result.ok, false, path);
    assert.equal(result.errors.some((error) => error.code === 'PATH_TRAVERSAL'), true, JSON.stringify(result.errors));
  }), { seed: FUZZ_SEED, numRuns: NUM_RUNS });
  assert.equal(cases, NUM_RUNS);
});

test('fuzz invariant: generated simple commands are accepted', () => {
  let cases = 0;
  fc.assert(fc.property(safeCommand, (command) => {
    cases += 1;
    assert.ok(command.length > 0);
    const result = validateCommand(command);
    assert.equal(result.ok, true, JSON.stringify(result.errors));
    assert.equal(result.normalizedArguments.command, command);
  }), { seed: FUZZ_SEED, numRuns: NUM_RUNS });
  assert.equal(cases, NUM_RUNS);
});

test('fuzz invariant: generated shell operator inclusions are rejected', () => {
  let cases = 0;
  fc.assert(fc.property(safeCommand, safeCommand, fc.constantFrom(...commandPayloads), (prefix, suffix, payload) => {
    cases += 1;
    const command = prefix + ' ' + payload + ' ' + suffix;
    assert.equal(command.includes(payload), true);
    const result = validateCommand(command);
    assert.equal(result.ok, false, command);
    assert.equal(result.errors.some((error) => error.code === 'SHELL_OPERATOR' || error.code === 'COMMAND_SUBSTITUTION'), true, JSON.stringify(result.errors));
  }), { seed: FUZZ_SEED, numRuns: NUM_RUNS });
  assert.equal(cases, NUM_RUNS);
});
