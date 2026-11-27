import assert from 'node:assert/strict';

export function basePolicy() {
  return {
    version: 1,
    tools: {
      read_file: {
        parameters: {
          path: { type: 'path', required: true, maxLength: 1024 },
          encoding: { type: 'string', enum: ['utf8'], required: false },
        },
        maxCalls: 3,
      },
      fetch_url: {
        parameters: {
          url: { type: 'url', required: true },
        },
      },
      run_command: {
        parameters: {
          command: { type: 'command', required: true },
        },
      },
    },
    budget: {
      maxCalls: 8,
      maxBytes: 4096,
      windowMs: 1000,
      windowMaxCalls: 5,
      duplicateWindowMs: 1000,
      maxDuplicates: 2,
    },
  };
}

export function expectFailureCode(result, code) {
  assert.equal(result.ok, false);
  const errors = result.errors || [];
  assert.equal(errors.some((entry) => entry.code === code), true, JSON.stringify(errors));
}

export function makeDepth(value, depth) {
  let output = value;
  for (let index = 0; index < depth; index += 1) output = { child: output };
  return output;
}
