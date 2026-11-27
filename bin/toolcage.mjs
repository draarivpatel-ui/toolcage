#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { auditPolicy, createFirewall, sanitizeToolResult, VERSION } from '../src/index.mjs';

function usage() {
  return [
    'toolcage ' + VERSION,
    '',
    'Usage:',
    '  toolcage audit-policy --policy policy.json [--json]',
    '  toolcage validate --policy policy.json --tool NAME (--arguments JSON | --arguments-file FILE) [--show-arguments] [--json]',
    '  toolcage sanitize [--input FILE | --text TEXT] [--json]',
    '  toolcage --version',
    '',
    'Validation output hides argument values unless --show-arguments is explicit.',
  ].join('\n');
}

function parseOptions(argv) {
  const options = { _: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith('--')) {
      options._.push(arg);
      continue;
    }
    if (arg === '--json' || arg === '--show-arguments' || arg === '--json-input' || arg === '--input-json') {
      options[arg.slice(2)] = true;
      continue;
    }
    if (index + 1 >= argv.length) throw new Error('missing value for ' + arg);
    options[arg.slice(2)] = argv[index + 1];
    index += 1;
  }
  return options;
}

function readJsonFile(file, label) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    throw new Error('cannot read ' + label + ': ' + error.message);
  }
}

function printPayload(payload, jsonMode) {
  if (jsonMode) process.stdout.write(JSON.stringify(payload, null, 2) + '\n');
  else process.stdout.write(JSON.stringify(payload) + '\n');
}

function readStdin() {
  return readFileSync(0, 'utf8');
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv.includes('--version') || argv.includes('-v')) {
    process.stdout.write('toolcage ' + VERSION + '\n');
    return 0;
  }
  if (argv.length === 0 || argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(usage() + '\n');
    return argv.length === 0 ? 2 : 0;
  }
  const command = argv[0];
  const options = parseOptions(argv.slice(1));
  if (command === 'audit-policy') {
    if (!options.policy) throw new Error('audit-policy requires --policy');
    const policy = readJsonFile(options.policy, 'policy');
    const audit = auditPolicy(policy);
    printPayload(audit, options.json === true);
    return audit.ok ? 0 : 1;
  }
  if (command === 'validate') {
    if (!options.policy) throw new Error('validate requires --policy');
    if (!options.tool) throw new Error('validate requires --tool');
    if (options.arguments !== undefined && options['arguments-file'] !== undefined) throw new Error('use only one argument input');
    const policy = readJsonFile(options.policy, 'policy');
    let args = {};
    if (options.arguments !== undefined) args = JSON.parse(String(options.arguments));
    else if (options['arguments-file'] !== undefined) args = readJsonFile(options['arguments-file'], 'arguments');
    const firewall = createFirewall(policy);
    const result = firewall.validateCall(String(options.tool), args);
    if (!options['show-arguments'] && result.normalizedArguments) {
      const copy = { ...result };
      delete copy.normalizedArguments;
      printPayload({ ...copy, argumentBytes: result.bytes, argumentKeys: Object.keys(result.normalizedArguments).sort() }, options.json === true);
    } else {
      printPayload(result, options.json === true);
    }
    return result.ok ? 0 : 1;
  }
  if (command === 'sanitize') {
    let input;
    if (options.text !== undefined) input = String(options.text);
    else if (options.input !== undefined) input = readFileSync(String(options.input), 'utf8');
    else input = readStdin();
    let value = input;
    if (options['json-input'] === true || options['input-json'] === true) value = JSON.parse(input);
    const result = sanitizeToolResult(value);
    if (options.json === true) printPayload(result, true);
    else if (typeof result.value === 'string') process.stdout.write(result.value + '\n');
    else process.stdout.write(JSON.stringify(result.value) + '\n');
    return result.ok ? 0 : 1;
  }
  throw new Error('unknown command ' + command);
}

main().then((code) => {
  process.exitCode = code;
}).catch((error) => {
  process.stderr.write('toolcage: ' + error.message + '\n');
  process.stderr.write(usage() + '\n');
  process.exitCode = 2;
});
