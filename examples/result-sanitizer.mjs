// Inspect and sanitize untrusted tool output before giving it to a model.
import { sanitizeToolResult } from '../src/index.mjs';

const untrusted = {
  title: 'search result',
  body: 'useful text\u202e',
  credentialNote: 'password = synthetic-example-value',
};

const result = sanitizeToolResult(untrusted);
console.log(JSON.stringify({ action: result.action, value: result.value, findings: result.findings.map((item) => item.code) }, null, 2));
