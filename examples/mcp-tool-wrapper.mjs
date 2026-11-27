// Wrap an MCP-style tool handler with policy validation, budgets and output sanitization.
import { createFirewall } from '../src/index.mjs';

const policy = {
  version: 1,
  tools: {
    read_file: {
      description: 'Read a small UTF-8 file inside the workspace',
      parameters: {
        path: { type: 'path', required: true, maxLength: 1024 },
      },
      maxCalls: 5,
      rateLimit: { windowMs: 1000, maxCalls: 2 },
    },
  },
};

const firewall = createFirewall(policy);

async function readFileTool(args) {
  return { path: args.path, bytes: 128, preview: 'safe example content' };
}

const safeReadFile = firewall.wrapTool('read_file', readFileTool);
const allowed = await safeReadFile({ path: 'notes/readme.txt' });
const rejected = await safeReadFile({ path: '../outside.txt' });

console.log(JSON.stringify({ allowed: allowed.ok, rejected: !rejected.ok, auditDigest: firewall.auditDigest() }, null, 2));
