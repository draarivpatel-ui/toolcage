import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const declaration = fs.readFileSync(path.join(root, 'types', 'index.d.ts'), 'utf8');
if (/(:|=>)\s*any\b|\bas\s+any\b|\bArray<\s*any\s*>|\bany\s*\[\s*\]/u.test(declaration)) {
  console.error('types/index.d.ts must not use an explicit any type');
  process.exit(1);
}
for (const required of ['ToolCage', 'createFirewall', 'validateToolArguments', 'sanitizeToolResult', 'auditPolicy', 'CapabilityBudget', 'AuditTrail', 'ToolCageError']) {
  if (!declaration.includes(required)) {
    console.error('types/index.d.ts does not declare ' + required);
    process.exit(1);
  }
}

const command = process.platform === 'win32' ? 'tsc.cmd' : 'tsc';
const probe = spawnSync(command, ['--version'], { encoding: 'utf8', shell: false, windowsHide: true });
if (probe.error || probe.status !== 0) {
  console.log('strict type check skipped: tsc is not installed');
  process.exitCode = 0;
} else {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'toolcage-types-'));
  try {
    fs.copyFileSync(path.join(root, 'types', 'index.d.ts'), path.join(scratch, 'index.d.ts'));
    fs.writeFileSync(path.join(scratch, 'check.ts'), [
      'import {',
      '  ToolCage,',
      '  ToolCagePolicy,',
      '  PolicyAudit,',
      '  SanitizeResult,',
      '  auditPolicy,',
      '  createFirewall,',
      '  sanitizeToolResult,',
      '  VERSION,',
      '} from "./index";',
      'const version: "1.0.0" = VERSION;',
      'const policy: ToolCagePolicy = {',
      '  tools: {',
      '    read_file: {',
      '      parameters: {',
      '        path: { type: "path", required: true, maxLength: 1024 },',
      '        url: { type: "url", required: false },',
      '      },',
      '      maxCalls: 2,',
      '    },',
      '  },',
      '  budget: { maxCalls: 4, maxBytes: 10000, windowMs: 1000, windowMaxCalls: 3, duplicateWindowMs: 1000, maxDuplicates: 2 },',
      '};',
      'const audit: PolicyAudit = auditPolicy(policy);',
      'const firewall: ToolCage = createFirewall(policy);',
      'const validation = firewall.validateCall("read_file", { path: "safe.txt" });',
      'const sanitized: SanitizeResult = sanitizeToolResult("clean");',
      'const wrapped = firewall.wrapTool("read_file", async (args) => ({ path: String(args.path || "") }));',
      'async function run(): Promise<void> {',
      '  const result = await wrapped({ path: "safe.txt" });',
      '  if (result.ok) console.log(version, audit.ok, validation.ok, sanitized.action, result.inputHash);',
      '}',
      'void run();',
    ].join('\n'), 'utf8');
    const result = spawnSync(command, ['--noEmit', '--strict', '--exactOptionalPropertyTypes', '--noUncheckedIndexedAccess', '--target', 'es2022', '--module', 'commonjs', 'check.ts'], { cwd: scratch, encoding: 'utf8', shell: false, windowsHide: true });
    if (result.status !== 0) {
      process.stderr.write(result.stderr + result.stdout);
      process.exitCode = 1;
    } else {
      console.log('strict type check ok');
    }
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}
