# toolcage

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/draarivpatel-ui/toolcage/badge)](https://scorecard.dev/viewer/?uri=github.com/draarivpatel-ui/toolcage)

Zero-dependency AI-agent and MCP tool-call security firewall for Node.js.

`toolcage` sits between a model and your real tools. It validates every tool name and argument object before execution, blocks dangerous command, path and URL inputs, enforces capability budgets, stops duplicate runaway loops, writes a tamper-evident audit trail, and sanitizes untrusted tool output before the output goes back to a model.

- Zero runtime dependencies
- ESM and CommonJS builds
- Strict TypeScript declarations
- Node.js 18, 20, 22 and 24
- Synchronous policy validation plus async execution wrapping
- No network access and no hidden process, file or environment side effects

## Install

```sh
npm install toolcage
```

This repository is prepared for independent audit before publication. Do not treat a local checkout as proof that the package is available on npm.

## Quick start

```js
import { createFirewall } from 'toolcage';

const firewall = createFirewall({
  version: 1,
  tools: {
    read_file: {
      parameters: {
        path: { type: 'path', required: true, maxLength: 1024 },
      },
      maxCalls: 10,
      rateLimit: { windowMs: 1000, maxCalls: 3 },
    },
  },
  budget: {
    maxCalls: 100,
    maxBytes: 1_000_000,
    windowMs: 60_000,
    windowMaxCalls: 30,
    duplicateWindowMs: 10_000,
    maxDuplicates: 4,
  },
});

const result = await firewall.execute('read_file', { path: 'notes/today.txt' }, async (args) => {
  // Call the real implementation only after the firewall has admitted the call.
  return { path: args.path, bytes: 42 };
});

if (!result.ok) {
  console.error(result.error || result.errors);
} else {
  console.log(result.value);
}
```

## What is enforced

### Tool policy and argument firewall

Every enabled tool is declared in policy. Unknown tools are denied by default. Tool arguments must be plain JSON-compatible objects. Unknown argument keys are rejected fail closed, including unknown keys inside nested objects unless `additionalProperties: true` is an explicit policy choice.

The validator blocks prototype-pollution keys, object and array getters, symbol keys, class instances, cyclic values, unsupported primitive values and non-finite numbers. Size and depth limits apply globally, per tool and per parameter.

### Dangerous argument guards

Declared parameter types receive additional inspection:

- `command`: shell operators, substitution, process substitution, expansion, control characters, unbalanced quoting, dangerous git flags and git SSH command overrides.
- `path`: parent traversal, encoded traversal, absolute paths, Windows drive paths, UNC paths, home expansion, null bytes and control characters.
- `url`: unsafe schemes, userinfo, whitespace and backslash ambiguity, non-default ports, local hostnames, direct private or reserved IP literals, IPv4 spelling obfuscation, IPv4-mapped IPv6, host allowlists and host denylists.

These guards are validation layers. They are not a replacement for least-privilege tool implementations.

### Capability budgets and runaway-loop detection

`CapabilityBudget` supports:

- Per-session maximum calls
- Per-tool maximum calls
- Session sliding-window rate limits
- Per-tool sliding-window rate limits
- Cumulative byte budgets across inputs and outputs
- Duplicate identical-call loop detection inside a configurable window

Budget admission is reserved before the handler runs, so concurrent asynchronous calls cannot bypass call-count limits.

### Immutable audit trail

Every admitted, denied, failed, sanitized and completed execution appends a hash-chained entry to `AuditTrail`. Entries contain metadata and hashes, never raw argument or result values. Entries are deeply frozen and can be verified with `verifyAudit()`.

### Indirect prompt-injection and output sanitization

`sanitizeToolResult` inspects untrusted output before it is shown to a model. It removes Trojan Source bidirectional controls, zero-width characters, Unicode Tag characters and unsafe control characters. It detects high-confidence instruction-override, prompt-exfiltration, secret-exfiltration, safety-bypass and tool-hijack markers. It redacts structured sensitive fields and common secret-shaped strings without echoing secret values into findings.

Output that exceeds configured byte or depth limits, is not JSON-compatible, contains unsafe structured keys or contains high-confidence injection text is blocked rather than partially trusted.

## Policy format

```js
const policy = {
  version: 1,
  allowedTools: ['read_file', 'fetch_url'],
  deniedTools: ['dangerous_tool'],
  allowUnknownTools: false,
  tools: {
    read_file: {
      enabled: true,
      parameters: {
        path: {
          type: 'path',
          required: true,
          maxLength: 1024,
          allowAbsolute: false,
          allowParentTraversal: false,
        },
      },
      maxCalls: 20,
      rateLimit: { windowMs: 1000, maxCalls: 5 },
      maxDepth: 8,
      maxBytes: 16384,
      result: { maxBytes: 65536, maxDepth: 8 },
    },
    fetch_url: {
      parameters: {
        url: {
          type: 'url',
          required: true,
          allowedSchemes: ['https'],
          hostPolicy: { allow: ['example.com'], deny: ['bad.example.com'] },
        },
      },
    },
  },
  budget: {
    maxCalls: 100,
    maxBytes: 1000000,
    windowMs: 60000,
    windowMaxCalls: 30,
    duplicateWindowMs: 10000,
    maxDuplicates: 4,
  },
  sanitizer: {
    maxBytes: 65536,
    maxDepth: 12,
    blockOnInstruction: true,
    redactSecrets: true,
    removeHiddenUnicode: true,
  },
};
```

Validate a policy statically before deployment:

```js
import { auditPolicy } from 'toolcage';

const audit = auditPolicy(policy);
if (!audit.ok) console.error(audit.errors);
if (audit.warnings.length > 0) console.warn(audit.warnings);
```

## Public API

### Firewall

- `createFirewall(policy, options)` creates a `ToolCage` instance.
- `new ToolCage(policy, options)` is the class form.
- `firewall.validateCall(toolName, args)` validates policy and arguments without consuming budget.
- `firewall.execute(toolName, args, handler)` validates, admits, executes, sanitizes and audits a call.
- `firewall.wrapTool(toolName, handler)` returns a reusable async wrapper.
- `firewall.wrapTools(handlers)` wraps a map of handlers.
- `firewall.sanitizeResult(value, toolName)` sanitizes output with global and tool-specific policy.
- `firewall.auditEntries()` returns frozen audit entries.
- `firewall.verifyAudit()` verifies the hash chain.
- `firewall.auditDigest()` returns the current chain head.
- `firewall.budgetSnapshot()` returns budget consumption.

### Validation and policy

- `validateToolArguments(args, toolSpec)`
- `inspectToolArguments(args)`
- `auditPolicy(policy)`
- `normalizePolicy(policy)`

### Guards

- `guardCommand(value, spec)`
- `guardPath(value, spec)`
- `guardUrl(value, spec)`
- `splitCommandWords(command)`
- `parseIpv4`, `parseIpv6`, `normalizeIp`, `classifyIp`, `isPublicIp`

### Output sanitization and audit

- `sanitizeToolResult(value, options)`
- `resultLooksDangerous(value)`
- `AuditTrail`
- `CapabilityBudget`
- `canonicalHash`, `stableStringify`, `sha256Text`

## CLI

```sh
toolcage audit-policy --policy policy.json --json
toolcage validate --policy policy.json --tool read_file --arguments-file args.json --json
toolcage sanitize --input untrusted.txt --json
```

Validation output hides argument values by default. Pass `--show-arguments` only when the values are safe to print.

## Examples

```sh
node examples/mcp-tool-wrapper.mjs
node examples/policy-audit.mjs
node examples/result-sanitizer.mjs
```

## Threat model and boundaries

In scope: untrusted model-selected tool names, malformed or hostile arguments, dangerous command/path/URL values, runaway automation loops, oversized outputs, hidden Unicode in tool output, high-confidence indirect prompt injection and accidental secret exposure.

Out of scope: compromise of the host process itself, malicious policy authors, side-channel-free execution, network pinning after a URL is validated, full natural-language injection detection, and safety of the underlying tool implementation. A permissive policy can weaken every control here. Treat policy changes as security-sensitive code changes.

## Development

```sh
node scripts/build-cjs.mjs
node scripts/run-tests.mjs
node scripts/check-types.mjs
node scripts/cli-smoke.mjs
node scripts/check-pack.mjs
```

The package has zero runtime dependencies and zero development dependencies. Generated CommonJS files in `cjs/` are tracked so the published tarball is reproducible without a build dependency.

## License

MIT
