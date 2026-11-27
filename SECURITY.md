# Security policy

`toolcage` is a security boundary for AI-agent tool calls. Reports about bypasses are especially important.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |

## Reporting a vulnerability

Report vulnerabilities privately through GitHub at <https://github.com/draarivpatel-ui/toolcage/security/advisories/new>. Private vulnerability reporting is enabled for this repository. Do not open a public issue with a working exploit, a real secret, personal data or a third party's private endpoint.

Include:

- A minimal policy and input that reproduce the bypass
- The expected decision and the actual decision
- Whether the issue concerns validation, command/path/URL guards, budgets, audit integrity or output sanitization
- Node.js version and operating system

Do not include live credentials. Use synthetic values.

## Disclosure timeline

We aim to acknowledge new reports within 72 hours, complete triage within 7 days, and release a fix or mitigation within 90 days when the report is valid. Reporters will be credited after disclosure unless they ask not to be credited.

## Scope notes

The library validates inputs and outputs. It cannot make an underlying dangerous tool safe. It also cannot protect against a host process that is already compromised. DNS resolution and network connection pinning are intentionally outside this version's runtime boundary.

## Hardening guidance

- Keep `allowUnknownTools` false.
- Prefer exact host allowlists for URL tools.
- Do not enable shell operators unless commands are never passed to a shell and the policy has been reviewed.
- Treat audit hashes as tamper evidence, not as a substitute for isolating the tool process.
