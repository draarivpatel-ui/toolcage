# Contributing

Thanks for helping improve `toolcage`.

## Ground rules

- Keep runtime and development dependencies at zero unless the maintainer explicitly approves a change.
- Preserve Node.js 18 compatibility.
- Every security behavior change needs deterministic tests in both success and failure directions.
- Do not add real credentials, personal data or complete vendor token fixtures. Use synthetic values.
- Do not introduce Unicode em dashes or en dashes in repository text.
- Do not commit local machine paths.

## Verification

Run these commands before sending a change:

```sh
node scripts/build-cjs.mjs --check
node scripts/run-tests.mjs
node scripts/check-types.mjs
node scripts/cli-smoke.mjs
node scripts/check-pack.mjs
```

If `src/` changes, run `node scripts/build-cjs.mjs` first and commit the regenerated `cjs/` output.

## Style

Small modules, explicit error codes, no hidden global state and no network, file, process or environment access in the core library. Security defaults fail closed. Ergonomic escape hatches must be explicit and must produce policy-audit warnings where appropriate.
