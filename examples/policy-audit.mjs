// Statically audit a tool policy before putting it into production.
import { auditPolicy } from '../src/index.mjs';

const policy = {
  version: 1,
  allowUnknownTools: true,
  tools: {
    fetch_url: {
      parameters: {
        url: {
          type: 'url',
          required: true,
          allowPrivateNetworks: true,
        },
      },
    },
  },
};

const audit = auditPolicy(policy);
console.log(JSON.stringify({ ok: audit.ok, errors: audit.errors.length, warnings: audit.warnings.map((item) => item.code) }, null, 2));
