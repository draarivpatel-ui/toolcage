// Dangerous argument guards for command, path and URL typed parameters.

const { failure } = require('./errors.cjs');
const { normalizeIp, classifyIp } = require('./ip.cjs');

const CONTROL_RE = /[\u0000-\u001f\u007f]/u;
const SHELL_OPERATOR_PATTERNS = [
  ['COMMAND_SUBSTITUTION', /\$\{/u],
  ['COMMAND_SUBSTITUTION', /\$\(/u],
  ['COMMAND_SUBSTITUTION', /`/u],
  ['PROCESS_SUBSTITUTION', /[<>]\(/u],
  ['SHELL_OPERATOR', /&&|\|\||;;/u],
  ['SHELL_OPERATOR', /[;&|<>*?[\]]/u],
  ['SHELL_EXPANSION', /\$[A-Za-z_{(]/u],
];
const GIT_ENV_RE = /(?:^|\s)GIT_(?:SSH_COMMAND|SSH|ASKPASS)=(?:"[^"]*"|'[^']*'|\S+)/iu;
const DANGEROUS_GIT_LONG_FLAGS = new Set([
  '--upload-pack',
  '--exec-path',
  '--config',
  '--config-env',
  '--git-dir',
  '--work-tree',
  '--namespace',
  '--super-prefix',
]);
const LOCAL_HOSTNAMES = new Set(['localhost', 'ip6-localhost', 'ip6-loopback']);
const LOCAL_HOST_SUFFIXES = ['.localhost', '.local', '.lan', '.home', '.internal', '.intranet', '.corp'];
const WINDOWS_DRIVE_RE = /^[a-zA-Z]:[\\/]/u;
const CONTROL_PERCENT_RE = /%(?:0[0-9a-f]|1[f]|7[f])/iu;

function err(code, message, path) {
  return failure(code, message, path);
}

function splitCommandWords(command) {
  const words = [];
  let current = '';
  let quote = null;
  let escaped = false;
  let hasToken = false;
  for (const ch of command) {
    if (escaped) {
      current += ch;
      hasToken = true;
      escaped = false;
      continue;
    }
    if (ch === '\\' && quote !== "'") {
      escaped = true;
      continue;
    }
    if (quote !== null) {
      if (ch === quote) quote = null;
      else current += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      hasToken = true;
      continue;
    }
    if (/\s/u.test(ch)) {
      if (hasToken) {
        words.push(current);
        current = '';
        hasToken = false;
      }
      continue;
    }
    current += ch;
    hasToken = true;
  }
  if (escaped || quote !== null) return null;
  if (hasToken) words.push(current);
  return words;
}

function isGitExecutable(word) {
  const base = word.split('/').pop().split('\\').pop().toLowerCase();
  return base === 'git' || base === 'git.exe';
}

function guardCommand(value, spec, path) {
  const errors = [];
  if (CONTROL_RE.test(value)) errors.push(err('CONTROL_CHARACTER', 'command contains a control character', path));
  if (value.includes('\u0000')) errors.push(err('NULL_BYTE', 'command contains a null byte', path));
  if (spec.allowShellOperators !== true) {
    for (const [code, regex] of SHELL_OPERATOR_PATTERNS) {
      if (regex.test(value)) {
        errors.push(err(code, 'command contains shell syntax that is not allowed', path));
        break;
      }
    }
  }
  if (GIT_ENV_RE.test(value)) errors.push(err('GIT_COMMAND_INJECTION', 'git process execution environment override is not allowed', path));
  const words = splitCommandWords(value);
  if (words === null) {
    errors.push(err('UNBALANCED_QUOTE', 'command quoting is unbalanced', path));
    return errors;
  }
  let gitMode = false;
  for (let i = 0; i < words.length; i += 1) {
    const word = words[i];
    const lower = word.toLowerCase();
    if (isGitExecutable(word)) gitMode = true;
    if (!gitMode) continue;
    if (lower === '-c' || lower === '--config' || lower === '--config-env') {
      errors.push(err('GIT_CONFIG_INJECTION', 'git command-line configuration injection is not allowed', path));
      continue;
    }
    const flag = lower.split('=')[0];
    if (DANGEROUS_GIT_LONG_FLAGS.has(flag)) {
      errors.push(err('GIT_FLAG_BLOCKED', `git flag ${flag} is not allowed`, path));
    }
    if (lower.includes('core.sshcommand') || lower.includes('core.sshvariant') || lower.includes('ssh.command')) {
      errors.push(err('GIT_COMMAND_INJECTION', 'git ssh command override is not allowed', path));
    }
  }
  return errors;
}

function percentDecodeRepeated(value) {
  let text = value;
  for (let round = 0; round < 4; round += 1) {
    let decoded = '';
    let changed = false;
    for (let i = 0; i < text.length; i += 1) {
      if (text[i] === '%' && i + 2 < text.length && /^[0-9a-fA-F]{2}$/u.test(text.slice(i + 1, i + 3))) {
        decoded += String.fromCharCode(Number.parseInt(text.slice(i + 1, i + 3), 16));
        i += 2;
        changed = true;
      } else {
        decoded += text[i];
      }
    }
    text = decoded;
    if (!changed) break;
  }
  return text;
}

function guardPath(value, spec, path) {
  const errors = [];
  if (CONTROL_RE.test(value) || CONTROL_PERCENT_RE.test(value)) errors.push(err('CONTROL_CHARACTER', 'path contains a control character', path));
  if (value.includes('\u0000')) errors.push(err('NULL_BYTE', 'path contains a null byte', path));
  const decoded = percentDecodeRepeated(value).replace(/\\/g, '/');
  if (decoded.includes('\u0000')) errors.push(err('NULL_BYTE', 'encoded path contains a null byte', path));
  if (WINDOWS_DRIVE_RE.test(decoded) || decoded.startsWith('/') || decoded.startsWith('//')) {
    if (spec.allowAbsolute !== true) errors.push(err('ABSOLUTE_PATH', 'absolute paths are not allowed', path));
  }
  if (/^~(?:\/|$)/u.test(decoded)) errors.push(err('HOME_EXPANSION', 'home-directory expansion is not allowed', path));
  const segments = decoded.split('/').filter((segment) => segment.length > 0 && segment !== '.');
  if (spec.allowParentTraversal !== true && segments.includes('..')) {
    errors.push(err('PATH_TRAVERSAL', 'parent directory traversal is not allowed', path));
  }
  if (decoded.includes('..../') || decoded.includes('....//')) {
    errors.push(err('PATH_TRAVERSAL', 'ambiguous parent traversal sequence is not allowed', path));
  }
  if (spec.allowUnicodeNormalizationBypass !== true && /(?:%u202e|%e0%80%ae)/iu.test(value)) {
    errors.push(err('PATH_OBFUSCATION', 'encoded direction override or overlong path sequence is not allowed', path));
  }
  return errors;
}

function stripTrailingDots(host) {
  let output = host;
  while (output.endsWith('.')) output = output.slice(0, -1);
  return output;
}

function hostPatternMatches(host, pattern) {
  if (typeof pattern !== 'string' || pattern.length === 0) return false;
  let normalized = stripTrailingDots(pattern.trim().toLowerCase());
  if (normalized.startsWith('*.')) normalized = normalized.slice(2);
  const startsDot = normalized.startsWith('.');
  if (startsDot) normalized = normalized.slice(1);
  if (!normalized) return false;
  return host === normalized || host.endsWith('.' + normalized);
}

function hostnameLooksLocal(host) {
  if (LOCAL_HOSTNAMES.has(host)) return true;
  return LOCAL_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix));
}

function validHostnameShape(host) {
  if (host.length === 0 || host.length > 253 || host.includes('..')) return false;
  const labels = host.split('.');
  return labels.every((label) => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label));
}

function portIsAllowed(url, spec) {
  if (url.port === '') return true;
  const port = Number(url.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
  if (Array.isArray(spec.allowedPorts)) return spec.allowedPorts.includes(port);
  if (spec.allowedPorts === 'any') return true;
  return (url.protocol === 'http:' && port === 80) || (url.protocol === 'https:' && port === 443);
}

function guardUrl(value, spec, path) {
  const errors = [];
  const push = (code, message) => errors.push(err(code, message, path));
  if (CONTROL_RE.test(value)) push('CONTROL_CHARACTER', 'URL contains a control character');
  if (/\s/u.test(value)) push('URL_WHITESPACE', 'URL contains whitespace');
  if (value.includes('\u0000')) push('NULL_BYTE', 'URL contains a null byte');
  if (value.includes('\\')) push('URL_BACKSLASH', 'URL contains a backslash');
  if (value.startsWith('//')) push('SCHEME_RELATIVE_URL', 'scheme-relative URLs are not allowed');
  if (errors.length > 0) return errors;
  let url;
  try {
    url = new URL(value);
  } catch {
    push('INVALID_URL', 'URL cannot be parsed');
    return errors;
  }
  const schemes = Array.isArray(spec.allowedSchemes) && spec.allowedSchemes.length > 0
    ? spec.allowedSchemes.map((scheme) => String(scheme).toLowerCase().replace(/:$/, '') + ':')
    : ['http:', 'https:'];
  if (!schemes.includes(url.protocol)) push('UNSAFE_URL_SCHEME', `URL scheme ${url.protocol} is not allowed`);
  if (url.username !== '' || url.password !== '') push('URL_USERINFO', 'URL userinfo is not allowed');
  if (!portIsAllowed(url, spec)) push('URL_PORT_BLOCKED', 'URL port is not allowed');
  let host = url.hostname;
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  host = stripTrailingDots(host.toLowerCase());
  if (host.length === 0) push('INVALID_URL', 'URL host is empty');
  if (host.includes('%')) push('INVALID_URL', 'URL host contains percent encoding');
  const normalizedIp = normalizeIp(host);
  if (normalizedIp !== null) {
    const classification = classifyIp(normalizedIp);
    if (classification !== 'public' && spec.allowPrivateNetworks !== true) {
      push('SSRF_PRIVATE_NETWORK', `URL resolves to a ${classification} network literal`);
    }
  } else {
    if (!validHostnameShape(host)) push('INVALID_HOSTNAME', 'URL hostname is not a valid DNS name');
    if (hostnameLooksLocal(host) && spec.allowPrivateNetworks !== true) push('SSRF_LOCAL_HOSTNAME', 'URL hostname is reserved for local networks');
  }
  const hostPolicy = spec.hostPolicy && typeof spec.hostPolicy === 'object' ? spec.hostPolicy : {};
  const deny = Array.isArray(hostPolicy.deny) ? hostPolicy.deny : [];
  const allow = Array.isArray(hostPolicy.allow) ? hostPolicy.allow : [];
  for (const pattern of deny) {
    if (hostPatternMatches(host, pattern)) {
      push('HOST_DENIED', 'URL host is denied by policy');
      break;
    }
  }
  if (allow.length > 0 && !allow.some((pattern) => hostPatternMatches(host, pattern))) {
    push('HOST_NOT_ALLOWED', 'URL host is not on the allow list');
  }
  return errors;
}

function guardValueByKind(value, spec, path) {
  if (spec.type === 'command') return guardCommand(value, spec, path);
  if (spec.type === 'path') return guardPath(value, spec, path);
  if (spec.type === 'url') return guardUrl(value, spec, path);
  return [];
}

exports.splitCommandWords = splitCommandWords;
exports.guardCommand = guardCommand;
exports.guardPath = guardPath;
exports.guardUrl = guardUrl;
exports.guardValueByKind = guardValueByKind;
