import { test } from 'node:test';
import assert from 'node:assert/strict';
import { guardCommand, guardPath, guardUrl, splitCommandWords, parseIpv4, parseIpv6, classifyIp, normalizeIp } from '../src/index.mjs';

function codes(items) {
  return items.map((item) => item.code);
}

const commandSpec = { type: 'command' };

const shellPayloads = [
  ['semicolon chaining', 'cat a; cat b', 'SHELL_OPERATOR'],
  ['background ampersand', 'sleep 1 &', 'SHELL_OPERATOR'],
  ['and chain', 'test a && test b', 'SHELL_OPERATOR'],
  ['or chain', 'test a || test b', 'SHELL_OPERATOR'],
  ['pipe', 'cat a | cat b', 'SHELL_OPERATOR'],
  ['output redirection', 'cat a > out', 'SHELL_OPERATOR'],
  ['append redirection', 'cat a >> out', 'SHELL_OPERATOR'],
  ['input redirection', 'cat < in', 'SHELL_OPERATOR'],
  ['adjacent redirection', 'cat a>out', 'SHELL_OPERATOR'],
  ['stderr redirection', 'cat a 2>err', 'SHELL_OPERATOR'],
  ['process substitution input', 'cat <(echo x)', 'PROCESS_SUBSTITUTION'],
  ['process substitution output', 'cat >(echo x)', 'PROCESS_SUBSTITUTION'],
  ['dollar command substitution', 'cat $(pwd)', 'COMMAND_SUBSTITUTION'],
  ['backtick substitution', 'cat `pwd`', 'COMMAND_SUBSTITUTION'],
  ['parameter expansion', 'cat ${HOME}', 'COMMAND_SUBSTITUTION'],
  ['simple variable expansion', 'cat $HOME', 'SHELL_EXPANSION'],
  ['glob star', 'cat *', 'SHELL_OPERATOR'],
  ['glob question', 'cat ?.txt', 'SHELL_OPERATOR'],
  ['glob class', 'cat [a-z].txt', 'SHELL_OPERATOR'],
  ['newline injection', 'cat a\ncat b', 'CONTROL_CHARACTER'],
  ['carriage return injection', 'cat a\rcat b', 'CONTROL_CHARACTER'],
  ['null byte', 'cat a\u0000b', 'CONTROL_CHARACTER'],
  ['unbalanced single quote', "cat 'abc", 'UNBALANCED_QUOTE'],
  ['unbalanced double quote', 'cat "abc', 'UNBALANCED_QUOTE'],
];

for (const [name, input, code] of shellPayloads) {
  test(`command guard blocks ${name}`, () => {
    assert.equal(codes(guardCommand(input, commandSpec, '$')).includes(code), true, JSON.stringify(guardCommand(input, commandSpec, '$')));
  });
}

const safeCommands = [
  'git status',
  'git diff --stat',
  'python3 script.py --input file.txt',
  'npm test',
  'echo hello world',
  'tool --flag=value',
  'tool "two words"',
  "tool 'two words'",
  'tool alpha beta gamma',
  'git log -5 --oneline',
];

for (const input of safeCommands) {
  test(`command guard allows safe command ${input}`, () => {
    assert.deepEqual(guardCommand(input, commandSpec, '$'), []);
  });
}

const gitPayloads = [
  'git -c core.sshCommand=evil status',
  'git -c core.sshcommand=evil status',
  'git -c user.name=x status',
  'git --config core.sshCommand=evil status',
  'git --config-env core.sshCommand=evil status',
  'git clone --upload-pack=evil repo',
  'git clone --upload-pack evil repo',
  'git --exec-path=/tmp/evil status',
  'git --git-dir=/tmp/repo/.git status',
  'git --work-tree=/tmp/repo status',
  'git --namespace=x status',
  'GIT_SSH_COMMAND=evil git clone repo',
  'GIT_SSH=evil git clone repo',
  'GIT_ASKPASS=evil git clone repo',
  '/usr/bin/git -c core.sshCommand=evil status',
  'git.exe -c core.sshCommand=evil status',
];

for (const input of gitPayloads) {
  test(`git guard blocks ${input}`, () => {
    const result = guardCommand(input, commandSpec, '$');
    assert.equal(result.some((item) => item.code.startsWith('GIT_')), true, JSON.stringify(result));
  });
}

test('command shell operators can be explicitly enabled for trusted policies', () => {
  const result = guardCommand('cat a | cat b', { type: 'command', allowShellOperators: true }, '$');
  assert.equal(result.some((item) => item.code === 'SHELL_OPERATOR'), false);
});

for (const [input, expected] of [
  ['tool a b', ['tool', 'a', 'b']],
  ['tool "a b"', ['tool', 'a b']],
  ["tool 'a b'", ['tool', 'a b']],
  ['tool a\\ b', ['tool', 'a b']],
  ['tool "" empty', ['tool', '', 'empty']],
]) {
  test(`command tokenizer ${input}`, () => {
    assert.deepEqual(splitCommandWords(input), expected);
  });
}

for (const input of ["tool 'x", 'tool "x', 'tool trailing\\']) {
  test(`command tokenizer rejects unbalanced ${input}`, () => {
    assert.equal(splitCommandWords(input), null);
  });
}

const pathSpec = { type: 'path' };
const hostilePaths = [
  ['direct parent', '../secret', 'PATH_TRAVERSAL'],
  ['middle parent', 'safe/../secret', 'PATH_TRAVERSAL'],
  ['encoded parent', '%2e%2e/secret', 'PATH_TRAVERSAL'],
  ['encoded slash parent', '..%2fsecret', 'PATH_TRAVERSAL'],
  ['double encoded parent', '%252e%252e/secret', 'PATH_TRAVERSAL'],
  ['uppercase encoded parent', '%2E%2E/secret', 'PATH_TRAVERSAL'],
  ['backslash parent', '..\\secret', 'PATH_TRAVERSAL'],
  ['posix absolute', '/etc/passwd', 'ABSOLUTE_PATH'],
  ['unc absolute', '//server/share', 'ABSOLUTE_PATH'],
  ['windows drive', 'C:\\Windows\\system32', 'ABSOLUTE_PATH'],
  ['windows forward drive', 'C:/Windows/system32', 'ABSOLUTE_PATH'],
  ['home expansion', '~/secret', 'HOME_EXPANSION'],
  ['null byte', 'safe\u0000secret', 'CONTROL_CHARACTER'],
  ['newline', 'safe\nsecret', 'CONTROL_CHARACTER'],
  ['encoded newline', 'safe%0asecret', 'CONTROL_CHARACTER'],
  ['encoded null', 'safe%00secret', 'CONTROL_CHARACTER'],
  ['double encoded newline', 'safe%250asecret', 'CONTROL_CHARACTER'],
  ['triple encoded null', 'safe%252500secret', 'CONTROL_CHARACTER'],
  ['bidi encoded unicode', 'safe%u202esecret', 'PATH_OBFUSCATION'],
];

for (const [name, input, code] of hostilePaths) {
  test(`path guard blocks ${name}`, () => {
    assert.equal(codes(guardPath(input, pathSpec, '$')).includes(code), true, JSON.stringify(guardPath(input, pathSpec, '$')));
  });
}

const safePaths = [
  'file.txt',
  'nested/file.txt',
  './nested/file.txt',
  'nested/./file.txt',
  'a/b/c/d/e.txt',
  'name with spaces.txt',
  'unicode-\u00e9.txt',
  '.hidden',
  'nested/.hidden/file',
  'file..txt',
];

for (const input of safePaths) {
  test(`path guard allows safe path ${input}`, () => {
    assert.deepEqual(guardPath(input, pathSpec, '$'), []);
  });
}

test('path guard can explicitly allow absolute paths', () => {
  assert.deepEqual(guardPath('/tmp/file.txt', { type: 'path', allowAbsolute: true }, '$'), []);
});

test('path guard can explicitly allow parent traversal', () => {
  assert.deepEqual(guardPath('../file.txt', { type: 'path', allowParentTraversal: true }, '$'), []);
});

const urlSpec = { type: 'url' };
const hostileUrls = [
  ['file scheme', 'file:///etc/passwd', 'UNSAFE_URL_SCHEME'],
  ['ftp scheme', 'ftp://example.com/a', 'UNSAFE_URL_SCHEME'],
  ['gopher scheme', 'gopher://example.com/a', 'UNSAFE_URL_SCHEME'],
  ['javascript scheme', 'javascript:alert(1)', 'UNSAFE_URL_SCHEME'],
  ['data scheme', 'data:text/plain,x', 'UNSAFE_URL_SCHEME'],
  ['scheme relative', '//example.com/a', 'SCHEME_RELATIVE_URL'],
  ['whitespace', 'https://example.com/a b', 'URL_WHITESPACE'],
  ['newline', 'https://example.com/a\nb', 'CONTROL_CHARACTER'],
  ['backslash', 'https:\\example.com\\a', 'URL_BACKSLASH'],
  ['userinfo', 'https://user:pass@example.com/', 'URL_USERINFO'],
  ['localhost', 'http://localhost/', 'SSRF_LOCAL_HOSTNAME'],
  ['localhost subdomain', 'http://x.localhost/', 'SSRF_LOCAL_HOSTNAME'],
  ['local suffix', 'http://printer.local/', 'SSRF_LOCAL_HOSTNAME'],
  ['lan suffix', 'http://router.lan/', 'SSRF_LOCAL_HOSTNAME'],
  ['internal suffix', 'http://service.internal/', 'SSRF_LOCAL_HOSTNAME'],
  ['loopback', 'http://127.0.0.1/', 'SSRF_PRIVATE_NETWORK'],
  ['loopback high', 'http://127.255.255.255/', 'SSRF_PRIVATE_NETWORK'],
  ['private ten', 'http://10.1.2.3/', 'SSRF_PRIVATE_NETWORK'],
  ['private 172', 'http://172.16.0.1/', 'SSRF_PRIVATE_NETWORK'],
  ['private 192', 'http://192.168.1.1/', 'SSRF_PRIVATE_NETWORK'],
  ['link local', 'http://169.254.1.1/', 'SSRF_PRIVATE_NETWORK'],
  ['cgnat', 'http://100.64.0.1/', 'SSRF_PRIVATE_NETWORK'],
  ['decimal loopback', 'http://2130706433/', 'SSRF_PRIVATE_NETWORK'],
  ['hex loopback', 'http://0x7f000001/', 'SSRF_PRIVATE_NETWORK'],
  ['octal loopback', 'http://0177.0.0.1/', 'SSRF_PRIVATE_NETWORK'],
  ['ipv6 loopback', 'http://[::1]/', 'SSRF_PRIVATE_NETWORK'],
  ['ipv6 mapped loopback', 'http://[::ffff:127.0.0.1]/', 'SSRF_PRIVATE_NETWORK'],
  ['ipv6 link local', 'http://[fe80::1]/', 'SSRF_PRIVATE_NETWORK'],
  ['ipv6 unique local', 'http://[fd00::1]/', 'SSRF_PRIVATE_NETWORK'],
  ['multicast', 'http://224.0.0.1/', 'SSRF_PRIVATE_NETWORK'],
  ['documentation range', 'http://192.0.2.1/', 'SSRF_PRIVATE_NETWORK'],
  ['port zero rejected by parser', 'http://example.com:0/', 'URL_PORT_BLOCKED'],
  ['nondefault port', 'http://example.com:8080/', 'URL_PORT_BLOCKED'],
  ['denied host', 'https://bad.example/', 'HOST_DENIED'],
  ['outside allowlist', 'https://other.example/', 'HOST_NOT_ALLOWED'],
];

for (const [name, input, code] of hostileUrls) {
  test(`url guard blocks ${name}`, () => {
    const spec = { type: 'url', hostPolicy: { deny: ['bad.example'], allow: ['example.com'] } };
    const result = guardUrl(input, spec, '$');
    assert.equal(codes(result).includes(code), true, `${name}: ${JSON.stringify(result)}`);
  });
}

const safeUrls = [
  'https://example.com/',
  'http://example.com/a?x=1',
  'https://example.com:443/',
  'http://example.com:80/a',
  'https://sub.example.com/a%20b',
  'https://example.com/#fragment',
  'https://8.8.8.8/',
  'https://1.1.1.1/path',
  'https://example.co.uk/path',
  'https://xn--bcher-kva.example/',
];

for (const input of safeUrls) {
  test(`url guard allows safe URL ${input}`, () => {
    assert.deepEqual(guardUrl(input, urlSpec, '$'), [], input);
  });
}

for (const [port, ok] of [[80, true], [443, true], [8080, false], [22, false], [65535, false]]) {
  test(`url default port policy ${port}`, () => {
    const scheme = port === 443 ? 'https' : 'http';
    assert.equal(guardUrl(`${scheme}://example.com:${port}/`, urlSpec, '$').length === 0, ok);
  });
}

test('url allowedPorts array permits custom port', () => {
  assert.deepEqual(guardUrl('http://example.com:8080/', { type: 'url', allowedPorts: [8080] }, '$'), []);
});

test('url allowedPorts any permits custom port', () => {
  assert.deepEqual(guardUrl('http://example.com:65535/', { type: 'url', allowedPorts: 'any' }, '$'), []);
});

test('url custom scheme permits ftp', () => {
  assert.deepEqual(guardUrl('ftp://example.com/file', { type: 'url', allowedSchemes: ['ftp'], allowedPorts: 'any' }, '$'), []);
});

test('url private networks can be explicit policy choice', () => {
  assert.deepEqual(guardUrl('http://127.0.0.1/', { type: 'url', allowPrivateNetworks: true }, '$'), []);
});

test('url guard blocks bare single-label internal hostnames by default', () => {
  for (const host of ['intranet', 'router', 'nas', 'local', 'intranet.']) {
    const result = guardUrl(`https://${host}/`, { type: 'url' }, '$');
    assert.equal(codes(result).includes('SSRF_LOCAL_HOSTNAME'), true, `${host}: ${JSON.stringify(result)}`);
  }
});

test('url single-label hostnames require explicit opt-in or exact allowlist entry', () => {
  assert.deepEqual(guardUrl('https://intranet/', { type: 'url', allowSingleLabelHostnames: true }, '$'), []);
  assert.deepEqual(guardUrl('https://intranet/', { type: 'url', hostPolicy: { allow: ['intranet'] } }, '$'), []);

  const wildcard = guardUrl('https://intranet/', { type: 'url', hostPolicy: { allow: ['*.intranet'] } }, '$');
  assert.equal(codes(wildcard).includes('SSRF_LOCAL_HOSTNAME'), true, JSON.stringify(wildcard));
});

test('url single-label exact allowlist is order independent', () => {
  for (const allow of [['example.com', 'intranet'], ['intranet', 'example.com']]) {
    assert.deepEqual(guardUrl('https://intranet/', { type: 'url', hostPolicy: { allow } }, '$'), [], allow.join(','));
  }
});

test('url built-in local denies beat single-label exceptions', () => {
  for (const spec of [
    { type: 'url', allowSingleLabelHostnames: true },
    { type: 'url', hostPolicy: { allow: ['localhost'] } },
  ]) {
    const result = guardUrl('https://localhost/', spec, '$');
    assert.equal(codes(result).includes('SSRF_LOCAL_HOSTNAME'), true, JSON.stringify(result));
  }
});

test('url wildcard allowlist matches subdomain', () => {
  assert.deepEqual(guardUrl('https://api.example.com/', { type: 'url', hostPolicy: { allow: ['*.example.com'] } }, '$'), []);
});

test('url exact allowlist does not match evil suffix prefix', () => {
  assert.equal(guardUrl('https://evil-example.com/', { type: 'url', hostPolicy: { allow: ['example.com'] } }, '$').some((item) => item.code === 'HOST_NOT_ALLOWED'), true);
});

test('url denylist beats allowlist', () => {
  const result = guardUrl('https://api.example.com/', { type: 'url', hostPolicy: { allow: ['example.com'], deny: ['api.example.com'] } }, '$');
  assert.equal(result.some((item) => item.code === 'HOST_DENIED'), true);
});

const ipv4Cases = [
  ['127.0.0.1', '127.0.0.1'],
  ['2130706433', '127.0.0.1'],
  ['0x7f000001', '127.0.0.1'],
  ['0177.0.0.1', '127.0.0.1'],
  ['127.1', '127.0.0.1'],
  ['192.168.1.1', '192.168.1.1'],
  ['8.8.8.8', '8.8.8.8'],
];
for (const [input, expected] of ipv4Cases) {
  test(`ipv4 parser normalizes ${input}`, () => {
    assert.equal(parseIpv4(input), expected);
  });
}

for (const input of ['999.1.1.1', '1.2.3.4.5', 'x.1.1.1', '', '0xfffffffff']) {
  test(`ipv4 parser rejects ${input || 'empty'}`, () => {
    assert.equal(parseIpv4(input), null);
  });
}

for (const [input, valid] of [
  ['::1', true],
  ['::ffff:127.0.0.1', true],
  ['2001:db8::1', true],
  ['fe80::1', true],
  ['1:2:3:4:5:6:7:8', true],
  ['1:2:3:4:5:6:7', false],
  ['1::2::3', false],
]) {
  test(`ipv6 parser ${input}`, () => {
    assert.equal(parseIpv6(input) !== null, valid);
  });
}

for (const [input, classification] of [
  ['127.0.0.1', 'loopback'],
  ['10.0.0.1', 'private'],
  ['172.16.0.1', 'private'],
  ['192.168.0.1', 'private'],
  ['169.254.0.1', 'link-local'],
  ['100.64.0.1', 'carrier-grade-nat'],
  ['224.0.0.1', 'multicast'],
  ['8.8.8.8', 'public'],
  ['::1', 'loopback'],
  ['fe80::1', 'link-local'],
  ['fd00::1', 'private'],
  ['2001:db8::1', 'documentation'],
]) {
  test(`ip classifier ${input}`, () => {
    assert.equal(classifyIp(input), classification);
  });
}

for (const [input, expected] of [
  ['0177.0.0.1', '127.0.0.1'],
  ['::ffff:127.0.0.1', '127.0.0.1'],
  ['2001:db8::1', '2001:db8:0:0:0:0:0:1'],
]) {
  test(`ip normalization ${input}`, () => {
    assert.equal(normalizeIp(input), expected);
  });
}
