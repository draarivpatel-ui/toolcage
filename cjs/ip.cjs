// Strict IPv4 and IPv6 parsing plus non-public-range classification.

const DEC = /^\d+$/;
const HEX = /^0[xX][0-9a-fA-F]+$/;
const OCT = /^0[oO][0-7]+$/;
const LEGACY_OCT = /^0[0-7]+$/;
const BIN = /^0[bB][01]+$/;
const HEX_GROUP = /^[0-9a-fA-F]{1,4}$/;

function parseOctet(token) {
  if (!token || token.length > 16) return null;
  let base = 10;
  let body = token;
  if (HEX.test(token)) { base = 16; body = token.slice(2); }
  else if (OCT.test(token)) { base = 8; body = token.slice(2); }
  else if (LEGACY_OCT.test(token)) { base = 8; body = token.slice(1); }
  else if (BIN.test(token)) { base = 2; body = token.slice(2); }
  else if (!DEC.test(token)) return null;
  if (body.length === 0 || body.length > 16) return null;
  let value = 0;
  for (const ch of body) {
    const digit = parseInt(ch, base);
    if (!Number.isFinite(digit) || digit >= base) return null;
    value = value * base + digit;
    if (value > 0xffffffff) return null;
  }
  return value <= 0xffffff ? value : null;
}

function fromUint32(value) {
  return `${(value >>> 24) & 255}.${(value >>> 16) & 255}.${(value >>> 8) & 255}.${value & 255}`;
}

function parseIpv4(host) {
  if (typeof host !== 'string' || host.length === 0 || host.length > 64) return null;
  if (host.includes('%')) return null;
  if (DEC.test(host) || HEX.test(host) || OCT.test(host) || BIN.test(host) || LEGACY_OCT.test(host)) {
    let value = 0;
    if (HEX.test(host)) value = Number.parseInt(host.slice(2), 16);
    else if (OCT.test(host)) value = Number.parseInt(host.slice(2), 8);
    else if (BIN.test(host)) value = Number.parseInt(host.slice(2), 2);
    else if (LEGACY_OCT.test(host)) value = Number.parseInt(host.slice(1), 8);
    else value = Number.parseInt(host, 10);
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) return null;
    return fromUint32(value);
  }
  const parts = host.split('.');
  if (parts.length < 1 || parts.length > 4) return null;
  const values = [];
  for (const part of parts) {
    const octet = parseOctet(part);
    if (octet === null) return null;
    values.push(octet);
  }
  if (values.length === 4 && values.slice(0, 3).every((v) => v <= 255) && values[3] <= 255) {
    return fromUint32(((values[0] << 24) | (values[1] << 16) | (values[2] << 8) | values[3]) >>> 0);
  }
  if (values.length === 3 && values[0] <= 255 && values[1] <= 255 && values[2] <= 0xffff) {
    return fromUint32(((values[0] << 24) | (values[1] << 16) | values[2]) >>> 0);
  }
  if (values.length === 2 && values[0] <= 255 && values[1] <= 0xffffff) {
    return fromUint32(((values[0] << 24) | values[1]) >>> 0);
  }
  if (values.length === 1 && values[0] <= 0xffffffff) return fromUint32(values[0] >>> 0);
  return null;
}

function ipv4ToUint32(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!DEC.test(part)) return null;
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    value = value * 256 + n;
  }
  return value >>> 0;
}

function parseGroups(text) {
  if (text.length === 0) return [];
  const groups = [];
  for (const piece of text.split(':')) {
    if (!HEX_GROUP.test(piece)) return null;
    groups.push(Number.parseInt(piece, 16));
  }
  return groups;
}

function parseIpv6(host) {
  if (typeof host !== 'string' || host.length === 0 || host.length > 128) return null;
  let text = host;
  if (text.includes('%')) text = text.slice(0, text.indexOf('%'));
  if (text.includes('.')) {
    const lastColon = text.lastIndexOf(':');
    if (lastColon < 0) return null;
    const ipv4 = parseIpv4(text.slice(lastColon + 1));
    if (ipv4 === null) return null;
    const [a, b, c, d] = ipv4.split('.').map(Number);
    text = `${text.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  if (text.includes('::')) {
    if (text.indexOf('::') !== text.lastIndexOf('::')) return null;
    const [left, right] = text.split('::');
    const leftGroups = parseGroups(left);
    const rightGroups = parseGroups(right);
    if (!leftGroups || !rightGroups) return null;
    const missing = 8 - leftGroups.length - rightGroups.length;
    if (missing < 1) return null;
    return [...leftGroups, ...new Array(missing).fill(0), ...rightGroups];
  }
  const groups = parseGroups(text);
  if (!groups || groups.length !== 8) return null;
  return groups;
}

function mappedIpv4(groups) {
  if (!groups || groups.length !== 8) return null;
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    return fromUint32(((groups[6] << 16) | groups[7]) >>> 0);
  }
  return null;
}

function normalizeIp(host) {
  const ipv4 = parseIpv4(host);
  if (ipv4 !== null) return ipv4;
  const groups = parseIpv6(host);
  if (groups === null) return null;
  const mapped = mappedIpv4(groups);
  if (mapped !== null) return mapped;
  return groups.map((group) => group.toString(16)).join(':');
}

function classifyIpv4(ip) {
  const value = ipv4ToUint32(ip);
  if (value === null) return 'invalid';
  const a = value >>> 24;
  const b = (value >>> 16) & 255;
  if (a === 0) return 'reserved';
  if (a === 10) return 'private';
  if (a === 100 && b >= 64 && b <= 127) return 'carrier-grade-nat';
  if (a === 127) return 'loopback';
  if (a === 169 && b === 254) return 'link-local';
  if (a === 172 && b >= 16 && b <= 31) return 'private';
  if (a === 192 && b === 168) return 'private';
  if (a === 192 && b === 0) return 'reserved';
  if (a === 192 && b === 2) return 'documentation';
  if (a === 198 && (b === 18 || b === 19)) return 'benchmark';
  if (a === 198 && b === 51) return 'documentation';
  if (a === 203 && b === 0) return 'documentation';
  if (a >= 224 && a <= 239) return 'multicast';
  if (a >= 240) return 'reserved';
  return 'public';
}

function classifyIpv6(host) {
  const groups = parseIpv6(host);
  if (groups === null) return 'invalid';
  const mapped = mappedIpv4(groups);
  if (mapped !== null) return classifyIpv4(mapped);
  if (groups.every((group) => group === 0)) return 'reserved';
  if (groups.slice(0, 7).every((group) => group === 0) && groups[7] === 1) return 'loopback';
  if ((groups[0] & 0xffc0) === 0xfe80) return 'link-local';
  if ((groups[0] & 0xfe00) === 0xfc00) return 'private';
  if ((groups[0] & 0xff00) === 0xff00) return 'multicast';
  if (groups[0] === 0x2001 && groups[1] === 0x0db8) return 'documentation';
  if (groups[0] === 0x2002) return 'transition';
  if ((groups[0] & 0xff00) === 0x2000 && groups[1] === 0x0000 && groups[2] === 0x0000) return 'transition';
  return 'public';
}

function classifyIp(host) {
  const ipv4 = parseIpv4(host);
  if (ipv4 !== null) return classifyIpv4(ipv4);
  return classifyIpv6(host);
}

function isPublicIp(host) {
  return classifyIp(host) === 'public';
}

exports.parseIpv4 = parseIpv4;
exports.ipv4ToUint32 = ipv4ToUint32;
exports.parseIpv6 = parseIpv6;
exports.mappedIpv4 = mappedIpv4;
exports.normalizeIp = normalizeIp;
exports.classifyIpv4 = classifyIpv4;
exports.classifyIpv6 = classifyIpv6;
exports.classifyIp = classifyIp;
exports.isPublicIp = isPublicIp;
