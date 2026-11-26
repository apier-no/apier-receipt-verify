// Differential check: the Node and the Python verifier must give the same answer for every input.
// It generates random JSON texts and random certificates (valid ones, tampered ones and plain
// garbage) with fresh throwaway keys, runs both implementations and compares every result.
//
//   node test/parity.mjs --run [--count 2000] [--seed 12345] [--python python3]
//
// `node --test` runs every file under test/, so without --run this script does nothing.
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson, checkCertificate, checkCertificateText, parseJsonStrict } from '../node/verify.mjs';

const args = process.argv.slice(2);
if (!args.includes('--run')) {
  console.log('Usage: node test/parity.mjs --run [--count 2000] [--seed 12345] [--python python3]');
  process.exit(0);
}
const option = (name, fallback) => (args.includes(name) ? args[args.indexOf(name) + 1] : fallback);
const count = Number(option('--count', '2000'));
const seed = Number(option('--seed', String(Date.now() % 2147483647)));
const python = option('--python', process.platform === 'win32' ? 'python' : 'python3');

let state = seed | 0;
function random() {
  state = (state + 0x6d2b79f5) | 0;
  let t = Math.imul(state ^ (state >>> 15), 1 | state);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const int = (n) => Math.floor(random() * n);
const pick = (list) => list[int(list.length)];
const chance = (p) => random() < p;
const randomBytes = (n) => Buffer.from(Array.from({ length: n }, () => int(256)));
const b64u = (data) => Buffer.from(data).toString('base64url');

// --- Random JSON text ---------------------------------------------------------------------------
const KEYS = ['0', '1', '9', '10', '4294967294', '4294967295', '01', '-1', '1e3', '', 'a', 'B', 'æ', '€', '\u{e000}', '\u{ffee}',
  '\u{1f600}', '\u{10000}', '\ud800', '\udc00', '\u0000', '\u001f', '\u007f', '\u{2028}', '"', '\\', '__proto__', 'issuer'];
const view = new DataView(new ArrayBuffer(8));
function randomNumber() {
  view.setUint32(0, int(4294967296));
  view.setUint32(4, int(4294967296));
  const value = view.getFloat64(0);
  const kind = int(8);
  if (kind === 0 || !Number.isFinite(value)) return String(int(2000000) - 1000000);
  if (kind === 1) return `${pick(['', '-'])}${1 + int(9)}${Array.from({ length: int(40) }, () => int(10)).join('')}`;
  if (kind === 2) return `${int(1000)}.${int(1000000)}e${int(700) - 350}`;
  if (kind === 3) return value.toExponential(int(20));
  if (kind === 4) return value.toPrecision(1 + int(21));
  if (kind === 5) return `${pick(['', '-'])}0.${'0'.repeat(int(25))}${1 + int(999)}`;
  if (kind === 6) return `${1 + int(9)}e${int(60) - 30}`;
  return String(value);
}
function randomString() {
  const length = int(8);
  let text = '';
  for (let i = 0; i < length; i++) {
    const kind = int(6);
    if (kind === 0) text += String.fromCharCode(int(0x20));
    else if (kind === 1) text += String.fromCharCode(0xd800 + int(0x800));
    else if (kind === 2) text += String.fromCodePoint(0x10000 + int(0x100000));
    else if (kind === 3) text += String.fromCharCode(0x7f + int(0x2000));
    else text += String.fromCharCode(0x20 + int(0x5f));
  }
  return text;
}
function randomJson(depth = 0) {
  const kind = depth > 3 ? int(4) : int(6);
  if (kind === 0) return pick(['null', 'true', 'false']);
  if (kind === 1 || kind === 2) return randomNumber();
  if (kind === 3) return JSON.stringify(randomString());
  if (kind === 4) return `[${Array.from({ length: int(4) }, () => randomJson(depth + 1)).join(',')}]`;
  const keys = Array.from({ length: int(6) }, () => (chance(0.6) ? pick(KEYS) : randomString()));
  const unique = chance(0.97) ? [...new Set(keys)] : keys; // now and then, keep a repeated key
  return `{${unique.map((k) => `${JSON.stringify(k)}:${randomJson(depth + 1)}`).join(',')}}`;
}
const canonicalOrNull = (text) => {
  try {
    return canonicalJson(parseJsonStrict(text));
  } catch {
    return null;
  }
};

// --- Random certificates ------------------------------------------------------------------------
const rsa = (kid) => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const { n, e } = publicKey.export({ format: 'jwk' });
  return { kid, privateKey, jwk: { alg: 'RS256', e, kid, kty: 'RSA', n, use: 'sig' } };
};
const ed = (kid, extra = {}) => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { kid, privateKey, jwk: { alg: 'EdDSA', crv: 'Ed25519', kid, kty: 'OKP', use: 'sig', x: publicKey.export({ format: 'jwk' }).x, ...extra } };
};
const signers = [rsa('parity-rsa-1'), rsa('parity-rsa-2'), ed('apier-sandbox-cert-1', { apier_sandbox: true }), ed('parity-ed-marked', { apier_sandbox: true }), ed('parity-ed-plain')];
const isRsa = (key) => key.jwk.kty === 'RSA';
const signWith = (key, input) => (isRsa(key) ? sign('sha256', input, key.privateKey) : sign(null, input, key.privateKey));
const ED_ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;
const P = (1n << 255n) - 19n;
const littleEndian = (value) => Buffer.from(value.toString(16).padStart(64, '0'), 'hex').reverse();

function randomJwks() {
  const keys = signers.filter(() => chance(0.85)).map((key) => {
    const jwk = { ...key.jwk };
    if (chance(0.12)) jwk.apier_retired_at = pick(['2026-06-30', '', null, 0, 'soon']);
    if (chance(0.12)) jwk.apier_compromised_at = pick(['2026-09-01T00:00:00Z', null, '', 'bad']);
    if (chance(0.05)) jwk.apier_sandbox = pick([true, false, null]);
    if (chance(0.05)) jwk.alg = pick(['RS256', 'EdDSA', 'PS256', null]);
    if (chance(0.04)) delete jwk.alg;
    if (chance(0.04) && jwk.x) {
      // Odd Ed25519 key encodings: random bytes, non-canonical y, low-order points.
      jwk.x = b64u(pick([randomBytes(32), randomBytes(31), littleEndian(P + BigInt(int(19))), littleEndian(1n), littleEndian(0n), littleEndian(P - 1n),
        Buffer.concat([Buffer.from([1]), Buffer.alloc(30), Buffer.from([0x80])])]));
    }
    if (chance(0.03) && jwk.n) jwk.e = pick(['AQ', 'Aw', 'AQAB', 'AA', 'Ag', '', 'AQAB=']);
    if (chance(0.02) && jwk.n) jwk.n = b64u(randomBytes(pick([128, 255, 256, 257])));
    return jwk;
  });
  if (chance(0.05)) keys.push(null, 'text', { kid: 'parity-rsa-1' });
  if (chance(0.1)) keys.reverse();
  return chance(0.02) ? pick([null, {}, { keys: 'none' }, []]) : { keys };
}

function randomCertificate() {
  const key = pick(signers);
  const claims = {
    result: JSON.parse(canonicalOrNull(randomJson(2)) ?? 'null'),
    issuer: chance(0.85) ? 'https://www.apier.no' : pick(['https://apier.no', 'https://www.apier.no/', 'http://www.apier.no', '', null, 7]),
    issued_at: chance(0.9) ? '2026-11-20T10:00:00+01:00' : pick([null, 20261120, 'yesterday']),
    kid: key.kid,
    freshness: pick([{ stale: false }, { stale: true }, { stale: 'no' }, null, undefined, 'fresh']),
  };
  if (chance(isRsa(key) ? 0.1 : 0.8)) claims.is_sandbox = chance(0.92) ? true : pick([false, 'true', 1, null]);
  const header = { alg: isRsa(key) ? 'RS256' : 'EdDSA', kid: key.kid, typ: 'apier-verify-cert+jws' };
  if (chance(0.06)) header.alg = pick(['none', 'HS256', 'RS256', 'EdDSA', 'PS256', 'rs256', null, 256]);
  if (chance(0.06)) header.kid = pick([...signers.map((s) => s.kid), 'nobody', '', null, 5]);
  if (chance(0.05)) header.typ = pick(['JWT', 'apier-key-history+jws', undefined, null, 'APIER-VERIFY-CERT+JWS']);
  if (chance(0.02)) header.crit = ['b64'];
  let headerText = JSON.stringify(header);
  if (chance(0.02)) headerText = pick([`{"alg":"none",${headerText.slice(1)}`, '[]', 'null', '{', `${headerText} `]);
  const headerSegment = b64u(headerText);
  const body = JSON.parse(JSON.stringify(claims));
  let signature = signWith(key, Buffer.from(`${headerSegment}.${b64u(canonicalJson(body))}`, 'ascii'));
  const mutation = int(24);
  if (mutation === 0) signature = Buffer.from(signature.map((b, i) => (i === int(signature.length) ? b ^ (1 << int(8)) : b)));
  else if (mutation === 1) signature = signature.subarray(0, signature.length - 1 - int(3));
  else if (mutation === 2) signature = Buffer.concat([signature, randomBytes(1 + int(2))]);
  else if (mutation === 3) signature = randomBytes(signature.length);
  else if (mutation === 4 && !isRsa(key)) {
    const s = BigInt(`0x${Buffer.from(signature.subarray(32)).reverse().toString('hex')}`) + ED_ORDER;
    signature = Buffer.concat([signature.subarray(0, 32), littleEndian(s)]);
  } else if (mutation === 5 && !isRsa(key)) signature = Buffer.concat([pick([littleEndian(1n), littleEndian(0n), randomBytes(32)]), pick([Buffer.alloc(32), signature.subarray(32)])]);
  else if (mutation === 6) signature = Buffer.alloc(signature.length, pick([0, 0xff]));
  let segments = [headerSegment, '', b64u(signature)];
  if (chance(0.02)) segments = pick([[headerSegment, b64u('{}'), segments[2]], [headerSegment, segments[2]], [headerSegment, '', `${segments[2]}=`], [headerSegment, '', ''], ['', '', segments[2]], [`${headerSegment}A`, '', segments[2]]]);
  const certificate = { ...body, signature: chance(0.02) ? pick([null, 5, '', {}]) : segments.join('.') };
  if (chance(0.08)) certificate.result = pick([{ changed: true }, 'changed', null]);
  if (chance(0.03)) certificate.extra = 'added';
  if (chance(0.03)) delete certificate.is_sandbox;
  return certificate;
}

function randomKeyHistory(jwks) {
  if (chance(0.7)) return null;
  const signer = pick(signers);
  const document = {
    history_version: chance(0.95) ? '1' : 1,
    issued_at: '2026-11-26T00:00:00Z',
    keys: (jwks && Array.isArray(jwks.keys) ? jwks.keys : []).filter((k) => k && typeof k === 'object').map((k) => ({
      alg: 'RS256', compromised_at: pick([null, '2026-09-01T00:00:00Z']), environment: pick(['production', 'production', 'sandbox']),
      jwk_thumbprint: 'computed-below', jwks_uri: 'https://www.apier.no/.well-known/jwks.json', kid: k.kid,
      state: pick(['current', 'retired', 'compromised']), valid_from: null, valid_to: pick([null, '2026-06-30', '']), _jwk: k,
    })),
  };
  for (const entry of document.keys) {
    const k = entry._jwk;
    delete entry._jwk;
    // RFC 7638 thumbprint, written out here on its own.
    const members = k.kty === 'RSA' ? { e: k.e, kty: 'RSA', n: k.n } : { crv: 'Ed25519', kty: 'OKP', x: k.x };
    entry.jwk_thumbprint = chance(0.9) ? createHash('sha256').update(JSON.stringify(members)).digest('base64url') : 'not-a-thumbprint';
  }
  const headerSegment = b64u(JSON.stringify({ alg: isRsa(signer) ? 'RS256' : 'EdDSA', kid: signer.kid, typ: chance(0.9) ? 'apier-key-history+jws' : 'apier-verify-cert+jws' }));
  const signature = signWith(signer, Buffer.from(`${headerSegment}.${b64u(canonicalJson(document))}`, 'ascii'));
  const signed = { ...document, signature: `${headerSegment}..${b64u(signature)}` };
  if (chance(0.1)) signed.issued_at = '2026-11-27T00:00:00Z';
  return signed;
}

// --- Run both and compare -----------------------------------------------------------------------
const canonicalInputs = Array.from({ length: count }, () => randomJson());
const cases = Array.from({ length: count }, () => {
  const jwks = randomJwks();
  const certificate = randomCertificate();
  const base = { jwks, key_history: randomKeyHistory(jwks), allow_sandbox: chance(0.6) };
  if (chance(0.15)) {
    let text = JSON.stringify(certificate);
    if (chance(0.3)) text = pick([`{"issuer":"x",${text.slice(1)}`, JSON.stringify({ success: true, data: certificate }), `${text}x`, text.replace('"issued_at":', '"issued_at":1e999,"was":')]);
    return { ...base, certificate_text: text };
  }
  return { ...base, certificate };
});

const toShared = (r) => ({ findings: r.findings, reason: r.reason, kid: r.kid, alg: r.alg, is_sandbox: r.isSandbox, issued_at: r.issuedAt, stale: r.stale });
const nodeCanonical = canonicalInputs.map(canonicalOrNull);
const nodeResults = [];
for (const c of cases) {
  const options = { jwks: c.jwks, keyHistory: c.key_history, allowSandbox: c.allow_sandbox };
  nodeResults.push(toShared(c.certificate_text !== undefined ? await checkCertificateText(c.certificate_text, options) : await checkCertificate(c.certificate, options)));
}

const directory = mkdtempSync(join(tmpdir(), 'apier-parity-'));
let failures = 0;
try {
  const file = join(directory, 'work.json');
  writeFileSync(file, JSON.stringify({ canonical: canonicalInputs, cases }));
  const helper = fileURLToPath(new URL('./parity_helper.py', import.meta.url));
  const done = spawnSync(python, [helper, file], { encoding: 'utf8', maxBuffer: 1 << 30 });
  if (done.status !== 0) {
    console.error(done.stderr || done.error);
    process.exit(2);
  }
  const fromPython = JSON.parse(done.stdout);
  canonicalInputs.forEach((text, i) => {
    if (nodeCanonical[i] !== fromPython.canonical[i]) {
      failures++;
      if (failures <= 10) console.error(`canonical differs for ${JSON.stringify(text)}\n  node:   ${JSON.stringify(nodeCanonical[i])}\n  python: ${JSON.stringify(fromPython.canonical[i])}`);
    }
  });
  cases.forEach((c, i) => {
    const a = JSON.stringify(nodeResults[i]);
    const b = JSON.stringify(toShared({ ...fromPython.results[i], isSandbox: fromPython.results[i].is_sandbox, issuedAt: fromPython.results[i].issued_at }));
    if (a !== b) {
      failures++;
      if (failures <= 10) console.error(`result differs for case ${i}: ${JSON.stringify(c).slice(0, 1500)}\n  node:   ${a}\n  python: ${b}`);
    }
  });
} finally {
  rmSync(directory, { recursive: true, force: true });
}
const reasons = {};
for (const r of nodeResults) reasons[r.reason ?? 'none'] = (reasons[r.reason ?? 'none'] ?? 0) + 1;
console.log(`seed ${seed}: ${count} JSON texts (${nodeCanonical.filter((c) => c === null).length} refused), ${count} certificates`);
console.log(`reasons seen: ${Object.entries(reasons).sort().map(([k, v]) => `${k} ${v}`).join(', ')}`);
if (failures > 0) {
  console.error(`${failures} differences between Node and Python`);
  process.exit(1);
}
console.log('Node and Python agree on every input');
