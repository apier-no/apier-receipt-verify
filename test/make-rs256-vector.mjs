// Builds test/vectors/synthetic-cases.json: certificates signed with SYNTHETIC TEST KEYS generated
// here, on this machine, each time this script runs. None of these keys is Apier's, and no real
// production certificate or real company or person is involved. The private keys are never written
// to disk, so the committed vectors cannot be re-signed; run this script again to replace them all.
//
// It covers what the sandbox certificates cannot: the production RS256 path, retired and compromised
// keys, the key history, and inputs built to be refused. Each expected result is written by hand and
// nothing here imports the verifier. `canon` is the reference function from Apier's public guide.
import { createHash, createHmac, generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';

// `node --test` runs every file under test/, so this script only writes when asked to.
if (!process.argv.includes('--write')) {
  console.log('Usage: node test/make-rs256-vector.mjs --write   (replaces test/vectors/synthetic-cases.json)');
  process.exit(0);
}

const CERT_TYP = 'apier-verify-cert+jws';
const HISTORY_TYP = 'apier-key-history+jws';
const b64u = (data) => Buffer.from(data).toString('base64url');
const canon = (v) =>
  JSON.stringify(v, (_, val) =>
    val && typeof val === 'object' && !Array.isArray(val)
      ? Object.fromEntries(Object.entries(val).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : val,
  );

// --- Synthetic keys ---------------------------------------------------------------------------------
function rsaKey(kid, options = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, ...options });
  const { n, e } = publicKey.export({ format: 'jwk' });
  return { kid, privateKey, jwk: { alg: 'RS256', e, kid, kty: 'RSA', n, use: 'sig' } };
}
function edKey(kid, extra = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const { x } = publicKey.export({ format: 'jwk' });
  return { kid, privateKey, jwk: { alg: 'EdDSA', crv: 'Ed25519', kid, kty: 'OKP', use: 'sig', x, ...extra } };
}
const current = rsaKey('synthetic-test-rsa-current');
const retired = rsaKey('synthetic-test-rsa-retired');
const compromised = rsaKey('synthetic-test-rsa-compromised');
const stranger = rsaKey('synthetic-test-rsa-current'); // same kid as `current`, other key material
const small = rsaKey('synthetic-test-rsa-1024', { modulusLength: 1024 });
const cube = rsaKey('synthetic-test-rsa-e3', { publicExponent: 3 });
const rsaMarkedSandbox = rsaKey('synthetic-test-rsa-marked-sandbox');
const sandbox = edKey('synthetic-test-ed25519-sandbox', { apier_sandbox: true });
const edUnmarked = edKey('synthetic-test-ed25519-unmarked');

const RETIRED_AT = '2026-06-30';
const COMPROMISED_AT = '2026-09-01T00:00:00Z';
const thumbprint = ({ e, n }) => createHash('sha256').update(JSON.stringify({ e, kty: 'RSA', n })).digest('base64url');

const keysets = {
  production: { keys: [
    current.jwk,
    { ...retired.jwk, apier_retired_at: RETIRED_AT },
    { ...compromised.jwk, apier_compromised_at: COMPROMISED_AT },
  ] },
  // A copy "saved before" the retirement and the compromise: the same keys without their marks.
  'production-unmarked': { keys: [current.jwk, retired.jwk, compromised.jwk] },
  'production-unreadable-marks': { keys: [
    { ...current.jwk, apier_retired_at: '' },
    { ...retired.jwk, apier_retired_at: 20260630 },
    { ...compromised.jwk, apier_compromised_at: null },
  ] },
  // Production and sandbox keys in one set, as a caller might merge them.
  mixed: { keys: [current.jwk, sandbox.jwk, edUnmarked.jwk, { ...rsaMarkedSandbox.jwk, apier_sandbox: true }] },
  'duplicate-kid': { keys: [stranger.jwk, current.jwk] },
  weak: { keys: [small.jwk, cube.jwk, { ...current.jwk, kid: 'synthetic-test-rsa-e1', e: 'AQ' }] },
  'wrong-key-alg': { keys: [{ ...current.jwk, alg: 'PS256' }] },
  'signer-compromised': { keys: [{ ...current.jwk, apier_compromised_at: COMPROMISED_AT }, retired.jwk, compromised.jwk] },
  'bad-ed25519-keys': { keys: [
    { ...sandbox.jwk, kid: 'synthetic-test-ed25519-short', x: b64u(Buffer.alloc(31, 7)) },
    { ...sandbox.jwk, kid: 'synthetic-test-ed25519-noncanonical', x: b64u(Buffer.concat([Buffer.alloc(31, 0xff), Buffer.from([0x7f])])) },
  ] },
};

// --- Signing ----------------------------------------------------------------------------------------
const claimsFor = (key, extra = {}) => ({
  result: {
    org_number: '999000001',
    name: 'Synthetic Test AS',
    entity_type: 'AS',
    verification_status: 'pass',
    check_status: 'verified',
    last_accounts_year: 2024,
    verification_timestamp: '2026-11-20T10:00:00+01:00',
  },
  issuer: 'https://www.apier.no',
  issued_at: '2026-11-20T10:00:00+01:00',
  kid: key.kid,
  jwks_uri: 'https://www.apier.no/.well-known/jwks.json',
  rulebook_version: '1.0.0',
  audit_log_ref: `sha256:${createHash('sha256').update(key.kid).digest('hex')}`,
  freshness: { retrieved_at: '2026-11-20T08:00:00.000Z', served_from: 'live', stale: false },
  ...extra,
});
const algOf = (key) => (key.jwk.kty === 'RSA' ? 'RS256' : 'EdDSA');
const headerFor = (key, change = {}) => ({ alg: algOf(key), kid: key.kid, typ: CERT_TYP, ...change });
const rawSign = (key, input) => (key.jwk.kty === 'RSA' ? sign('sha256', input, key.privateKey) : sign(null, input, key.privateKey));

// A detached JWS over `payloadText`. `mutate` may change the signature bytes afterwards.
function detached(key, header, payloadText, mutate = (bytes) => bytes) {
  const headerSegment = b64u(JSON.stringify(header));
  const signature = rawSign(key, Buffer.from(`${headerSegment}.${b64u(payloadText)}`, 'ascii'));
  return `${headerSegment}..${b64u(mutate(signature))}`;
}
const certificate = (key, { claims = {}, header = {}, mutate, payloadText } = {}) => {
  const body = claimsFor(key, claims);
  return { ...body, signature: detached(key, headerFor(key, header), payloadText ?? canon(body), mutate) };
};

// --- Expected results -------------------------------------------------------------------------------
const ISSUED = '2026-11-20T10:00:00+01:00';
const findings = (signature, signing_key, environment, format_version = 'recognised') =>
  ({ signature, signing_key, environment, format_version });
const expected = (reason, found, rest = {}) =>
  ({ reason, findings: found, kid: null, alg: null, is_sandbox: false, issued_at: null, stale: null, ...rest });
const read = (key, rest = {}) => ({ kid: key.kid, alg: algOf(key), issued_at: ISSUED, stale: false, ...rest });
const unread = (key, rest = {}) => ({ kid: key.kid, alg: algOf(key), ...rest });

const cases = [];
const add = (name, note, fields, expect) =>
  cases.push({ name, note, jwks: 'production', allow_sandbox: false, ...fields, expect });

// --- The production path ----------------------------------------------------------------------------
add('rs256-current', 'A production-style RS256 certificate under the current key.',
  { certificate: certificate(current) }, expected(null, findings('matches', 'current', 'production'), read(current)));
add('rs256-current-sandbox-allowed', 'Allowing sandbox certificates does not refuse a production one.',
  { certificate: certificate(current), allow_sandbox: true },
  expected(null, findings('matches', 'current', 'production'), read(current)));
add('rs256-retired', 'A retired key still checks the certificates it signed.',
  { certificate: certificate(retired, { claims: { issued_at: '2026-05-01T10:00:00+02:00' } }) },
  expected(null, findings('matches', 'retired', 'production'), read(retired, { issued_at: '2026-05-01T10:00:00+02:00' })));
add('rs256-apex-issuer', 'The apex issuer that older certificates carry.',
  { certificate: certificate(current, { claims: { issuer: 'https://apier.no' } }) },
  expected(null, findings('matches', 'current', 'production'), read(current)));
add('rs256-no-freshness', 'A certificate from before November 2026 has no freshness member: stale is unknown.',
  { certificate: certificate(current, { claims: { freshness: undefined } }) },
  expected(null, findings('matches', 'current', 'production'), read(current, { stale: null })));
add('rs256-stale', 'freshness.stale is reported, never judged.',
  { certificate: certificate(current, { claims: { freshness: { retrieved_at: '2026-11-17T08:00:00.000Z', served_from: 'cache', stale: true } } }) },
  expected(null, findings('matches', 'current', 'production'), read(current, { stale: true })));
add('rs256-duplicate-kid', 'Two keys share a kid: the first one in the set is used, and it is not the signer.',
  { certificate: certificate(current), jwks: 'duplicate-kid' },
  expected('signature_invalid', findings('does_not_match', 'current', 'could_not_be_checked'), unread(current)));
add('rs256-retired-mark-empty', 'An empty apier_retired_at is no mark.',
  { certificate: certificate(current), jwks: 'production-unreadable-marks' },
  expected(null, findings('matches', 'current', 'production'), read(current)));
add('rs256-retired-mark-unreadable', 'A retirement mark that is not a date still marks the key retired.',
  { certificate: certificate(retired), jwks: 'production-unreadable-marks' },
  expected(null, findings('matches', 'retired', 'production'), read(retired)));

// --- Compromised keys: always refused offline -------------------------------------------------------
const revoked = (key, rest) => expected('compromised_key', findings('matches', 'revoked', 'production'), read(key, rest));
add('compromised-issued-after', 'issued_at after apier_compromised_at.',
  { certificate: certificate(compromised) }, revoked(compromised));
add('compromised-issued-before', 'issued_at before apier_compromised_at: still refused, because the leaked key signed that date.',
  { certificate: certificate(compromised, { claims: { issued_at: '2026-03-01T10:00:00+01:00' } }) },
  revoked(compromised, { issued_at: '2026-03-01T10:00:00+01:00' }));
add('compromised-issued-at-the-mark', 'issued_at exactly equal to apier_compromised_at.',
  { certificate: certificate(compromised, { claims: { issued_at: '2026-09-01T02:00:00+02:00' } }) },
  revoked(compromised, { issued_at: '2026-09-01T02:00:00+02:00' }));
add('compromised-mark-unreadable', 'apier_compromised_at is null: the member alone marks the key.',
  { certificate: certificate(compromised, { claims: { issued_at: '2026-03-01T10:00:00+01:00' } }), jwks: 'production-unreadable-marks' },
  revoked(compromised, { issued_at: '2026-03-01T10:00:00+01:00' }));
add('compromised-and-tampered', 'A compromised key and a changed certificate: compromised_key comes first in the order.',
  { certificate: { ...certificate(compromised), rulebook_version: '9.9.9' } },
  expected('compromised_key', findings('does_not_match', 'revoked', 'could_not_be_checked'), unread(compromised)));

// --- Issuer, typ, alg -------------------------------------------------------------------------------
add('issuer-other-environment', 'A valid signature over another issuer is not a production certificate.',
  { certificate: certificate(current, { claims: { issuer: 'https://staging.apier.example' } }) },
  expected('wrong_issuer', findings('matches', 'current', 'issuer_not_recognised'), read(current)));
add('issuer-missing', 'No issuer member.',
  { certificate: certificate(current, { claims: { issuer: undefined } }) },
  expected('wrong_issuer', findings('matches', 'current', 'issuer_not_recognised'), read(current)));
add('issuer-trailing-slash', 'The issuer is compared exactly.',
  { certificate: certificate(current, { claims: { issuer: 'https://www.apier.no/' } }) },
  expected('wrong_issuer', findings('matches', 'current', 'issuer_not_recognised'), read(current)));
add('typ-jwt', 'A valid signature under typ JWT is not a certificate.',
  { certificate: certificate(current, { header: { typ: 'JWT' } }) },
  expected('wrong_typ', findings('could_not_be_checked', 'could_not_be_checked', 'could_not_be_checked', 'not_recognised'), { alg: 'RS256' }));
add('typ-key-history', 'The key history typ is not a certificate typ.',
  { certificate: certificate(current, { header: { typ: HISTORY_TYP } }) },
  expected('wrong_typ', findings('could_not_be_checked', 'could_not_be_checked', 'could_not_be_checked', 'not_recognised'), { alg: 'RS256' }));
add('typ-uppercase', 'typ is compared exactly.',
  { certificate: certificate(current, { header: { typ: CERT_TYP.toUpperCase() } }) },
  expected('wrong_typ', findings('could_not_be_checked', 'could_not_be_checked', 'could_not_be_checked', 'not_recognised'), { alg: 'RS256' }));
{
  // HS256 keyed with the public key: the classic algorithm confusion.
  const body = claimsFor(current);
  const headerSegment = b64u(JSON.stringify(headerFor(current, { alg: 'HS256' })));
  const mac = createHmac('sha256', JSON.stringify(current.jwk)).update(`${headerSegment}.${b64u(canon(body))}`).digest();
  add('alg-hs256-public-key-as-secret', 'HS256 with the public key as the secret.',
    { certificate: { ...body, signature: `${headerSegment}..${b64u(mac)}` } },
    expected('alg_not_allowed', findings('could_not_be_checked', 'could_not_be_checked', 'could_not_be_checked')));
}
add('alg-none-with-signature', 'alg none over a real signature.',
  { certificate: certificate(current, { header: { alg: 'none' } }) },
  expected('alg_not_allowed', findings('could_not_be_checked', 'could_not_be_checked', 'could_not_be_checked')));
add('alg-ps256', 'Another RSA algorithm is not accepted.',
  { certificate: certificate(current, { header: { alg: 'PS256' } }) },
  expected('alg_not_allowed', findings('could_not_be_checked', 'could_not_be_checked', 'could_not_be_checked')));
add('alg-rs256-lowercase', 'alg is compared exactly.',
  { certificate: certificate(current, { header: { alg: 'rs256' } }) },
  expected('alg_not_allowed', findings('could_not_be_checked', 'could_not_be_checked', 'could_not_be_checked')));

// --- Keys -------------------------------------------------------------------------------------------
add('kid-unknown', 'No key in the set has this kid.',
  { certificate: certificate(current, { header: { kid: 'synthetic-test-rsa-absent' } }) },
  expected('unknown_kid', findings('could_not_be_checked', 'unknown', 'could_not_be_checked'), { alg: 'RS256' }));
add('kid-of-ed25519-key-as-rs256', 'A kid that exists only as a sandbox Ed25519 key, named by an RS256 header: the key is never used as an RSA key.',
  { certificate: certificate(current, { header: { kid: sandbox.kid } }), jwks: 'mixed' },
  expected('unknown_kid', findings('could_not_be_checked', 'unknown', 'could_not_be_checked'), { alg: 'RS256' }));
add('kid-of-rsa-key-as-eddsa', 'An RSA key presented as EdDSA, in a sandbox certificate.',
  { certificate: certificate(sandbox, { claims: { is_sandbox: true }, header: { kid: current.kid } }), jwks: 'mixed', allow_sandbox: true },
  expected('unknown_kid', findings('could_not_be_checked', 'unknown', 'could_not_be_checked'), { alg: 'EdDSA', is_sandbox: true }));
add('key-alg-member-differs', 'The key says it is for another algorithm.',
  { certificate: certificate(current), jwks: 'wrong-key-alg' },
  expected('unknown_kid', findings('could_not_be_checked', 'unknown', 'could_not_be_checked'), { alg: 'RS256' }));
add('key-rsa-1024', 'A validly signed certificate under a 1024-bit key: the key is not usable.',
  { certificate: certificate(small), jwks: 'weak' },
  expected('unknown_kid', findings('could_not_be_checked', 'unknown', 'could_not_be_checked'), { alg: 'RS256' }));
{
  // With e = 1 the "signature" is just the padded message, so anyone can make one.
  const key = { kid: 'synthetic-test-rsa-e1', jwk: current.jwk };
  const body = claimsFor(key);
  const headerSegment = b64u(JSON.stringify(headerFor(key)));
  const digest = createHash('sha256').update(`${headerSegment}.${b64u(canon(body))}`).digest();
  const info = Buffer.concat([Buffer.from('3031300d060960864801650304020105000420', 'hex'), digest]);
  const block = Buffer.concat([Buffer.from([0, 1]), Buffer.alloc(256 - info.length - 3, 0xff), Buffer.from([0]), info]);
  add('key-rsa-exponent-one', 'A key with public exponent 1 would accept the padded message as its own signature.',
    { certificate: { ...body, signature: `${headerSegment}..${b64u(block)}` }, jwks: 'weak' },
    expected('unknown_kid', findings('could_not_be_checked', 'unknown', 'could_not_be_checked'), { alg: 'RS256' }));
}
add('key-ed25519-short', 'An Ed25519 key of 31 bytes.',
  { certificate: certificate(sandbox, { claims: { is_sandbox: true }, header: { kid: 'synthetic-test-ed25519-short' } }), jwks: 'bad-ed25519-keys', allow_sandbox: true },
  expected('unknown_kid', findings('could_not_be_checked', 'unknown', 'could_not_be_checked'), { alg: 'EdDSA', is_sandbox: true }));
add('key-ed25519-noncanonical', 'An Ed25519 key that is not the canonical encoding of a point.',
  { certificate: certificate(sandbox, { claims: { is_sandbox: true }, header: { kid: 'synthetic-test-ed25519-noncanonical' } }), jwks: 'bad-ed25519-keys', allow_sandbox: true },
  expected('unknown_kid', findings('could_not_be_checked', 'unknown', 'could_not_be_checked'), { alg: 'EdDSA', is_sandbox: true }));

// --- Sandbox and production must not cross ----------------------------------------------------------
const sandboxClaims = { is_sandbox: true, jwks_uri: 'https://www.apier.no/.well-known/sandbox-jwks.json' };
const sandboxRead = (reason) => expected(reason, findings('matches', 'sandbox', 'sandbox'), read(sandbox, { is_sandbox: true }));
add('sandbox-synthetic-allowed', 'A sandbox-style EdDSA certificate under a key marked apier_sandbox.',
  { certificate: certificate(sandbox, { claims: sandboxClaims }), jwks: 'mixed', allow_sandbox: true }, sandboxRead(null));
add('sandbox-synthetic-not-allowed', 'The same certificate when sandbox certificates are refused.',
  { certificate: certificate(sandbox, { claims: sandboxClaims }), jwks: 'mixed' }, sandboxRead('sandbox_not_allowed'));
add('sandbox-key-without-claim', 'Signed with a sandbox key but without is_sandbox: it claims to be production.',
  { certificate: certificate(sandbox), jwks: 'mixed', allow_sandbox: true }, sandboxRead('alg_not_allowed'));
add('sandbox-key-without-claim-not-allowed', 'The same, in the default mode.',
  { certificate: certificate(sandbox), jwks: 'mixed' }, sandboxRead('alg_not_allowed'));
add('rsa-key-marked-sandbox', 'An RSA key carrying apier_sandbox is a sandbox key and never checks a production certificate.',
  { certificate: certificate(rsaMarkedSandbox), jwks: 'mixed' },
  expected('unknown_kid', findings('matches', 'sandbox', 'sandbox'), read(rsaMarkedSandbox, { is_sandbox: true })));
add('sandbox-claim-under-production-key', 'is_sandbox: true signed with a production RSA key, sandbox allowed.',
  { certificate: certificate(current, { claims: { is_sandbox: true } }), allow_sandbox: true },
  expected('alg_not_allowed', findings('matches', 'current', 'production'), read(current, { is_sandbox: true })));
add('sandbox-claim-under-production-key-not-allowed', 'The same, in the default mode.',
  { certificate: certificate(current, { claims: { is_sandbox: true } }) },
  expected('sandbox_not_allowed', findings('matches', 'current', 'production'), read(current, { is_sandbox: true })));
add('sandbox-claim-under-unmarked-ed25519-key', 'A sandbox certificate under an Ed25519 key that is not a sandbox key.',
  { certificate: certificate(edUnmarked, { claims: { is_sandbox: true } }), jwks: 'mixed', allow_sandbox: true },
  expected('unknown_kid', findings('matches', 'current', 'production'), read(edUnmarked, { is_sandbox: true })));
add('sandbox-issuer-not-checked', 'The issuer is not checked on a sandbox certificate.',
  { certificate: certificate(sandbox, { claims: { ...sandboxClaims, issuer: 'https://sandbox.apier.example' } }), jwks: 'mixed', allow_sandbox: true },
  sandboxRead(null));

// --- Signatures built to be refused -----------------------------------------------------------------
const bad = (key, rest) => expected('signature_invalid', findings('does_not_match', 'current', 'could_not_be_checked'), unread(key, rest));
const badSandbox = expected('signature_invalid', findings('does_not_match', 'sandbox', 'sandbox'), unread(sandbox, { is_sandbox: true }));
{
  const body = claimsFor(current);
  add('payload-not-canonical', 'Signed over the JSON text in insertion order instead of the canonical form.',
    { certificate: { ...body, signature: detached(current, headerFor(current), JSON.stringify(body)) } }, bad(current));
  add('payload-pretty-printed', 'Signed over pretty-printed JSON.',
    { certificate: { ...body, signature: detached(current, headerFor(current), JSON.stringify(body, null, 2)) } }, bad(current));
}
add('signature-for-another-certificate', 'A valid signature moved from another certificate.',
  { certificate: { ...certificate(current), signature: certificate(current, { claims: { rulebook_version: '2.0.0' } }).signature } }, bad(current));
add('rsa-signature-one-byte-short', 'An RSA signature one byte short.',
  { certificate: certificate(current, { mutate: (s) => s.subarray(1) }) }, bad(current));
add('rsa-signature-one-byte-long', 'An RSA signature with a leading zero byte.',
  { certificate: certificate(current, { mutate: (s) => Buffer.concat([Buffer.from([0]), s]) }) }, bad(current));
add('rsa-signature-plus-modulus', 'The signature value plus the modulus: the same residue, not below n.',
  { certificate: certificate(current, { mutate: (s) => {
    const n = BigInt(`0x${Buffer.from(current.jwk.n, 'base64url').toString('hex')}`);
    return Buffer.from((BigInt(`0x${s.toString('hex')}`) + n).toString(16).padStart(514, '0'), 'hex');
  } }) }, bad(current));
add('rsa-signature-bit-flipped', 'One bit of the RSA signature flipped.',
  { certificate: certificate(current, { mutate: (s) => { const c = Buffer.from(s); c[100] ^= 1; return c; } }) }, bad(current));
add('rsa-signature-zero', 'An all-zero signature.',
  { certificate: certificate(current, { mutate: (s) => Buffer.alloc(s.length) }) }, bad(current));
{
  // Bleichenbacher's 2006 forgery for exponent 3: a block that starts like a valid encoding and ends
  // in garbage, whose cube root is taken as the signature. A verifier that parses the padding instead
  // of comparing the whole block accepts it without ever seeing the private key.
  const body = claimsFor(cube);
  const headerSegment = b64u(JSON.stringify(headerFor(cube)));
  const digest = createHash('sha256').update(`${headerSegment}.${b64u(canon(body))}`).digest();
  const prefix = Buffer.concat([Buffer.from([0, 1, 0xff, 0]), Buffer.from('3031300d060960864801650304020105000420', 'hex'), digest]);
  const target = BigInt(`0x${Buffer.concat([prefix, Buffer.alloc(256 - prefix.length)]).toString('hex')}`);
  let root = 1n << 683n;
  for (;;) {
    const next = (2n * root + target / (root * root)) / 3n;
    if (next >= root) break;
    root = next;
  }
  if (root ** 3n < target) root += 1n;
  const forged = Buffer.from(root.toString(16).padStart(512, '0'), 'hex');
  if (!Buffer.from((root ** 3n).toString(16).padStart(512, '0'), 'hex').subarray(0, prefix.length).equals(prefix)) {
    throw new Error('the forged block does not start with the expected prefix');
  }
  add('rsa-exponent-three-forgery', 'A forged signature for an exponent-3 key that only a loose padding check accepts.',
    { certificate: { ...body, signature: `${headerSegment}..${b64u(forged)}` }, jwks: 'weak' }, bad(cube));
}
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const sandboxCertificate = (mutate) => certificate(sandbox, { claims: sandboxClaims, mutate });
add('ed25519-s-plus-l', 'The S half of the signature plus the group order: the same point, not the canonical S.',
  { certificate: sandboxCertificate((s) => {
    const sValue = BigInt(`0x${Buffer.from(s.subarray(32)).reverse().toString('hex')}`) + L;
    return Buffer.concat([s.subarray(0, 32), Buffer.from(sValue.toString(16).padStart(64, '0'), 'hex').reverse()]);
  }), jwks: 'mixed', allow_sandbox: true }, badSandbox);
add('ed25519-r-bit-flipped', 'One bit of R flipped.',
  { certificate: sandboxCertificate((s) => { const c = Buffer.from(s); c[3] ^= 4; return c; }), jwks: 'mixed', allow_sandbox: true }, badSandbox);
add('ed25519-s-bit-flipped', 'One bit of S flipped.',
  { certificate: sandboxCertificate((s) => { const c = Buffer.from(s); c[40] ^= 1; return c; }), jwks: 'mixed', allow_sandbox: true }, badSandbox);
add('ed25519-signature-63-bytes', 'A 63-byte signature.',
  { certificate: sandboxCertificate((s) => s.subarray(0, 63)), jwks: 'mixed', allow_sandbox: true }, badSandbox);
add('ed25519-signature-65-bytes', 'A 65-byte signature.',
  { certificate: sandboxCertificate((s) => Buffer.concat([s, Buffer.from([0])])), jwks: 'mixed', allow_sandbox: true }, badSandbox);
add('ed25519-r-sign-bit-flipped', 'The sign bit of R flipped.',
  { certificate: sandboxCertificate((s) => { const c = Buffer.from(s); c[31] ^= 0x80; return c; }), jwks: 'mixed', allow_sandbox: true }, badSandbox);
add('ed25519-s-high-bit-set', 'The top bit of S set.',
  { certificate: sandboxCertificate((s) => { const c = Buffer.from(s); c[63] |= 0x80; return c; }), jwks: 'mixed', allow_sandbox: true }, badSandbox);

// --- Canonical JSON inside a signed certificate ------------------------------------------------------
{
  // Written as text so each number keeps its spelling until the verifier parses it.
  const inner = '{"result":{"org_number":"999000001","name":"Synthetisk Prøve AS","10":"ten","9":"nine","-1":"minus","01":"leading zero",'
    + '"amount":100.0,"big":1e21,"tiny":1e-7,"small":0.000001,"negative_zero":-0.0,"beyond_2_53":12345678901234567890,"exponent":1.5E+3,'
    + '"third":0.3333333333333333,"max":1.7976931348623157e308,"min":5e-324,"control":"line\\nbreak\\u0001\\u007f","quote":"say \\"hei\\" \\\\ \\/",'
    + '"astral":"\\ud83d\\ude00","€":1.5,"æøå":["Brønnøysund",null,true,false,[],{}],"\\ud83d\\ude00":"astral key","\\uffee":"bmp key after surrogates"},'
    + `"issuer":"https://www.apier.no","issued_at":"${ISSUED}","kid":"${current.kid}","jwks_uri":"https://www.apier.no/.well-known/jwks.json",`
    + '"rulebook_version":"1.0.0","freshness":{"retrieved_at":"2026-11-20T08:00:00.000Z","served_from":"live","stale":false}}';
  const signature = detached(current, headerFor(current), canon(JSON.parse(inner)));
  add('canonical-number-and-key-forms', 'Numbers, escapes and key orders that a careless canonicaliser gets wrong.',
    { certificate_text: `{"signature":${JSON.stringify(signature)},${inner.slice(1)}` },
    expected(null, findings('matches', 'current', 'production'), read(current)));
}

// --- Key history ------------------------------------------------------------------------------------
const historyEntries = [
  { alg: 'RS256', compromised_at: null, environment: 'production', jwk_thumbprint: thumbprint(current.jwk), jwks_uri: 'https://www.apier.no/.well-known/jwks.json', kid: current.kid, state: 'current', valid_from: '2026-09-01', valid_to: null },
  { alg: 'RS256', compromised_at: null, environment: 'production', jwk_thumbprint: thumbprint(retired.jwk), jwks_uri: 'https://www.apier.no/.well-known/jwks.json', kid: retired.kid, state: 'retired', valid_from: null, valid_to: RETIRED_AT },
  { alg: 'RS256', compromised_at: COMPROMISED_AT, environment: 'production', jwk_thumbprint: thumbprint(compromised.jwk), jwks_uri: 'https://www.apier.no/.well-known/jwks.json', kid: compromised.kid, state: 'compromised', valid_from: '2026-07-01', valid_to: '2026-09-01' },
];
function history(entries, { key = current, typ = HISTORY_TYP } = {}) {
  const document = { history_version: '1', issued_at: '2026-11-26T00:00:00Z', keys: entries };
  return { ...document, signature: detached(key, { alg: 'RS256', kid: key.kid, typ }, canon(document)) };
}
const signedHistory = history(historyEntries);
const key_histories = {
  signed: signedHistory,
  altered: { ...signedHistory, keys: historyEntries.map((e) => ({ ...e, state: 'current', compromised_at: null })) },
  'wrong-typ': history(historyEntries, { typ: CERT_TYP }),
  'signed-by-key-not-in-set': history(historyEntries, { key: small }),
  'other-thumbprints': history(historyEntries.map((e) => ({ ...e, jwk_thumbprint: thumbprint(stranger.jwk) }))),
  unsigned: { history_version: '1', issued_at: '2026-11-26T00:00:00Z', keys: historyEntries, signature: null },
};
const early = { claims: { issued_at: '2026-03-01T10:00:00+01:00' } };
const earlyRead = (key) => read(key, { issued_at: '2026-03-01T10:00:00+01:00' });
const withHistory = (name, note, key, historyName, jwks, expect) =>
  add(name, note, { certificate: certificate(key, early), jwks, key_history: historyName }, expect);
withHistory('history-none-unmarked-set', 'Without a key history an unmarked key set shows the leaked key as current.',
  compromised, null, 'production-unmarked', expected(null, findings('matches', 'current', 'production'), earlyRead(compromised)));
withHistory('history-marks-compromised', 'A signed key history adds the compromise mark a saved key set is missing.',
  compromised, 'signed', 'production-unmarked', expected('compromised_key', findings('matches', 'revoked', 'production'), earlyRead(compromised)));
withHistory('history-marks-retired', 'A signed key history adds the retirement mark.',
  retired, 'signed', 'production-unmarked', expected(null, findings('matches', 'retired', 'production'), earlyRead(retired)));
withHistory('history-current-key-untouched', 'The current key stays current.',
  current, 'signed', 'production-unmarked', expected(null, findings('matches', 'current', 'production'), earlyRead(current)));
withHistory('history-altered-is-ignored', 'A key history changed after signing is ignored.',
  compromised, 'altered', 'production-unmarked', expected(null, findings('matches', 'current', 'production'), earlyRead(compromised)));
withHistory('history-wrong-typ-is-ignored', 'A key history signed under the certificate typ is ignored.',
  compromised, 'wrong-typ', 'production-unmarked', expected(null, findings('matches', 'current', 'production'), earlyRead(compromised)));
withHistory('history-unknown-signer-is-ignored', 'A key history signed by a key that is not in the key set is ignored.',
  compromised, 'signed-by-key-not-in-set', 'production-unmarked', expected(null, findings('matches', 'current', 'production'), earlyRead(compromised)));
withHistory('history-unsigned-is-ignored', 'A key history without a signature is ignored.',
  compromised, 'unsigned', 'production-unmarked', expected(null, findings('matches', 'current', 'production'), earlyRead(compromised)));
withHistory('history-signed-by-compromised-key-is-ignored', 'A key history signed by a key the key set marks compromised is ignored.',
  retired, 'signed', 'signer-compromised', expected(null, findings('matches', 'current', 'production'), earlyRead(retired)));
withHistory('history-other-thumbprint-not-applied', 'Marks are applied by fingerprint: an entry for other key material with the same kid is not this key.',
  compromised, 'other-thumbprints', 'production-unmarked', expected(null, findings('matches', 'current', 'production'), earlyRead(compromised)));
withHistory('history-never-removes-a-mark', 'A key history cannot clear a mark the key set already carries.',
  compromised, 'signed', 'production', expected('compromised_key', findings('matches', 'revoked', 'production'), earlyRead(compromised)));

const out = {
  note: 'Generated by test/make-rs256-vector.mjs. Every key here is a SYNTHETIC TEST KEY made by that script, not an Apier key, and every certificate is made-up test data. Do not edit by hand.',
  keysets,
  key_histories,
  cases,
};
writeFileSync(new URL('./vectors/synthetic-cases.json', import.meta.url), `${JSON.stringify(out, null, 2)}\n`);
console.log(`wrote ${cases.length} cases`);
