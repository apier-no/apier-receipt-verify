// Offline check of an Apier certificate against a JSON Web Key Set the caller supplies.
// Node 20+, node:crypto only. Nothing here opens a network connection or reads a file.
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';

export const CERTIFICATE_TYP = 'apier-verify-cert+jws';
export const KEY_HISTORY_TYP = 'apier-key-history+jws';
export const SANDBOX_KID = 'apier-sandbox-cert-1';
// The apex is carried by older production certificates.
export const PRODUCTION_ISSUERS = ['https://www.apier.no', 'https://apier.no'];
// `reason` is the first of these that applies, in this order.
export const REASONS = [
  'malformed_certificate', 'missing_signature', 'sandbox_not_allowed', 'wrong_issuer', 'bad_header',
  'wrong_typ', 'alg_not_allowed', 'unknown_kid', 'compromised_key', 'signature_invalid',
];

const P25519 = (1n << 255n) - 19n;
const INDEX_KEY = /^(0|[1-9][0-9]*)$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const utf8 = new TextDecoder('utf-8', { fatal: true });

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isIndexKey = (k) => INDEX_KEY.test(k) && Number(k) < 4294967295;
const isSandboxKey = (jwk) => jwk.kid === SANDBOX_KID || 'apier_sandbox' in jwk;
const isRetired = (jwk) => jwk.apier_retired_at !== undefined && jwk.apier_retired_at !== null && jwk.apier_retired_at !== '';
// Any `apier_compromised_at` member marks the key, whether or not its value can be read.
const isCompromised = (jwk) => 'apier_compromised_at' in jwk;

/**
 * Apier's canonical JSON: no whitespace; in every object the integer index keys first in numeric
 * order, then the other keys by UTF-16 code units; strings and numbers as JSON.stringify prints
 * them. Throws on anything that is not a finite JSON value.
 */
export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean') return String(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('not a finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${Array.from(value, canonicalJson).join(',')}]`;
  const proto = typeof value === 'object' ? Object.getPrototypeOf(value) : undefined;
  if (proto !== Object.prototype && proto !== null) throw new TypeError('not a JSON value');
  const keys = Object.keys(value);
  const ordered = [
    ...keys.filter(isIndexKey).sort((a, b) => Number(a) - Number(b)),
    ...keys.filter((k) => !isIndexKey(k)).sort(), // the default sort compares UTF-16 code units
  ];
  return `{${ordered.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

/**
 * Parse JSON text, refusing a repeated key in one object. JSON.parse keeps the last of two equal
 * keys while other parsers keep the first, so one file could be read as two different certificates.
 * JSON.parse checks the grammar here and reads each string and number on its own; the objects and
 * arrays are built by this function, so the result does not depend on how an engine caches object
 * keys. (Node 24.11 was seen to read an escaped key as a lone backslash after it had parsed an
 * object with the same first key and a lone backslash as its second.)
 */
export function parseJsonStrict(text) {
  JSON.parse(text); // throws on anything that is not JSON; its value is not used
  let i = 0;
  const skipSpace = () => {
    while (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r') i++;
  };
  const readString = () => {
    const start = i++;
    while (text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
    return JSON.parse(text.slice(start, ++i));
  };
  const readValue = () => {
    skipSpace();
    const start = i;
    if (text[i] === '"') return readString();
    if (text[i] === '[') {
      const array = [];
      for (i++, skipSpace(); text[i] !== ']'; skipSpace()) {
        array.push(readValue());
        skipSpace();
        if (text[i] === ',') i++;
      }
      i++;
      return array;
    }
    if (text[i] === '{') {
      const object = {};
      for (i++, skipSpace(); text[i] !== '}'; skipSpace()) {
        const key = readString();
        if (Object.hasOwn(object, key)) throw new SyntaxError('duplicate object key');
        skipSpace();
        i++; // the colon
        // defineProperty, so that a key named __proto__ is an ordinary member
        Object.defineProperty(object, key, { value: readValue(), enumerable: true, writable: true, configurable: true });
        skipSpace();
        if (text[i] === ',') i++;
      }
      i++;
      return object;
    }
    while (i < text.length && !' \t\n\r,]}'.includes(text[i])) i++;
    return JSON.parse(text.slice(start, i)); // a number, true, false or null
  };
  return readValue();
}

// Unpadded base64url in its one canonical spelling, or null.
function decodeBase64url(segment) {
  if (typeof segment !== 'string' || !BASE64URL.test(segment)) return null;
  const bytes = Buffer.from(segment, 'base64url');
  return bytes.toString('base64url') === segment ? bytes : null;
}

/** RFC 7638 SHA-256 thumbprint of an RSA or Ed25519 public JWK, base64url; null for any other key. */
export function jwkThumbprint(jwk) {
  let members = null;
  if (jwk.kty === 'RSA' && typeof jwk.n === 'string' && typeof jwk.e === 'string') {
    members = { e: jwk.e, kty: 'RSA', n: jwk.n };
  } else if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && typeof jwk.x === 'string') {
    members = { crv: 'Ed25519', kty: 'OKP', x: jwk.x };
  }
  return members === null ? null : createHash('sha256').update(JSON.stringify(members)).digest('base64url');
}

// The key type must fit the algorithm, so an Ed25519 key is never used as RS256 or the reverse.
const keyFits = (jwk, alg) =>
  (jwk.alg === undefined || jwk.alg === alg) &&
  (alg === 'RS256' ? jwk.kty === 'RSA' : jwk.kty === 'OKP' && jwk.crv === 'Ed25519');

function importKey(jwk, alg) {
  try {
    if (alg === 'RS256') {
      if (decodeBase64url(jwk.n) === null || decodeBase64url(jwk.e) === null) return null;
      const key = createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' });
      const { modulusLength, publicExponent } = key.asymmetricKeyDetails;
      return modulusLength >= 2048 && publicExponent >= 3n && publicExponent % 2n === 1n ? key : null;
    }
    const x = decodeBase64url(jwk.x);
    if (x === null || x.length !== 32) return null;
    const y = BigInt(`0x${Buffer.from(x).reverse().toString('hex')}`) & ((1n << 255n) - 1n);
    if (y >= P25519) return null; // not the canonical encoding of a point
    return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' });
  } catch {
    return null;
  }
}

function signatureMatches(alg, key, signingInput, signature) {
  try {
    if (alg === 'RS256') return cryptoVerify('sha256', signingInput, key, signature);
    return signature.length === 64 && cryptoVerify(null, signingInput, key, signature);
  } catch {
    return false;
  }
}

// A detached compact JWS, `header..signature`: { headerSegment, header, signature } or null.
function parseDetachedJws(jws) {
  const parts = typeof jws === 'string' ? jws.split('.') : [];
  if (parts.length !== 3 || parts[1] !== '') return null;
  const headerBytes = decodeBase64url(parts[0]);
  const signature = decodeBase64url(parts[2]);
  if (headerBytes === null || signature === null) return null;
  try {
    const header = parseJsonStrict(utf8.decode(headerBytes));
    return isObject(header) ? { headerSegment: parts[0], header, signature } : null;
  } catch {
    return null;
  }
}

// The signed bytes are `<header segment>.<base64url of the canonical JSON without "signature">`.
const payloadSegment = (unsigned) => Buffer.from(canonicalJson(unsigned), 'utf8').toString('base64url');
const signingInput = (headerSegment, payload) => Buffer.from(`${headerSegment}.${payload}`, 'ascii');

const readKeys = (jwks) => (isObject(jwks) && Array.isArray(jwks.keys) ? jwks.keys.filter(isObject) : []);

/**
 * True when the key history document is signed (RS256, typ apier-key-history+jws) by a key in
 * `jwks` that is neither a sandbox key nor marked compromised. Only then may it be used.
 */
export function verifyKeyHistory(document, jwks) {
  try {
    if (!isObject(document) || document.history_version !== '1' || !Array.isArray(document.keys)) return false;
    const { signature, ...unsigned } = document;
    const jws = parseDetachedJws(signature);
    if (jws === null || jws.header.alg !== 'RS256' || jws.header.typ !== KEY_HISTORY_TYP || 'crit' in jws.header) return false;
    const jwk = readKeys(jwks).find((k) => k.kid === jws.header.kid && keyFits(k, 'RS256'));
    if (jwk === undefined || isSandboxKey(jwk) || isCompromised(jwk)) return false;
    const key = importKey(jwk, 'RS256');
    return key !== null && signatureMatches('RS256', key, signingInput(jws.headerSegment, payloadSegment(unsigned)), jws.signature);
  } catch {
    return false;
  }
}

// A verified key history only ever adds marks, and only to the key whose thumbprint it lists.
function withKeyHistoryMarks(keys, document) {
  const entries = document.keys.filter(
    (e) => isObject(e) && typeof e.kid === 'string' && e.kid !== '' && e.environment === 'production' &&
      ['current', 'retired', 'compromised'].includes(e.state) && typeof e.alg === 'string' &&
      typeof e.jwk_thumbprint === 'string' && typeof e.jwks_uri === 'string',
  );
  return keys.map((key) => {
    if (isSandboxKey(key)) return key;
    const thumbprint = jwkThumbprint(key);
    const entry = entries.find((e) => e.kid === key.kid && e.jwk_thumbprint === thumbprint);
    if (entry === undefined || entry.state === 'current') return key;
    const marked = { ...key };
    if (!isRetired(key) && typeof entry.valid_to === 'string') marked.apier_retired_at = entry.valid_to;
    if (entry.state === 'compromised' && !isCompromised(key)) {
      marked.apier_compromised_at = typeof entry.compromised_at === 'string' ? entry.compromised_at : '';
    }
    return marked;
  });
}

/**
 * Check one certificate (the `data` object of a `?certificate=true` response). Pure: it never
 * fetches. Returns separate findings and the first failing `reason`, never one overall verdict.
 * `now` is accepted for callers that pass a clock; no rule here depends on the time.
 */
export async function checkCertificate(cert, { jwks, keyHistory = null, allowSandbox = false, now = new Date() } = {}) {
  const findings = {
    signature: 'could_not_be_checked',
    signing_key: 'could_not_be_checked',
    environment: 'could_not_be_checked',
    format_version: 'could_not_be_checked',
  };
  const result = { findings, reason: null, kid: null, alg: null, isSandbox: false, issuedAt: null, stale: null };
  const failed = new Set();
  const finish = (...reasons) => {
    for (const reason of reasons) failed.add(reason);
    result.reason = REASONS.find((reason) => failed.has(reason)) ?? null;
    // Nothing passes without a matching signature, whatever path led here.
    if (result.reason === null && findings.signature !== 'matches') result.reason = 'signature_invalid';
    result.isSandbox = result.isSandbox || findings.environment === 'sandbox';
    return result;
  };

  if (!isObject(cert) || ('is_sandbox' in cert && typeof cert.is_sandbox !== 'boolean')) return finish('malformed_certificate');
  const { signature: jwsText, ...claims } = cert;
  let payload;
  try {
    payload = payloadSegment(claims);
  } catch {
    return finish('malformed_certificate');
  }
  const sandboxCertificate = claims.is_sandbox === true;
  result.isSandbox = sandboxCertificate;
  if (typeof jwsText !== 'string' || jwsText === '') return finish('missing_signature');
  if (sandboxCertificate && !allowSandbox) failed.add('sandbox_not_allowed');
  if (!sandboxCertificate && !PRODUCTION_ISSUERS.includes(claims.issuer)) failed.add('wrong_issuer');

  const jws = parseDetachedJws(jwsText);
  if (jws === null) return finish('bad_header');
  const { header } = jws;
  findings.format_version = header.typ === CERTIFICATE_TYP ? 'recognised' : 'not_recognised';
  if (typeof header.alg !== 'string' || typeof header.kid !== 'string' || header.kid === '' || 'crit' in header) {
    return finish('bad_header');
  }
  const knownAlg = header.alg === 'RS256' || header.alg === 'EdDSA';
  if (knownAlg) result.alg = header.alg;
  if (header.typ !== CERTIFICATE_TYP) failed.add('wrong_typ');
  // Production certificates are RS256 and sandbox certificates EdDSA. `none` is never accepted.
  if (header.alg !== (sandboxCertificate ? 'EdDSA' : 'RS256')) failed.add('alg_not_allowed');
  if (header.typ !== CERTIFICATE_TYP || !knownAlg) {
    // The check stops before any key is looked up. A header naming the sandbox key is still labelled.
    if (header.kid === SANDBOX_KID) findings.signing_key = findings.environment = 'sandbox';
    return finish();
  }

  // Keys come only from the key set the caller passed, never from the certificate's own jwks_uri.
  let keys = readKeys(jwks);
  if (keyHistory !== null && verifyKeyHistory(keyHistory, { keys })) keys = withKeyHistoryMarks(keys, keyHistory);
  const jwk = keys.find((k) => k.kid === header.kid && keyFits(k, header.alg));
  const key = jwk === undefined ? null : importKey(jwk, header.alg);
  if (key === null) {
    findings.signing_key = 'unknown';
    if (header.kid === SANDBOX_KID) findings.environment = 'sandbox';
    return finish('unknown_kid');
  }
  result.kid = header.kid;
  const sandboxKey = isSandboxKey(jwk);
  const compromised = !sandboxKey && isCompromised(jwk);
  findings.signing_key = sandboxKey ? 'sandbox' : compromised ? 'revoked' : isRetired(jwk) ? 'retired' : 'current';
  // A sandbox certificate is only ever checked against a sandbox key, a production one never.
  if (sandboxKey !== sandboxCertificate) failed.add('unknown_kid');
  // A leaked key can sign any date, so the certificate's own issued_at proves nothing: always refused.
  if (compromised) failed.add('compromised_key');

  const matches = signatureMatches(header.alg, key, signingInput(jws.headerSegment, payload), jws.signature);
  findings.signature = matches ? 'matches' : 'does_not_match';
  if (!matches) failed.add('signature_invalid');
  if (sandboxKey) findings.environment = 'sandbox';
  else if (matches) findings.environment = PRODUCTION_ISSUERS.includes(claims.issuer) ? 'production' : 'issuer_not_recognised';
  if (matches) {
    // Read from the certificate only once the signature covers it.
    result.issuedAt = typeof claims.issued_at === 'string' ? claims.issued_at : null;
    result.stale = isObject(claims.freshness) && typeof claims.freshness.stale === 'boolean' ? claims.freshness.stale : null;
  }
  return finish();
}

/**
 * The same check from JSON text. Invalid JSON or a repeated object key gives
 * `malformed_certificate`. A full API response is accepted too: its `data` member is checked.
 */
export async function checkCertificateText(text, options) {
  let value;
  try {
    value = parseJsonStrict(text);
  } catch {
    value = undefined;
  }
  if (isObject(value) && !('signature' in value) && isObject(value.data)) value = value.data;
  return checkCertificate(value, options);
}
