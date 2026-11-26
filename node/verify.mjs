// Offline check of an Apier certificate. The caller supplies the key set (JWKS) to check against.
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
// Objects and arrays nested deeper than this are refused, so both implementations stop at the same
// place instead of wherever a runtime's stack happens to end. Real certificates nest about 5 deep.
export const MAX_DEPTH = 64;

const P25519 = (1n << 255n) - 19n;
const INDEX_KEY = /^(0|[1-9][0-9]*)$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
// Strict UTF-8 that keeps a byte order mark, so a header that starts with one is not valid JSON.
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
// Read a member only when the object itself has it, so nothing is ever taken from a prototype.
const own = (object, key) => (Object.hasOwn(object, key) ? object[key] : undefined);
const isIndexKey = (k) => INDEX_KEY.test(k) && Number(k) < 4294967295;
const isSandboxKey = (jwk) => own(jwk, 'kid') === SANDBOX_KID || Object.hasOwn(jwk, 'apier_sandbox');
const isRetired = (jwk) => ![undefined, null, ''].includes(own(jwk, 'apier_retired_at'));
// The member's presence is the mark. Its value is not read, so null or an unreadable date counts too.
const isCompromised = (jwk) => Object.hasOwn(jwk, 'apier_compromised_at');
// A stack overflow says nothing about the input, so it is passed on instead of being read as a refusal.
const rethrowOverflow = (error) => {
  if (error instanceof RangeError && /call stack/i.test(error.message)) throw error;
};

/**
 * Apier's canonical JSON: no whitespace; in every object the integer index keys first in numeric
 * order, then the other keys by UTF-16 code units; strings and numbers as JSON.stringify prints
 * them. Throws on anything that is not a finite JSON value or is nested deeper than MAX_DEPTH.
 */
export function canonicalJson(value, depth = 0) {
  if (value === null || typeof value === 'boolean') return String(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('not a finite number');
    return JSON.stringify(value);
  }
  if (depth >= MAX_DEPTH) throw new TypeError('nested too deep');
  if (Array.isArray(value)) return `[${Array.from(value, (item) => canonicalJson(item, depth + 1)).join(',')}]`;
  const proto = typeof value === 'object' ? Object.getPrototypeOf(value) : undefined;
  if (proto !== Object.prototype && proto !== null) throw new TypeError('not a JSON value');
  const keys = Object.keys(value);
  const ordered = [
    ...keys.filter(isIndexKey).sort((a, b) => Number(a) - Number(b)),
    ...keys.filter((k) => !isIndexKey(k)).sort(), // the default sort compares UTF-16 code units
  ];
  return `{${ordered.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k], depth + 1)}`).join(',')}}`;
}

// False when brackets outside strings open more than MAX_DEPTH levels. Counted on the text, before
// any parser runs, so the answer does not depend on how much stack is left.
function withinDepth(text) {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (c === '\\') i++;
      else if (c === '"') inString = false;
    } else if (c === '"') inString = true;
    else if (c === '[' || c === '{') {
      if (++depth > MAX_DEPTH) return false;
    } else if (c === ']' || c === '}') depth--;
  }
  return true;
}

/**
 * Parse JSON text, refusing a repeated key in one object and nesting deeper than MAX_DEPTH.
 * JSON.parse keeps the last of two equal keys while other parsers keep the first, so one file could
 * be read as two different certificates. JSON.parse checks the grammar here and reads each string
 * and number on its own; the objects and arrays are built by this function, so the result does not
 * depend on how an engine caches object keys. (Node 24.11 was seen to read an escaped key as a lone
 * backslash after it had parsed an object with the same first key and a lone backslash as its second.)
 */
export function parseJsonStrict(text) {
  if (typeof text !== 'string') throw new TypeError('JSON text must be a string');
  if (!withinDepth(text)) throw new SyntaxError('nested too deep');
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
  const [kty, crv, n, e, x] = ['kty', 'crv', 'n', 'e', 'x'].map((member) => own(jwk, member));
  let members = null;
  if (kty === 'RSA' && typeof n === 'string' && typeof e === 'string') members = { e, kty, n };
  else if (kty === 'OKP' && crv === 'Ed25519' && typeof x === 'string') members = { crv, kty, x };
  return members === null ? null : createHash('sha256').update(JSON.stringify(members)).digest('base64url');
}

// The key type must fit the algorithm, so an Ed25519 key is never used as RS256 or the reverse.
const keyFits = (jwk, alg) =>
  (!Object.hasOwn(jwk, 'alg') || jwk.alg === alg) &&
  (alg === 'RS256' ? own(jwk, 'kty') === 'RSA' : own(jwk, 'kty') === 'OKP' && own(jwk, 'crv') === 'Ed25519');

const ed25519Y = (bytes) => BigInt(`0x${Buffer.from(bytes).reverse().toString('hex')}`) & ((1n << 255n) - 1n);
// The y coordinates of the eight points of small order. Under such a key anyone can make a signature.
const SMALL_ORDER_Y = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
].map((hex) => ed25519Y(Buffer.from(hex, 'hex')));

// A usable public key, or null. Both implementations apply the same rules here, so neither depends
// on what its crypto library happens to tolerate.
function importKey(jwk, alg) {
  try {
    if (alg === 'RS256') {
      const n = decodeBase64url(own(jwk, 'n'));
      const e = decodeBase64url(own(jwk, 'e'));
      // Minimal encodings, an odd modulus of 2048 to 16384 bits, an odd exponent from 3 to below 2^64.
      if (n === null || e === null || n[0] === 0 || e[0] === 0 || e.length > 8) return null;
      const bits = n.length * 8 - Math.clz32(n[0]) + 24;
      if (bits < 2048 || bits > 16384 || n[n.length - 1] % 2 === 0) return null;
      if (e[e.length - 1] % 2 === 0 || (e.length === 1 && e[0] < 3)) return null;
      return createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' });
    }
    const x = decodeBase64url(own(jwk, 'x'));
    if (x === null || x.length !== 32) return null;
    const y = ed25519Y(x);
    if (y >= P25519 || SMALL_ORDER_Y.includes(y)) return null; // not canonical, or of small order
    return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' });
  } catch (error) {
    rethrowOverflow(error);
    return null;
  }
}

function signatureMatches(alg, key, signingInput, signature) {
  try {
    if (alg === 'RS256') return cryptoVerify('sha256', signingInput, key, signature);
    return signature.length === 64 && cryptoVerify(null, signingInput, key, signature);
  } catch (error) {
    rethrowOverflow(error);
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
  } catch (error) {
    rethrowOverflow(error);
    return null;
  }
}

// The signed bytes are `<header segment>.<base64url of the canonical JSON without "signature">`.
const signingInput = (headerSegment, canonical) =>
  Buffer.from(`${headerSegment}.${Buffer.from(canonical, 'utf8').toString('base64url')}`, 'ascii');

const readKeys = (jwks) => {
  const keys = isObject(jwks) ? own(jwks, 'keys') : null;
  return Array.isArray(keys) ? keys.filter(isObject) : [];
};

/**
 * True when the key history document is signed (RS256, typ apier-key-history+jws) by a key in
 * `jwks` that is neither a sandbox key nor marked compromised. Only then may it be used.
 */
export function verifyKeyHistory(document, jwks) {
  try {
    if (!isObject(document) || own(document, 'history_version') !== '1' || !Array.isArray(own(document, 'keys'))) return false;
    const { signature, ...unsigned } = document;
    const jws = parseDetachedJws(signature);
    if (jws === null) return false;
    const [alg, kid, typ] = ['alg', 'kid', 'typ'].map((member) => own(jws.header, member));
    if (alg !== 'RS256' || typ !== KEY_HISTORY_TYP || typeof kid !== 'string' || kid === '' || Object.hasOwn(jws.header, 'crit')) return false;
    const jwk = readKeys(jwks).find((k) => own(k, 'kid') === kid && keyFits(k, 'RS256'));
    if (jwk === undefined || isSandboxKey(jwk) || isCompromised(jwk)) return false;
    const key = importKey(jwk, 'RS256');
    return key !== null && signatureMatches('RS256', key, signingInput(jws.headerSegment, canonicalJson(unsigned)), jws.signature);
  } catch (error) {
    rethrowOverflow(error);
    return false;
  }
}

// A verified key history only ever adds marks, and only to the key whose thumbprint an entry lists.
// Every matching entry counts, and anything but a plain current or retired entry marks the key
// compromised, so a repeated or oddly shaped entry cannot hide a compromise.
function withKeyHistoryMarks(keys, document) {
  const entries = own(document, 'keys').filter(
    (e) => isObject(e) && own(e, 'environment') === 'production' && typeof own(e, 'kid') === 'string' && typeof own(e, 'jwk_thumbprint') === 'string',
  );
  return keys.map((key) => {
    if (isSandboxKey(key)) return key;
    const thumbprint = jwkThumbprint(key);
    const marked = { ...key };
    for (const entry of entries) {
      if (own(entry, 'kid') !== own(key, 'kid') || own(entry, 'jwk_thumbprint') !== thumbprint) continue;
      const [state, validTo, compromisedAt] = ['state', 'valid_to', 'compromised_at'].map((member) => own(entry, member));
      if (state !== 'current' && !isRetired(marked) && typeof validTo === 'string') marked.apier_retired_at = validTo;
      const leaked = (state !== 'current' && state !== 'retired') || (compromisedAt !== undefined && compromisedAt !== null);
      if (leaked && !isCompromised(marked)) marked.apier_compromised_at = typeof compromisedAt === 'string' ? compromisedAt : '';
    }
    return marked;
  });
}

/**
 * Check one certificate (the `data` object of a `?certificate=true` response). Pure: it never
 * fetches. Returns separate findings and the first failing `reason`, never one overall verdict.
 * Options: { jwks, keyHistory = null, allowSandbox = false, now }. `now` is accepted for callers
 * that pass a clock and is not used, because no rule here depends on the time.
 */
export async function checkCertificate(cert, options) {
  const { jwks, keyHistory = null, allowSandbox = false } = options ?? {};
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

  // `claims` is a private copy made from the canonical bytes. Everything read below comes from it,
  // so what is reported is exactly what the signature is checked over, whatever the caller passed.
  let canonical;
  let claims;
  let jwsText;
  try {
    if (!isObject(cert)) return finish('malformed_certificate');
    const { signature, ...unsigned } = cert;
    canonical = canonicalJson(unsigned);
    claims = parseJsonStrict(canonical);
    jwsText = signature;
  } catch {
    return finish('malformed_certificate');
  }
  const [sandboxClaim, issuer, issuedAt, freshness] = ['is_sandbox', 'issuer', 'issued_at', 'freshness'].map((member) => own(claims, member));
  if (sandboxClaim !== undefined && typeof sandboxClaim !== 'boolean') return finish('malformed_certificate');
  const sandboxCertificate = sandboxClaim === true;
  const issuerIsProduction = PRODUCTION_ISSUERS.includes(issuer);
  result.isSandbox = sandboxCertificate;
  if (typeof jwsText !== 'string' || jwsText === '') return finish('missing_signature');
  if (sandboxCertificate && allowSandbox !== true) failed.add('sandbox_not_allowed');
  if (!sandboxCertificate && !issuerIsProduction) failed.add('wrong_issuer');

  const jws = parseDetachedJws(jwsText);
  if (jws === null) return finish('bad_header');
  const [headerAlg, headerKid, typ] = ['alg', 'kid', 'typ'].map((member) => own(jws.header, member));
  const alg = typeof headerAlg === 'string' ? headerAlg : null;
  const kid = typeof headerKid === 'string' && headerKid !== '' ? headerKid : null;
  findings.format_version = typ === CERTIFICATE_TYP ? 'recognised' : 'not_recognised';
  if (alg === null || kid === null || Object.hasOwn(jws.header, 'crit')) failed.add('bad_header');
  const knownAlg = alg === 'RS256' || alg === 'EdDSA';
  if (knownAlg) result.alg = alg;
  if (typ !== CERTIFICATE_TYP) failed.add('wrong_typ');
  // Production certificates are RS256 and sandbox certificates EdDSA. `none` is never accepted.
  if (alg !== (sandboxCertificate ? 'EdDSA' : 'RS256')) failed.add('alg_not_allowed');
  if (typ !== CERTIFICATE_TYP || !knownAlg) {
    // No key lookup and no signature check in this case. A header naming the sandbox key is still labelled.
    if (kid === SANDBOX_KID) findings.signing_key = findings.environment = 'sandbox';
    return finish();
  }

  // Keys come only from the key set the caller passed, never from the certificate's own jwks_uri.
  let keys = readKeys(jwks);
  if (keyHistory !== null && keyHistory !== undefined && verifyKeyHistory(keyHistory, { keys })) keys = withKeyHistoryMarks(keys, keyHistory);
  const jwk = keys.find((k) => kid !== null && own(k, 'kid') === kid && keyFits(k, alg));
  const key = jwk === undefined ? null : importKey(jwk, alg);
  if (key === null) {
    findings.signing_key = 'unknown';
    if (kid === SANDBOX_KID) findings.environment = 'sandbox';
    return finish('unknown_kid');
  }
  result.kid = kid;
  // The same key can be listed twice, for example when a cached key set and a fresh one are merged.
  // A mark on any entry with this kid and this key material counts.
  const thumbprint = jwkThumbprint(jwk);
  const entries = keys.filter((k) => own(k, 'kid') === kid && jwkThumbprint(k) === thumbprint);
  const sandboxKey = entries.some(isSandboxKey);
  const compromised = !sandboxKey && entries.some(isCompromised);
  findings.signing_key = sandboxKey ? 'sandbox' : compromised ? 'revoked' : entries.some(isRetired) ? 'retired' : 'current';
  // A sandbox certificate is only ever checked against a sandbox key, a production one never.
  if (sandboxKey !== sandboxCertificate) failed.add('unknown_kid');
  // A leaked key can sign any date, so the certificate's own issued_at proves nothing: always refused.
  if (compromised) failed.add('compromised_key');

  const matches = signatureMatches(alg, key, signingInput(jws.headerSegment, canonical), jws.signature);
  findings.signature = matches ? 'matches' : 'does_not_match';
  if (!matches) failed.add('signature_invalid');
  if (sandboxKey) findings.environment = 'sandbox';
  else if (matches) findings.environment = issuerIsProduction ? 'production' : 'issuer_not_recognised';
  if (matches) {
    // Read from the certificate only once the signature covers it.
    result.issuedAt = typeof issuedAt === 'string' ? issuedAt : null;
    const stale = isObject(freshness) ? own(freshness, 'stale') : null;
    result.stale = typeof stale === 'boolean' ? stale : null;
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
  } catch (error) {
    rethrowOverflow(error);
    value = undefined;
  }
  if (isObject(value) && !Object.hasOwn(value, 'signature') && isObject(own(value, 'data'))) value = value.data;
  return checkCertificate(value, options);
}
