// Builds test/vectors/sandbox-cases.json from the three real sandbox certificates in test/vectors/.
// Deterministic: the same input files always give the same output. No key is needed, because every
// tampered copy is meant to fail.
//
// The sandbox certificates are fictional fixture data served by Apier's sandbox and signed with the
// public sandbox key. Each expected result below is written by hand; nothing here calls the verifier.
import { readFileSync, writeFileSync } from 'node:fs';

// `node --test` runs every file under test/, so this script only writes when asked to.
if (!process.argv.includes('--write')) {
  console.log('Usage: node test/make-sandbox-cases.mjs --write   (replaces test/vectors/sandbox-cases.json)');
  process.exit(0);
}

const vectors = new URL('./vectors/', import.meta.url);
const read = (name) => JSON.parse(readFileSync(new URL(name, vectors), 'utf8'));
const clone = (value) => JSON.parse(JSON.stringify(value));
const encode = (text) => Buffer.from(text, 'utf8').toString('base64url');

const REAL = ['sandbox-verify-999000001', 'sandbox-authority-999000001', 'sandbox-verify-818444443'];
const base = read('sandbox-verify-999000001.json');
const KID = 'apier-sandbox-cert-1';
const ISSUED = '2026-01-01T09:00:00+01:00';

const findings = (signature, signing_key, environment, format_version = 'recognised') =>
  ({ signature, signing_key, environment, format_version });
const expected = (reason, found, rest = {}) =>
  ({ reason, findings: found, kid: null, alg: null, is_sandbox: true, issued_at: null, stale: null, ...rest });
const intact = (reason) =>
  expected(reason, findings('matches', 'sandbox', 'sandbox'), { kid: KID, alg: 'EdDSA', issued_at: ISSUED, stale: false });
const broken = (reason) =>
  expected(reason, findings('does_not_match', 'sandbox', 'sandbox'), { kid: KID, alg: 'EdDSA' });

// Re-encode the protected header with a change; the signature segment is kept.
function withHeader(certificate, change) {
  const [headerSegment, , signatureSegment] = certificate.signature.split('.');
  const header = change(JSON.parse(Buffer.from(headerSegment, 'base64url').toString('utf8')));
  const text = typeof header === 'string' ? header : JSON.stringify(header);
  return { ...certificate, signature: `${encode(text)}..${signatureSegment}` };
}
const edit = (change) => {
  const copy = clone(base);
  change(copy);
  return copy;
};
const [headerSegment, , signatureSegment] = base.signature.split('.');
const flipFirst = (segment) => (segment[0] === 'A' ? 'B' : 'A') + segment.slice(1);

const cases = [];
const add = (name, note, fields, expect) => cases.push({ name, note, jwks: 'sandbox', allow_sandbox: true, ...fields, expect });

for (const name of REAL) {
  add(name, 'Real sandbox certificate, sandbox allowed.', { certificate_file: `${name}.json` }, intact(null));
  add(`${name}-sandbox-not-allowed`, 'The same certificate when sandbox certificates are refused.',
    { certificate_file: `${name}.json`, allow_sandbox: false }, intact('sandbox_not_allowed'));
}
add('sandbox-against-empty-key-set', 'A sandbox certificate checked against a key set without the sandbox key.',
  { certificate_file: `${REAL[0]}.json`, jwks: 'empty', allow_sandbox: false },
  expected('sandbox_not_allowed', findings('could_not_be_checked', 'unknown', 'sandbox'), { alg: 'EdDSA' }));
add('sandbox-allowed-against-empty-key-set', 'Sandbox allowed, but the key set does not hold the key.',
  { certificate_file: `${REAL[0]}.json`, jwks: 'empty' },
  expected('unknown_kid', findings('could_not_be_checked', 'unknown', 'sandbox'), { alg: 'EdDSA' }));

// Tampered copies. The first five are the ones also sent to Apier's own receipt check
// (official-findings.json).
add('tampered-result-field', 'One field inside result changed.',
  { certificate: edit((c) => { c.result.verification_status = 'fail'; }) }, broken('signature_invalid'));
add('tampered-header-kid', 'Header kid swapped for one no key set holds.',
  { certificate: withHeader(base, (h) => ({ ...h, kid: 'apier-sandbox-cert-2' })) },
  expected('unknown_kid', findings('could_not_be_checked', 'unknown', 'could_not_be_checked'), { alg: 'EdDSA' }));
add('tampered-header-alg-none', 'Header alg changed to none.',
  { certificate: withHeader(base, (h) => ({ ...h, alg: 'none' })) },
  expected('alg_not_allowed', findings('could_not_be_checked', 'sandbox', 'sandbox')));
add('tampered-header-typ', 'Header typ changed.',
  { certificate: withHeader(base, (h) => ({ ...h, typ: 'JWT' })) },
  expected('wrong_typ', findings('could_not_be_checked', 'sandbox', 'sandbox', 'not_recognised'), { alg: 'EdDSA' }));
add('tampered-is-sandbox-removed', 'is_sandbox removed, so the certificate claims to be a production one.',
  { certificate: edit((c) => { delete c.is_sandbox; }) }, broken('alg_not_allowed'));

add('tampered-claims-kid', 'The kid member of the certificate (not the header) changed.',
  { certificate: edit((c) => { c.kid = 'apier-sandbox-cert-2'; }) }, broken('signature_invalid'));
add('tampered-issued-at', 'issued_at moved.',
  { certificate: edit((c) => { c.issued_at = '2026-06-01T09:00:00+02:00'; }) }, broken('signature_invalid'));
add('tampered-freshness-removed', 'The signed freshness member removed.',
  { certificate: edit((c) => { delete c.freshness; }) }, broken('signature_invalid'));
add('tampered-stale-flipped', 'freshness.stale flipped.',
  { certificate: edit((c) => { c.freshness.stale = true; }) }, broken('signature_invalid'));
add('tampered-member-added', 'An unsigned member added beside the signed ones.',
  { certificate: edit((c) => { c.note = 'added later'; }) }, broken('signature_invalid'));
add('tampered-signature-bytes', 'One character of the signature segment changed.',
  { certificate: { ...base, signature: `${headerSegment}..${flipFirst(signatureSegment)}` } }, broken('signature_invalid'));
add('tampered-header-typ-removed', 'Header without typ.',
  { certificate: withHeader(base, ({ typ, ...rest }) => rest) },
  expected('wrong_typ', findings('could_not_be_checked', 'sandbox', 'sandbox', 'not_recognised'), { alg: 'EdDSA' }));
add('tampered-header-alg-rs256', 'Header alg changed to RS256: the Ed25519 key must not be used as an RSA key.',
  { certificate: withHeader(base, (h) => ({ ...h, alg: 'RS256' })) },
  expected('alg_not_allowed', findings('could_not_be_checked', 'unknown', 'sandbox'), { alg: 'RS256' }));

// Missing or unreadable parts.
const undecided = findings('could_not_be_checked', 'could_not_be_checked', 'could_not_be_checked', 'could_not_be_checked');
add('signature-missing', 'No signature member.',
  { certificate: edit((c) => { delete c.signature; }) }, expected('missing_signature', undecided));
add('signature-empty', 'An empty signature.',
  { certificate: { ...base, signature: '' } }, expected('missing_signature', undecided));
add('signature-not-a-string', 'A signature that is not a string.',
  { certificate: { ...base, signature: 12345 } }, expected('missing_signature', undecided));
add('signature-attached', 'An attached JWS (payload in the middle segment) is not the certificate format.',
  { certificate: { ...base, signature: `${headerSegment}.${encode('{}')}.${signatureSegment}` } }, expected('bad_header', undecided));
add('signature-two-segments', 'Only two segments.',
  { certificate: { ...base, signature: `${headerSegment}.${signatureSegment}` } }, expected('bad_header', undecided));
add('signature-segment-empty', 'alg none in its usual shape: no signature bytes at all.',
  { certificate: { ...base, signature: `${encode('{"alg":"none","kid":"apier-sandbox-cert-1","typ":"apier-verify-cert+jws"}')}..` } },
  expected('bad_header', undecided));
add('signature-padded', 'Padded base64 in the signature segment.',
  { certificate: { ...base, signature: `${headerSegment}..${signatureSegment}==` } }, expected('bad_header', undecided));
add('header-not-json', 'The header segment does not decode to JSON.',
  { certificate: withHeader(base, () => 'not json') }, expected('bad_header', undecided));
add('header-is-array', 'The header is a JSON array.',
  { certificate: withHeader(base, () => '["EdDSA"]') }, expected('bad_header', undecided));
add('header-duplicate-key', 'The header repeats alg, so two parsers could read two algorithms.',
  { certificate: withHeader(base, () => '{"alg":"none","alg":"EdDSA","kid":"apier-sandbox-cert-1","typ":"apier-verify-cert+jws"}') },
  expected('bad_header', undecided));
add('header-crit', 'A header with crit names an extension this verifier does not implement.',
  { certificate: withHeader(base, (h) => ({ ...h, crit: ['b64'], b64: false })) },
  expected('bad_header', findings('could_not_be_checked', 'could_not_be_checked', 'could_not_be_checked')));
add('header-kid-missing', 'A header without kid.',
  { certificate: withHeader(base, ({ kid, ...rest }) => rest) },
  expected('bad_header', findings('could_not_be_checked', 'could_not_be_checked', 'could_not_be_checked')));
add('header-alg-not-a-string', 'A header whose alg is a list.',
  { certificate: withHeader(base, (h) => ({ ...h, alg: ['EdDSA'] })) },
  expected('bad_header', findings('could_not_be_checked', 'could_not_be_checked', 'could_not_be_checked')));

const notSandbox = { is_sandbox: false };
add('certificate-is-array', 'A JSON array is not a certificate.', { certificate: [base] }, expected('malformed_certificate', undecided, notSandbox));
add('certificate-is-null', 'null is not a certificate.', { certificate: null }, expected('malformed_certificate', undecided, notSandbox));
add('certificate-is-string', 'A string is not a certificate.', { certificate: base.signature }, expected('malformed_certificate', undecided, notSandbox));
add('is-sandbox-not-boolean', 'is_sandbox must be a boolean when present.',
  { certificate: { ...base, is_sandbox: 'true' } }, expected('malformed_certificate', undecided, notSandbox));

// From text: what the command line reads.
const text = JSON.stringify(base);
add('text-certificate', 'The certificate as JSON text.', { certificate_text: text }, intact(null));
add('text-api-response', 'A full API response: the data member is checked.',
  { certificate_text: JSON.stringify({ success: true, data: base, _meta: { is_sandbox: true } }) }, intact(null));
add('text-duplicate-key', 'A repeated key: the last one would make the signature match, the first one says fail.',
  { certificate_text: text.replace('"result":{', '"result":{"verification_status":"fail",') },
  expected('malformed_certificate', undecided, notSandbox));
add('text-duplicate-top-level-key', 'A repeated top-level key.',
  { certificate_text: `{"is_sandbox":false,${text.slice(1)}` }, expected('malformed_certificate', undecided, notSandbox));
add('text-not-json', 'Text that is not JSON.', { certificate_text: `${text}}` }, expected('malformed_certificate', undecided, notSandbox));
add('text-nan', 'NaN is not JSON.',
  { certificate_text: text.replace('"last_accounts_year":2024', '"last_accounts_year":NaN') },
  expected('malformed_certificate', undecided, notSandbox));
add('text-number-overflow', 'A number too large for a double has no canonical form.',
  { certificate_text: text.replace('"last_accounts_year":2024', '"last_accounts_year":1e999') },
  expected('malformed_certificate', undecided, notSandbox));
add('text-number-respelled', 'The same number written another way is the same certificate.',
  { certificate_text: text.replace('"last_accounts_year":2024', '"last_accounts_year":2.024e3') }, intact(null));

for (const check of ['"result":{', '"last_accounts_year":2024']) {
  if (!text.includes(check)) throw new Error(`the base certificate no longer contains ${check}`);
}

const out = {
  note: 'Generated by test/make-sandbox-cases.mjs from the real sandbox certificates beside this file. Do not edit by hand.',
  keysets: { sandbox: 'sandbox-jwks.json', empty: { keys: [] } },
  key_histories: {},
  cases,
};
writeFileSync(new URL('sandbox-cases.json', vectors), `${JSON.stringify(out, null, 2)}\n`);
console.log(`wrote ${cases.length} cases`);
