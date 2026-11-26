// Run with: node --test
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalJson, checkCertificate, checkCertificateText, parseJsonStrict, REASONS } from '../node/verify.mjs';

const vectors = new URL('./vectors/', import.meta.url);
const readText = (name) => readFileSync(new URL(name, vectors), 'utf8');
const read = (name) => JSON.parse(readText(name));
const cli = fileURLToPath(new URL('../node/cli.mjs', import.meta.url));
const vectorPath = (name) => fileURLToPath(new URL(name, vectors));

// The shared case files use snake_case names; the Node result uses camelCase.
const toShared = (r) => ({
  reason: r.reason, findings: r.findings, kid: r.kid, alg: r.alg, is_sandbox: r.isSandbox, issued_at: r.issuedAt, stale: r.stale,
});

function loadCases(file) {
  const document = read(file);
  const named = (table, name) => (typeof table[name] === 'string' ? read(table[name]) : table[name]);
  return document.cases.map((c) => ({
    ...c,
    jwks: named(document.keysets, c.jwks),
    keyHistory: c.key_history ? named(document.key_histories, c.key_history) : null,
    certificate: c.certificate_file ? read(c.certificate_file) : c.certificate,
  }));
}

async function run(c) {
  const options = { jwks: c.jwks, keyHistory: c.keyHistory, allowSandbox: c.allow_sandbox };
  return toShared(
    c.certificate_text !== undefined ? await checkCertificateText(c.certificate_text, options) : await checkCertificate(c.certificate, options),
  );
}

test('canonical JSON: the test vector from the guide', () => {
  const vector = read('canonical-vector.json');
  const bytes = Buffer.from(canonicalJson(JSON.parse(vector.input)), 'utf8');
  assert.equal(bytes.toString('utf8'), vector.canonical);
  assert.equal(bytes.length, 131);
  assert.equal(bytes.length, vector.bytes);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), vector.sha256);
});

test('canonical JSON: generated cases', () => {
  const { cases } = read('canonical-cases.json');
  assert.ok(cases.length > 100);
  for (const c of cases) assert.equal(canonicalJson(parseJsonStrict(c.input)), c.canonical, c.input);
});

test('strict JSON: an escaped key is read as written, whatever was parsed before', () => {
  // Node 24.11 reads the second text with a lone backslash as its second key after parsing the first.
  const backslash = String.fromCharCode(92);
  assert.deepEqual(Object.keys(parseJsonStrict(`{"a":1,"${backslash}${backslash}":2}`)), ['a', backslash]);
  assert.deepEqual(Object.keys(parseJsonStrict(`{"a":1,"${backslash}u0041":2}`)), ['a', 'A']);
  assert.deepEqual(Object.keys(parseJsonStrict(`{"a":1,"${backslash}n":2}`)), ['a', '\n']);
  const proto = parseJsonStrict('{"__proto__":{"x":1},"b":2}');
  assert.deepEqual(Object.keys(proto), ['__proto__', 'b']);
  assert.equal(Object.getPrototypeOf(proto), Object.prototype);
});

test('canonical JSON: refuses what has no canonical form', () => {
  for (const value of [NaN, Infinity, -Infinity, undefined, 1n, new Date(0), () => 1, { a: [undefined] }, new Map()]) {
    assert.throws(() => canonicalJson(value));
  }
});

test('strict JSON: refuses a repeated key at any depth and keeps everything else', () => {
  for (const text of ['{"a":1,"a":2}', '{"a":{"b":1,"b":1}}', '[{"a":1,"\\u0061":2}]', '{"a":[{"x":1,"y":2,"x":3}]}']) {
    assert.throws(() => parseJsonStrict(text), /duplicate/);
  }
  for (const text of ['{"a":1,"b":{"a":1}}', '[{"a":1},{"a":2}]', '{"a":"\\"a\\":1,\\"a\\":2"}', '{"a,":1,"a":[1,2],"{":{"a":1}}', '{}', '[]', '"x"']) {
    assert.deepEqual(parseJsonStrict(text), JSON.parse(text));
  }
  assert.throws(() => parseJsonStrict('{"a":1,}'));
});

for (const file of ['sandbox-cases.json', 'synthetic-cases.json', 'adversarial-cases.json']) {
  for (const c of loadCases(file)) {
    test(`${file}: ${c.name}`, async () => {
      assert.deepEqual(await run(c), c.expect, c.note);
    });
  }
}

test('every reason code is exercised by a case, and no case uses another', () => {
  const used = new Set();
  for (const file of ['sandbox-cases.json', 'synthetic-cases.json', 'adversarial-cases.json']) {
    for (const c of read(file).cases) used.add(c.expect.reason);
  }
  assert.deepEqual([...used].filter((r) => r !== null).sort(), [...REASONS].sort());
});

test("the findings agree with Apier's own receipt check on every recorded vector", async () => {
  const official = read('official-findings.json').vectors;
  const cases = loadCases('sandbox-cases.json');
  assert.equal(Object.keys(official).length, 11);
  for (const [name, findings] of Object.entries(official)) {
    const c = cases.find((candidate) => candidate.name === name);
    assert.ok(c, name);
    assert.deepEqual((await run(c)).findings, findings, name);
  }
});

test('the result never carries an overall verdict', async () => {
  const [c] = loadCases('sandbox-cases.json');
  const result = await checkCertificate(c.certificate, { jwks: c.jwks, allowSandbox: true });
  assert.deepEqual(Object.keys(result).sort(), ['alg', 'findings', 'isSandbox', 'issuedAt', 'kid', 'reason', 'stale']);
  assert.deepEqual(Object.keys(result.findings).sort(), ['environment', 'format_version', 'signature', 'signing_key']);
});

test('the certificate jwks_uri is never used for key lookup', async () => {
  // A certificate that points at a key set of its own, with no key set passed in, finds no key.
  const certificate = read('sandbox-verify-999000001.json');
  const result = await checkCertificate(certificate, { jwks: { keys: [] }, allowSandbox: true });
  assert.equal(result.reason, 'unknown_kid');
  assert.equal((await checkCertificate(certificate, null)).reason, 'sandbox_not_allowed');
});

test('sandbox certificates are allowed only by allowSandbox: true itself', async () => {
  const [c] = loadCases('sandbox-cases.json');
  for (const allowSandbox of ['true', 'false', 1, {}, [], null, undefined]) {
    assert.equal((await checkCertificate(c.certificate, { jwks: c.jwks, allowSandbox })).reason, 'sandbox_not_allowed');
  }
});

test('what is reported comes from the signed bytes, not from the object passed in', async () => {
  // An object whose freshness.stale reads true once (when it is signed over) and false afterwards.
  const [c] = loadCases('sandbox-cases.json');
  let reads = 0;
  const freshness = { ...c.certificate.freshness };
  Object.defineProperty(freshness, 'stale', { enumerable: true, get: () => reads++ > 0 });
  const result = await checkCertificate({ ...c.certificate, freshness }, { jwks: c.jwks, allowSandbox: true });
  assert.equal(result.reason, null);
  assert.equal(result.stale, false);
  assert.equal(reads, 1);
});

test('command line: output, exit codes and offline use', () => {
  const certificate = vectorPath('sandbox-verify-999000001.json');
  const jwks = vectorPath('sandbox-jwks.json');
  const text = execFileSync(process.execPath, [cli, certificate, '--sandbox', '--jwks', jwks], { encoding: 'utf8' });
  assert.equal(text, [
    'signature: matches',
    'signing_key: sandbox (kid "apier-sandbox-cert-1")',
    'environment: sandbox',
    'format_version: recognised',
    'issued_at: "2026-01-01T09:00:00+01:00"',
    'stale: false',
    'reason: none',
    '',
  ].join('\n'));
  assert.doesNotMatch(text, /\bvalid\b/i);

  const refused = spawnSync(process.execPath, [cli, certificate, '--jwks', jwks], { encoding: 'utf8' });
  assert.equal(refused.status, 1);
  assert.match(refused.stdout, /^reason: sandbox_not_allowed$/m);

  const json = spawnSync(process.execPath, [cli, '-', '--sandbox', '--jwks', jwks, '--json'], { encoding: 'utf8', input: readText('sandbox-verify-999000001.json') });
  assert.equal(json.status, 0);
  assert.equal(JSON.parse(json.stdout).reason, null);

  assert.equal(spawnSync(process.execPath, [cli], { encoding: 'utf8' }).status, 2);
  assert.equal(spawnSync(process.execPath, [cli, certificate, '--nope'], { encoding: 'utf8' }).status, 2);
  assert.equal(spawnSync(process.execPath, [cli, vectorPath('absent.json'), '--jwks', jwks], { encoding: 'utf8' }).status, 2);
  assert.equal(spawnSync(process.execPath, [cli, certificate, '--jwks', vectorPath('absent.json')], { encoding: 'utf8' }).status, 2);
  assert.equal(spawnSync(process.execPath, [cli, certificate, '--jwks', 'http://www.apier.no/.well-known/jwks.json'], { encoding: 'utf8' }).status, 2);
});
