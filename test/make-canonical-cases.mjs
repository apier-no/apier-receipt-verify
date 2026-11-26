// Builds test/vectors/canonical-cases.json: JSON texts and the canonical form each must take.
// Deterministic (fixed seed). The expected output comes from `canon`, the reference function printed
// in Apier's public guide, not from this repository's own canonicaliser.
import { writeFileSync } from 'node:fs';

// `node --test` runs every file under test/, so this script only writes when asked to.
if (!process.argv.includes('--write')) {
  console.log('Usage: node test/make-canonical-cases.mjs --write   (replaces test/vectors/canonical-cases.json)');
  process.exit(0);
}

const canon = (v) =>
  JSON.stringify(v, (_, val) =>
    val && typeof val === 'object' && !Array.isArray(val)
      ? Object.fromEntries(Object.entries(val).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : val,
  );

// mulberry32: a small seeded generator, so the file is the same on every run.
let state = 0x5eed1234;
function random() {
  state = (state + 0x6d2b79f5) | 0;
  let t = Math.imul(state ^ (state >>> 15), 1 | state);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const int = (n) => Math.floor(random() * n);
const pick = (list) => list[int(list.length)];

const inputs = [];

// Numbers: spellings that print differently in JavaScript and in other languages.
const numbers = [
  '0', '-0', '0.0', '-0.0', '0e0', '0E-5', '1', '-1', '1.0', '100.0', '1e0', '1E3', '1e+3', '1.5E+3', '1e21', '1e20', '1e22', '1.5e300',
  '123456789012345680000', '999999999999999900000', '1e15', '1e16', '1e17', '1e-5', '1e-6', '1e-7', '0.00001', '0.000001', '0.0000001',
  '2e-7', '-1e-7', '0.000001234', '0.1', '0.2', '0.30000000000000004', '0.3333333333333333', '4.35', '4.350', '123456789.123456789',
  '9007199254740991', '9007199254740992', '9007199254740993', '-9007199254740993', '12345678901234567890', '123456789012345678901234567890',
  '5e-324', '4.9e-324', '2.2250738585072014e-308', '2.225073858507201e-308', '1.7976931348623157e308', '1.7976931348623157E+308',
  '4294967295', '4294967296', '1.0000000000000002', '0.1e1', '10e-1', '123e-20', '123e20', '1.25e-3', '-123.456e7', '1e-324', '1e-400',
];
for (const n of numbers) inputs.push(n, `[${n}]`, `{"n":${n}}`);
const bytes = new DataView(new ArrayBuffer(8));
for (let i = 0; i < 120; i++) {
  bytes.setUint32(0, int(4294967296));
  bytes.setUint32(4, int(4294967296));
  const value = bytes.getFloat64(0);
  if (!Number.isFinite(value)) continue;
  inputs.push(pick([String(value), value.toExponential(), value.toPrecision(17), value.toExponential(int(20))]));
}
for (let i = 0; i < 60; i++) {
  // Integers of 1 to 30 digits, and decimals with a random number of places.
  let digits = String(1 + int(9));
  for (let d = int(30); d > 0; d--) digits += String(int(10));
  inputs.push(pick(['', '-']) + digits, `${digits}.${int(1000000)}`, `0.${'0'.repeat(int(12))}${digits}`);
}

// Keys: integer index keys first in numeric order, then the rest by UTF-16 code units.
const keys = [
  '0', '1', '2', '9', '10', '11', '100', '4294967294', '4294967295', '4294967296', '99999999999999999999', '00', '01', '-0', '-1',
  '1.0', '1e3', ' 1', '1 ', '+1', '', 'a', 'A', 'b', 'aa', 'Z', '_', '~', 'æ', 'ø', 'å', 'Å', 'é', '€', '\u{b2}', '\u{661}', '\u{7c1}',
  '\u{e000}', '\u{ffee}', '\u{ffff}', '\u{1f600}', '\u{10000}', '\u{10ffff}', '\ud800', '\udfff', '\u0000', '\u0001', '\u001f', '\u007f',
  '\u{2028}', '\u{2029}', '"', '\\', '/', '\n', '\t', 'issued_at', 'issuer', 'signature', '__proto__', 'constructor', 'toString',
];
const scalars = ['null', 'true', 'false', '1', '"x"', '[]', '{}', '1.50', '"æ"'];
for (let i = 0; i < 60; i++) {
  const chosen = new Set();
  for (let k = 2 + int(10); k > 0; k--) chosen.add(pick(keys));
  inputs.push(`{${[...chosen].map((k) => `${JSON.stringify(k)}:${pick(scalars)}`).join(',')}}`);
}

// Strings and nesting.
const strings = [
  '', 'plain', 'Brønnøysundregistrene', 'tab\there', 'line\nbreak', 'carriage\rreturn', 'form\ffeed', 'back\bspace', 'quote"inside',
  'back\\slash', 'slash/kept', '\u0000\u0001\u000b\u001f', '\u007f\u0080\u009f', '\u{2028}\u{2029}', '\u{1f600} astral', '\ud800 lone high',
  'lone low \udc00', '\udc00\ud800 reversed', '<script>&amp;', '\u{feff}', 'é combining',
];
for (const s of strings) inputs.push(JSON.stringify(s), JSON.stringify({ [s]: [s] }));
inputs.push(
  '"\\u00e6\\u00F8\\u00e5"', '"\\/"', '"\\ud83d\\ude00"', '"\\uD83D\\uDE00"', '"\\ud83d"', '{"\\u0061":1,"b":2}',
  ' [ 1 , { "b" : [ ] , "a" : { } } ] ', '[[[[[[[[[[1]]]]]]]]]]', '{"a":{"b":{"c":{"d":{"10":1,"9":2}}}}}', 'null', 'true', 'false',
  '{"z":[{"b":1,"a":2},{"2":1,"1":2,"a":0}],"a":[3,2,1]}',
);
function nested(depth) {
  const kind = depth > 3 ? 0 : int(3);
  if (kind === 1) return `[${Array.from({ length: int(4) }, () => nested(depth + 1)).join(',')}]`;
  if (kind === 2) {
    const chosen = new Set(Array.from({ length: int(5) }, () => pick(keys)));
    return `{${[...chosen].map((k) => `${JSON.stringify(k)}:${nested(depth + 1)}`).join(',')}}`;
  }
  return pick([...scalars, ...numbers, JSON.stringify(pick(strings))]);
}
for (let i = 0; i < 60; i++) inputs.push(nested(0));

const cases = [...new Set(inputs)].map((input) => ({ input, canonical: canon(JSON.parse(input)) }));
const out = {
  note: 'Generated by test/make-canonical-cases.mjs. `canonical` is what the reference function in the public guide gives for JSON.parse(input). Do not edit by hand.',
  cases,
};
writeFileSync(new URL('./vectors/canonical-cases.json', import.meta.url), `${JSON.stringify(out, null, 1)}\n`);
console.log(`wrote ${cases.length} cases`);
