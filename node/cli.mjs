#!/usr/bin/env node
// Command line for the offline certificate check. The check itself is in verify.mjs and never
// fetches; this file reads the certificate and loads the key set from a file or an https URL.
import { readFile } from 'node:fs/promises';
import { checkCertificateText, parseJsonStrict, verifyKeyHistory } from './verify.mjs';

const PRODUCTION_JWKS = 'https://www.apier.no/.well-known/jwks.json';
const SANDBOX_JWKS = 'https://www.apier.no/.well-known/sandbox-jwks.json';
const USAGE = `Usage: apier-receipt-verify <certificate.json | -> [--sandbox] [--jwks <file|url>] [--key-history <file|url>] [--json]

  <certificate.json | ->   the certificate (or the full API response), from a file or stdin
  --sandbox                use the sandbox key set and allow sandbox certificates
  --jwks <file|url>        key set to check against (default: Apier's production key set)
  --key-history <file|url> signed key history; used only when its own signature checks
  --json                   print the result object as JSON

Exit code: 0 when reason is none, 1 when a reason is set, 2 on a usage or network error.`;

class UsageError extends Error {}

function parseArgs(argv) {
  const options = { file: null, sandbox: false, jwks: null, keyHistory: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--sandbox') options.sandbox = true;
    else if (arg === '--json') options.json = true;
    else if (arg === '--jwks' || arg === '--key-history') {
      const value = argv[++i];
      if (value === undefined) throw new UsageError(`${arg} needs a file or an https URL`);
      options[arg === '--jwks' ? 'jwks' : 'keyHistory'] = value;
    } else if (arg !== '-' && arg.startsWith('-')) throw new UsageError(`unknown option ${arg}`);
    else if (options.file !== null) throw new UsageError('give one certificate file, or - for stdin');
    else options.file = arg;
  }
  if (options.file === null) throw new UsageError('no certificate given');
  return options;
}

const decodeText = (bytes) => new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks);
}

// A key set or key history from a local file or an https URL.
async function loadJson(source, label) {
  let bytes;
  if (/^https:\/\//i.test(source)) {
    let response;
    try {
      response = await fetch(source, { signal: AbortSignal.timeout(15000), redirect: 'error' });
    } catch {
      throw new Error(`${label}: could not fetch ${source}`);
    }
    if (!response.ok) throw new Error(`${label}: ${source} answered HTTP ${response.status}`);
    bytes = new Uint8Array(await response.arrayBuffer());
  } else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(source)) {
    throw new UsageError(`${label}: only https URLs and local files are read`);
  } else {
    bytes = await readFile(source);
  }
  try {
    return parseJsonStrict(decodeText(bytes));
  } catch {
    throw new Error(`${label}: ${source} is not valid JSON`);
  }
}

// Printable ASCII only, so nothing read from a file can drive the terminal. JSON.stringify has
// already escaped everything below the space character.
const asciiOnly = (json) => json.replace(/[^\x20-\x7e\n]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
const quote = (text) => asciiOnly(JSON.stringify(text));

function render(result) {
  const { findings } = result;
  const kid = result.kid === null ? '' : ` (kid ${quote(result.kid)})`;
  return [
    `signature: ${findings.signature}`,
    `signing_key: ${findings.signing_key}${kid}`,
    `environment: ${findings.environment}`,
    `format_version: ${findings.format_version}`,
    `issued_at: ${result.issuedAt === null ? 'not read' : quote(result.issuedAt)}`,
    `stale: ${result.stale === null ? 'not stated' : result.stale}`,
    `reason: ${result.reason ?? 'none'}`,
  ].join('\n');
}

async function main() {
  if (process.argv.includes('--help') || process.argv.includes('-h')) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  const options = parseArgs(process.argv.slice(2));
  const certificateBytes = options.file === '-' ? await readStdin() : await readFile(options.file);
  const jwks = await loadJson(options.jwks ?? (options.sandbox ? SANDBOX_JWKS : PRODUCTION_JWKS), 'key set');
  let keyHistory = null;
  if (options.keyHistory !== null) {
    keyHistory = await loadJson(options.keyHistory, 'key history');
    if (!verifyKeyHistory(keyHistory, jwks)) {
      process.stderr.write('warning: the key history was ignored: its signature does not check against this key set\n');
    }
  }
  let text = null;
  try {
    text = decodeText(certificateBytes);
  } catch {
    // Not UTF-8: checkCertificateText answers malformed_certificate for it.
  }
  const result = await checkCertificateText(text, { jwks, keyHistory, allowSandbox: options.sandbox });
  process.stdout.write(`${options.json ? asciiOnly(JSON.stringify(result, null, 2)) : render(result)}\n`);
  return result.reason === null ? 0 : 1;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (error) => {
    process.stderr.write(`${error.message}\n`);
    if (error instanceof UsageError) process.stderr.write(`\n${USAGE}\n`);
    process.exitCode = 2;
  },
);
