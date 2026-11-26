# apier-receipt-verify

[![CI](https://github.com/apier-no/apier-receipt-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/apier-no/apier-receipt-verify/actions/workflows/ci.yml)

This checks the signature on an [Apier](https://www.apier.no) certificate offline, against a key set (JWKS) that you supply. It is one file in Node and one file in Python, and neither has any dependency. It reports four separate findings and one reason code, and it never gives a single verdict.

## What an Apier certificate is

Apier answers questions about Norwegian companies from Brønnøysundregistrene: whether a company is registered and active, and who can sign for it (signaturrett and prokura). Add `?certificate=true` to a request and the answer comes back as a certificate (a kvittering): the same JSON, with a detached JWS signature over it. Whoever holds the certificate can check that Apier signed exactly this content, using Apier's public keys, with no account and without calling Apier. An auditor can do that years later from a stored copy of the certificate and the key set, which is why the check has to work offline.

## Check one in 30 seconds

Fetch a sandbox certificate and check it. The sandbox needs no signup; the bearer is `apier_sandbox_test_` followed by any suffix you make up.

```bash
curl -s -H "Authorization: Bearer apier_sandbox_test_demo123" \
  -o cert.json "https://www.apier.no/api/v1/sandbox/company/999000001/verify?certificate=true"

npx github:apier-no/apier-receipt-verify cert.json --sandbox
```

```text
signature: matches
signing_key: sandbox (kid "apier-sandbox-cert-1")
environment: sandbox
format_version: recognised
issued_at: "2026-01-01T09:00:00+01:00"
stale: false
reason: none
```

The same with Python 3.9 or later:

```bash
curl -sO https://raw.githubusercontent.com/apier-no/apier-receipt-verify/main/python/apier_receipt_verify.py
python apier_receipt_verify.py cert.json --sandbox
```

A sandbox certificate is test data signed with a key that is public, so anyone can make one. Without `--sandbox` the same file is refused with `reason: sandbox_not_allowed` and exit code 1. On Windows PowerShell, write `curl.exe` and keep `-o cert.json`: redirecting with `>` saves the file as UTF-16, which is not valid JSON input.

## How it fits together

```mermaid
flowchart LR
    A["Apier API<br/>?certificate=true"] --> B["Certificate<br/>JSON with a detached JWS"]
    B --> C["Your storage"]
    C --> D["apier-receipt-verify"]
    K["JWKS<br/>cached file or live URL"] --> D
    D --> E["Findings and a reason code"]
```

## Command line

```text
apier-receipt-verify <certificate.json | -> [--sandbox] [--jwks <file|url>] [--key-history <file|url>] [--json]
```

- `<certificate.json | ->` is the certificate, from a file or from stdin. The full API response is accepted too; its `data` member is then checked.
- `--sandbox` uses the sandbox key set and allows sandbox certificates.
- `--jwks <file|url>` names the key set. The default is `https://www.apier.no/.well-known/jwks.json`. With a file, nothing is fetched and the check runs with no network.
- `--key-history <file|url>` adds Apier's signed key history (see "Key states" below).
- `--json` prints the result object.

The exit code is 0 when the reason is `none`, 1 when a reason is set, and 2 on a usage or network error. The Python file takes the same arguments: `python python/apier_receipt_verify.py cert.json --jwks jwks.json`.

## As a library

Both functions are pure: they never fetch and never read a file. You pass the key set.

```js
import { checkCertificateText } from './node/verify.mjs';

const result = await checkCertificateText(certificateText, { jwks, keyHistory: null, allowSandbox: false });
// { findings: { signature, signing_key, environment, format_version },
//   reason, kid, alg, isSandbox, issuedAt, stale }
```

```python
from apier_receipt_verify import check_certificate_text

result = check_certificate_text(certificate_text, jwks, key_history=None, allow_sandbox=False)
# {"findings": {...}, "reason": ..., "kid": ..., "alg": ..., "is_sandbox": ..., "issued_at": ..., "stale": ...}
```

`checkCertificate(cert, options)` and `check_certificate(cert, jwks, ...)` take an object you have already parsed. Use the text functions when you can: a repeated key in a JSON object can only be seen in the text, and they refuse it. Both forms accept a `now` argument and ignore it, because no rule here depends on the clock.

Sandbox certificates are allowed only when the flag is exactly `true` (`True` in Python). A bad certificate never raises: it gives a reason. The one thing that is passed on to the caller is a stack overflow (`RangeError` in Node, `RecursionError` in Python), because running out of stack says nothing about the certificate.

## What is checked

`reason` is the first of these that fails, in this order. It is `null` (printed as `none`) when none does.

1. `malformed_certificate`: the input is not a JSON object, has a repeated key, holds a number that is not finite, is nested more than 64 levels deep, or has an `is_sandbox` that is not a boolean.
2. `missing_signature`: there is no `signature` member, or it is not a non-empty string.
3. `sandbox_not_allowed`: the certificate says `is_sandbox: true` and sandbox certificates were not allowed.
4. `wrong_issuer`: a production certificate must name `https://www.apier.no` as `issuer` (the apex `https://apier.no`, which older certificates carry, is accepted too).
5. `bad_header`: `signature` is not a detached compact JWS (`header..signature`, RFC 7515 Appendix F) in unpadded base64url, or its header is not a JSON object with a string `alg` and a non-empty string `kid`, repeats a key, or carries `crit`.
6. `wrong_typ`: the header `typ` is not `apier-verify-cert+jws`. Apier's keys sign other things as well, so a matching signature under another `typ` is not a certificate.
7. `alg_not_allowed`: a production certificate must be `RS256` and a sandbox certificate `EdDSA`. `none`, `HS256` and everything else are refused, and the algorithm is always checked against the type of the key.
8. `unknown_kid`: the key set has no usable key with the header's `kid` for that algorithm. A sandbox key is never used for a production certificate, and only a sandbox key is used for a sandbox certificate. An RSA key is used only when its modulus is odd and 2048 to 16384 bits long and its exponent is odd, at least 3 and below 2^64. An Ed25519 key is used only when it is the canonical 32-byte encoding of a point that is not of small order.
9. `compromised_key`: the key is marked as leaked (see below).
10. `signature_invalid`: the signature does not match the certificate.

The signed bytes are the header segment, a dot, and the base64url of the certificate's canonical JSON with the `signature` member removed. The canonical form is the one in [Apier's guide](https://www.apier.no/docs/guides/verify-certificate): no whitespace, integer index keys first and then the other keys by UTF-16 code unit, and numbers written the way JavaScript writes them. Keys are looked up only in the key set you pass. The `jwks_uri` inside a certificate is never used, because whoever made the file controls it.

### Findings

The findings have the same names and values as the first four findings of Apier's own receipt check (`POST /api/v1/public/receipts/verify`). Each stands alone, and they are worked out from the header and the key, not from what the certificate says about itself.

| Finding | Value | Meaning |
|---|---|---|
| `signature` | `matches` | The signature is over exactly this content, under the key the header names. |
| | `does_not_match` | The content or the signature was changed, or another key signed it. |
| | `could_not_be_checked` | The check stopped before a signature could be checked: unreadable header, wrong `typ`, unsupported algorithm or unknown key. |
| `signing_key` | `current`, `retired` | A production key. A retired key still checks the certificates it signed. |
| | `revoked` | The key is marked as leaked. |
| | `sandbox` | The public sandbox key. |
| | `unknown` | No key with this `kid` is in the key set. |
| | `could_not_be_checked` | The check stopped before the key lookup. |
| `environment` | `production` | The signature matches under a production key and the issuer is production's. |
| | `sandbox` | The certificate names a sandbox key. It is labelled so whatever else is wrong with it. |
| | `issuer_not_recognised` | A production key signed content that names another issuer. |
| | `could_not_be_checked` | The signature did not match or was not checked, so nothing is claimed. |
| `format_version` | `recognised`, `not_recognised` | Whether the header `typ` is `apier-verify-cert+jws`. |
| | `could_not_be_checked` | The header could not be read. |

`issued_at` and `stale` are read from the certificate only when the signature matches. `stale` is the certificate's own `freshness.stale`; a certificate issued before November 2026 has no `freshness` member, and `stale` is then `null` (printed as `not stated`).

### Key states

Apier marks keys in its key set. A key with `apier_retired_at` stopped signing on that date and stays published, so its certificates still check and `signing_key` reads `retired`. A key with `apier_compromised_at` leaked: `signing_key` reads `revoked` and the reason is `compromised_key`.

A certificate under a compromised key is always refused here, including one whose `issued_at` is earlier than the compromise. Whoever holds a leaked key can sign any date, and offline there is no other date to compare with. Apier's own check is more lenient on this point: it answers `verified`, flagged, for a certificate dated before the compromise.

A key set saved before a key was retired or marked does not carry the mark. The signed key history (`https://www.apier.no/.well-known/signing-key-history.json`) fills that gap. It is used only when its own signature checks against a production key in the key set you passed, and it can only add marks, never remove one. An entry applies to a key when its `kid` and its fingerprint (RFC 7638 thumbprint) are that key's. Every such entry counts, and an entry whose state is anything other than `current` or `retired` marks the key compromised. If the history does not check, it is ignored and the command line prints a warning.

## Production use

- Pin or cache the key set and pass it with `--jwks`. Refresh it about once a day, because a compromise mark only reaches you through a fresh copy.
- Never take keys from the `jwks_uri` inside a certificate.
- Refuse sandbox certificates: leave out `--sandbox` and keep `allowSandbox` false.
- Read `stale` and decide by your own policy. A stale certificate was built from a stored copy of the register that was more than 24 hours old.
- Store the key set you checked against together with the certificate, so the check can be repeated later.
- For a certificate under a compromised key, use Apier's public receipt log at https://www.apier.no/receipt-check to find out when the receipt was logged. That date does not depend on the leaked key.

## What this does not prove

A matching signature shows that Apier signed this content and that it has not changed since. It does not show that the register says the same today, and it is not a legal conclusion: Apier's results are the register's own coding, passed on without interpretation. It does not show internal authority, board resolutions or authority that follows from a position (stillingsfullmakt). It is not AML or PEP screening and does not replace either.

This verifier also leaves out three things that Apier's own check reports: whether the receipt is in the public receipt log, whether a daily anchor covers it, and the warning for a certificate dated after its key was retired. The first two need the network. Use https://www.apier.no/receipt-check for them.

## Tests

```bash
node --test
python -m unittest discover -s test
node test/parity.mjs --run
```

Both implementations run the same case files in `test/vectors/`:

- `canonical-vector.json` is the 131-byte test vector from Apier's guide, and `canonical-cases.json` holds 634 more JSON texts with their canonical form.
- `sandbox-*.json` are three real sandbox certificates (fictional fixture data) and the sandbox key set. `sandbox-cases.json` adds tampered copies of them.
- `official-findings.json` records what Apier's own receipt check answered for eleven of those vectors. The tests require the same four findings.
- `synthetic-cases.json` covers the production RS256 path, retired and compromised keys, the key history and forged signatures. Its keys are synthetic test keys made by `test/make-rs256-vector.mjs`. They are not Apier's keys, and no real production certificate is in this repository.
- `adversarial-cases.json` holds 541 cases written by an independent reviewer who was given only the specification and this repository: repeated keys, signatures over non-canonical bytes, keys presented under the wrong algorithm, sandbox keys in production mode, compromised keys with and without a key history, and malformed keys, headers and signatures. Its keys are throwaway test keys too.

`test/parity.mjs` generates random JSON texts and random certificates, runs the Node and the Python verifier on each, and fails on any difference. CI runs all of this on Node 20 and 22 and Python 3.9 and 3.12. On every pull request and once a week it also fetches a fresh sandbox certificate and checks it with both command lines.

## Links

- Guide: [How to verify an Apier certificate](https://www.apier.no/docs/guides/verify-certificate)
- Guide: [Check an Apier receipt, online or offline](https://www.apier.no/docs/guides/check-receipt)
- Apier's own receipt check: https://www.apier.no/receipt-check
- Key sets: [production](https://www.apier.no/.well-known/jwks.json), [sandbox](https://www.apier.no/.well-known/sandbox-jwks.json)
- [apier.no](https://www.apier.no)
- Examples that call the API: [apier-quickstart](https://github.com/apier-no/apier-quickstart)

## License

MIT. See [LICENSE](./LICENSE).
