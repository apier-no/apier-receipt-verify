#!/usr/bin/env python3
"""Offline check of an Apier certificate against a JSON Web Key Set the caller supplies.

Python 3.9+, standard library only. check_certificate() never opens a network connection or reads
a file; only the command line at the bottom of this file does.

The RSA and Ed25519 code below only verifies signatures over public data with public keys. It is
not constant-time, which is acceptable because no secret is involved. Do not reuse it for signing.
"""

import base64
import hashlib
import hmac
import json
import re
import sys

CERTIFICATE_TYP = "apier-verify-cert+jws"
KEY_HISTORY_TYP = "apier-key-history+jws"
SANDBOX_KID = "apier-sandbox-cert-1"
# The apex is carried by older production certificates.
PRODUCTION_ISSUERS = ("https://www.apier.no", "https://apier.no")
# `reason` is the first of these that applies, in this order.
REASONS = (
    "malformed_certificate", "missing_signature", "sandbox_not_allowed", "wrong_issuer", "bad_header",
    "wrong_typ", "alg_not_allowed", "unknown_kid", "compromised_key", "signature_invalid",
)

PRODUCTION_JWKS = "https://www.apier.no/.well-known/jwks.json"
SANDBOX_JWKS = "https://www.apier.no/.well-known/sandbox-jwks.json"

_BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z")
_INDEX_KEY = re.compile(r"(0|[1-9][0-9]{0,9})\Z")
_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


# --- Canonical JSON -------------------------------------------------------------------------------

def _is_index_key(key):
    return _INDEX_KEY.match(key) is not None and int(key) < 4294967295


def _utf16(text):
    return text.encode("utf-16-be", "surrogatepass")


def _js_string(text):
    """A string as JavaScript's JSON.stringify writes it."""
    if any("\ud800" <= ch <= "\udfff" for ch in text):
        # Join surrogate pairs the way JavaScript reads them; a lone surrogate stays and is escaped.
        text = _utf16(text).decode("utf-16-be", "surrogatepass")
    out = ['"']
    for ch in text:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ch < " " or "\ud800" <= ch <= "\udfff":
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _js_number(value):
    """A number as JavaScript prints a double (ECMAScript Number::toString, RFC 8785 3.2.2.3)."""
    value = float(value)  # every JSON number is a double in JavaScript; a huge int raises here
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("not a finite number")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    # repr() gives the shortest digits that round-trip, as JavaScript does; only the layout differs.
    mantissa, _, exponent = repr(abs(value)).partition("e")
    whole, _, fraction = mantissa.partition(".")
    digits = (whole + fraction).lstrip("0")
    # The value is 0.<digits> times 10 to the power n.
    n = len(whole) - (len(whole + fraction) - len(digits)) + int(exponent or 0)
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * -n + digits
    exp = n - 1
    return sign + digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if exp >= 0 else "-") + str(abs(exp))


def canonical_json(value):
    """Apier's canonical JSON as a str: no whitespace; in every object the integer index keys first
    in numeric order, then the other keys by UTF-16 code units; strings and numbers as JavaScript
    prints them. Raises on anything that is not a finite JSON value."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _js_string(value)
    if isinstance(value, (int, float)):
        return _js_number(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("object keys must be strings")
        index = sorted((key for key in value if _is_index_key(key)), key=int)
        other = sorted((key for key in value if not _is_index_key(key)), key=_utf16)
        return "{" + ",".join(_js_string(key) + ":" + canonical_json(value[key]) for key in index + other) + "}"
    raise TypeError("not a JSON value")


def parse_json_strict(text):
    """json.loads that also refuses a repeated key in one object and the NaN and Infinity literals.
    Parsers disagree on which of two equal keys wins, so one file could be read as two different
    certificates."""
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise ValueError("duplicate object key")
            obj[key] = value
        return obj

    def constant(name):
        raise ValueError("not a JSON number: " + name)

    if not isinstance(text, str):
        raise TypeError("JSON text must be a str")
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


# --- Base64url and keys ---------------------------------------------------------------------------

def _decode_base64url(segment):
    """Unpadded base64url in its one canonical spelling, or None."""
    if not isinstance(segment, str) or _BASE64URL.match(segment) is None or len(segment) % 4 == 1:
        return None
    data = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    return data if _encode_base64url(data) == segment else None


def _encode_base64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwk_thumbprint(jwk):
    """RFC 7638 SHA-256 thumbprint of an RSA or Ed25519 public JWK, base64url; None for any other."""
    if jwk.get("kty") == "RSA" and isinstance(jwk.get("n"), str) and isinstance(jwk.get("e"), str):
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519" and isinstance(jwk.get("x"), str):
        members = {"crv": "Ed25519", "kty": "OKP", "x": jwk["x"]}
    else:
        return None
    return _encode_base64url(hashlib.sha256(canonical_json(members).encode("utf-8")).digest())


def _is_sandbox_key(jwk):
    return jwk.get("kid") == SANDBOX_KID or "apier_sandbox" in jwk


def _is_retired(jwk):
    return jwk.get("apier_retired_at") not in (None, "")


def _is_compromised(jwk):
    # Any `apier_compromised_at` member marks the key, whether or not its value can be read.
    return "apier_compromised_at" in jwk


def _key_fits(jwk, alg):
    """The key type must fit the algorithm, so an Ed25519 key is never used as RS256 or the reverse."""
    if "alg" in jwk and jwk["alg"] != alg:
        return False
    if alg == "RS256":
        return jwk.get("kty") == "RSA"
    return jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519"


def _import_key(jwk, alg):
    """The public key as numbers or bytes, or None when the JWK is unusable."""
    if alg == "RS256":
        n_bytes, e_bytes = _decode_base64url(jwk.get("n")), _decode_base64url(jwk.get("e"))
        if n_bytes is None or e_bytes is None:
            return None
        n, e = int.from_bytes(n_bytes, "big"), int.from_bytes(e_bytes, "big")
        return (n, e) if n.bit_length() >= 2048 and e >= 3 and e % 2 == 1 else None
    x = _decode_base64url(jwk.get("x"))
    if x is None or len(x) != 32:
        return None
    if int.from_bytes(x, "little") & ((1 << 255) - 1) >= _P:
        return None  # not the canonical encoding of a point
    return x


# --- RS256: RSASSA-PKCS1-v1_5 verification with SHA-256 (RFC 8017 section 8.2.2) -------------------

# DER DigestInfo prefix for SHA-256 (RFC 8017 section 9.2, note 1).
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _rsa_verify(public_key, message, signature):
    n, e = public_key
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    encoded = pow(s, e, n).to_bytes(k, "big")
    # Build the one valid encoded message and compare the whole block. The padding is never parsed,
    # so a forged block with shortened padding and trailing garbage cannot pass.
    digest_info = _SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(digest_info) - 3) + b"\x00" + digest_info
    return hmac.compare_digest(encoded, expected)


# --- EdDSA: Ed25519 verification (RFC 8032 section 5.1.7) ------------------------------------------

_P = 2**255 - 19  # the field prime
_L = 2**252 + 27742317777372353535851937790883648493  # the order of the base point
_D = -121665 * pow(121666, _P - 2, _P) % _P  # the curve constant d
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)  # a square root of -1


def _recover_x(y, sign):
    """The x coordinate for y with the given low bit, or None when (x, y) is not on the curve."""
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None  # x2 has no square root: the point is not on the curve
    return _P - x if (x & 1) != sign else x


def _point_add(p, q):
    """Add two points in extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, x*y = T/Z."""
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(scalar, point):
    result = (0, 1, 1, 0)  # the neutral element
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _point_decode(data):
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _point_encode(point):
    z_inverse = pow(point[2], _P - 2, _P)
    x, y = point[0] * z_inverse % _P, point[1] * z_inverse % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_BASE_Y = 4 * pow(5, _P - 2, _P) % _P
_BASE = (_recover_x(_BASE_Y, 0), _BASE_Y, 1, _recover_x(_BASE_Y, 0) * _BASE_Y % _P)


def _ed25519_verify(public_key, message, signature):
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _point_decode(public_key)  # fails when the key is not a point on the curve
    if a is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False  # only the one canonical S is accepted
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _L
    # The check is [S]B = R + [h]A. Compute [S]B - [h]A and compare its encoding with the R bytes of
    # the signature: this also refuses an R that is not on the curve or not canonically encoded.
    minus_a = (-a[0] % _P, a[1], 1, -a[3] % _P)
    r = _point_add(_point_mul(s, _BASE), _point_mul(h, minus_a))
    return hmac.compare_digest(_point_encode(r), signature[:32])


def _signature_matches(alg, public_key, signing_input, signature):
    if alg == "RS256":
        return _rsa_verify(public_key, signing_input, signature)
    return _ed25519_verify(public_key, signing_input, signature)


# --- The certificate check ------------------------------------------------------------------------

def _parse_detached_jws(jws):
    """A detached compact JWS, `header..signature`: (header segment, header, signature) or None."""
    parts = jws.split(".") if isinstance(jws, str) else []
    if len(parts) != 3 or parts[1] != "":
        return None
    header_bytes, signature = _decode_base64url(parts[0]), _decode_base64url(parts[2])
    if header_bytes is None or signature is None:
        return None
    try:
        header = parse_json_strict(header_bytes.decode("utf-8"))
    except (ValueError, RecursionError):
        return None
    return (parts[0], header, signature) if isinstance(header, dict) else None


def _payload_segment(unsigned):
    return _encode_base64url(canonical_json(unsigned).encode("utf-8"))


def _signing_input(header_segment, payload_segment):
    # The signed bytes are `<header segment>.<base64url of the canonical JSON without "signature">`.
    return (header_segment + "." + payload_segment).encode("ascii")


def _read_keys(jwks):
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    return [key for key in keys if isinstance(key, dict)] if isinstance(keys, list) else []


def verify_key_history(document, jwks):
    """True when the key history document is signed (RS256, typ apier-key-history+jws) by a key in
    `jwks` that is neither a sandbox key nor marked compromised. Only then may it be used."""
    try:
        if not isinstance(document, dict) or document.get("history_version") != "1":
            return False
        if not isinstance(document.get("keys"), list):
            return False
        unsigned = {key: value for key, value in document.items() if key != "signature"}
        jws = _parse_detached_jws(document.get("signature"))
        if jws is None:
            return False
        header_segment, header, signature = jws
        if header.get("alg") != "RS256" or header.get("typ") != KEY_HISTORY_TYP or "crit" in header:
            return False
        jwk = next((k for k in _read_keys(jwks) if k.get("kid") == header.get("kid") and _key_fits(k, "RS256")), None)
        if jwk is None or _is_sandbox_key(jwk) or _is_compromised(jwk):
            return False
        public_key = _import_key(jwk, "RS256")
        if public_key is None:
            return False
        return _rsa_verify(public_key, _signing_input(header_segment, _payload_segment(unsigned)), signature)
    except (TypeError, ValueError, OverflowError, RecursionError):
        return False


def _with_key_history_marks(keys, document):
    """A verified key history only ever adds marks, and only to the key whose thumbprint it lists."""
    entries = [
        e for e in document["keys"]
        if isinstance(e, dict) and isinstance(e.get("kid"), str) and e["kid"] != ""
        and e.get("environment") == "production" and e.get("state") in ("current", "retired", "compromised")
        and isinstance(e.get("alg"), str) and isinstance(e.get("jwk_thumbprint"), str)
        and isinstance(e.get("jwks_uri"), str)
    ]
    out = []
    for key in keys:
        entry = None
        if not _is_sandbox_key(key):
            thumbprint = jwk_thumbprint(key)
            entry = next((e for e in entries if e["kid"] == key.get("kid") and e["jwk_thumbprint"] == thumbprint), None)
        if entry is None or entry["state"] == "current":
            out.append(key)
            continue
        marked = dict(key)
        if not _is_retired(key) and isinstance(entry.get("valid_to"), str):
            marked["apier_retired_at"] = entry["valid_to"]
        if entry["state"] == "compromised" and not _is_compromised(key):
            compromised_at = entry.get("compromised_at")
            marked["apier_compromised_at"] = compromised_at if isinstance(compromised_at, str) else ""
        out.append(marked)
    return out


def check_certificate(cert, jwks, key_history=None, allow_sandbox=False, now=None):
    """Check one certificate (the `data` object of a `?certificate=true` response). Pure: it never
    fetches. Returns separate findings and the first failing `reason`, never one overall verdict.
    `now` is accepted for callers that pass a clock; no rule here depends on the time."""
    findings = {
        "signature": "could_not_be_checked",
        "signing_key": "could_not_be_checked",
        "environment": "could_not_be_checked",
        "format_version": "could_not_be_checked",
    }
    result = {"findings": findings, "reason": None, "kid": None, "alg": None,
              "is_sandbox": False, "issued_at": None, "stale": None}
    failed = set()

    def finish(*reasons):
        failed.update(reasons)
        result["reason"] = next((reason for reason in REASONS if reason in failed), None)
        # Nothing passes without a matching signature, whatever path led here.
        if result["reason"] is None and findings["signature"] != "matches":
            result["reason"] = "signature_invalid"
        result["is_sandbox"] = result["is_sandbox"] or findings["environment"] == "sandbox"
        return result

    if not isinstance(cert, dict) or ("is_sandbox" in cert and not isinstance(cert["is_sandbox"], bool)):
        return finish("malformed_certificate")
    claims = {key: value for key, value in cert.items() if key != "signature"}
    try:
        payload = _payload_segment(claims)
    except (TypeError, ValueError, OverflowError, RecursionError):
        return finish("malformed_certificate")
    sandbox_certificate = claims.get("is_sandbox") is True
    result["is_sandbox"] = sandbox_certificate
    jws_text = cert.get("signature")
    if not isinstance(jws_text, str) or jws_text == "":
        return finish("missing_signature")
    if sandbox_certificate and not allow_sandbox:
        failed.add("sandbox_not_allowed")
    issuer = claims.get("issuer")
    issuer_is_production = isinstance(issuer, str) and issuer in PRODUCTION_ISSUERS
    if not sandbox_certificate and not issuer_is_production:
        failed.add("wrong_issuer")

    jws = _parse_detached_jws(jws_text)
    if jws is None:
        return finish("bad_header")
    header_segment, header, signature = jws
    typ, alg, kid = header.get("typ"), header.get("alg"), header.get("kid")
    findings["format_version"] = "recognised" if typ == CERTIFICATE_TYP else "not_recognised"
    if not isinstance(alg, str) or not isinstance(kid, str) or kid == "" or "crit" in header:
        return finish("bad_header")
    known_alg = alg in ("RS256", "EdDSA")
    if known_alg:
        result["alg"] = alg
    if typ != CERTIFICATE_TYP:
        failed.add("wrong_typ")
    # Production certificates are RS256 and sandbox certificates EdDSA. `none` is never accepted.
    if alg != ("EdDSA" if sandbox_certificate else "RS256"):
        failed.add("alg_not_allowed")
    if typ != CERTIFICATE_TYP or not known_alg:
        # The check stops before any key is looked up. A header naming the sandbox key is still labelled.
        if kid == SANDBOX_KID:
            findings["signing_key"] = findings["environment"] = "sandbox"
        return finish()

    # Keys come only from the key set the caller passed, never from the certificate's own jwks_uri.
    keys = _read_keys(jwks)
    if key_history is not None and verify_key_history(key_history, {"keys": keys}):
        keys = _with_key_history_marks(keys, key_history)
    jwk = next((k for k in keys if k.get("kid") == kid and _key_fits(k, alg)), None)
    public_key = None if jwk is None else _import_key(jwk, alg)
    if public_key is None:
        findings["signing_key"] = "unknown"
        if kid == SANDBOX_KID:
            findings["environment"] = "sandbox"
        return finish("unknown_kid")
    result["kid"] = kid
    sandbox_key = _is_sandbox_key(jwk)
    compromised = not sandbox_key and _is_compromised(jwk)
    if sandbox_key:
        findings["signing_key"] = "sandbox"
    elif compromised:
        findings["signing_key"] = "revoked"
    else:
        findings["signing_key"] = "retired" if _is_retired(jwk) else "current"
    # A sandbox certificate is only ever checked against a sandbox key, a production one never.
    if sandbox_key != sandbox_certificate:
        failed.add("unknown_kid")
    # A leaked key can sign any date, so the certificate's own issued_at proves nothing: always refused.
    if compromised:
        failed.add("compromised_key")

    matches = _signature_matches(alg, public_key, _signing_input(header_segment, payload), signature)
    findings["signature"] = "matches" if matches else "does_not_match"
    if not matches:
        failed.add("signature_invalid")
    if sandbox_key:
        findings["environment"] = "sandbox"
    elif matches:
        findings["environment"] = "production" if issuer_is_production else "issuer_not_recognised"
    if matches:
        # Read from the certificate only once the signature covers it.
        issued_at, freshness = claims.get("issued_at"), claims.get("freshness")
        result["issued_at"] = issued_at if isinstance(issued_at, str) else None
        stale = freshness.get("stale") if isinstance(freshness, dict) else None
        result["stale"] = stale if isinstance(stale, bool) else None
    return finish()


def check_certificate_text(text, jwks, key_history=None, allow_sandbox=False, now=None):
    """The same check from JSON text. Invalid JSON or a repeated object key gives
    `malformed_certificate`. A full API response is accepted too: its `data` member is checked."""
    try:
        value = parse_json_strict(text)
    except (TypeError, ValueError, RecursionError):
        value = None
    if isinstance(value, dict) and "signature" not in value and isinstance(value.get("data"), dict):
        value = value["data"]
    return check_certificate(value, jwks, key_history=key_history, allow_sandbox=allow_sandbox, now=now)


# --- Command line ---------------------------------------------------------------------------------

USAGE = """Usage: apier_receipt_verify.py <certificate.json | -> [--sandbox] [--jwks <file|url>] [--key-history <file|url>] [--json]

  <certificate.json | ->   the certificate (or the full API response), from a file or stdin
  --sandbox                use the sandbox key set and allow sandbox certificates
  --jwks <file|url>        key set to check against (default: Apier's production key set)
  --key-history <file|url> signed key history; used only when its own signature checks
  --json                   print the result object as JSON

Exit code: 0 when reason is none, 1 when a reason is set, 2 on a usage or network error."""


class _UsageError(Exception):
    pass


def _parse_args(argv):
    options = {"file": None, "sandbox": False, "jwks": None, "key_history": None, "json": False}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--sandbox":
            options["sandbox"] = True
        elif arg == "--json":
            options["json"] = True
        elif arg in ("--jwks", "--key-history"):
            i += 1
            if i >= len(argv):
                raise _UsageError(arg + " needs a file or an https URL")
            options["jwks" if arg == "--jwks" else "key_history"] = argv[i]
        elif arg != "-" and arg.startswith("-"):
            raise _UsageError("unknown option " + arg)
        elif options["file"] is not None:
            raise _UsageError("give one certificate file, or - for stdin")
        else:
            options["file"] = arg
        i += 1
    if options["file"] is None:
        raise _UsageError("no certificate given")
    return options


def _decode_text(data):
    return data.decode("utf-8-sig")  # strict UTF-8; a leading byte order mark is dropped


def _load_json(source, label):
    """A key set or key history from a local file or an https URL."""
    if re.match(r"https://", source, re.IGNORECASE):
        import urllib.error
        import urllib.request

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        try:
            request = urllib.request.Request(source, headers={"User-Agent": "apier-receipt-verify"})
            with urllib.request.build_opener(NoRedirect).open(request, timeout=15) as response:
                data = response.read()
        except urllib.error.HTTPError as error:
            raise RuntimeError("%s: %s answered HTTP %d" % (label, source, error.code))
        except OSError:
            raise RuntimeError("%s: could not fetch %s" % (label, source))
    elif re.match(r"[a-z][a-z0-9+.-]*://", source, re.IGNORECASE):
        raise _UsageError(label + ": only https URLs and local files are read")
    else:
        with open(source, "rb") as handle:
            data = handle.read()
    try:
        return parse_json_strict(_decode_text(data))
    except (ValueError, RecursionError):
        raise RuntimeError("%s: %s is not valid JSON" % (label, source))


def _ascii_only(dumped):
    # Printable ASCII only, so nothing read from a file can drive the terminal. json.dumps has
    # already escaped everything else.
    return dumped.replace("\x7f", "\\u007f")


def _quote(text):
    return _ascii_only(json.dumps(text))


def _render(result):
    findings = result["findings"]
    kid = "" if result["kid"] is None else " (kid %s)" % _quote(result["kid"])
    stale = "not stated" if result["stale"] is None else ("true" if result["stale"] else "false")
    return "\n".join([
        "signature: " + findings["signature"],
        "signing_key: " + findings["signing_key"] + kid,
        "environment: " + findings["environment"],
        "format_version: " + findings["format_version"],
        "issued_at: " + ("not read" if result["issued_at"] is None else _quote(result["issued_at"])),
        "stale: " + stale,
        "reason: " + (result["reason"] or "none"),
    ])


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--help" in argv or "-h" in argv:
        print(USAGE)
        return 0
    try:
        options = _parse_args(argv)
        if options["file"] == "-":
            certificate_bytes = sys.stdin.buffer.read()
        else:
            with open(options["file"], "rb") as handle:
                certificate_bytes = handle.read()
        jwks = _load_json(options["jwks"] or (SANDBOX_JWKS if options["sandbox"] else PRODUCTION_JWKS), "key set")
        key_history = None
        if options["key_history"] is not None:
            key_history = _load_json(options["key_history"], "key history")
            if not verify_key_history(key_history, jwks):
                sys.stderr.write("warning: the key history was ignored: its signature does not check against this key set\n")
    except _UsageError as error:
        sys.stderr.write("%s\n\n%s\n" % (error, USAGE))
        return 2
    except (OSError, RuntimeError) as error:
        sys.stderr.write("%s\n" % error)
        return 2
    try:
        text = _decode_text(certificate_bytes)
    except UnicodeDecodeError:
        text = None  # not UTF-8: check_certificate_text answers malformed_certificate for it
    result = check_certificate_text(text, jwks, key_history=key_history, allow_sandbox=options["sandbox"])
    sys.stdout.write((_ascii_only(json.dumps(result, indent=2)) if options["json"] else _render(result)) + "\n")
    return 0 if result["reason"] is None else 1


if __name__ == "__main__":
    sys.exit(main())
