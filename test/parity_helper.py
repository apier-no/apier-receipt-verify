"""Used by test/parity.mjs: runs the Python verifier over a file of generated inputs and prints
the results as JSON, so they can be compared with the Node verifier's results."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))

import apier_receipt_verify as verifier  # noqa: E402


def canonical(text):
    try:
        return verifier.canonical_json(verifier.parse_json_strict(text))
    except (TypeError, ValueError, OverflowError, RecursionError):
        return None


def check(case):
    options = {"key_history": case.get("key_history"), "allow_sandbox": case["allow_sandbox"]}
    if "certificate_text" in case:
        return verifier.check_certificate_text(case["certificate_text"], case["jwks"], **options)
    return verifier.check_certificate(case["certificate"], case["jwks"], **options)


def main():
    with open(sys.argv[1], encoding="utf-8") as handle:
        work = json.load(handle)
    out = {
        "canonical": [canonical(text) for text in work["canonical"]],
        "results": [check(case) for case in work["cases"]],
    }
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
