"""Run with: python -m unittest discover -s test"""

import hashlib
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "vectors")
MODULE = os.path.join(HERE, "..", "python", "apier_receipt_verify.py")
sys.path.insert(0, os.path.join(HERE, "..", "python"))

import apier_receipt_verify as verifier  # noqa: E402


def read_text(name):
    with open(os.path.join(VECTORS, name), encoding="utf-8") as handle:
        return handle.read()


def read(name):
    return json.loads(read_text(name))


def load_cases(name):
    document = read(name)

    def named(table, key):
        return read(table[key]) if isinstance(table[key], str) else table[key]

    cases = []
    for case in document["cases"]:
        case = dict(case)
        case["jwks"] = named(document["keysets"], case["jwks"])
        case["key_history"] = named(document["key_histories"], case["key_history"]) if case.get("key_history") else None
        if "certificate_file" in case:
            case["certificate"] = read(case["certificate_file"])
        cases.append(case)
    return cases


def run(case):
    options = {"key_history": case["key_history"], "allow_sandbox": case["allow_sandbox"]}
    if "certificate_text" in case:
        return verifier.check_certificate_text(case["certificate_text"], case["jwks"], **options)
    return verifier.check_certificate(case["certificate"], case["jwks"], **options)


def cli(*args, **kwargs):
    return subprocess.run([sys.executable, MODULE] + list(args), capture_output=True, **kwargs)


class CanonicalJson(unittest.TestCase):
    def test_vector_from_the_guide(self):
        vector = read("canonical-vector.json")
        data = verifier.canonical_json(json.loads(vector["input"])).encode("utf-8")
        self.assertEqual(data.decode("utf-8"), vector["canonical"])
        self.assertEqual(len(data), 131)
        self.assertEqual(len(data), vector["bytes"])
        self.assertEqual(hashlib.sha256(data).hexdigest(), vector["sha256"])

    def test_generated_cases(self):
        cases = read("canonical-cases.json")["cases"]
        self.assertGreater(len(cases), 100)
        for case in cases:
            with self.subTest(input=case["input"]):
                self.assertEqual(verifier.canonical_json(json.loads(case["input"])), case["canonical"])

    def test_refuses_what_has_no_canonical_form(self):
        for value in (float("nan"), float("inf"), float("-inf"), 10**400, (1, 2), {1: "a"}, b"bytes", {"a": [object()]}):
            with self.subTest(value=repr(value)[:40]):
                with self.assertRaises((TypeError, ValueError, OverflowError)):
                    verifier.canonical_json(value)


class StrictJson(unittest.TestCase):
    def test_refuses_a_repeated_key_at_any_depth(self):
        for text in ('{"a":1,"a":2}', '{"a":{"b":1,"b":1}}', '[{"a":1,"\\u0061":2}]', '{"a":[{"x":1,"y":2,"x":3}]}'):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    verifier.parse_json_strict(text)

    def test_keeps_everything_else(self):
        for text in ('{"a":1,"b":{"a":1}}', '[{"a":1},{"a":2}]', '{"a":"\\"a\\":1,\\"a\\":2"}', '{"a,":1,"a":[1,2],"{":{"a":1}}', "{}", "[]", '"x"'):
            with self.subTest(text=text):
                self.assertEqual(verifier.parse_json_strict(text), json.loads(text))

    def test_refuses_what_is_not_json(self):
        for text in ('{"a":1,}', "NaN", "[Infinity]", "[-Infinity]"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    verifier.parse_json_strict(text)


class Cases(unittest.TestCase):
    maxDiff = None

    def test_sandbox_cases(self):
        for case in load_cases("sandbox-cases.json"):
            with self.subTest(case=case["name"]):
                self.assertEqual(run(case), case["expect"], case["note"])

    def test_synthetic_cases(self):
        for case in load_cases("synthetic-cases.json"):
            with self.subTest(case=case["name"]):
                self.assertEqual(run(case), case["expect"], case["note"])

    def test_every_reason_code_is_exercised(self):
        used = set()
        for name in ("sandbox-cases.json", "synthetic-cases.json"):
            used.update(case["expect"]["reason"] for case in read(name)["cases"])
        used.discard(None)
        self.assertEqual(sorted(used), sorted(verifier.REASONS))

    def test_findings_agree_with_apiers_own_receipt_check(self):
        official = read("official-findings.json")["vectors"]
        cases = {case["name"]: case for case in load_cases("sandbox-cases.json")}
        self.assertEqual(len(official), 8)
        for name, findings in official.items():
            with self.subTest(vector=name):
                self.assertEqual(run(cases[name])["findings"], findings)

    def test_result_never_carries_an_overall_verdict(self):
        case = load_cases("sandbox-cases.json")[0]
        result = verifier.check_certificate(case["certificate"], case["jwks"], allow_sandbox=True)
        self.assertEqual(sorted(result), ["alg", "findings", "is_sandbox", "issued_at", "kid", "reason", "stale"])
        self.assertEqual(sorted(result["findings"]), ["environment", "format_version", "signature", "signing_key"])

    def test_certificate_jwks_uri_is_never_used(self):
        certificate = read("sandbox-verify-999000001.json")
        result = verifier.check_certificate(certificate, {"keys": []}, allow_sandbox=True)
        self.assertEqual(result["reason"], "unknown_kid")


class CommandLine(unittest.TestCase):
    certificate = os.path.join(VECTORS, "sandbox-verify-999000001.json")
    jwks = os.path.join(VECTORS, "sandbox-jwks.json")

    def test_output_and_offline_use(self):
        done = cli(self.certificate, "--sandbox", "--jwks", self.jwks)
        self.assertEqual(done.returncode, 0)
        text = done.stdout.decode("utf-8").replace("\r\n", "\n")
        self.assertEqual(text, "\n".join([
            "signature: matches",
            'signing_key: sandbox (kid "apier-sandbox-cert-1")',
            "environment: sandbox",
            "format_version: recognised",
            'issued_at: "2026-01-01T09:00:00+01:00"',
            "stale: false",
            "reason: none",
            "",
        ]))
        self.assertNotRegex(text.lower(), r"\bvalid\b")

    def test_exit_codes(self):
        refused = cli(self.certificate, "--jwks", self.jwks)
        self.assertEqual(refused.returncode, 1)
        self.assertIn(b"reason: sandbox_not_allowed", refused.stdout)
        with open(self.certificate, "rb") as handle:
            as_json = cli("-", "--sandbox", "--jwks", self.jwks, "--json", input=handle.read())
        self.assertEqual(as_json.returncode, 0)
        self.assertIsNone(json.loads(as_json.stdout)["reason"])
        self.assertEqual(cli().returncode, 2)
        self.assertEqual(cli(self.certificate, "--nope").returncode, 2)
        self.assertEqual(cli(os.path.join(VECTORS, "absent.json"), "--jwks", self.jwks).returncode, 2)
        self.assertEqual(cli(self.certificate, "--jwks", os.path.join(VECTORS, "absent.json")).returncode, 2)
        self.assertEqual(cli(self.certificate, "--jwks", "http://www.apier.no/.well-known/jwks.json").returncode, 2)


if __name__ == "__main__":
    unittest.main()
