import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from license_fields import normalize, validate
from license_scope import attach, collect, record


class LicenseFieldTests(unittest.TestCase):
    def test_digest_evidence_preserved_and_valid_terms_unchanged(self):
        bad = {"license": {"name": "sha256:" + "a" * 64}}
        c = {"name": "mixed", "bom-ref": "c", "licenses": [bad, {"license": {"id": "MIT"}}]}
        target = record(
            c,
            "src/*",
            "source-file-declaration",
            "GPL-2.0-only",
            "unknown",
            "unknown",
            {"copyright": "Author"},
        )
        attach(c, [target], "Scanner declaration, separate source scopes")
        bom = {"components": [c]}
        before = copy.deepcopy(bom)
        out, report = normalize(bom)
        self.assertEqual(before, bom)
        self.assertEqual(out["components"][0]["licenses"], [{"license": {"id": "MIT"}}])
        rows = collect(out)
        self.assertEqual(rows[0]["id"], target["id"])
        self.assertEqual(rows[1]["evidence"]["scanner_declaration"], bad)
        self.assertIsNone(rows[1]["declared_expression"])
        self.assertEqual(len(report["unresolved"]), 1)
        self.assertEqual(normalize(out)[0], out)
        with self.assertRaises(ValueError):
            validate(before)

    def test_hash_only_is_unknown_not_fabricated_license(self):
        for item in [
            {"license": {"name": "SHA-256:" + "b" * 64}},
            {"license": {"id": "c" * 64}},
            {"expression": "md5:" + "d" * 32},
        ]:
            out, _ = normalize({"components": [{"name": "p", "bom-ref": "p", "licenses": [item]}]})
            self.assertNotIn("licenses", out["components"][0])
            self.assertEqual(collect(out)[0]["applicability"], "unknown")

    def test_real_license_names_and_refs_are_not_rejected(self):
        items = [
            {"expression": "MIT AND LicenseRef-Node-" + "a" * 16},
            {"license": {"name": "public-domain-sha1"}},
            {"license": {"name": "BSD-3-clause-Aaron-D-Gifford"}},
        ]
        bom = {"components": [{"name": "p", "bom-ref": "p", "licenses": items}]}
        self.assertEqual(normalize(bom)[0], bom)
        validate(bom)


if __name__ == "__main__":
    unittest.main()
