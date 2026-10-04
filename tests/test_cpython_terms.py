import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from audit_cpython_terms import audit, sha


class CPythonTests(unittest.TestCase):
    def fixture(self):
        source = {"Lib/a.py": b"# terms\n", "Modules/a.c": b"/* MIT */"}
        base = "usr/local/lib/python3.13/"
        installed = {
            base + "_sysconfigdata_test.py": b"build_time_vars = {'MODULE_A_DEPS':'bundled.a'}",
            base + "a.py": source["Lib/a.py"],
            base + "lib-dynload/a.test.so": b"compiled",
        }
        rules = []
        for name, path, selector, mode, key, indicator, expr in [
            ("py", "Lib/a.py", "a.py", "source-match", "", "", "LicenseRef-test"),
            (
                "c",
                "Modules/a.c",
                "lib-dynload/a.*.so",
                "binary-build",
                "MODULE_A_DEPS",
                "bundled.a",
                "MIT",
            ),
        ]:
            rules.append(
                {
                    "name": name,
                    "version": "3.13.16",
                    "archive_sha256": "archive",
                    "source_path": path,
                    "source_sha256": sha(source[path]),
                    "notice_path": path,
                    "notice_sha256": sha(source[path]),
                    "installed_selector": selector,
                    "mode": mode,
                    "build_key": key,
                    "build_indicator": indicator,
                    "expression": expr,
                }
            )
        bom = {
            "components": [
                {
                    "name": "python",
                    "version": "3.13.16",
                    "bom-ref": "py",
                    "purl": "pkg:generic/python@3.13.16",
                    "licenses": [{"expression": "Python-2.0.1"}],
                }
            ]
        }
        return (
            bom,
            installed,
            source,
            rules,
            {"PYTHON_VERSION": "3.13.16", "PYTHON_SHA256": "archive"},
        )

    def test_confirmed_source_and_inferred_binary_are_distinguished(self):
        bom, installed, source, rules, env = self.fixture()
        original = copy.deepcopy(bom)
        result, report, notices = audit(bom, installed, source, rules, "archive", env)
        self.assertEqual(bom, original)
        self.assertIn("MIT", result["components"][0]["licenses"][0]["expression"])
        self.assertEqual(report["terms"][0]["assessment"], "confirmed-source-bytes-and-notice")
        self.assertTrue(report["terms"][1]["assessment"].startswith("inferred"))
        self.assertEqual(len(report["unresolved"]), 1)
        self.assertTrue(notices)

    def test_source_change_cannot_inherit_terms(self):
        bom, installed, source, rules, env = self.fixture()
        installed["usr/local/lib/python3.13/a.py"] = b"patched"
        result, report, _ = audit(bom, installed, source, rules, "archive", env)
        self.assertNotIn("LicenseRef-test", result["components"][0]["licenses"][0]["expression"])
        self.assertTrue(any("differs" in x["reason"] for x in report["unresolved"]))

    def test_wrong_image_source_hash_rejected(self):
        bom, installed, source, rules, env = self.fixture()
        env["PYTHON_SHA256"] = "other"
        with self.assertRaisesRegex(ValueError, "association mismatch"):
            audit(bom, installed, source, rules, "archive", env)

    def test_external_build_does_not_inherit_bundled_license(self):
        bom, installed, source, rules, env = self.fixture()
        installed["usr/local/lib/python3.13/_sysconfigdata_test.py"] = (
            b"build_time_vars = {'MODULE_A_DEPS':'external.so'}"
        )
        result, report, _ = audit(bom, installed, source, rules, "archive", env)
        self.assertNotIn("MIT", result["components"][0]["licenses"][0]["expression"])
        self.assertTrue(any("indicator" in x["reason"] for x in report["unresolved"]))
