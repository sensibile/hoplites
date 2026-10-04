import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from hoplites_knowledge import encode, prepare, report


class ConsumerContract(unittest.TestCase):
    def setUp(self):
        self.bom = {
            "components": [
                {
                    "bom-ref": "component-1",
                    "purl": "pkg:deb/example@1",
                    "name": "example",
                    "version": "1",
                }
            ]
        }
        self.scopes = {
            "rule_version": "license-scope-v1",
            "records": [
                {
                    "id": "scope-1",
                    "owner_bom_ref": "component-1",
                    "subject": "notice",
                    "declared_expression": "MIT",
                    "inclusion": "inferred",
                    "applicability": "unknown",
                    "fulfillment": "not-verified",
                    "review_actions": ["Inspect exact shipped document terms."],
                    "evidence": {"path": "/doc/copyright", "sha256": "b" * 64},
                }
            ],
        }
        self.bundle = prepare(
            self.bom,
            self.scopes,
            "pkg:deb/example@1",
            "sha256:" + "a" * 64,
            "linux/arm64",
            {"bom": "b" * 64, "scopes": "c" * 64},
        )
        ops = self.bundle["write_template"]["request"]["operations"]
        self.snapshot = {
            "tenant": "hoplites",
            "version": 1,
            "graph": {
                "records": {op["record"]["id"]: op["record"] for op in ops if op["op"] == "put"},
                "links": [op["link"] for op in ops if op["op"] == "link"],
            },
        }

    def test_scope_uncertainty_and_next_work_survive_without_promotion(self):
        result = report(self.bundle, self.snapshot, 1)
        self.assertEqual(result["authentication"], "not-connected")
        self.assertEqual(result["status"], "offline-draft")
        question = result["records"][result["open_questions"][0]]
        content = json.loads(question["content"])
        self.assertEqual(content["inclusion"], "inferred")
        self.assertEqual(content["applicability"], "unknown")
        self.assertEqual(content["fulfillment"], "not-verified")
        self.assertTrue(content["next_actions"])

    def test_pinned_report_is_unchanged_after_another_revision(self):
        first = encode(report(self.bundle, self.snapshot, 1))
        second = copy.deepcopy(self.snapshot)
        second["version"] = 2
        old = next(iter(second["graph"]["records"].values()))
        second["graph"]["records"]["new-question"] = dict(
            old,
            id="new-question",
            kind="question",
            assessment="unresolved",
            content="new investigation",
        )
        self.assertIn("new-question", report(self.bundle, second, 2)["open_questions"])
        self.assertEqual(first, encode(report(self.bundle, self.snapshot, 1)))
        with self.assertRaises(ValueError):
            report(self.bundle, second, 1)

    def test_missing_cross_namespace_and_mutated_sources_are_rejected(self):
        for tenant in (None, "another-tenant"):
            other = dict(self.snapshot, tenant=tenant)
            with self.assertRaises(ValueError):
                report(self.bundle, other, 1)
        broken = copy.deepcopy(self.snapshot)
        next(iter(broken["graph"]["records"].values()))["sources"][0]["sha256"] = "d" * 64
        with self.assertRaises(ValueError):
            report(self.bundle, broken, 1)
        # These checks are offline namespace/data checks, not authentication tests.

    def test_cli_uses_real_files_and_never_overwrites_or_writes_failed_report(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "bundle.json").write_bytes(encode(self.bundle))
            (path / "snapshot.json").write_bytes(encode(self.snapshot))
            command = [
                sys.executable,
                str(root / "scripts/hoplites_knowledge.py"),
                "report",
                "--bundle",
                str(path / "bundle.json"),
                "--snapshot",
                str(path / "snapshot.json"),
                "--version",
                "1",
                "--output",
                str(path / "report.json"),
            ]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            before = (path / "report.json").read_bytes()
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(before, (path / "report.json").read_bytes())
            command[-1] = str(path / "failed.json")
            command[command.index("--version") + 1] = "99"
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertFalse((path / "failed.json").exists())
            (path / "snapshot.json").write_text('{"tenant":"hoplites","tenant":"other"}')
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertFalse((path / "failed.json").exists())


if __name__ == "__main__":
    unittest.main()
