import copy
import json
import io
import tarfile
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from hoplites_knowledge import encode, prepare, report, installation_from_tar
from render_knowledge_report import render, draft
from acropolis_consumer import endpoint, checked_response, ConsumerError


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

    def test_tar_inventory_and_reverse_dependency_boundary(self):
        files = {
            "var/lib/dpkg/info/example:arm64.list": b"/.\n/usr\n/usr/share/doc/example/copyright\n",
            "var/lib/dpkg/status": b"Package: example\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1\n\nPackage: consumer\nStatus: install ok installed\nVersion: 2\nArchitecture: arm64\nDepends: example (= 1), libc6\n\nPackage: false-match\nStatus: install ok installed\nVersion: 2\nDepends: example-extra\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rootfs.tar"
            with tarfile.open(path, "w") as archive:
                for name, data in files.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            facts, digest = installation_from_tar(path, "example", "arm64", "1")
            self.assertTrue(facts["documentation_paths_only"])
            self.assertEqual(
                [d["package"] for d in facts["reverse_dependency_declarations"]], ["consumer"]
            )
            self.assertEqual(len(digest), 64)
            with self.assertRaises(ValueError):
                installation_from_tar(path, "example", "arm64", "2")
            with tarfile.open(path, "a") as archive:
                info = tarfile.TarInfo("./var/lib/dpkg/status")
                info.size = 0
                archive.addfile(info, io.BytesIO())
            with self.assertRaises(ValueError):
                installation_from_tar(path, "example", "arm64", "1")
            self.assertFalse((Path(directory) / "var").exists())

    def test_report_html_preserves_work_and_escapes_untrusted_sources(self):
        value = draft(self.bundle)
        body = render(value)
        self.assertIn("지식 저장 전", body)
        self.assertIn("미확인", body)
        self.assertIn("미검증", body)
        self.assertIn("Inspect exact shipped document terms.", body)
        self.assertNotIn("<script", body)
        record = next(iter(value["records"].values()))
        record["author"]["name"] = '<script>alert("injected")</script>'
        body = render(value)
        self.assertNotIn("<script", body)
        self.assertIn("&lt;script&gt;", body)
        self.assertEqual(body, render(value))

    def test_authentication_and_endpoint_claims_are_not_accepted_from_caller(self):
        for url in (
            "http://example.com/v1/tenants/hoplites/knowledge",
            "http://127.0.0.1:9000/v1/tenants/other/knowledge",
            "http://user:secret@127.0.0.1:9000/v1/tenants/hoplites/knowledge",
            "http://127.0.0.1:9000/v1/tenants/hoplites/knowledge?redirect=other",
        ):
            with self.assertRaises(ConsumerError):
                endpoint(url)
        for value in (
            {"ok": True, "tenant": "other", "principal": "service"},
            {"ok": True, "tenant": "hoplites", "principal": "other"},
            {"ok": False, "tenant": "hoplites", "principal": "service"},
        ):
            with self.assertRaises(ConsumerError):
                checked_response(value, "service")

    def test_same_purl_from_another_artifact_is_not_reused(self):
        other = copy.deepcopy(next(iter(self.snapshot["graph"]["records"].values())))
        other["id"] = "other-image"
        other["conditions"]["image_manifest"] = "sha256:" + "d" * 64
        self.snapshot["graph"]["records"][other["id"]] = other
        result = report(self.bundle, self.snapshot, 1)
        self.assertNotIn("other-image", result["records"])
        self.assertEqual(result["excluded_condition_records"], ["other-image"])

    def test_scanner_digest_is_preserved_as_observation_not_another_license_task(self):
        row = self.scopes["records"][0]
        row["relation"] = "scanner-evidence-reference"
        row["evidence"]["scanner_declaration"] = {"license": {"name": "sha256:" + "b" * 64}}
        bundle = prepare(
            self.bom,
            self.scopes,
            "pkg:deb/example@1",
            "sha256:" + "a" * 64,
            "linux/arm64",
            {"bom": "b" * 64, "scopes": "c" * 64},
        )
        records = [
            op["record"]
            for op in bundle["write_template"]["request"]["operations"]
            if op["op"] == "put"
        ]
        self.assertFalse(any(r["kind"] == "question" for r in records))
        observed = next(r for r in records if r["kind"] == "statement")
        content = json.loads(observed["content"])
        self.assertEqual(content["applicability"], "unknown")
        self.assertIn("not license terms", content["observation"])


if __name__ == "__main__":
    unittest.main()
