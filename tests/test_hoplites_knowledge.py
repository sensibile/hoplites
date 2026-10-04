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
from hoplites_knowledge import component_architecture


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
            "var/lib/dpkg/status": b"Package: example\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1\n\nPackage: consumer\nStatus: install ok installed\nVersion: 2\nArchitecture: arm64\nDepends: libc6,\n example (= 1)\n\nPackage: pre-consumer\nStatus: install ok installed\nVersion: 2\nArchitecture: arm64\nPre-Depends: libc6,\n\texample (= 1)\n\nPackage: false-match\nStatus: install ok installed\nVersion: 2\nDepends: example-extra\n",
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
                [d["package"] for d in facts["reverse_dependency_declarations"]],
                ["consumer", "pre-consumer"],
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

    def test_cli_uses_selected_debian_architecture_for_multiarch_and_arm_variant(self):
        script = Path(__file__).parents[1] / "scripts/hoplites_knowledge.py"
        for arch, platform in (("i386", "linux/amd64"), ("armhf", "linux/arm/v7")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                bom = copy.deepcopy(self.bom)
                purl = "pkg:deb/debian/example@1?arch=" + arch
                bom["components"][0]["purl"] = purl
                (root / "bom.json").write_bytes(encode(bom))
                (root / "scopes.json").write_bytes(encode(self.scopes))
                with tarfile.open(root / "rootfs.tar", "w") as archive:
                    for name, raw in {
                        "var/lib/dpkg/info/example:"
                        + arch
                        + ".list": b"/usr/share/doc/example/copyright\n",
                        "var/lib/dpkg/status": (
                            "Package: example\nStatus: install ok installed\nArchitecture: "
                            + arch
                            + "\nVersion: 1\n"
                        ).encode(),
                    }.items():
                        info = tarfile.TarInfo(name)
                        info.size = len(raw)
                        archive.addfile(info, io.BytesIO(raw))
                run = subprocess.run(
                    [
                        sys.executable,
                        str(script),
                        "prepare",
                        "--bom",
                        str(root / "bom.json"),
                        "--scopes",
                        str(root / "scopes.json"),
                        "--purl",
                        purl,
                        "--manifest",
                        "sha256:" + "a" * 64,
                        "--platform",
                        platform,
                        "--rootfs",
                        str(root / "rootfs.tar"),
                        "--output",
                        str(root / "bundle.json"),
                    ],
                    capture_output=True,
                )
                self.assertEqual(run.returncode, 0, run.stderr)
                records = json.loads((root / "bundle.json").read_text())["write_template"][
                    "request"
                ]["operations"]
                installation = json.loads(records[0]["record"]["content"])["installation"]
                self.assertEqual(installation["architecture"], arch)
        for purl in (
            "pkg:deb/debian/example@1",
            "pkg:deb/debian/example@1?arch=",
            "pkg:deb/debian/example@1?arch=arm64&arch=i386",
        ):
            with self.assertRaises(ValueError):
                component_architecture({"purl": purl})

    def test_verifier_comparisons_cannot_be_removed_by_optimization(self):
        scripts = str(Path(__file__).parents[1] / "scripts")
        code = "import sys; sys.path.insert(0, sys.argv[1]); from check_acropolis_consumer import require; require(False, 'intentional mismatch')"
        for flags in ([], ["-O"]):
            run = subprocess.run(
                [sys.executable] + flags + ["-c", code, scripts], capture_output=True
            )
            self.assertNotEqual(run.returncode, 0)
            self.assertIn(b"intentional mismatch", run.stderr)

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

    def test_architecture_scoped_knowledge_uses_debian_package_identity(self):
        for arch, platform in (("i386", "linux/amd64"), ("armhf", "linux/arm/v7")):
            with self.subTest(arch=arch):
                bundle = copy.deepcopy(self.bundle)
                bundle["subject"] = "pkg:deb/debian/example@1?arch=" + arch
                bundle["artifact"]["platform"] = platform
                snapshot = copy.deepcopy(self.snapshot)
                for op in bundle["write_template"]["request"]["operations"]:
                    if op["op"] == "put":
                        snapshot["graph"]["records"][op["record"]["id"]] = copy.deepcopy(
                            op["record"]
                        )
                extra = copy.deepcopy(next(iter(snapshot["graph"]["records"].values())))
                extra.update(id="arch-support", subject=bundle["subject"])
                extra["conditions"] = dict(bundle["artifact"], architecture=arch)
                snapshot["graph"]["records"][extra["id"]] = extra
                self.assertIn("arch-support", report(bundle, snapshot, 1)["records"])

    def test_transitive_support_rejects_conflicting_conditions_but_allows_reuse(self):
        target = self.bundle["record_ids"][-1]
        for key, wrong in (
            ("image_manifest", "sha256:" + "d" * 64),
            ("package_version", "2"),
            ("platform", "linux/amd64"),
            ("architecture", "i386"),
        ):
            snapshot = copy.deepcopy(self.snapshot)
            template = next(iter(snapshot["graph"]["records"].values()))
            for name, conditions in (("conflict", {key: wrong}), ("reusable", {})):
                r = copy.deepcopy(template)
                r.update(id=name, subject="other", conditions=conditions)
                snapshot["graph"]["records"][name] = r
                snapshot["graph"]["links"].append({"from": name, "to": target, "kind": "supports"})
            result = report(self.bundle, snapshot, 1)
            self.assertNotIn("conflict", result["records"])
            self.assertIn("conflict", result["excluded_condition_records"])
            self.assertIn("reusable", result["records"])

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
