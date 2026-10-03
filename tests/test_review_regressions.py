import copy
import csv
import hashlib
import io
import json
from pathlib import Path
import sys
import subprocess
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from image_pipeline import Pipeline, database, SYFT, TRIVY
from normalize_debian_bom import process


def archive(path, files):
    with tarfile.open(path, "w") as tar:
        for name, raw in files.items():
            item = tarfile.TarInfo(name)
            item.size = len(raw)
            tar.addfile(item, io.BytesIO(raw))


class ReviewRegressions(unittest.TestCase):
    def test_debian_csv_quotes_supplier_reference_after_verified_replay(self):
        scripts = Path(__file__).parents[1] / "scripts"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive(
                root / "rootfs.tar",
                {
                    "var/lib/dpkg/status": b"Package: pkg\nStatus: install ok installed\nVersion: 1\nArchitecture: arm64\n",
                    "var/lib/dpkg/info/pkg.list": b"/usr/bin/a\n",
                    "usr/bin/a": b"abc",
                    "usr/share/doc/pkg/copyright": b"Files: *\nLicense: Expat\n",
                },
            )
            original = {
                "components": [
                    {
                        "bom-ref": "pkg",
                        "name": "pkg",
                        "version": "1",
                        "type": "library",
                        "purl": "pkg:deb/ubuntu/pkg@1",
                    },
                    {
                        "bom-ref": "os",
                        "name": "ubuntu",
                        "version": "24.04",
                        "type": "operating-system",
                    },
                    {
                        "bom-ref": "=1+1",
                        "name": "/usr/bin/a",
                        "type": "file",
                        "hashes": [
                            {"alg": "SHA-256", "content": hashlib.sha256(b"abc").hexdigest()}
                        ],
                    },
                ]
            }
            db = database()
            self.addCleanup(db.close)
            bom, report, sources = process(
                original,
                root / "rootfs.tar",
                dict(db.execute("SELECT label,spdx_expression FROM debian_license_alias")),
            )
            (root / "syft.cdx.json").write_text(json.dumps(original))
            (root / "normalized-v2.cdx.json").write_text(json.dumps(bom))
            report.update(
                input_sha256=hashlib.sha256((root / "syft.cdx.json").read_bytes()).hexdigest(),
                output_sha256=hashlib.sha256(
                    (root / "normalized-v2.cdx.json").read_bytes()
                ).hexdigest(),
                rootfs_sha256=hashlib.sha256((root / "rootfs.tar").read_bytes()).hexdigest(),
            )
            (root / "normalization-v2-evidence.json").write_text(json.dumps(report))
            for path, raw in sources.items():
                target = root / "normalization-v2-sources" / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            for name in [
                "trivy.cdx.json",
                "image-ref.txt",
                "image-inspect.json",
                "Dockerfile.upstream",
                "dt-upload.json",
                "dt-verification.json",
                "syft-run.json",
                "trivy-run.json",
            ]:
                (root / name).write_text("{}")
            subprocess.run(
                [
                    sys.executable,
                    str(scripts / "build_debian_evidence_bundle.py"),
                    "--experiment",
                    str(root),
                    "--output-dir",
                    str(root / "bundle"),
                ],
                check=True,
                capture_output=True,
            )
            with (root / "bundle/excluded-files.csv").open() as stream:
                rows = list(csv.reader(stream))
            self.assertEqual(rows[1][1], "'=1+1")
            self.assertEqual(json.loads((root / "bundle/syft.cdx.json").read_bytes()), original)
            self.assertTrue((root / "bundle/scripts/build_evidence_bundle.py").exists())

    def test_empty_dt_export_without_arrays_through_collector_and_builder(self):
        scripts = Path(__file__).parents[1] / "scripts"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "metadata": {"component": {"bom-ref": "project", "version": "sha256:abc"}},
            }
            sbom = {"metadata": {"component": {"version": "sha256:abc"}}, "components": []}
            (root / "export.json").write_text(json.dumps(export))
            (root / "sbom.json").write_text(json.dumps(sbom))
            archive(
                root / "rootfs.tar",
                {
                    "var/lib/dpkg/status": b"",
                    "usr/lib/os-release": b'ID=ubuntu\nVERSION_ID="24.04"\n',
                },
            )
            (root / "evidence.json").write_text(
                json.dumps(
                    {
                        "rootfs_sha256": hashlib.sha256(
                            (root / "rootfs.tar").read_bytes()
                        ).hexdigest(),
                        "output_sha256": hashlib.sha256(
                            (root / "sbom.json").read_bytes()
                        ).hexdigest(),
                    }
                )
            )
            (root / "reviewed").mkdir()
            subprocess.run(
                [
                    sys.executable,
                    str(scripts / "collect_project_advisories.py"),
                    "--export",
                    str(root / "export.json"),
                    "--output-dir",
                    str(root / "snapshot"),
                    "--cache",
                    str(root / "cache.sqlite"),
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    str(scripts / "build_project_vex.py"),
                    "--export",
                    str(root / "export.json"),
                    "--sbom",
                    str(root / "sbom.json"),
                    "--normalization-evidence",
                    str(root / "evidence.json"),
                    "--rootfs",
                    str(root / "rootfs.tar"),
                    "--index",
                    str(root / "snapshot/advisory-index.json"),
                    "--sources",
                    str(root / "snapshot/advisories"),
                    "--reviewed-sources",
                    str(root / "reviewed"),
                    "--output",
                    str(root / "vex.json"),
                    "--evidence",
                    str(root / "decisions.json"),
                ],
                check=True,
                capture_output=True,
            )
            self.assertEqual(json.loads((root / "vex.json").read_bytes())["vulnerabilities"], [])
            self.assertEqual(
                json.loads((root / "decisions.json").read_bytes())["coverage"]["finding_pairs"], 0
            )

    def test_submission_csv_quotes_formula_and_preserves_original_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = {"components": [{"bom-ref": "=1+1", "name": "=1+1", "type": "file"}]}
            bom = {"components": []}
            for name in [
                "original.cdx.json",
                "normalized.cdx.json",
                "normalization-evidence.json",
                "image.json",
                "commands.json",
                "summary.json",
            ]:
                (root / name).write_text(
                    json.dumps(original if name == "original.cdx.json" else bom)
                )
            (root / "rootfs.tar").write_bytes(b"rootfs")
            (root / "image-save.tar").write_bytes(b"image")
            Pipeline(root, root / "cache").bundle(original, bom)
            with (root / "submission/excluded-components.csv").open() as stream:
                rows = list(csv.reader(stream))
            self.assertEqual(rows[1][:2], ["'=1+1", "'=1+1"])
            self.assertEqual(rows[1][3], "")
            self.assertEqual(
                json.loads((root / "submission/original.cdx.json").read_bytes()), original
            )

    def test_multiarch_packages_licenses_and_ownership(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            status = b""
            files = {}
            components = []
            for arch, label in [("arm64", "MIT"), ("amd64", "Apache-2.0")]:
                status += f"Package: pkg\nStatus: install ok installed\nVersion: 1\nArchitecture: {arch}\n\n".encode()
                binary = f"/usr/bin/{arch}"
                files["var/lib/dpkg/info/pkg:" + arch + ".list"] = (binary + "\n/shared\n").encode()
                files["usr/share/doc/pkg:" + arch + "/copyright"] = (
                    f"Files: *\nLicense: {label}\n".encode()
                )
                files[binary.lstrip("/")] = arch.encode()
                components.append(
                    {
                        "bom-ref": arch,
                        "name": "pkg",
                        "version": "1",
                        "type": "library",
                        "purl": "pkg:deb/ubuntu/pkg@1?arch=" + arch,
                    }
                )
                components.append(
                    {
                        "bom-ref": "file-" + arch,
                        "name": binary,
                        "type": "file",
                        "hashes": [
                            {"alg": "SHA-256", "content": hashlib.sha256(arch.encode()).hexdigest()}
                        ],
                    }
                )
            files["var/lib/dpkg/status"] = status
            files["shared"] = b"shared"
            components.extend(
                [
                    {
                        "bom-ref": "os",
                        "name": "ubuntu",
                        "version": "24.04",
                        "type": "operating-system",
                    },
                    {
                        "bom-ref": "shared",
                        "name": "/shared",
                        "type": "file",
                        "hashes": [
                            {"alg": "SHA-256", "content": hashlib.sha256(b"shared").hexdigest()}
                        ],
                    },
                ]
            )
            archive(root / "rootfs.tar", files)
            original = {"components": components}
            out, report, _ = process(
                original, root / "rootfs.tar", {"mit": "MIT", "apache-2.0": "Apache-2.0"}
            )
            packages = {c["bom-ref"]: c for c in out["components"]}
            self.assertEqual(packages["arm64"]["licenses"], [{"expression": "MIT"}])
            self.assertEqual(packages["amd64"]["licenses"], [{"expression": "Apache-2.0"}])
            self.assertIn("shared", packages)
            self.assertEqual(report["file_normalization"]["removed_count"], 2)
            invalid = copy.deepcopy(original)
            invalid["components"][0]["purl"] = "pkg:deb/ubuntu/pkg@1"
            with self.assertRaisesRegex(ValueError, "architecture"):
                process(invalid, root / "rootfs.tar", {})
            invalid = copy.deepcopy(original)
            invalid["components"].append(copy.deepcopy(invalid["components"][0]))
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                process(invalid, root / "rootfs.tar", {})

    def test_runtime_license_on_dpkg_and_unknown_package_database(self):
        for dpkg in [False, True]:
            with self.subTest(dpkg=dpkg), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                out = root / "out"
                out.mkdir()
                cache = root / "cache"
                (cache / "blobs").mkdir(parents=True)
                license_raw = b"Apache License\nVersion 2.0"
                license_hash = hashlib.sha256(license_raw).hexdigest()
                (cache / "blobs" / license_hash).write_bytes(license_raw)
                db = database()
                self.addCleanup(db.close)
                db.execute(
                    "UPDATE runtime_enrichment_release SET license_sha256=?,version_marker='elixir.app' WHERE name='elixir'",
                    (license_hash,),
                )
                files = {"elixir.app": b'{application,elixir,[{vsn,"1.18.4"}]}.'}
                if dpkg:
                    files["var/lib/dpkg/status"] = b""
                archive(root / "rootfs.tar", files)
                bom = {
                    "metadata": {"component": {"version": "sha256:" + "a" * 64}},
                    "components": [
                        {
                            "bom-ref": "runtime",
                            "type": "application",
                            "name": "elixir",
                            "version": "1.18.4",
                            "purl": "pkg:generic/elixir@1.18.4",
                            "properties": [
                                {"name": "syft:location:0:path", "value": "/elixir.app"}
                            ],
                        },
                        {
                            "bom-ref": "os",
                            "type": "operating-system",
                            "name": "ubuntu",
                            "version": "24.04",
                        },
                    ],
                }
                pipe = Pipeline(out, cache)
                normalized = pipe.normalize(
                    bom, root / "rootfs.tar", root / "unused.tar", "image@sha256:" + "a" * 64, db
                )
                runtime = next(c for c in normalized["components"] if c["name"] == "elixir")
                self.assertEqual(runtime["licenses"][0]["license"]["id"], "Apache-2.0")
                self.assertTrue((out / "stages/runtime-evidence.json").exists())

    def test_pinned_scanner_selection_and_evidence(self):
        class FixtureDocker(Pipeline):
            def command(self, args, name):
                self.commands.append(args)
                if name.startswith("resolve-"):
                    return json.dumps(
                        {
                            "digest": args[4].split("@")[1],
                            "manifests": [
                                {
                                    "digest": "sha256:" + "b" * 64,
                                    "platform": {"os": "linux", "architecture": "arm64"},
                                }
                            ],
                        }
                    ).encode()
                if name.startswith("inspect-"):
                    return json.dumps(
                        [
                            {
                                "Id": "sha256:" + "c" * 64,
                                "Os": "linux",
                                "Architecture": "arm64",
                                "RepoDigests": [args[-1]],
                            }
                        ]
                    ).encode()
                return b""

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pipe = FixtureDocker(root, root / "cache")
            for name, pin in [("syft", SYFT), ("trivy", TRIVY)]:
                ref = pipe.scanner(pin, name, "linux/arm64")
                self.assertTrue(ref.endswith("@sha256:" + "b" * 64))
            evidence = json.loads((root / "scanners.json").read_bytes())
            self.assertEqual(evidence["syft"]["pinned_reference"], SYFT)
            self.assertEqual(evidence["trivy"]["image_ref"].split("@")[1], "sha256:" + "b" * 64)
            self.assertTrue(
                all(
                    "@sha256:" in args[-1]
                    for args in pipe.commands
                    if args[:3] == ["docker", "image", "inspect"]
                )
            )
