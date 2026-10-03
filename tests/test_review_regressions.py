import copy
import hashlib
import io
import json
from pathlib import Path
import sys
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
