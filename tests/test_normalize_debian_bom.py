import copy
import hashlib
import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from normalize_debian_bom import fields, license_expression, process


class DebianTests(unittest.TestCase):
    def test_license_relationships_and_unknowns(self):
        refs = {}
        self.assertEqual(license_expression("GPL-2+", {}, "p", "h", refs), "GPL-2.0-or-later")
        self.assertEqual(
            license_expression("GPL-2 or Expat", {"expat": "MIT"}, "p", "h", refs),
            "(GPL-2.0-only) OR (MIT)",
        )
        unknown = license_expression("GPL-3+ with special exception", {}, "p", "h", refs)
        self.assertEqual(refs[unknown]["source_label"], "GPL-3+ with special exception")
        self.assertTrue(
            license_expression("MIT and/or BSD", {}, "p", "h", refs).startswith("LicenseRef-")
        )

    def test_reviewed_mapping_requires_exact_document_and_label(self):
        refs = {}
        rule = {
            (
                "reviewed-hash",
                "GPL-3+ with Bison exception",
            ): "GPL-3.0-or-later WITH Bison-exception-2.2"
        }
        self.assertEqual(
            license_expression(
                "GPL-3+ with Bison exception", {}, "pkg", "reviewed-hash", refs, rule
            ),
            "GPL-3.0-or-later WITH Bison-exception-2.2",
        )
        self.assertTrue(
            license_expression(
                "GPL-3+ with Bison exception", {}, "pkg", "different-hash", refs, rule
            ).startswith("LicenseRef-")
        )
        self.assertTrue(
            license_expression(
                "GPL-3+ with another exception", {}, "pkg", "reviewed-hash", refs, rule
            ).startswith("LicenseRef-")
        )

    def test_control_continuation(self):
        self.assertEqual(fields("License: MIT\n body\n more")["License"], "MIT\nbody\nmore")

    def test_parent_symlink_ownership_and_integrity(self):
        bom = {
            "components": [
                {
                    "bom-ref": "p",
                    "type": "library",
                    "name": "pkg",
                    "version": "1",
                    "purl": "pkg:deb/ubuntu/pkg@1",
                },
                {"bom-ref": "j", "type": "application", "name": "openjdk", "version": "21+1"},
                {"bom-ref": "jar", "type": "library", "name": "jrt-fs", "version": "21"},
                {"bom-ref": "os", "type": "operating-system", "name": "ubuntu", "version": "24.04"},
                {
                    "bom-ref": "f",
                    "type": "file",
                    "name": "/usr/bin/a",
                    "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(b"abc").hexdigest()}],
                },
            ]
        }
        original = copy.deepcopy(bom)
        payloads = {
            "var/lib/dpkg/status": b"Package: pkg\nStatus: install ok installed\nVersion: 1\nArchitecture: arm64\n",
            "var/lib/dpkg/info/pkg.list": b"/bin/a\n",
            "usr/bin/a": b"abc",
            "usr/share/doc/shared/copyright": b"Files: *\nLicense: Expat\n",
            "opt/java/openjdk/release": b'IMPLEMENTOR="Eclipse Adoptium"\nJAVA_RUNTIME_VERSION="21+1"\n',
            "opt/java/openjdk/legal/java.base/LICENSE": b"Version 2, June 1991",
            "opt/java/openjdk/legal/java.base/ADDITIONAL_LICENSE_INFO": b"Classpath",
            "opt/java/openjdk/legal/java.base/zlib.md": b"zlib terms",
        }
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "rootfs.tar"
            with tarfile.open(path, "w") as t:
                for name, raw in payloads.items():
                    m = tarfile.TarInfo(name)
                    m.size = len(raw)
                    t.addfile(m, io.BytesIO(raw))
                m = tarfile.TarInfo("bin")
                m.type = tarfile.SYMTYPE
                m.linkname = "usr/bin"
                t.addfile(m)
                m = tarfile.TarInfo("usr/share/doc/pkg")
                m.type = tarfile.SYMTYPE
                m.linkname = "shared"
                t.addfile(m)
            out, report, _ = process(bom, path, {"expat": "MIT"})
            self.assertEqual(bom, original)
            self.assertEqual(len(out["components"]), 4)
            self.assertEqual(report["file_normalization"]["removed_count"], 1)
            from license_scope import collect

            self.assertFalse(out["components"][0].get("licenses"))
            self.assertEqual(collect(out)[0]["declared_expression"], "MIT")
            self.assertEqual(collect(out)[0]["applicability"], "unknown")
            rerun, _, _ = process(out, path, {"expat": "MIT"})
            self.assertEqual(out, rerun)
            bom["components"][-1]["hashes"][0]["content"] = "bad"
            self.assertEqual(len(process(bom, path, {"expat": "MIT"})[0]["components"]), 5)
            bom["components"][0]["version"] = "2"
            with self.assertRaisesRegex(ValueError, "version mismatch"):
                process(bom, path, {"expat": "MIT"})


if __name__ == "__main__":
    unittest.main()
