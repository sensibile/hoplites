import base64
import copy
import csv
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from enrich_python_bom import enrich, sha


class PythonTests(unittest.TestCase):
    def fixture(self):
        base = "usr/local/lib/python3.13/"
        site = base + "site-packages/"
        files = {
            "usr/local/include/python3.13/patchlevel.h": b'#define PY_VERSION "3.13.16"\n',
            base + "LICENSE.txt": b"Python terms",
            site + "pip-26.2.1.dist-info/METADATA": b"Name: pip\nVersion: 26.2.1\n",
            site + "pip/_vendor/vendor.txt": b"distlib==0.4.2\n",
            site + "pip/_vendor/distlib/LICENSE.txt": b"distlib terms",
            site + "pip/_vendor/distlib/t32.exe": b"binary32",
            site + "pip/_vendor/distlib/t64.exe": b"binary64",
        }
        output = io.StringIO()
        writer = csv.writer(output)
        for path, raw in files.items():
            if path.startswith(site):
                encoded = base64.urlsafe_b64encode(bytes.fromhex(sha(raw))).decode().rstrip("=")
                writer.writerow([path[len(site) :], "sha256=" + encoded, str(len(raw))])
        files[site + "pip-26.2.1.dist-info/RECORD"] = output.getvalue().encode()
        rules = [
            {
                "name": "python",
                "version": "3.13.16",
                "path": base + "LICENSE.txt",
                "sha256": sha(b"Python terms"),
                "expression": "Python-2.0.1",
            },
            {
                "name": "distlib",
                "version": "0.4.2",
                "path": site + "pip/_vendor/distlib/LICENSE.txt",
                "sha256": sha(b"distlib terms"),
                "expression": "Python-2.0.1",
            },
        ]
        bom = {
            "components": [
                {
                    "bom-ref": "py",
                    "name": "python",
                    "version": "3.13.16",
                    "type": "application",
                    "purl": "pkg:generic/python@3.13.16",
                },
                {
                    "bom-ref": "pip",
                    "name": "pip",
                    "version": "26.2.1",
                    "type": "library",
                    "purl": "pkg:pypi/pip@26.2.1",
                },
            ],
            "dependencies": [],
        }
        for file in ["t32.exe", "t64.exe"]:
            path = site + "pip/_vendor/distlib/" + file
            bom["components"].extend(
                [
                    {
                        "bom-ref": file,
                        "name": "Simple Launcher",
                        "version": "1.1.0.14",
                        "type": "application",
                        "properties": [{"name": "syft:location:0:path", "value": "/" + path}],
                    },
                    {
                        "bom-ref": file + "-file",
                        "type": "file",
                        "name": "/" + path,
                        "hashes": [{"alg": "SHA-256", "content": sha(files[path])}],
                    },
                ]
            )
            bom["dependencies"].append({"ref": "pip", "dependsOn": [file + "-file"]})
        return bom, files, rules

    def test_record_ownership_and_distinct_launchers(self):
        bom, files, rules = self.fixture()
        original = copy.deepcopy(bom)
        result, evidence, sources = enrich(bom, files, rules)
        self.assertEqual(bom, original)
        launchers = [c for c in result["components"] if c["name"] == "Simple Launcher"]
        self.assertEqual(len({c["purl"] for c in launchers}), 2)
        self.assertEqual(evidence["removed_count"], 2)
        self.assertEqual(result["components"][0]["licenses"], [{"expression": "Python-2.0.1"}])
        self.assertIn(
            "hoplites:pip-vendor:distlib@0.4.2", [c["bom-ref"] for c in result["components"]]
        )
        valid = {c["bom-ref"] for c in result["components"]}
        self.assertTrue(
            all(
                v in valid
                for d in result["dependencies"]
                for v in [d["ref"]] + d.get("dependsOn", [])
            )
        )
        self.assertTrue(sources)

    def test_record_inventory_linked_as_evidence_and_hash_verified(self):
        bom, files, rules = self.fixture()
        path = "usr/local/lib/python3.13/site-packages/pip-26.2.1.dist-info/RECORD"
        row = {
            "bom-ref": "record",
            "type": "file",
            "name": "/" + path,
            "hashes": [{"alg": "SHA-256", "content": sha(files[path])}],
        }
        bom["components"].append(row)
        result, evidence, _ = enrich(bom, files, rules)
        self.assertFalse(any(c["bom-ref"] == "record" for c in result["components"]))
        self.assertEqual(evidence["retained_inventory"][0]["component"]["hashes"], row["hashes"])
        self.assertEqual(evidence["retained_inventory"][0]["owner_bom_ref"], "pip")
        row["hashes"][0]["content"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "inventory rootfs hash mismatch"):
            enrich(bom, files, rules)

    def test_marker_and_record_tampering_rejected(self):
        bom, files, rules = self.fixture()
        files["usr/local/include/python3.13/patchlevel.h"] = b'#define PY_VERSION "3.12.0"'
        with self.assertRaisesRegex(ValueError, "marker mismatch"):
            enrich(bom, files, rules)
        bom, files, rules = self.fixture()
        files["usr/local/lib/python3.13/site-packages/pip/_vendor/distlib/t32.exe"] = b"altered"
        with self.assertRaisesRegex(ValueError, "RECORD hash"):
            enrich(bom, files, rules)

    def test_license_hash_tampering_rejected(self):
        bom, files, rules = self.fixture()
        files["usr/local/lib/python3.13/LICENSE.txt"] = b"changed"
        with self.assertRaisesRegex(ValueError, "license hash"):
            enrich(bom, files, rules)

    def test_unrelated_image_unchanged(self):
        bom = {"components": [{"type": "library", "name": "a", "bom-ref": "a"}]}
        self.assertEqual(enrich(bom, {}, [])[0], bom)
