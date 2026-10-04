import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from normalize_node_bom import process


class NodeViewTests(unittest.TestCase):
    def fixture(self):
        files = {
            "/usr/local/include/node/node_version.h": b"#define NODE_MAJOR_VERSION 24\n#define NODE_MINOR_VERSION 21\n#define NODE_PATCH_VERSION 0\n",
            "/usr/local/LICENSE": b"Node.js is licensed for use as follows:\nPermission is hereby granted, free of charge\nThis license applies\n- uv, located at deps/uv, is licensed as follows:\nMIT\n",
            "/usr/local/bin/node": b"node",
            "/usr/local/lib/node_modules/npm/package.json": json.dumps(
                {"name": "npm", "version": "1"}
            ).encode(),
            "/usr/local/lib/node_modules/npm/node_modules/a/package.json": json.dumps(
                {"name": "a", "version": "2"}
            ).encode(),
            "/usr/local/lib/node_modules/npm/node_modules/a/index.js": b"a",
        }
        components = [
            {
                "bom-ref": "node",
                "name": "node",
                "version": "24.21.0",
                "type": "application",
                "purl": "pkg:generic/node@24.21.0",
            }
        ]
        for name, version, path in [
            ("npm", "1", "/usr/local/lib/node_modules/npm/package.json"),
            ("a", "2", "/usr/local/lib/node_modules/npm/node_modules/a/package.json"),
        ]:
            components.append(
                {
                    "bom-ref": name,
                    "name": name,
                    "version": version,
                    "type": "library",
                    "purl": f"pkg:npm/{name}@{version}",
                    "properties": [{"name": "syft:location:0:path", "value": path}],
                }
            )
        for path in [
            "/usr/local/bin/node",
            "/usr/local/lib/node_modules/npm/node_modules/a/index.js",
        ]:
            components.append(
                {
                    "bom-ref": path,
                    "name": path,
                    "type": "file",
                    "hashes": [
                        {"alg": "SHA-256", "content": hashlib.sha256(files[path]).hexdigest()}
                    ],
                }
            )
        return {"components": components}, files

    def test_verified_runtime_and_nearest_package_preserve_raw(self):
        bom, files = self.fixture()
        original = json.dumps(bom)
        result, report, sources = process(bom, files)
        self.assertEqual(json.dumps(bom), original)
        self.assertEqual(len(result["components"]), 3)
        self.assertEqual(result["components"][0]["licenses"], [{"license": {"id": "MIT"}}])
        from license_scope import collect

        self.assertEqual(collect(result)[0]["applicability"], "unknown")
        owners = [
            x["ownership"]["owner_bom_ref"] for x in report["file_normalization"]["removed_files"]
        ]
        self.assertEqual(owners, ["node", "a"])
        self.assertIn("usr/local/LICENSE", sources)
        self.assertTrue(report["unresolved"])

    def test_version_conflict_fails(self):
        bom, files = self.fixture()
        bom["components"][0]["version"] = "24.1.0"
        with self.assertRaises(ValueError):
            process(bom, files)

    def test_hash_mismatch_retains_file(self):
        bom, files = self.fixture()
        files["/usr/local/bin/node"] = b"changed"
        result, _, _ = process(bom, files)
        self.assertTrue(any(c["name"] == "/usr/local/bin/node" for c in result["components"]))

    def test_package_identity_conflict_fails(self):
        bom, files = self.fixture()
        files["/usr/local/lib/node_modules/npm/package.json"] = b'{"name":"npm","version":"wrong"}'
        with self.assertRaises(ValueError):
            process(bom, files)

    def test_usr_merge_does_not_transfer_leaf_symlink_ownership(self):
        import io
        import tarfile
        import tempfile
        from normalize_debian_bom import process as debian

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rootfs.tar"
            files = {
                "var/lib/dpkg/status": b"Package: runtime\nStatus: install ok installed\nVersion: 1\nArchitecture: arm64\n\nPackage: tools\nStatus: install ok installed\nVersion: 1\nArchitecture: arm64\n",
                "var/lib/dpkg/info/runtime.list": b"/lib/loader\n",
                "var/lib/dpkg/info/tools.list": b"/usr/bin/ld.so\n",
                "usr/lib/loader": b"binary",
            }
            with tarfile.open(path, "w") as tar:
                for name, raw in files.items():
                    m = tarfile.TarInfo(name)
                    m.size = len(raw)
                    tar.addfile(m, io.BytesIO(raw))
                for name, target in [("lib", "usr/lib"), ("usr/bin/ld.so", "../lib/loader")]:
                    m = tarfile.TarInfo(name)
                    m.type = tarfile.SYMTYPE
                    m.linkname = target
                    tar.addfile(m)
            components = [
                {
                    "bom-ref": name,
                    "name": name,
                    "version": "1",
                    "type": "library",
                    "purl": f"pkg:deb/debian/{name}@1?arch=arm64",
                }
                for name in ("runtime", "tools")
            ]
            components += [
                {"bom-ref": "os", "name": "debian", "version": "12", "type": "operating-system"},
                {
                    "bom-ref": "f",
                    "name": "/usr/lib/loader",
                    "type": "file",
                    "hashes": [
                        {"alg": "SHA-256", "content": hashlib.sha256(b"binary").hexdigest()}
                    ],
                },
            ]
            result, report, _ = debian({"components": components}, path, {})
            self.assertEqual(len(result["components"]), 3)
            self.assertEqual(
                report["file_normalization"]["removed_files"][0]["ownership"]["owner_bom_ref"],
                "runtime",
            )

    def test_scoped_purl_identity_does_not_merge_namespaces(self):
        from compare_image_boms import compare

        left = {
            "components": [
                {"type": "library", "name": "@x/a", "version": "1", "purl": "pkg:npm/%40x/a@1"},
                {"type": "library", "name": "@y/a", "version": "1", "purl": "pkg:npm/%40y/a@1"},
            ]
        }
        right = {
            "components": [
                {
                    "type": "library",
                    "name": "a",
                    "group": "@x",
                    "version": "1",
                    "purl": "pkg:npm/%40x/a@1",
                }
            ]
        }
        report = compare(left, right)
        self.assertEqual(len(report["shared"]), 1)
        self.assertEqual(report["left_only"][0]["name"], "@y/a")
