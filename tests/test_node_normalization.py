import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from normalize_node_bom import process


class NodeViewTests(unittest.TestCase):
    def test_modified_apache_header_is_inferred_and_unresolved(self):
        from license_scope import collect

        bom, files = self.fixture()
        path = "/usr/local/lib/node_modules/npm/package.json"
        files[path] = b'{"name":"npm","version":"1","license":"Apache 2.0"}'
        files["/usr/local/lib/node_modules/npm/LICENSE"] = (
            b"Apache License\nVersion 2.0, January 2004\nAdditional downstream conditions."
        )
        out, report, _ = process(bom, files)
        change = next(c for c in report["changes"] if c["bom_ref"] == "npm")
        self.assertTrue(change["assessment"].startswith("inferred-"))
        self.assertTrue(all(change[k] for k in ("rationale", "limitations", "use_risk")))
        scope = next(r for r in collect(out) if r["owner_bom_ref"] == "npm")
        self.assertEqual(scope["applicability"], "unknown")
        self.assertEqual(collect(process(out, files)[0]), collect(out))

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
        self.assertEqual(len(result["components"]), 4)
        self.assertEqual(result["components"][0]["licenses"], [{"license": {"id": "MIT"}}])
        from license_scope import collect

        self.assertEqual(collect(result)[0]["applicability"], "unknown")
        owners = [
            x["ownership"]["owner_bom_ref"] for x in report["file_normalization"]["removed_files"]
        ]
        self.assertEqual(owners, ["node"])
        self.assertTrue(
            any(c.get("bom-ref", "").endswith("/a/index.js") for c in result["components"])
        )
        self.assertIn("usr/local/LICENSE", sources)
        self.assertTrue(report["unresolved"])

    def test_unscanned_nested_software_is_retained_without_directory_ownership(self):
        bom, files = self.fixture()
        path = "/usr/local/lib/node_modules/npm/node_modules/unscanned/index.js"
        files[path] = b"vendored software"
        bom["components"].append(
            {
                "bom-ref": path,
                "name": path,
                "type": "file",
                "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(files[path]).hexdigest()}],
            }
        )
        manifest = "/usr/local/lib/node_modules/npm/package.json"
        bom["components"].append(
            {
                "bom-ref": manifest,
                "name": manifest,
                "type": "file",
                "hashes": [
                    {"alg": "SHA-256", "content": hashlib.sha256(files[manifest]).hexdigest()}
                ],
            }
        )
        result, report, _ = process(bom, files)
        refs = {c["bom-ref"] for c in result["components"]}
        self.assertIn(path, refs)
        self.assertNotIn(manifest, refs)
        self.assertTrue(any(r.get("path") == path for r in report["unresolved"]))

    def test_unverified_node_headers_are_retained_and_project_license_is_inferred(self):
        bom, files = self.fixture()
        path = "/usr/local/include/node/third-party/library.h"
        files[path] = b"third-party code"
        bom["components"].append(
            {
                "name": path,
                "bom-ref": path,
                "type": "file",
                "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(files[path]).hexdigest()}],
            }
        )
        files["/usr/local/LICENSE"] = files["/usr/local/LICENSE"].replace(
            b"This license applies", b"Additional downstream restrictions.\nThis license applies"
        )
        out, report, _ = process(bom, files)
        self.assertIn(path, {c["bom-ref"] for c in out["components"]})
        change = next(c for c in report["changes"] if c["bom_ref"] == "node")
        self.assertTrue(change["assessment"].startswith("inferred-"))
        self.assertTrue(change["limitations"])
        from license_scope import collect

        project = next(r for r in collect(out) if r["subject"] == "Node project terms")
        self.assertEqual(project["applicability"], "unknown")

    def test_leaf_symlink_cannot_own_unlisted_target_bytes(self):
        import io
        import tarfile
        import tempfile
        from normalize_debian_bom import process as debian

        with tempfile.TemporaryDirectory() as directory:
            rootfs = Path(directory) / "rootfs.tar"
            with tarfile.open(rootfs, "w") as tar:
                for name, data in {
                    "var/lib/dpkg/status": b"Package: tools\nStatus: install ok installed\nVersion: 1\nArchitecture: arm64\n",
                    "var/lib/dpkg/info/tools.list": b"/usr/bin/tool\n",
                    "usr/lib/real": b"unowned binary",
                }.items():
                    m = tarfile.TarInfo(name)
                    m.size = len(data)
                    tar.addfile(m, io.BytesIO(data))
                m = tarfile.TarInfo("usr/bin/tool")
                m.type = tarfile.SYMTYPE
                m.linkname = "../lib/real"
                tar.addfile(m)
            file = {
                "name": "/usr/bin/tool",
                "bom-ref": "target",
                "type": "file",
                "hashes": [
                    {"alg": "SHA-256", "content": hashlib.sha256(b"unowned binary").hexdigest()}
                ],
            }
            bom = {
                "components": [
                    {
                        "name": "tools",
                        "bom-ref": "tools",
                        "type": "library",
                        "version": "1",
                        "purl": "pkg:deb/debian/tools@1?arch=arm64",
                    },
                    file,
                    {
                        "name": "debian",
                        "version": "12",
                        "type": "operating-system",
                        "bom-ref": "os",
                    },
                ]
            }
            out, _, _ = debian(bom, rootfs, {})
            self.assertIn("target", {c["bom-ref"] for c in out["components"]})

    def test_version_conflict_fails(self):
        bom, files = self.fixture()
        bom["components"][0]["version"] = "24.1.0"
        with self.assertRaises(ValueError):
            process(bom, files)

    def test_unsupported_elf_encodings_preserve_node_and_unknown_scopes(self):
        from license_scope import collect
        from elf_linkage import inspect

        for encoding in (b"\x01\x01", b"\x02\x02"):
            bom, files = self.fixture()
            files["/usr/local/bin/node"] = b"\x7fELF" + encoding + b"\x01" + b"\0" * 57
            files["/usr/local/include/node/config.gypi"] = (
                b"{'variables': {'node_shared_libuv': 'false'}}"
            )
            files["/usr/local/LICENSE"] = files["/usr/local/LICENSE"].replace(b"- uv,", b"- libuv,")
            out, report, _ = process(bom, files)
            node = next(c for c in out["components"] if c["bom-ref"] == "node")
            self.assertEqual(node["version"], "24.21.0")
            self.assertEqual(node["licenses"], [{"license": {"id": "MIT"}}])
            scope = next(r for r in collect(out) if r["subject"] == "libuv")
            self.assertEqual(scope["inclusion"], "unknown")
            self.assertEqual(scope["evidence"]["linkage_assessment"], "unresolved")
            self.assertTrue(any("ELF" in p.get("reason", "") for p in report["unresolved"]))
        with self.assertRaises(ValueError):
            inspect(b"not ELF")

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
