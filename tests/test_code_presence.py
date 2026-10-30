import base64
import copy
import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from code_presence import analysis, build, in_range, merge, package_roots, verify_sources

ROOT = "usr/local/lib/node_modules/npm/node_modules/pkg"
VULNERABLE = b"function parse(input) { return unbounded(input) }\n"
FIXED = b"function parse(input) { return bounded(input, LIMIT) }\n"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def tiny_elf(symbols):
    """Minimal ELF64 LE with one dynamic segment and a symbol table."""
    names = b"\0" + b"\0".join(s.encode() for s in symbols) + b"\0"
    dyn_off, str_off = 64 + 2 * 56, 64 + 2 * 56 + 32
    sym_off = str_off + len(names)
    symtab = b"\0" * 24
    position = 1
    for s in symbols:
        symtab += struct.pack("<IBBHQQ", position, 0x12, 0, 1, 0, 0)
        position += len(s) + 1
    sh_off = sym_off + len(symtab)
    total = sh_off + 3 * 64
    header = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header += struct.pack("<HHIQQQIHHHHHH", 3, 183, 1, 0, 64, sh_off, 0, 64, 56, 2, 64, 3, 0)
    phdrs = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, total, total, 0)
    phdrs += struct.pack("<IIQQQQQQ", 2, 6, dyn_off, dyn_off, 0, 32, 32, 8)
    dynamic = struct.pack("<qQ", 5, str_off) + struct.pack("<qQ", 0, 0)
    shdrs = b"\0" * 64
    shdrs += struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, str_off, len(names), 0, 0, 1, 0)
    shdrs += struct.pack("<IIQQQQIIQQ", 0, 2, 0, 0, sym_off, len(symtab), 1, 0, 8, 24)
    return header + phdrs + dynamic + names + symtab + shdrs


class Fixture:
    def __init__(self):
        self.advisory = {
            "ghsa_id": "GHSA-test",
            "cve_id": "CVE-test",
            "references": ["https://example.test/fix"],
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "npm", "name": "pkg"},
                    "vulnerable_version_range": "< 1.2.0",
                }
            ],
        }
        self.fix = {
            "sha": "f" * 40,
            "html_url": "https://example.test/fix",
            "files": [{"filename": "lib/parse.js"}],
        }
        self.release = {
            "path": "lib/parse.js",
            "url": "https://api.example.test/contents/lib/parse.js?ref=v1.1.0",
            "content": base64.b64encode(VULNERABLE).decode(),
        }
        self.ordering = {"base": "v1.1.0", "head": "f" * 40, "status": "ahead", "behind_by": 0}

    def sources(self):
        return {
            name: json.dumps(value).encode()
            for name, value in [
                ("advisory.json", self.advisory),
                ("fix.json", self.fix),
                ("release.json", self.release),
                ("ordering.json", self.ordering),
            ]
        }

    def rule(self, **changes):
        s = self.sources()
        rule = {
            "cve": "CVE-test",
            "advisory_id": "GHSA-test",
            "ecosystem": "npm",
            "package": "pkg",
            "vulnerable_range": "< 1.2.0",
            "evidence_kind": "package-file",
            "target": "lib/parse.js",
            "vulnerable_marker": None,
            "fix_marker": None,
            "release_ref": "v1.1.0",
            "release_file": "release.json",
            "release_sha256": sha(s["release.json"]),
            "ordering_file": "ordering.json",
            "ordering_sha256": sha(s["ordering.json"]),
            "advisory_file": "advisory.json",
            "advisory_sha256": sha(s["advisory.json"]),
            "fix_file": "fix.json",
            "fix_sha256": sha(s["fix.json"]),
            "fix_url": "https://example.test/fix",
        }
        rule.update(changes)
        return rule


def documents(version="1.1.0", purl=None):
    purl = purl or "pkg:npm/pkg@" + version
    component = {"bom-ref": "dt-uuid", "name": "pkg", "version": version, "purl": purl}
    export = {
        "metadata": {"component": {"bom-ref": "project", "version": "sha256:image"}},
        "components": [component],
        "vulnerabilities": [{"id": "CVE-test", "affects": [{"ref": "dt-uuid"}]}],
    }
    sbom = {
        "metadata": {"component": {"version": "sha256:image"}},
        "components": [
            {
                "name": "pkg",
                "version": version,
                "purl": purl,
                "properties": [
                    {"name": "syft:location:0:path", "value": "/" + ROOT + "/package.json"}
                ],
            }
        ],
    }
    return export, sbom


def run(rules, files, version="1.1.0", roots=(ROOT,), purl=None, links=(), rejected=()):
    export, sbom = documents(version, purl)
    manifests = {r: {"name": "pkg", "version": version} for r in roots}
    prepared = {"dt-uuid": (list(roots), files, manifests, set(links))}
    return build(export, sbom, rules, prepared, "now", "urn:uuid:x", rejected)


class RangeTests(unittest.TestCase):
    def test_ghsa_bounds(self):
        self.assertTrue(in_range("6.27.0", ">= 6.7.0, < 6.28.1"))
        self.assertFalse(in_range("6.28.1", ">= 6.7.0, < 6.28.1"))
        self.assertFalse(in_range("6.6.9", ">= 6.7.0, < 6.28.1"))
        self.assertTrue(in_range("5.0.7", "< 5.0.8"))

    def test_unsupported_forms_raise(self):
        for version, expression in [
            ("1.0.0-rc.1", "< 2.0.0"),
            ("1.0.0", "~1.0"),
            ("1.0", "< 2.0.0"),
        ]:
            with self.assertRaises(ValueError):
                in_range(version, expression)


class SourceTests(unittest.TestCase):
    def test_valid_rule_carries_release_bytes(self):
        f = Fixture()
        usable, rejected = verify_sources([f.rule()], f.sources())
        self.assertEqual(rejected, [])
        self.assertEqual(usable[0]["release_content"], VULNERABLE)

    def test_changed_or_inconsistent_sources_reject_rule(self):
        f = Fixture()
        cases = [
            f.rule(advisory_sha256="0" * 64),
            f.rule(vulnerable_range="< 9.0.0"),
            f.rule(fix_url="https://example.test/other"),
            f.rule(release_ref="v1.0.0"),
        ]
        behind = Fixture()
        behind.ordering["status"], behind.ordering["behind_by"] = "behind", 3
        for rule in cases:
            self.assertEqual(verify_sources([rule], f.sources())[0], [])
        # A fix already contained in the release means the release is not pre-fix code.
        self.assertEqual(verify_sources([behind.rule()], behind.sources())[0], [])


class DecisionTests(unittest.TestCase):
    def usable(self, **changes):
        f = Fixture()
        return verify_sources([f.rule(**changes)], f.sources())[0]

    def test_release_identical_module_is_confirmed_present_and_stays_in_triage(self):
        vex, report = run(self.usable(), {ROOT + "/lib/parse.js": VULNERABLE})
        self.assertEqual(report["decisions"][0]["grade"], "confirmed-present")
        self.assertEqual(vex["vulnerabilities"][0]["analysis"]["state"], "in_triage")
        self.assertNotIn("justification", vex["vulnerabilities"][0]["analysis"])
        self.assertIn(
            "code_not_reachable is not used", vex["vulnerabilities"][0]["analysis"]["detail"]
        )

    def test_modified_module_is_only_inferred(self):
        _, report = run(self.usable(), {ROOT + "/lib/parse.js": FIXED})
        self.assertEqual(report["decisions"][0]["grade"], "inferred-present")

    def test_markers_confirm_compiled_output(self):
        rules = self.usable(
            release_ref=None,
            release_file=None,
            vulnerable_marker="function parse(",
            fix_marker="LIMIT",
        )
        _, report = run(rules, {ROOT + "/lib/parse.js": VULNERABLE})
        self.assertEqual(report["decisions"][0]["grade"], "confirmed-present")
        _, report = run(rules, {ROOT + "/lib/parse.js": FIXED})
        self.assertEqual(report["decisions"][0]["grade"], "inferred-present")

    def marked(self):
        return self.usable(release_ref=None, release_file=None, vulnerable_marker="unbounded(")

    def test_absence_is_never_confirmed_in_v1(self):
        files = {ROOT + "/index.js": b"module.exports = {}\n"}
        for rules in [self.marked(), self.usable(release_ref=None, release_file=None)]:
            vex, report = run(rules, files)
            self.assertEqual(report["decisions"][0]["grade"], "inferred-absent")
            self.assertEqual(vex["vulnerabilities"][0]["analysis"]["state"], "in_triage")
            self.assertNotIn("justification", vex["vulnerabilities"][0]["analysis"])
        # Relocated code (e.g. a bundle) is reported as present.
        _, report = run(self.marked(), dict(files, **{ROOT + "/dist/bundle.js": VULNERABLE}))
        self.assertEqual(report["decisions"][0]["grade"], "inferred-present")

    def test_confirmed_absent_mapping_is_reserved_for_code_not_present(self):
        decision = {
            "component": "pkg",
            "version": "1",
            "grade": "confirmed-absent",
            "advisory_id": "G",
            "advisory_sha256": "a",
            "fix_url": "u",
            "fix_sha256": "f",
            "vulnerable_range": "< 2.0.0",
            "evidence": [],
        }
        result = analysis(decision)
        self.assertEqual(
            (result["state"], result["justification"]), ("not_affected", "code_not_present")
        )

    def test_symlinked_target_is_unresolved(self):
        marked = self.marked()
        files = {ROOT + "/index.js": b"{}"}
        # Target stored as a symbolic link: content unknown.
        vex, report = run(marked, files, links={ROOT + "/lib/parse.js"})
        self.assertEqual(report["decisions"][0]["grade"], "unresolved")
        self.assertEqual(vex["vulnerabilities"][0]["analysis"]["state"], "in_triage")

    def test_rejected_sibling_rule_keeps_cve_unresolved(self):
        rejected = [{"cve": "CVE-test", "package": "pkg", "target": "lib/other.js", "reason": "x"}]
        vex, report = run(self.marked(), {ROOT + "/index.js": b"{}"}, rejected=rejected)
        self.assertEqual(report["decisions"][0]["grade"], "unresolved")
        self.assertEqual(vex["vulnerabilities"][0]["analysis"]["state"], "in_triage")

    def test_rule_ecosystem_must_match_purl_type(self):
        _, report = run(
            self.usable(), {ROOT + "/lib/parse.js": VULNERABLE}, purl="pkg:generic/pkg@1.1.0"
        )
        self.assertEqual(report["decisions"][0]["reason"], "no reviewed code-presence rule")

    def test_any_present_copy_outranks_absent_copies(self):
        marked = self.marked()
        other = "opt/app/node_modules/pkg"
        files = {ROOT + "/index.js": b"{}", other + "/lib/parse.js": VULNERABLE}
        vex, report = run(marked, files, roots=(ROOT, other))
        self.assertEqual(report["decisions"][0]["grade"], "confirmed-present")
        self.assertEqual(vex["vulnerabilities"][0]["analysis"]["state"], "in_triage")

    def test_unresolved_cases_stay_in_triage(self):
        rules = self.usable()
        cases = [
            ([], {}, "1.1.0", "no reviewed code-presence rule"),
            (rules, {}, "1.2.0", "installed version outside reviewed vulnerable range"),
        ]
        for rules_, files, version, reason in cases:
            vex, report = run(rules_, files, version)
            self.assertEqual(report["decisions"][0]["reason"], reason)
            self.assertEqual(vex["vulnerabilities"][0]["analysis"]["state"], "in_triage")
        export, sbom = documents()
        _, report = build(
            export,
            sbom,
            rules,
            {"dt-uuid": ([ROOT], {}, {ROOT: {"name": "other"}}, set())},
            "t",
            "s",
        )
        self.assertEqual(report["decisions"][0]["grade"], "unresolved")

    def test_elf_symbol_absence_never_suppresses(self):
        f = Fixture()
        f.advisory["vulnerabilities"][0]["package"]["ecosystem"] = "generic"
        rule, _ = verify_sources(
            [
                f.rule(
                    evidence_kind="elf-symbol",
                    ecosystem="generic",
                    target="bin/tool",
                    vulnerable_marker="vuln_fn",
                    release_ref=None,
                    release_file=None,
                )
            ],
            f.sources(),
        )
        purl = "pkg:generic/pkg@1.1.0"
        _, report = run(rule, {ROOT + "/bin/tool": tiny_elf(["vuln_fn"])}, purl=purl)
        self.assertEqual(report["decisions"][0]["grade"], "confirmed-present")
        vex, report = run(rule, {ROOT + "/bin/tool": tiny_elf(["other_fn"])}, purl=purl)
        self.assertEqual(report["decisions"][0]["grade"], "inferred-absent")
        self.assertEqual(vex["vulnerabilities"][0]["analysis"]["state"], "in_triage")
        _, report = run(rule, {ROOT + "/bin/tool": b"not elf"}, purl=purl)
        self.assertEqual(report["decisions"][0]["grade"], "unresolved")

    def test_distro_packages_are_left_to_distro_adapters(self):
        purl = "pkg:deb/debian/pkg@1.1.0?arch=arm64"
        vex, report = run(self.usable(), {}, purl=purl)
        self.assertEqual((vex["vulnerabilities"], report["out_of_scope"]), ([], 1))

    def test_component_outside_verified_sbom_raises(self):
        export, sbom = documents()
        sbom["components"][0]["version"] = "9.9.9"
        with self.assertRaises(ValueError):
            build(export, sbom, [], {}, "t", "s")

    def test_unresolved_analysis_text(self):
        result = analysis(
            {"component": "pkg", "version": "1", "grade": "unresolved", "reason": "x"}
        )
        self.assertEqual(result["state"], "in_triage")


class LayoutTests(unittest.TestCase):
    def test_package_roots_from_sbom_locations(self):
        export, sbom = documents()
        self.assertEqual(package_roots(sbom, export["components"][0]), [ROOT])
        generic = {"name": "node", "version": "1", "purl": "pkg:generic/node@1"}
        sbom = {
            "components": [
                dict(
                    generic,
                    properties=[{"name": "syft:location:0:path", "value": "/usr/local/bin/node"}],
                )
            ]
        }
        self.assertEqual(package_roots(sbom, generic), ["usr/local/bin"])

    def test_merge_overrides_only_matching_findings(self):
        meta = {"component": {"bom-ref": "project"}}
        distro = {
            "metadata": meta,
            "components": [{"bom-ref": "a"}, {"bom-ref": "b"}],
            "vulnerabilities": [
                {"id": "CVE-1", "affects": [{"ref": "a"}], "analysis": {"state": "resolved"}},
                {"id": "CVE-2", "affects": [{"ref": "b"}], "analysis": {"state": "in_triage"}},
            ],
        }
        presence = {
            "metadata": meta,
            "components": [{"bom-ref": "b"}],
            "vulnerabilities": [
                {"id": "CVE-2", "affects": [{"ref": "b"}], "analysis": {"state": "not_affected"}}
            ],
        }
        merged = merge(distro, presence)
        self.assertEqual(
            {(v["id"], v["analysis"]["state"]) for v in merged["vulnerabilities"]},
            {("CVE-1", "resolved"), ("CVE-2", "not_affected")},
        )
        self.assertEqual(len(merged["components"]), 2)
        other = copy.deepcopy(presence)
        other["metadata"] = {"component": {"bom-ref": "elsewhere"}}
        with self.assertRaises(ValueError):
            merge(distro, other)


class ShellTests(unittest.TestCase):
    def test_read_roots_resolves_hard_links_and_reports_symlinks(self):
        import io
        import tarfile
        import tempfile

        from build_code_presence_vex import prepare, read_roots

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rootfs.tar"
            with tarfile.open(path, "w") as tar:
                for name, data in [
                    ("./" + ROOT + "/dist/esm/index.js", VULNERABLE),
                    (ROOT + "/package.json", b'{"name":"pkg"}'),
                ]:
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
                hard = tarfile.TarInfo(ROOT + "/dist/commonjs/index.js")
                hard.type, hard.linkname = tarfile.LNKTYPE, "./" + ROOT + "/dist/esm/index.js"
                tar.addfile(hard)
                soft = tarfile.TarInfo(ROOT + "/lib/parse.js")
                soft.type, soft.linkname = tarfile.SYMTYPE, "../dist/esm/index.js"
                tar.addfile(soft)
                dangling = tarfile.TarInfo(ROOT + "/dist/gone.js")
                dangling.type, dangling.linkname = tarfile.LNKTYPE, "missing/target.js"
                tar.addfile(dangling)
                outside = tarfile.TarInfo(".hidden/x")
                tar.addfile(outside, io.BytesIO(b""))
            files, links = read_roots(path, [ROOT])
            self.assertEqual(files[ROOT + "/dist/commonjs/index.js"], VULNERABLE)
            self.assertEqual(sorted(links), [ROOT + "/dist/gone.js", ROOT + "/lib/parse.js"])
            self.assertNotIn("hidden/x", files)
            prepared = prepare({"ref": [ROOT]}, files, links)
            self.assertEqual(prepared["ref"][2][ROOT], {"name": "pkg"})
            self.assertEqual(prepared["ref"][3], {ROOT + "/dist/gone.js", ROOT + "/lib/parse.js"})


if __name__ == "__main__":
    unittest.main()
