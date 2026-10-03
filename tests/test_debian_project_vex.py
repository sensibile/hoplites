import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from build_debian_project_vex import build


class DebianVexTests(unittest.TestCase):
    def fixture(self):
        bom = {
            "components": [
                {
                    "bom-ref": "a",
                    "name": "binary",
                    "version": "2:1.2-3",
                    "purl": "pkg:deb/debian/binary@2%3A1.2-3?arch=arm64&distro=debian-12.15",
                }
            ],
            "vulnerabilities": [{"id": "CVE-test", "affects": [{"ref": "a"}]}],
        }
        status = b"Package: binary\nStatus: install ok installed\nVersion: 2:1.2-3\nArchitecture: arm64\nSource: source (2:1.2-3)\n"
        release = b"ID=debian\nVERSION_ID=12.15\nVERSION_CODENAME=bookworm\n"
        return bom, status, release

    def test_fixed_endpoint_uses_exact_source_epoch_and_version(self):
        args = self.fixture()
        tracker = {
            "source": {
                "CVE-test": {
                    "releases": {"bookworm": {"status": "resolved", "fixed_version": "2:1.2-2"}}
                }
            }
        }
        result, evidence = build(*args, tracker, "hash", "url")
        self.assertEqual(result["vulnerabilities"][0]["analysis"]["state"], "resolved")
        self.assertFalse(evidence["applied"])

    def test_open_and_zero_do_not_suppress(self):
        for status, fixed in [("open", None), ("resolved", "0")]:
            tracker = {
                "source": {
                    "CVE-test": {
                        "releases": {"bookworm": {"status": status, "fixed_version": fixed}}
                    }
                }
            }
            result, _ = build(*self.fixture(), tracker, "hash", "url")
            self.assertEqual(result["vulnerabilities"][0]["analysis"]["state"], "in_triage")

    def test_actual_point_release_required_for_minor_purl(self):
        bom, status, _ = self.fixture()
        release = b"ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n"
        tracker = {"source": {"CVE-test": {"releases": {"bookworm": {"status": "open"}}}}}
        result, _ = build(bom, status, release, tracker, "hash", "url", "12.15")
        self.assertEqual(result["vulnerabilities"][0]["analysis"]["state"], "in_triage")
        result, evidence = build(bom, status, release, tracker, "hash", "url", "12.14")
        self.assertFalse(result["vulnerabilities"])
        self.assertEqual(evidence["unresolved"][0]["reason"], "Debian version/distro mismatch")

    def test_missing_advisory_is_unresolved(self):
        result, report = build(*self.fixture(), {}, "hash", "url")
        self.assertFalse(result["vulnerabilities"])
        self.assertEqual(len(report["unresolved"]), 1)

    def test_wrong_distro_is_rejected(self):
        bom, status, _ = self.fixture()
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            build(bom, status, b"ID=ubuntu\nVERSION_CODENAME=noble", {}, "hash", "url")
