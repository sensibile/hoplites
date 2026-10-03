import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from compare_image_boms import compare
from investigate_debian_cves import investigate


class ComparisonTests(unittest.TestCase):
    def test_architecture_and_versions_remain_distinct(self):
        left = {
            "components": [
                {
                    "type": "library",
                    "name": "a",
                    "version": "1",
                    "purl": "pkg:deb/debian/a@1?arch=arm64",
                }
            ]
        }
        right = {
            "components": [
                {
                    "type": "library",
                    "name": "a",
                    "version": "1",
                    "purl": "pkg:deb/debian/a@1?arch=amd64",
                }
            ]
        }
        result = compare(left, right)
        self.assertFalse(result["shared"])
        self.assertEqual(len(result["left_only"]), 1)

    def test_advisory_uses_source_version_and_never_applies_vex(self):
        bom = {
            "components": [
                {
                    "bom-ref": "c",
                    "name": "binary",
                    "version": "9",
                    "purl": "pkg:deb/debian/binary@9",
                }
            ],
            "vulnerabilities": [{"id": "CVE-1", "affects": [{"ref": "c"}]}],
        }
        installed = {"binary": {"Package": "binary", "Version": "9", "Source": "source (2:1.2-3)"}}
        tracker = {
            "source": {
                "CVE-1": {
                    "releases": {"bookworm": {"status": "resolved", "fixed_version": "2:1.2-2"}}
                }
            }
        }
        result = investigate(bom, tracker, installed)
        self.assertEqual(
            result[0]["assessment"], "installed-source-version-at-or-above-vendor-fixed-version"
        )
        self.assertFalse(result[0]["vex_applied"])
        self.assertEqual(result[0]["source_version"], "2:1.2-3")

    def test_missing_advisory_stays_unresolved(self):
        bom = {
            "components": [{"bom-ref": "c", "name": "a", "version": "1", "purl": "pkg:pypi/a@1"}],
            "vulnerabilities": [{"id": "CVE-1", "affects": [{"ref": "c"}]}],
        }
        result = investigate(bom, {}, {})
        self.assertTrue(result[0]["assessment"].startswith("unresolved"))
