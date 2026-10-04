import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from audit_erlang_licenses import audit, declarations, installed_candidates, UNKNOWN


class OtpAuditTests(unittest.TestCase):
    def setUp(self):
        self.bom = {
            "components": [
                {
                    "name": "erlang",
                    "type": "application",
                    "version": "28.5.0.7",
                    "bom-ref": "erlang",
                    "licenses": [{"license": {"id": "Apache-2.0"}}],
                }
            ]
        }
        self.installed = {
            "usr/local/lib/erlang/releases/28/OTP_VERSION": b"28.5.0.7\n",
            "usr/local/lib/erlang/erts-16.4/bin/beam.smp": b"ELF test native",
            "usr/local/lib/erlang/lib/eldap-1/ebin/eldap.beam": b"compiled",
            "usr/local/lib/erlang/lib/snmp-1/mibs/example.mib": b"-- SPDX-License-Identifier: LicenseRef-IETF-MIB\n",
        }
        self.source = {
            "lib/eldap/src/eldap.erl": b"%% SPDX-License-Identifier: MIT\n",
            "lib/snmp/mibs/example.mib": self.installed[
                "usr/local/lib/erlang/lib/snmp-1/mibs/example.mib"
            ],
            "lib/eldap/test/example.erl": b"%% SPDX-License-Identifier: MPL-1.1\n",
            "native/LICENSE": b"native license",
        }

    def test_declaration_comments_and_operators(self):
        self.assertEqual(
            declarations(b"%% SPDX-License-Identifier: Apache-2.0 OR LGPL-2.1-or-later\n"),
            ["Apache-2.0 OR LGPL-2.1-or-later"],
        )
        self.assertEqual(
            declarations(b"| SPDX-License-Identifier: | BSD-3-Clause WITH PCRE2-exception |\n"),
            ["BSD-3-Clause WITH PCRE2-exception"],
        )
        self.assertEqual(declarations(b'print("SPDX-License-Identifier: MIT")'), [])

    def test_mapped_license_standard_field_and_excluded_test(self):
        before = copy.deepcopy(self.bom)
        result, report, _ = audit(
            self.bom, self.installed, self.source, [("native", "native/LICENSE", "Zlib", "native")]
        )
        self.assertEqual(self.bom, before)
        self.assertEqual(result["components"][0]["licenses"], [{"license": {"id": "Apache-2.0"}}])
        expression = str(report["license_scopes"])
        self.assertIn("MIT", expression)
        self.assertIn("LicenseRef-IETF-MIB", expression)
        self.assertIn("Zlib", expression)
        self.assertNotIn("MPL", expression)
        direct = next(
            x for x in report["source_file_assessments"] if x["source_path"].endswith("example.mib")
        )
        self.assertEqual(direct["installed_files"][0]["assessment"], "exact-file-match")
        again, _, _ = audit(
            result, self.installed, self.source, [("native", "native/LICENSE", "Zlib", "native")]
        )
        self.assertEqual(again, result)

    def test_unresolved_source_is_explicit_not_omitted(self):
        self.source["lib/megaco/src/binary/MEDIA-GATEWAY-CONTROL-v1.asn"] = (
            b"-- SPDX-License-Identifier: NOASSERTION\n"
        )
        self.installed[
            "usr/local/lib/erlang/lib/megaco-1/ebin/megaco_ber_media_gateway_control_v1.beam"
        ] = b"compiled"
        result, report, _ = audit(self.bom, self.installed, self.source, [])
        self.assertNotIn(UNKNOWN, str(result["components"][0]["licenses"]))
        self.assertTrue(
            any(
                r["declared_expression"] is None and r["applicability"] == "unknown"
                for r in report["license_scopes"]
            )
        )
        self.assertTrue(report["unresolved"])

    def test_changed_marker_missing_native_and_license_conflict_rejected(self):
        with self.assertRaises(ValueError):
            audit(
                self.bom, self.installed, self.source, [("n", "native/LICENSE", "Zlib", "absent")]
            )
        self.bom["components"][0]["licenses"] = [{"license": {"id": "MIT"}}]
        with self.assertRaises(ValueError):
            audit(self.bom, self.installed, self.source, [])
        self.bom["components"][0]["licenses"] = [{"license": {"id": "Apache-2.0"}}]
        self.installed["usr/local/lib/erlang/releases/28/OTP_VERSION"] = b"29"
        with self.assertRaises(ValueError):
            audit(self.bom, self.installed, self.source, [])
