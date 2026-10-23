import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from audit_erlang_licenses import audit
from image_pipeline import database, notice_ranges
from notice_range import otp_block, reviewed, sha

ERL = (
    b"%% header\n"
    b"%% %CopyrightBegin%\n"
    b"%%\n"
    b"%% SPDX-License-Identifier: Apache-2.0\n"
    b"%% Copyright Ericsson AB 2025.\n"
    b"%% %CopyrightEnd%\n"
    b"-module(x).\n"
)


def text(evidence, raw):
    return raw[evidence["source_byte_start"] : evidence["source_byte_end"]]


class OtpBlockTests(unittest.TestCase):
    def test_line_comment_block_excludes_code(self):
        e = otp_block("lib/x/src/x.erl", ERL, ["Apache-2.0"])
        self.assertEqual(e["notice_range_status"], "located")
        self.assertTrue(text(e, ERL).startswith(b"%% %CopyrightBegin%"))
        self.assertTrue(text(e, ERL).endswith(b"%% %CopyrightEnd%\n"))
        self.assertNotIn(b"-module", text(e, ERL))
        self.assertEqual(e["text_sha256"], sha(text(e, ERL)))
        self.assertEqual(e["notice_sha256"], sha(ERL))

    def test_xml_block_comment(self):
        raw = (
            b"<?xml version='1.0'?>\n<!--\n  %CopyrightBegin%\n"
            b"  SPDX-License-Identifier: MIT\n  %CopyrightEnd%\n-->\n<!ELEMENT a>\n"
        )
        e = otp_block("lib/x/priv/x.dtd", raw, ["MIT"])
        self.assertEqual(e["notice_range_style"], "block-comment")
        self.assertNotIn(b"ELEMENT", text(e, raw))

    def test_reuse_sidecar(self):
        raw = b"%CopyrightBegin%\n\nSPDX-License-Identifier: MIT\n\n%CopyrightEnd%\n"
        e = otp_block("lib/x/priv/a.js.license", raw, ["MIT"])
        self.assertEqual((e["notice_range_style"], text(e, raw)), ("reuse-sidecar", raw))

    def test_unlocatable_notices_stay_unresolved_without_range(self):
        cases = [
            (b"%% SPDX-License-Identifier: MIT\n", ["MIT"]),
            (ERL, ["MIT"]),
            (ERL.replace(b"%% Copyright Ericsson", b"code(). % Copyright"), ["Apache-2.0"]),
            (ERL + ERL, ["Apache-2.0"]),
        ]
        for raw, declared in cases:
            e = otp_block("lib/x/src/x.erl", raw, declared)
            self.assertEqual(e["notice_range_status"], "unresolved")
            self.assertNotIn("source_byte_start", e)
            self.assertTrue(e["notice_range_reason"] and e["notice_range_next_action"])


class ReviewedAnchorTests(unittest.TestCase):
    raw = b"/* Copyright X\n * Permission granted.\n */\nint main(void) { return 0; }\n"

    def rule(self, **kw):
        rule = {
            "notice_sha256": sha(self.raw),
            "style": "comment",
            "start_marker": "/* Copyright X",
            "end_marker": " * Permission granted.",
            "text_sha256": sha(b"/* Copyright X\n * Permission granted.\n"),
        }
        rule.update(kw)
        return rule

    def test_reviewed_comment_range(self):
        e = reviewed("a.c", self.raw, self.rule())
        self.assertEqual(text(e, self.raw), b"/* Copyright X\n * Permission granted.\n")
        self.assertEqual(e["notice_range_style"], "block-comment")

    def test_rejections_do_not_guess(self):
        cases = [
            reviewed("a.c", self.raw, None),
            reviewed("a.c", self.raw, self.rule(notice_sha256="0" * 64)),
            reviewed("a.c", self.raw, self.rule(text_sha256="0" * 64)),
            reviewed("a.c", self.raw, self.rule(end_marker="int main", text_sha256="x")),
            reviewed("a.c", self.raw, self.rule(start_marker="missing")),
        ]
        for e in cases:
            self.assertEqual(e["notice_range_status"], "unresolved")
            self.assertNotIn("source_byte_start", e)

    def test_license_document_is_whole_file(self):
        e = reviewed(
            "LICENSE",
            b"terms\n",
            self.rule(
                notice_sha256=sha(b"terms\n"), style="license-document", text_sha256=sha(b"terms\n")
            ),
        )
        self.assertEqual((e["source_byte_start"], e["source_byte_end"]), (0, 6))

    def test_migration_rules_are_complete(self):
        db = database()
        self.assertEqual(len(notice_ranges(db, "erlang", "28.5.0.7")), 6)
        self.assertEqual(len(notice_ranges(db, "cpython", "3.13.16")), 10)
        for r in db.execute("SELECT * FROM notice_range_rule"):
            if r["style"] != "license-document":
                self.assertTrue(r["start_marker"] and r["end_marker"])
            self.assertRegex(r["text_sha256"], "^[0-9a-f]{64}$")


class ErlangAuditRangeTests(unittest.TestCase):
    def test_scope_evidence_carries_resolvable_range(self):
        bom = {
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
        raw = ERL.replace(b"Apache-2.0", b"MIT")
        installed = {
            "usr/local/lib/erlang/releases/28/OTP_VERSION": b"28.5.0.7\n",
            "usr/local/lib/erlang/erts-16.4/bin/beam.smp": b"ELF native",
            "usr/local/lib/erlang/lib/x-1/ebin/x.beam": b"compiled",
        }
        source = {"lib/x/src/x.erl": raw, "native/n.c": b"// Copyright N\n// Terms.\nint n;\n"}
        rule = {
            "notice_sha256": sha(source["native/n.c"]),
            "style": "comment",
            "start_marker": "// Copyright N",
            "end_marker": "// Terms.",
            "text_sha256": sha(b"// Copyright N\n// Terms.\n"),
        }
        _, report, notices = audit(
            bom, installed, source, [("n", "native/n.c", "MIT", "native")], {"native/n.c": rule}
        )
        for record in report["license_scopes"]:
            e = record["evidence"]
            preserved = notices[e["notice_path"]]
            self.assertEqual(sha(preserved), e["notice_sha256"])
            self.assertEqual(sha(text(e, preserved)), e["text_sha256"])
            self.assertIn("source_path", e)
        self.assertFalse([u for u in report["unresolved"] if "notice byte range" in u["reason"]])
        _, report, _ = audit(bom, installed, source, [("n", "native/n.c", "MIT", "native")])
        self.assertEqual(
            [u["source_path"] for u in report["unresolved"] if "notice byte range" in u["reason"]],
            ["native/n.c"],
        )


if __name__ == "__main__":
    unittest.main()
