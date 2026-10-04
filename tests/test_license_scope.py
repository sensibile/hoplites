import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from license_scope import attach, collect, record, render
from elf_linkage import inspect


class LicenseScopeTests(unittest.TestCase):
    def test_changed_scope_content_with_copied_id_is_rejected(self):
        c = {"name": "runtime", "bom-ref": "owner"}
        r = record(c, "target", "binary-embedded-code", "MIT", "unknown", "unknown", {})
        r.update(inclusion="confirmed", applicability="confirmed")
        attach(c, [r], "project")
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            collect({"components": [c]})

    def test_same_terms_preserve_distinct_targets_and_review_actions(self):
        component = {
            "name": "runtime",
            "bom-ref": "owner",
            "licenses": [{"license": {"id": "MIT"}}],
        }
        a = record(
            component,
            "a",
            "binary-embedded",
            "MIT OR Apache-2.0",
            "confirmed",
            "unknown",
            {"copyright": "A"},
        )
        b = record(
            component,
            "b",
            "build-tool",
            "GPL-2.0-only WITH Classpath-exception-2.0",
            "unknown",
            "unknown",
            {"copyright": "B"},
        )
        attach(component, [a, b], "Own code only; bundled scopes separate")
        bom = {"components": [component]}
        rows = collect(json.loads(json.dumps(bom)))
        self.assertNotEqual(rows[0]["id"], rows[1]["id"])
        self.assertTrue(any("selected" in s for s in rows[0]["review_actions"]))
        self.assertTrue(any("exception" in s for s in rows[1]["review_actions"]))
        self.assertEqual(component["licenses"], [{"license": {"id": "MIT"}}])
        previous = copy.deepcopy(component)
        attach(component, [a, b], "Own code only; bundled scopes separate")
        self.assertEqual(previous, component)

    def test_unknown_and_html_escape_and_owner_guard(self):
        c = {"name": "<script>x</script>", "bom-ref": "owner"}
        r = record(
            c, "<target>", "source-notice", None, "unknown", "unknown", {"source": "<raw>" * 1000}
        )
        attach(c, [r], "unknown")
        bom = {"components": [c]}
        self.assertTrue(
            all(len(p["value"]) <= 800 for p in c["properties"] if ":record:" in p["name"])
        )
        self.assertEqual(collect(bom)[0]["evidence"]["source"], "<raw>" * 1000)
        output = render(bom)
        self.assertNotIn("<script>", output)
        self.assertIn("&lt;target&gt;", output)
        self.assertIn("unresolved", output)
        self.assertIn("Standard license field", output)
        damaged = copy.deepcopy(bom)
        damaged["components"][0]["properties"] = [
            p
            for p in damaged["components"][0]["properties"]
            if not p["name"].endswith(":part:0001")
        ]
        with self.assertRaises(ValueError):
            collect(damaged)
        c["bom-ref"] = "different"
        with self.assertRaises(ValueError):
            collect(bom)

    def test_elf_wrong_format_cannot_be_linkage_evidence(self):
        with self.assertRaises(ValueError):
            inspect(b"not an ELF")


if __name__ == "__main__":
    unittest.main()
