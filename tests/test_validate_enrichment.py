import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from validate_enrichment import audit, draft
from license_scope import attach, record


class EnrichmentValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.evidence = self.root / "source.txt"
        self.evidence.write_text(
            "Example source declaration MIT; target mapping reviewed separately."
        )
        self.bom = {
            "components": [
                {
                    "name": "p",
                    "type": "library",
                    "bom-ref": "p",
                    "licenses": [{"license": {"id": "MIT"}}],
                }
            ]
        }
        self.before = copy.deepcopy(self.bom)
        self.contract = draft(self.before, self.bom, "input", "output")
        self.contract["purpose"] = {
            "consumer": "release reviewer",
            "decision": "Identify license terms and required investigations",
            "required_output": "Standard licenses with source evidence and unresolved work",
        }
        self.contract["assessments"][0]["fields"]["licenses"].update(
            status="confirmed",
            finding="Project license and target checked",
            evidence=[
                {
                    "path": "source.txt",
                    "sha256": hashlib.sha256(self.evidence.read_bytes()).hexdigest(),
                    "supports": "License declaration and target mapping",
                }
            ],
        )

    def run_audit(self):
        return audit(self.before, self.bom, self.contract, self.root, "input", "output")

    def codes(self):
        return {row["code"] for row in self.run_audit()["errors"]}

    def test_complete_populated_field_with_bound_evidence(self):
        self.contract["claim"] = "complete"
        self.assertEqual(self.run_audit()["status"], "complete")
        self.assertEqual(self.run_audit()["legal_fulfillment"], "not-assessed")

    def test_inference_is_allowed_with_source_reason_limits_and_risk(self):
        row = self.contract["assessments"][0]["fields"]["licenses"]
        row.update(
            status="inferred",
            rationale="Distribution mapping",
            limitations="No rebuilt-byte equivalence",
            use_risk="Requires target review before fulfillment",
        )
        self.assertEqual(self.run_audit()["status"], "complete")
        row.pop("limitations")
        self.assertIn("inference-reason-limits-risk-missing", self.codes())

    def test_empty_standard_field_cannot_pass_using_only_evidence(self):
        self.bom["components"][0].pop("licenses")
        self.contract["assessments"][0]["fields"]["licenses"]["value"] = None
        self.assertIn("evidence-only-or-empty-standard-field", self.codes())

    def test_honest_unresolved_is_partial_and_complete_claim_rejected(self):
        row = self.contract["assessments"][0]["fields"]["licenses"]
        row.update(
            status="unresolved",
            attempts=[
                {
                    "method": "Read exact source notice",
                    "status": "executed",
                    "result": "Applicability remains unclear",
                }
            ],
            remaining_problem="Binary target correspondence",
            next_action="Check build selectors",
        )
        self.assertEqual(self.run_audit()["status"], "partial")
        self.contract["claim"] = "complete"
        self.assertIn("false-completion-claim", self.codes())

    def test_known_processing_cannot_be_skipped_as_unknown(self):
        row = self.contract["assessments"][0]["fields"]["licenses"]
        row.update(
            status="unresolved",
            attempts=[{"method": "adapter", "status": "skipped"}],
            known_processing_available=True,
            remaining_problem="Not run",
            next_action="Run adapter",
        )
        self.assertIn("known-processing-not-executed", self.codes())

    def test_artifact_scopes_prevent_main_mit_from_claiming_complete_bundle(self):
        c = self.bom["components"][0]
        attach(
            c,
            [
                record(
                    c,
                    "embedded library",
                    "binary-embedded-code",
                    "LicenseRef-Example",
                    "confirmed",
                    "unknown",
                    {"source": "notice"},
                )
            ],
            "Project MIT only",
        )
        self.assertEqual(self.run_audit()["status"], "partial")
        self.contract["claim"] = "complete"
        self.assertIn("false-completion-claim", self.codes())

    def test_missing_and_invalid_scope_states_never_complete(self):
        for field in ("inclusion", "applicability"):
            for value in (None, "", "unexpected", [], {}):
                with self.subTest(field=field, value=value):
                    c = self.bom["components"][0]
                    row = record(
                        c, "target", "binary-embedded-code", "MIT", "confirmed", "confirmed", {}
                    )
                    if value is None:
                        row.pop(field)
                    else:
                        row[field] = value
                    attach(c, [row], "project declaration")
                    result = self.run_audit()
                    self.assertFalse(result["enrichment_complete"])
                    self.assertIn(
                        "artifact-license-scope-state-invalid",
                        {e["code"] for e in result["errors"]},
                    )

    def test_changed_artifact_or_tampered_source_is_rejected(self):
        self.contract["output_sha256"] = "different"
        self.assertIn("artifact-hash-mismatch", self.codes())
        self.evidence.write_text("changed")
        self.assertIn("evidence-hash-or-support-mismatch", self.codes())

    def test_missing_duplicate_assessment_and_dropped_target_are_rejected(self):
        self.contract["assessments"].append(copy.deepcopy(self.contract["assessments"][0]))
        self.assertIn("missing-or-duplicate-assessment", self.codes())
        self.before["components"].append({"name": "other", "type": "library", "bom-ref": "other"})
        self.assertIn("requested-source-component-dropped-or-unmapped", self.codes())
        self.contract["assessments"] = []
        self.assertFalse(self.run_audit()["enrichment_complete"])

    def test_digest_and_evidence_outside_root_are_rejected(self):
        value = [{"license": {"name": "sha256:" + "a" * 64}}]
        self.bom["components"][0]["licenses"] = value
        self.contract["assessments"][0]["fields"]["licenses"]["value"] = value
        self.assertIn("digest-is-not-license", self.codes())
        self.contract["assessments"][0]["fields"]["licenses"]["evidence"][0]["path"] = (
            "../outside.txt"
        )
        self.assertIn("evidence-unavailable-or-outside-root", self.codes())

    def test_missing_contract_cannot_be_completion(self):
        self.assertFalse(audit(self.before, self.bom)["enrichment_complete"])

    def test_cli_returns_nonzero_for_unreviewed_and_false_complete(self):
        before, bom = self.root / "before.json", self.root / "bom.json"
        before.write_text(json.dumps(self.before))
        bom.write_text(json.dumps(self.bom))
        script = Path(__file__).parents[1] / "scripts/validate_enrichment.py"
        contract = self.root / "contract.json"
        init = subprocess.run(
            [
                sys.executable,
                str(script),
                "init",
                "--before",
                str(before),
                "--bom",
                str(bom),
                "--contract",
                str(contract),
            ],
            capture_output=True,
        )
        self.assertEqual(init.returncode, 0)
        payload = json.loads(contract.read_text())
        payload["purpose"] = self.contract["purpose"]
        contract.write_text(json.dumps(payload))
        check = [
            sys.executable,
            str(script),
            "check",
            "--before",
            str(before),
            "--bom",
            str(bom),
            "--contract",
            str(contract),
            "--report",
        ]
        self.assertEqual(
            subprocess.run(
                check + [str(self.root / "partial.json")], capture_output=True
            ).returncode,
            1,
        )
        payload["claim"] = "complete"
        contract.write_text(json.dumps(payload))
        self.assertEqual(
            subprocess.run(
                check + [str(self.root / "invalid.json")], capture_output=True
            ).returncode,
            2,
        )

    def test_cli_malformed_input_fails_closed_without_overwriting(self):
        source = self.root / "broken.json"
        source.write_text("{broken")
        script = Path(__file__).parents[1] / "scripts/validate_enrichment.py"
        report = self.root / "failure.json"
        args = [
            sys.executable,
            str(script),
            "check",
            "--before",
            str(source),
            "--bom",
            str(source),
            "--contract",
            str(source),
            "--report",
            str(report),
        ]
        self.assertEqual(subprocess.run(args, capture_output=True).returncode, 2)
        self.assertFalse(json.loads(report.read_text())["enrichment_complete"])
        original = report.read_bytes()
        self.assertEqual(subprocess.run(args, capture_output=True).returncode, 2)
        self.assertEqual(report.read_bytes(), original)

    def test_exclusion_requires_reason_and_real_evidence(self):
        self.before["components"].append(
            {"name": "inventory", "type": "library", "bom-ref": "inventory"}
        )
        self.contract["scope"]["exclusions"] = [
            {
                "bom_ref": "inventory",
                "reason": "Verified inventory evidence is linked to its owner",
                "evidence": self.contract["assessments"][0]["fields"]["licenses"]["evidence"],
            }
        ]
        self.assertEqual(self.run_audit()["status"], "complete")
        self.contract["scope"]["exclusions"][0]["evidence"] = []
        self.assertIn("evidence-missing", self.codes())


if __name__ == "__main__":
    unittest.main()
