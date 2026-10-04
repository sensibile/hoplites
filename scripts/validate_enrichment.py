#!/usr/bin/env python3
"""Check requested enrichment, evidence and completion claims; never infer legal fulfillment."""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from license_fields import invalid_fields
from license_scope import collect

RULE = "enrichment-purpose-v1"
SUPPORTED = {"licenses", "version", "purl"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def text(value):
    return isinstance(value, str) and bool(value.strip())


def populated(field, value):
    if field != "licenses":
        return text(value)
    return (
        isinstance(value, list)
        and bool(value)
        and all(
            isinstance(item, dict)
            and not invalid_fields(item)
            and (
                text(item.get("expression"))
                or text(item.get("license", {}).get("id"))
                or text(item.get("license", {}).get("name"))
            )
            for item in value
        )
    )


def draft(before, bom, before_hash, bom_hash, fields=("licenses",)):
    original = {c["bom-ref"] for c in before.get("components", [])}
    return {
        "schema": RULE,
        "input_sha256": before_hash,
        "output_sha256": bom_hash,
        "purpose": {"consumer": "", "decision": "", "required_output": ""},
        "scope": {
            "types": ["application", "library"],
            "fields": list(fields),
            "exclusions": [],
            "license_coverage": "delivered-artifact",
        },
        "claim": "partial",
        "assessments": [
            {
                "bom_ref": c["bom-ref"],
                "source_refs": [c["bom-ref"]] if c["bom-ref"] in original else [],
                "fields": {
                    field: {
                        "status": "unreviewed",
                        "value": c.get(field),
                        "finding": "",
                        "evidence": [],
                        "known_processing_available": False,
                        "attempts": [],
                        "remaining_problem": "",
                        "next_action": "",
                    }
                    for field in fields
                },
            }
            for c in bom.get("components", [])
            if c.get("type") in {"application", "library"}
        ],
    }


def audit(before, bom, contract=None, root=None, before_hash=None, bom_hash=None):
    errors, pending, checks = [], [], []

    def error(code, target=None):
        errors.append({"code": code, "target": target})

    if contract is None:
        for c in bom.get("components", []):
            if c.get("type") not in {"application", "library"}:
                continue
            value = c.get("licenses")
            if value and not populated("licenses", value):
                error("malformed-or-digest-license-field", c.get("bom-ref"))
            if not value:
                pending.append(
                    {"code": "requested-license-field-empty", "target": c.get("bom-ref")}
                )
        pending.append({"code": "request-contract-and-field-assessments-missing"})
        return {
            "rule_version": RULE,
            "status": "invalid" if errors else "partial",
            "enrichment_complete": False,
            "errors": errors,
            "pending": pending,
            "checks": [],
            "legal_fulfillment": "not-assessed",
            "limits": "Artifact generation and DT equality do not establish requested enrichment completion.",
        }
    if contract.get("schema") != RULE:
        error("contract-schema")
    for field, expected in [("input_sha256", before_hash), ("output_sha256", bom_hash)]:
        if not expected or contract.get(field) != expected:
            error("artifact-hash-mismatch", field)
    if any(
        not text(contract.get("purpose", {}).get(k))
        for k in ["consumer", "decision", "required_output"]
    ):
        error("purpose-missing")
    scope = contract.get("scope", {})
    types, fields = scope.get("types", []), scope.get("fields", [])
    if not types or not set(types) <= {"application", "library", "file", "operating-system"}:
        error("scope-types-missing-or-invalid")
    if not fields or not set(fields) <= SUPPORTED or len(fields) != len(set(fields)):
        error("requested-fields-missing-or-invalid")
    if scope.get("license_coverage") not in {"project-declaration", "delivered-artifact"}:
        error("license-coverage-missing-or-invalid")

    def index(rows, label, key="bom-ref"):
        result = {}
        for row in rows:
            ref = row.get(key)
            if not text(ref) or ref in result:
                error("missing-or-duplicate-" + label, ref)
            else:
                result[ref] = row
        return result

    source = index(before.get("components", []), "source-component")
    output = index(bom.get("components", []), "output-component")
    assessments = index(contract.get("assessments", []), "assessment", "bom_ref")
    exclusions = index(scope.get("exclusions", []), "exclusion", "bom_ref")

    def evidence(items, target):
        if not items:
            error("evidence-missing", target)
            return
        for item in items:
            path = item.get("path")
            if not text(path) or root is None:
                error("evidence-path-missing", target)
                continue
            dest = (root / path).resolve()
            if (
                Path(path).is_absolute()
                or not dest.is_relative_to(root.resolve())
                or not dest.is_file()
            ):
                error("evidence-unavailable-or-outside-root", target)
            elif not text(item.get("supports")) or digest(dest) != item.get("sha256"):
                error("evidence-hash-or-support-mismatch", target)

    for ref, exclusion in exclusions.items():
        if ref not in source and ref not in output:
            error("exclusion-target-missing", ref)
        if not text(exclusion.get("reason")):
            error("exclusion-purpose-missing", ref)
        evidence(exclusion.get("evidence", []), ref)
    selected = {
        ref for ref, c in output.items() if c.get("type") in types and ref not in exclusions
    }
    if not selected:
        error("no-requested-targets")
    for ref in set(assessments) - selected:
        error("assessment-outside-scope", ref)
    covered_source = set(exclusions)
    for ref in sorted(selected):
        component = output[ref]
        assessment = assessments.get(ref)
        if assessment is None:
            pending.append({"code": "field-assessment-missing", "target": ref})
            continue
        refs = assessment.get("source_refs", [])
        if any(r not in source for r in refs) or len(refs) != len(set(refs)):
            error("source-mapping-invalid", ref)
        covered_source.update(refs)
        if set(assessment.get("fields", {})) != set(fields):
            error("requested-field-coverage-mismatch", ref)
        for field in fields:
            target = ref + ":" + field
            value = component.get(field)
            row = assessment.get("fields", {}).get(field, {})
            status = row.get("status")
            if row.get("value") != value:
                error("assessment-value-differs-from-standard-field", target)
            if field == "licenses" and any(invalid_fields(item) for item in value or []):
                error("digest-is-not-license", target)
            checks.append({"target": target, "status": status, "standard_value": value})
            if status == "unreviewed":
                pending.append({"code": "assessment-unreviewed", "target": target})
                continue
            if status not in {"confirmed", "inferred", "unresolved"}:
                error("assessment-status-invalid", target)
                continue
            if not text(row.get("finding")):
                error("investigation-finding-missing", target)
            evidence(row.get("evidence", []), target)
            if status in {"confirmed", "inferred"} and not populated(field, value):
                error("evidence-only-or-empty-standard-field", target)
            if status == "inferred" and any(
                not text(row.get(k)) for k in ["rationale", "limitations", "use_risk"]
            ):
                error("inference-reason-limits-risk-missing", target)
            if status == "unresolved":
                pending.append({"code": "requested-field-unresolved", "target": target})
                if any(
                    not text(row.get(k)) for k in ["remaining_problem", "next_action"]
                ) or not row.get("attempts"):
                    error("unresolved-investigation-and-next-action-missing", target)
                if row.get("known_processing_available") and not any(
                    a.get("status") == "executed"
                    and text(a.get("method"))
                    and text(a.get("result"))
                    for a in row.get("attempts", [])
                ):
                    error("known-processing-not-executed", target)
    for ref, c in source.items():
        if c.get("type") in types and ref not in covered_source:
            error("requested-source-component-dropped-or-unmapped", ref)
    if "licenses" in fields and scope.get("license_coverage") == "delivered-artifact":
        for row in collect(bom):
            if (
                row["owner_bom_ref"] not in selected
                or row["relation"] == "scanner-evidence-reference"
            ):
                continue
            if (
                row["inclusion"] == "unknown"
                or row["applicability"] == "unknown"
                or not row["declared_expression"]
            ):
                pending.append(
                    {
                        "code": "artifact-license-scope-unresolved",
                        "target": row["id"],
                        "subject": row["subject"],
                    }
                )
    if contract.get("claim") not in {"partial", "complete"}:
        error("completion-claim-invalid")
    if contract.get("claim") == "complete" and (pending or errors):
        error("false-completion-claim")
    status = "invalid" if errors else "partial" if pending else "complete"
    return {
        "rule_version": RULE,
        "status": status,
        "enrichment_complete": status == "complete",
        "errors": errors,
        "pending": pending,
        "checks": checks,
        "legal_fulfillment": "not-assessed",
        "limits": "Checks bind field values, scope and evidence files. They do not prove factual/legal correctness of reviewer judgments or license fulfillment.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["init", "check"])
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--bom", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--fields", nargs="+", choices=sorted(SUPPORTED), default=["licenses"])
    args = parser.parse_args()
    if args.mode == "check" and args.report is None:
        parser.error("--report is required for check")
    try:
        before_raw, bom_raw = args.before.read_bytes(), args.bom.read_bytes()
        before, bom = json.loads(before_raw), json.loads(bom_raw)
        before_hash, bom_hash = (
            hashlib.sha256(before_raw).hexdigest(),
            hashlib.sha256(bom_raw).hexdigest(),
        )
        if args.mode == "init":
            payload = draft(before, bom, before_hash, bom_hash, args.fields)
            with args.contract.open("x") as stream:
                json.dump(payload, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
            print("Draft created; field assessments are unreviewed. No completion asserted.")
            return 0
        report = audit(
            before,
            bom,
            json.loads(args.contract.read_bytes()),
            args.evidence_root or args.contract.parent,
            before_hash,
            bom_hash,
        )
    except (ValueError, KeyError, TypeError, AttributeError, OSError) as error:
        report = {
            "rule_version": RULE,
            "status": "invalid",
            "enrichment_complete": False,
            "errors": [{"code": "malformed-input-or-evidence", "detail": str(error)}],
        }
    if args.mode == "init":
        print("invalid: contract could not be created", file=sys.stderr)
        return 2
    try:
        with args.report.open("x") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except OSError as error:
        print("invalid: report not written: " + str(error), file=sys.stderr)
        return 2
    print(report["status"] + ": requested enrichment; legal fulfillment not assessed")
    return {"complete": 0, "partial": 1, "invalid": 2}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
