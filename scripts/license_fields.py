"""Reject digest placeholders as licenses while retaining their scanner evidence."""

import copy
import re
from license_scope import attach, collect, record, PREFIX

RULE_VERSION = "license-field-semantics-v1"
DIGEST = re.compile(
    r"(?i)(?:(?:sha-?(?:1|224|256|384|512)|md5):[0-9a-f]+|[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{96}|[0-9a-f]{128})"
)


def invalid_fields(item):
    fields = []
    for key, value in [
        ("expression", item.get("expression")),
        ("license.name", item.get("license", {}).get("name")),
        ("license.id", item.get("license", {}).get("id")),
    ]:
        if isinstance(value, str) and DIGEST.fullmatch(value.strip()):
            fields.append(key)
    return fields


def validate(bom):
    for c in bom.get("components", []):
        for item in c.get("licenses", []):
            if invalid_fields(item):
                raise ValueError("Digest placeholder in license field: " + c["name"])


def normalize(bom):
    result = copy.deepcopy(bom)
    changes, unresolved = [], []
    for c in result.get("components", []):
        before = copy.deepcopy(c.get("licenses", []))
        rejected = [(item, invalid_fields(item)) for item in before if invalid_fields(item)]
        if not rejected:
            continue
        retained = [item for item in before if not invalid_fields(item)]
        # A malformed declaration is not replaced with a guessed source-wide expression.
        if retained:
            c["licenses"] = retained
        else:
            c.pop("licenses", None)
        existing = [
            {k: v for k, v in r.items() if k not in ("component", "version")}
            for r in collect({"components": [c]})
        ]
        for item, fields in rejected:
            existing.append(
                record(
                    c,
                    "scanner license digest placeholder",
                    "scanner-evidence-reference",
                    None,
                    "unknown",
                    "unknown",
                    {
                        "scanner_declaration": item,
                        "rejected_fields": fields,
                        "assessment": "Digest identifies scanner evidence, not license terms; original SBOM retained",
                    },
                )
            )
        scope = next(
            (
                p["value"]
                for p in c.get("properties", [])
                if p["name"] == PREFIX + "standard-field-scope"
            ),
            "Scanner declarations; applicability not verified",
        )
        attach(c, existing, scope + "; digest placeholders excluded from license fields")
        changes.append(
            {
                "bom_ref": c["bom-ref"],
                "name": c["name"],
                "purl": c.get("purl"),
                "before": before,
                "after": retained,
                "rejected": [{"declaration": item, "fields": fields} for item, fields in rejected],
            }
        )
        unresolved.append(
            {
                "component": c["name"],
                "purl": c.get("purl"),
                "reason": "Scanner digest is not a license; applicable terms remain unresolved for the referenced declaration",
                "next": "Review preserved per-target copyright/source notices and establish exact artifact applicability; do not infer exemption",
            }
        )
    validate(result)
    return result, {"rule_version": RULE_VERSION, "changes": changes, "unresolved": unresolved}
