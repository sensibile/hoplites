#!/usr/bin/env python3
"""Preserve per-target declarations independently from parent license summaries."""

import base64
import hashlib
import html
import json

RULE_VERSION = "license-scope-v1"
PREFIX = "hoplites:license-scope:"


def record(component, subject, relation, expression, inclusion, applicability, evidence):
    value = {
        "owner_bom_ref": component["bom-ref"],
        "subject": subject,
        "relation": relation,
        "declared_expression": expression,
        "inclusion": inclusion,
        "applicability": applicability,
        "evidence": evidence,
        "fulfillment": "not-verified",
        "reviewer": "unassigned",
    }
    value["id"] = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:24]
    actions = []
    if inclusion == "unknown":
        actions.append(
            "Verify whether the delivered artifact includes this code or only uses it during production."
        )
    if applicability != "confirmed":
        actions.append(
            "Determine applicable terms for this target from the preserved source and build evidence."
        )
    if expression and " OR " in expression:
        actions.append("Record the selected license branch for this target; preserve alternatives.")
    if expression and " WITH " in expression:
        actions.append("Check the exception and its conditions for this target.")
    # These are review tasks, not automatically concluded legal obligations.
    actions.append(
        "Review notice, attribution, source provision and modification requirements separately for this target and distribution mode."
    )
    value["review_actions"] = actions
    return value


def attach(component, records, standard_scope):
    retained = []
    for p in component.get("properties", []):
        if not p["name"].startswith(PREFIX):
            retained.append(p)
    component["properties"] = (
        retained
        + [
            {"name": PREFIX + "rule-version", "value": RULE_VERSION},
            {"name": PREFIX + "standard-field-scope", "value": standard_scope},
            {"name": PREFIX + "fulfillment", "value": "not-verified"},
        ]
        + [
            {
                "name": PREFIX + "record:" + r["id"] + ":part:" + str(i // 570).zfill(4),
                "value": "b64:" + base64.b64encode(payload[i : i + 570]).decode(),
            }
            for r in records
            for payload in [json.dumps(r, ensure_ascii=False, sort_keys=True).encode()]
            for i in range(0, len(payload), 570)
        ]
    )


def collect(bom):
    rows = []
    for c in bom.get("components", []):
        grouped = {}
        for p in c.get("properties", []):
            if p["name"].startswith(PREFIX + "record:"):
                suffix = p["name"][len(PREFIX + "record:") :]
                identifier, separator, part = suffix.partition(":part:")
                grouped.setdefault(identifier, []).append(
                    (int(part) if separator else 0, p["value"])
                )
        for identifier, parts in grouped.items():
            parts.sort()
            if [i for i, _ in parts] != list(range(len(parts))):
                raise ValueError("License scope parts missing or duplicated")
            r = json.loads(
                b"".join(
                    base64.b64decode(value[4:], validate=True)
                    if value.startswith("b64:")
                    else value.encode()
                    for _, value in parts
                )
            )
            if r["owner_bom_ref"] != c["bom-ref"] or r["id"] != identifier:
                raise ValueError("License scope owner or identity mismatch")
            rows.append(dict(r, component=c["name"], version=c.get("version")))
    return rows


def render(bom):
    rows = collect(bom)
    fields = [
        ("Component", "component"),
        ("Target", "subject"),
        ("Relationship", "relation"),
        ("Declared terms", "declared_expression"),
        ("Included", "inclusion"),
        ("Applicability", "applicability"),
        ("Evidence", "evidence"),
        ("Review tasks", "review_actions"),
    ]
    cells = []
    for r in rows:
        cells.append(
            "<tr>"
            + "".join(
                "<td>"
                + html.escape(
                    json.dumps(r[k], ensure_ascii=False)
                    if isinstance(r[k], (dict, list))
                    else str(r[k] or "unresolved")
                )
                + "</td>"
                for _, k in fields
            )
            + "</tr>"
        )
    summaries = "".join(
        "<tr><td>"
        + html.escape(c["name"])
        + "</td><td>"
        + html.escape(json.dumps(c.get("licenses", []), ensure_ascii=False))
        + "</td><td>"
        + html.escape(p["value"])
        + "</td></tr>"
        for c in bom.get("components", [])
        for p in c.get("properties", [])
        if p["name"] == PREFIX + "standard-field-scope"
    )
    return (
        '<!doctype html><meta charset="utf-8"><title>License scope review</title><style>body{font:14px sans-serif;padding:24px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:8px;vertical-align:top;overflow-wrap:anywhere}th{background:#eee}td{max-width:300px}</style><h1>License scope and review tasks</h1><p>Project license summaries do not cover every bundled target. Inclusion, applicability and fulfillment are independent. Tasks below require review; they are not legal conclusions. Fulfillment is not verified.</p><table><thead><tr>'.replace(
            "<table><thead><tr>",
            "<h2>Summary field scope</h2><table><tr><th>Component</th><th>Standard license field</th><th>Meaning and limits</th></tr>"
            + summaries
            + "</table><h2>Per-target review</h2><table><thead><tr>",
        )
        + "".join("<th>" + label + "</th>" for label, _ in fields)
        + "</tr></thead><tbody>"
        + "".join(cells)
        + "</tbody></table>"
    )
