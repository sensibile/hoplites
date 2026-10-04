#!/usr/bin/env python3
"""Offline Acropolis consumer experiment; never authenticates or uploads knowledge."""

import argparse
import hashlib
import json
from pathlib import Path

RULE = "hoplites-knowledge-consumer-v1"
TENANT = "hoplites"


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def valid_digest(value):
    return (
        isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    )


def read_json(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key: " + key)
            value[key] = item
        return value

    raw = path.read_bytes()
    return json.loads(raw, object_pairs_hook=unique), sha(raw)


def prepare(bom, scopes, component_purl, manifest, platform, input_hashes):
    """Pure mapping of recorded observations; scope applicability stays in the payload."""
    if not manifest.startswith("sha256:") or not valid_digest(manifest[7:]):
        raise ValueError("immutable platform manifest required")
    if not platform or not all(valid_digest(v) for v in input_hashes.values()):
        raise ValueError("platform and input hashes required")
    components = [c for c in bom.get("components", []) if c.get("purl") == component_purl]
    if len(components) != 1:
        raise ValueError("component must resolve uniquely")
    component = components[0]
    rows = [r for r in scopes.get("records", []) if r.get("owner_bom_ref") == component["bom-ref"]]
    if not rows:
        raise ValueError("component scope records missing")
    conditions = {
        "image_manifest": manifest,
        "platform": platform,
        "package_version": component["version"],
    }
    author = {"kind": "static", "name": "hoplites-scope-export", "version": RULE}
    subject = component_purl
    sources = [
        {"locator": "urn:hoplites:sha256:" + v, "sha256": v} for v in sorted(input_hashes.values())
    ]
    identity = sha(encode({"subject": subject, "conditions": conditions}))[:24]
    records = []
    links = []

    def record(identifier, kind, content, assessment):
        return {
            "id": identifier,
            "kind": kind,
            "subject": subject,
            "content": content,
            "author": author,
            "assessment": assessment,
            "sources": sources,
            "conditions": conditions,
            "rationale": None,
            "limitations": [],
        }

    evidence_id = "evidence-" + identity
    records.append(
        record(
            evidence_id,
            "evidence",
            encode(
                {
                    "observation": "Preserved BOM component and per-target scope records; not an applicability conclusion.",
                    "component": {
                        k: component.get(k)
                        for k in ("name", "version", "purl", "bom-ref", "licenses")
                    },
                    "license_scopes": rows,
                }
            ).decode(),
            "confirmed",
        )
    )
    # Confirmed means the source data was observed, not that every source assertion is true.
    for row in rows:
        if not row.get("id") or not row.get("review_actions"):
            raise ValueError("scope identity and follow-up actions required")
        identifier = "question-" + identity + "-" + row["id"]
        records.append(
            record(
                identifier,
                "question",
                encode(
                    {
                        "scope_id": row["id"],
                        "subject": row.get("subject"),
                        "declared_expression": row.get("declared_expression"),
                        "inclusion": row.get("inclusion"),
                        "applicability": row.get("applicability"),
                        "fulfillment": row.get("fulfillment"),
                        "next_actions": row["review_actions"],
                    }
                ).decode(),
                "unresolved",
            )
        )
        links.append({"from": evidence_id, "to": identifier, "kind": "supports"})
    operations = [{"op": "put", "record": r} for r in records] + [
        {"op": "link", "link": l} for l in links
    ]
    return {
        "schema": RULE,
        "tenant": TENANT,
        "status": "offline-draft",
        "authentication": "not-connected",
        "artifact": conditions,
        "subject": subject,
        "input_sha256": input_hashes,
        "source_rule_version": scopes.get("rule_version"),
        "mapping": "provisional-local-akashic-v1",
        "record_ids": [r["id"] for r in records],
        "write_template": {
            "command": "apply",
            "request": {
                "request_id": "hoplites-" + sha(encode(operations)),
                "expected_version": None,
                "operations": operations,
            },
        },
    }


def report(bundle, exported, version):
    """Consume explicitly namespaced offline export; never infer authenticated tenant."""
    if (
        bundle.get("schema") != RULE
        or bundle.get("tenant") != TENANT
        or exported.get("tenant") != TENANT
    ):
        raise ValueError("namespace mismatch or missing")
    if type(version) is not int or version < 1 or exported.get("version") != version:
        raise ValueError("exact knowledge version required; no latest fallback")
    graph = exported["graph"]
    records = graph["records"]
    expected = {
        op["record"]["id"]: op["record"]
        for op in bundle["write_template"]["request"]["operations"]
        if op["op"] == "put"
    }
    for identifier, original in expected.items():
        actual = records.get(identifier)
        if actual != original:
            raise ValueError("snapshot does not contain exact exported record: " + identifier)
    links = graph["links"]
    for link in links:
        if link["from"] not in records or link["to"] not in records:
            raise ValueError("dangling snapshot relationship")
    for op in bundle["write_template"]["request"]["operations"]:
        if op["op"] == "link" and op["link"] not in links:
            raise ValueError("missing exported relationship")
    for item in records.values():
        if (
            item.get("subject") == bundle["subject"]
            and item.get("conditions") != bundle["artifact"]
        ):
            raise ValueError("artifact conditions differ")
    selected = {k: v for k, v in records.items() if v.get("subject") == bundle["subject"]}
    # Keep incoming transitive supporting evidence, even when its subject differs.
    while True:
        extra = {l["from"] for l in links if l["kind"] == "supports" and l["to"] in selected}
        missing = extra - selected.keys()
        if not missing:
            break
        selected.update({k: records[k] for k in missing})
    return {
        "schema": RULE,
        "status": "offline-draft",
        "tenant": TENANT,
        "authentication": "not-connected",
        "artifact": bundle["artifact"],
        "subject": bundle["subject"],
        "knowledge_version": version,
        "snapshot_sha256": sha(encode(exported)),
        "bundle_sha256": sha(encode(bundle)),
        "rule_version": RULE,
        "source_rule_version": bundle["source_rule_version"],
        "input_sha256": bundle["input_sha256"],
        "records": selected,
        "links": [l for l in links if l["from"] in selected and l["to"] in selected],
        "open_questions": sorted(
            k
            for k, v in selected.items()
            if v["kind"] == "question" and v["assessment"] == "unresolved"
        ),
        "legal_fulfillment": "not-assessed",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    prep = subs.add_parser("prepare")
    for name in ("bom", "scopes", "purl", "manifest", "platform", "output"):
        prep.add_argument("--" + name, required=True)
    view = subs.add_parser("report")
    for name in ("bundle", "snapshot", "output"):
        view.add_argument("--" + name, required=True)
    view.add_argument("--version", required=True, type=int)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            bom, bh = read_json(Path(args.bom))
            scopes, sh = read_json(Path(args.scopes))
            result = prepare(
                bom, scopes, args.purl, args.manifest, args.platform, {"bom": bh, "scopes": sh}
            )
        else:
            bundle, _ = read_json(Path(args.bundle))
            snapshot, _ = read_json(Path(args.snapshot))
            result = report(bundle, snapshot, args.version)
        # Never overwrite a prior report or evidence bundle.
        with Path(args.output).open("xb") as output:
            output.write(encode(result))
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
