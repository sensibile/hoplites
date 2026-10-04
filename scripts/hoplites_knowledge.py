#!/usr/bin/env python3
"""Offline Acropolis consumer experiment; never authenticates or uploads knowledge."""

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from normalize_debian_bom import fields

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


def prepare(bom, scopes, component_purl, manifest, platform, input_hashes, installation=None):
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
                    "installation": installation,
                }
            ).decode(),
            "confirmed",
        )
    )
    if installation is not None:
        role_id = "role-" + identity
        records.append(
            record(
                role_id,
                "statement",
                encode(
                    {
                        "finding": "Installed package paths and reverse dependency declarations observed in the pinned package database.",
                        "installation": installation,
                    }
                ).decode(),
                "confirmed",
            )
        )
        links.append({"from": evidence_id, "to": role_id, "kind": "supports"})
    # Confirmed means the source data was observed, not that every source assertion is true.
    for row in rows:
        if not row.get("id") or not row.get("review_actions"):
            raise ValueError("scope identity and follow-up actions required")
        scanner_name = (
            row.get("evidence", {}).get("scanner_declaration", {}).get("license", {}).get("name")
        )
        digest_reference = (
            row.get("relation") == "scanner-evidence-reference"
            and isinstance(scanner_name, str)
            and scanner_name.startswith("sha256:")
            and valid_digest(scanner_name[7:])
        )
        identifier = (
            ("observation-" if digest_reference else "question-") + identity + "-" + row["id"]
        )
        records.append(
            record(
                identifier,
                "statement" if digest_reference else "question",
                encode(
                    {
                        "scope_id": row["id"],
                        "relation": row.get("relation"),
                        "observation": "Scanner digest is evidence identity, not license terms."
                        if digest_reference
                        else None,
                        "subject": row.get("subject"),
                        "declared_expression": row.get("declared_expression"),
                        "inclusion": row.get("inclusion"),
                        "applicability": row.get("applicability"),
                        "fulfillment": row.get("fulfillment"),
                        "next_actions": row["review_actions"],
                    }
                ).decode(),
                "confirmed" if digest_reference else "unresolved",
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

    def compatible(item):
        conditions = item.get("conditions", {})
        artifact = bundle["artifact"]
        if (
            conditions.get("image_manifest") != artifact["image_manifest"]
            or conditions.get("package_version") != artifact["package_version"]
        ):
            return False
        for key, value in conditions.items():
            expected_value = artifact.get(key)
            if key == "architecture":
                expected_value = artifact["platform"].split("/")[-1]
            if value != expected_value:
                return False
        return "platform" in conditions or "architecture" in conditions

    selected = {
        k: v for k, v in records.items() if v.get("subject") == bundle["subject"] and compatible(v)
    }
    excluded = sorted(
        k for k, v in records.items() if v.get("subject") == bundle["subject"] and not compatible(v)
    )
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
        "excluded_condition_records": excluded,
        "legal_fulfillment": "not-assessed",
    }


def component_architecture(component):
    """Use the selected Debian package identity, including multiarch packages."""
    purl = component.get("purl", "")
    values = parse_qs(urlsplit(purl).query, keep_blank_values=True).get("arch", [])
    if (
        not purl.startswith("pkg:deb/")
        or len(values) != 1
        or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", values[0])
    ):
        raise ValueError("unambiguous Debian PURL architecture required for dpkg evidence")
    return values[0]


def installation_from_tar(path, package, architecture, version):
    """Read bounded regular dpkg evidence without extracting or following tar links."""
    wanted = {f"var/lib/dpkg/info/{package}:{architecture}.list", "var/lib/dpkg/status"}
    captured = {}
    rootfs_hash = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            rootfs_hash.update(block)
        source.seek(0)
        with tarfile.open(fileobj=source, mode="r:*") as archive:
            for member in archive:
                name = member.name.removeprefix("./").removeprefix("/")
                if name not in wanted:
                    continue
                if name in captured or not member.isfile() or member.size > 8 * 1024 * 1024:
                    raise ValueError("duplicate, linked or oversized dpkg evidence")
                captured[name] = archive.extractfile(member).read()
    if captured.keys() != wanted:
        raise ValueError("exact dpkg evidence missing")
    list_path = f"var/lib/dpkg/info/{package}:{architecture}.list"
    paths = captured[list_path].decode().splitlines()
    entries = []
    for paragraph in captured["var/lib/dpkg/status"].decode().split("\n\n"):
        entry = fields(paragraph)
        if entry.get("Package"):
            entries.append(entry)
    owner = [
        e for e in entries if e["Package"] == package and e.get("Architecture") == architecture
    ]
    if (
        len(owner) != 1
        or owner[0].get("Version") != version
        or owner[0].get("Status") != "install ok installed"
    ):
        raise ValueError("dpkg owner identity/version/status differs")
    dependency = re.compile(r"(?:^|[,|])\s*" + re.escape(package) + r"(?:\s|\(|:|$)")
    dependents = [
        {
            k.lower(): e.get(k)
            for k in ("Package", "Version", "Architecture", "Depends", "Pre-Depends")
        }
        for e in entries
        if e.get("Status") == "install ok installed"
        and dependency.search(e.get("Depends", "") + "," + e.get("Pre-Depends", ""))
    ]
    ancestors = {"/.", "/", "/usr", "/usr/share", "/usr/share/doc"}
    docs_only = bool(paths) and all(
        p in ancestors
        or p == "/usr/share/doc/" + package
        or p.startswith("/usr/share/doc/" + package + "/")
        for p in paths
    )
    return {
        "package": package,
        "version": version,
        "architecture": architecture,
        "installed_paths": paths,
        "documentation_paths_only": docs_only,
        "reverse_dependency_declarations": sorted(dependents, key=lambda e: e["package"]),
        "sources": [{"path": "/" + k, "sha256": sha(v)} for k, v in sorted(captured.items())],
        "limits": "Package database declarations and file inventory; not a dependency solver or license applicability decision.",
    }, rootfs_hash.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    prep = subs.add_parser("prepare")
    for name in ("bom", "scopes", "purl", "manifest", "platform", "output"):
        prep.add_argument("--" + name, required=True)
    prep.add_argument("--rootfs")
    view = subs.add_parser("report")
    for name in ("bundle", "snapshot", "output"):
        view.add_argument("--" + name, required=True)
    view.add_argument("--version", required=True, type=int)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            bom, bh = read_json(Path(args.bom))
            scopes, sh = read_json(Path(args.scopes))
            hashes = {"bom": bh, "scopes": sh}
            installation = None
            if args.rootfs:
                candidates = [c for c in bom.get("components", []) if c.get("purl") == args.purl]
                if len(candidates) != 1:
                    raise ValueError("component must resolve uniquely")
                c = candidates[0]
                installation, hashes["rootfs"] = installation_from_tar(
                    Path(args.rootfs), c["name"], component_architecture(c), c["version"]
                )
            result = prepare(
                bom, scopes, args.purl, args.manifest, args.platform, hashes, installation
            )
        else:
            bundle, _ = read_json(Path(args.bundle))
            snapshot, _ = read_json(Path(args.snapshot))
            result = report(bundle, snapshot, args.version)
        # Never overwrite a prior report or evidence bundle.
        with Path(args.output).open("xb") as output:
            output.write(encode(result))
    except (ValueError, KeyError, TypeError, OSError, tarfile.TarError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
