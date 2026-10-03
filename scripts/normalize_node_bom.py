#!/usr/bin/env python3
"""Node tarball and installed npm package evidence; no application execution."""

import copy
import hashlib
import json
import re
import tarfile
from pathlib import PurePosixPath
from normalize_syft_bom import normalize

RULE_VERSION = "node-installed-view-v1"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def process(bom, files):
    result = copy.deepcopy(bom)
    sources, changes, entries, pending, inventory = {}, [], [], [], []
    roots = {}
    nodes = [c for c in result["components"] if c.get("purl", "").startswith("pkg:generic/node@")]
    if len(nodes) > 1:
        raise ValueError("Ambiguous Node runtime")
    node = nodes[0] if nodes else None
    if node:
        marker = "/usr/local/include/node/node_version.h"
        license_path = "/usr/local/LICENSE"
        if marker not in files or license_path not in files:
            pending.append(
                {
                    "component": node["bom-ref"],
                    "reason": "Node release evidence missing",
                    "next": "Inspect installation layout and add verified adapter",
                }
            )
            node = None
        else:
            version = ".".join(
                re.search(rb"#define NODE_" + part + rb"_VERSION\s+(\d+)", files[marker])
                .group(1)
                .decode()
                for part in (b"MAJOR", b"MINOR", b"PATCH")
            )
            if version != node.get("version"):
                raise ValueError("Node header and scanner version mismatch")
            raw = files[license_path]
            if (
                not raw.startswith(b"Node.js is licensed for use as follows:")
                or b"Permission is hereby granted, free of charge"
                not in raw.split(b"This license applies")[0]
            ):
                raise ValueError("Unrecognized Node license")
            sources[marker.lstrip("/")] = files[marker]
            sources[license_path.lstrip("/")] = raw
            text = raw.decode()
            sections = list(
                re.finditer(r"(?m)^- (.+?), located at (.+?), is licensed as follows:", text)
            )
            terms = []
            for i, match in enumerate(sections):
                section = text[
                    match.start() : sections[i + 1].start() if i + 1 < len(sections) else len(text)
                ]
                ref = "LicenseRef-Node-" + sha(section.encode())[:16]
                terms.append(ref)
                inventory.append(
                    {
                        "name": match[1],
                        "source_path": match[2],
                        "license_ref": ref,
                        "text_sha256": sha(section.encode()),
                        "assessment": "shipped-source-notice; binary-inclusion-and-version-unresolved",
                    }
                )
            if not terms:
                raise ValueError("Node bundled notice inventory missing")
            proposed = [{"expression": " AND ".join(["MIT"] + terms)}]
            changes.append(
                {
                    "bom_ref": node["bom-ref"],
                    "field": "licenses",
                    "before": node.get("licenses"),
                    "after": proposed,
                    "source_path": license_path,
                    "source_sha256": sha(raw),
                    "assessment": "MIT project terms verified; complete source-notice aggregate has inferred binary applicability",
                }
            )
            node["licenses"] = proposed
            node.setdefault("properties", []).append(
                {
                    "name": "hoplites:node:license-scope",
                    "value": "MIT project plus shipped source notice inventory; per-binary applicability and bundled versions unresolved",
                }
            )
            pending.append(
                {
                    "component": node["bom-ref"],
                    "reason": "Node bundled source notices require canonical mapping and binary applicability",
                    "inventory": inventory,
                    "next": "Inspect exact release build/source for each notice; retain full shipped LICENSE",
                }
            )
    for c in result["components"]:
        if not c.get("purl", "").startswith("pkg:npm/"):
            continue
        locations = [
            p["value"]
            for p in c.get("properties", [])
            if p["name"].startswith("syft:location:")
            and p["name"].endswith(":path")
            and p["value"].endswith("/package.json")
        ]
        for location in locations:
            if location not in files:
                continue
            raw = files[location]
            package = json.loads(raw)
            if (package.get("name"), package.get("version")) != (c["name"], c.get("version")):
                raise ValueError("npm package identity mismatch")
            root = str(PurePosixPath(location).parent)
            if root in roots and roots[root]["bom-ref"] != c["bom-ref"]:
                raise ValueError("Ambiguous npm directory owner")
            roots[root] = c
            sources[location.lstrip("/")] = raw
            for leaf in ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING"):
                path = root + "/" + leaf
                if path in files:
                    sources[path.lstrip("/")] = files[path]
            if (
                package.get("license") == "Apache 2.0"
                and files.get(root + "/LICENSE", b"").lstrip().startswith(b"Apache License")
                and b"Version 2.0, January 2004" in files[root + "/LICENSE"]
            ):
                proposed = [{"license": {"id": "Apache-2.0"}}]
                changes.append(
                    {
                        "bom_ref": c["bom-ref"],
                        "field": "licenses",
                        "before": c.get("licenses"),
                        "after": proposed,
                        "source_path": root + "/LICENSE",
                        "source_sha256": sha(files[root + "/LICENSE"]),
                        "assessment": "verified-installed-Apache-2.0-text",
                    }
                )
                c["licenses"] = proposed
    for c in result["components"]:
        if c.get("type") != "file" or c["name"] not in files:
            continue
        path, raw = c["name"], files[c["name"]]
        if [h["content"] for h in c.get("hashes", []) if h["alg"] == "SHA-256"] != [sha(raw)]:
            continue
        matches = [root for root in roots if path.startswith(root + "/")]
        owner = roots[max(matches, key=len)] if matches else None
        kind = "verified-installed-package-json-directory"
        if (
            owner is None
            and node
            and (
                path == "/usr/local/bin/node"
                or path == "/usr/local/LICENSE"
                or path.startswith("/usr/local/include/node/")
            )
        ):
            owner, kind = node, "verified-Node-header-and-distribution-directory"
        if owner:
            entries.append(
                {
                    "bom_ref": c["bom-ref"],
                    "path": path,
                    "status": "linked",
                    "owner_bom_ref": owner["bom-ref"],
                    "owner": {"name": owner["name"], "version": owner["version"]},
                    "file_sha256": sha(raw),
                    "source_kind": kind,
                }
            )
    result, report = normalize(result, {"files": entries})
    return (
        result,
        {
            "rule_version": RULE_VERSION,
            "changes": changes,
            "file_normalization": report,
            "bundled_inventory": inventory,
            "unresolved": pending,
            "remaining_count": len(result["components"]),
            "limitations": [
                "Package directory attribution is not upstream byte equivalence.",
                "Bundled source notices include build/test code; aggregate is not a final binary obligation determination.",
            ],
        },
        sources,
    )


def archive_files(rootfs):
    with tarfile.open(rootfs) as tar:
        return {
            "/" + m.name.lstrip("./"): tar.extractfile(m).read()
            for m in tar
            if m.isfile() and (m.name.lstrip("./").startswith(("usr/local/", "opt/yarn-")))
        }
