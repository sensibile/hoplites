#!/usr/bin/env python3
"""Node tarball and installed npm package evidence; no application execution."""

import ast
import copy
import hashlib
import json
import re
import tarfile
from pathlib import PurePosixPath
from normalize_syft_bom import normalize
from license_scope import record as scope_record, attach as scope_attach, collect as collect_scopes
from elf_linkage import inspect as inspect_elf
from elf_linkage import UnsupportedEncoding

RULE_VERSION = "node-installed-view-v2"


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
            scoped = []
            linkage = None
            linkage_issue = None
            config = None
            config_path = "/usr/local/include/node/config.gypi"
            binary_path = "/usr/local/bin/node"
            if config_path in files and binary_path in files:
                config = ast.literal_eval(files[config_path].decode())["variables"]
                try:
                    linkage = inspect_elf(files[binary_path], ("SSL_new", "inflate", "uv_run"))
                except UnsupportedEncoding as exc:
                    linkage_issue = str(exc)
                    pending.append(
                        {
                            "component": node["bom-ref"],
                            "reason": linkage_issue,
                            "next": "Inspect linkage with a reader supporting this ELF encoding",
                        }
                    )
                sources[config_path.lstrip("/")] = files[config_path]
            inclusion_rules = {
                "OpenSSL": ("node_shared_openssl", "SSL_new", ("libssl", "libcrypto")),
                "zlib": ("node_shared_zlib", "inflate", ("libz.so",)),
                "libuv": ("node_shared_libuv", "uv_run", ("libuv",)),
            }
            for i, match in enumerate(sections):
                section = text[
                    match.start() : sections[i + 1].start() if i + 1 < len(sections) else len(text)
                ]
                ref = "LicenseRef-Node-" + sha(section.encode())[:16]
                terms.append(ref)
                inclusion, relation = "unknown", "source-notice"
                evidence = {
                    "source_path": match[2],
                    "notice_path": license_path,
                    "notice_sha256": sha(raw),
                    "text_sha256": sha(section.encode()),
                    "source_byte_start": len(text[: match.start()].encode()),
                    "source_byte_end": len(
                        text[
                            : sections[i + 1].start() if i + 1 < len(sections) else len(text)
                        ].encode()
                    ),
                }
                if linkage_issue:
                    evidence.update(
                        linkage_assessment="unresolved",
                        reason=linkage_issue,
                        binary_sha256=sha(files[binary_path]),
                        config_sha256=sha(files[config_path]),
                        next_action="Inspect linkage with a reader supporting this ELF encoding",
                    )
                if config is not None and linkage is not None:
                    evidence.update(
                        binary_sha256=sha(files[binary_path]), config_sha256=sha(files[config_path])
                    )
                    if match[1] in inclusion_rules:
                        key, symbol, libraries = inclusion_rules[match[1]]
                        needed = any(
                            any(lib in n for lib in libraries) for n in linkage["dt_needed"]
                        )
                        if (
                            config.get(key) == "false"
                            and symbol in linkage["defined_symbols"]
                            and not needed
                        ):
                            inclusion, relation = "confirmed", "binary-embedded-code"
                        elif config.get(key) == "true" and needed:
                            inclusion, relation = "external", "shared-runtime-dependency"
                        evidence.update(build_key=key, build_value=config.get(key), linkage=linkage)
                    elif match[1] == "V8" and config.get("node_use_bundled_v8") == "true":
                        inclusion, relation = "inferred", "binary-embedded-code"
                        evidence.update(build_key="node_use_bundled_v8", build_value="true")
                item = {
                    "name": match[1],
                    "source_path": match[2],
                    "license_ref": ref,
                    "text_sha256": sha(section.encode()),
                    "assessment": "per-target-inclusion; license applicability requires reviewed mapping",
                }
                inventory.append(item)
                scoped.append(
                    scope_record(node, match[1], relation, ref, inclusion, "unknown", evidence)
                )
            if not terms:
                raise ValueError("Node bundled notice inventory missing")
            scoped.append(
                scope_record(
                    node,
                    "Node project terms",
                    "project-declaration",
                    "MIT",
                    "confirmed",
                    "unknown",
                    {
                        "notice_path": license_path,
                        "notice_sha256": sha(raw),
                        "assessment": "inferred-from-excerpts",
                        "limitations": "Full project notice identity unverified",
                        "next_action": "Review full shipped project terms against the exact upstream release",
                    },
                )
            )
            proposed = [{"license": {"id": "MIT"}}]
            scope_attach(
                node,
                scoped,
                "MIT is inferred from project notice excerpts; full project and per-target terms require review",
            )
            changes.append(
                {
                    "bom_ref": node["bom-ref"],
                    "field": "licenses",
                    "before": node.get("licenses"),
                    "after": proposed,
                    "source_path": license_path,
                    "source_sha256": sha(raw),
                    "assessment": "inferred-MIT-from-installed-excerpts; full project terms unverified",
                    "license_scopes": scoped,
                    "rationale": "Installed notice excerpts resemble MIT",
                    "limitations": "Full project terms are not bound to a reviewed release",
                    "use_risk": "Modified downstream conditions may differ; review the full shipped project terms",
                }
            )
            node["licenses"] = proposed
            node.setdefault("properties", []).append(
                {
                    "name": "hoplites:node:license-scope",
                    "value": "inferred Node project MIT; full project terms and third-party applicability unverified; fulfillment not verified",
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
                        "assessment": "inferred-Apache-2.0-from-installed-header",
                        "rationale": "Installed package declaration and license header resemble Apache-2.0",
                        "limitations": "Full installed terms have not been matched to reviewed text",
                        "use_risk": "Downstream modifications may add different conditions; review full installed terms",
                    }
                )
                c["licenses"] = proposed
                existing = [
                    {k: v for k, v in r.items() if k not in {"component", "version"}}
                    for r in collect_scopes({"components": [c]})
                ]
                existing.append(
                    scope_record(
                        c,
                        "npm project terms",
                        "project-declaration",
                        "Apache-2.0",
                        "confirmed",
                        "unknown",
                        {
                            "notice_path": root + "/LICENSE",
                            "notice_sha256": sha(files[root + "/LICENSE"]),
                            "assessment": "inferred-from-header",
                            "next_action": "Review full installed terms against reviewed Apache-2.0 text",
                        },
                    )
                )
                scope_attach(
                    c,
                    existing,
                    "Apache-2.0 inferred from installed declaration/header; full terms unverified",
                )
                pending.append(
                    {
                        "component": c["bom-ref"],
                        "reason": "npm Apache project terms inferred; full-text review unresolved",
                        "next": "Review complete shipped license and downstream changes",
                    }
                )
    for c in result["components"]:
        if c.get("type") != "file" or c["name"] not in files:
            continue
        path, raw = c["name"], files[c["name"]]
        if [h["content"] for h in c.get("hashes", []) if h["alg"] == "SHA-256"] != [sha(raw)]:
            continue
        matches = [root for root in roots if path.startswith(root + "/")]
        root = max(matches, key=len) if matches else None
        # A directory and matching bytes do not establish ownership of descendants.
        owner = roots[root] if root and path == root + "/package.json" else None
        kind = "verified-installed-package-json"
        if root and owner is None:
            pending.append(
                {
                    "component": c["bom-ref"],
                    "path": path,
                    "reason": "npm descendant ownership unverified; file retained",
                    "next": "Compare a verified package file manifest or identify nested software",
                }
            )
        if (
            owner is None
            and node
            and (
                path == "/usr/local/bin/node"
                or path == "/usr/local/LICENSE"
                or path == "/usr/local/include/node/node_version.h"
            )
        ):
            owner, kind = node, "verified-Node-header-and-distribution-directory"
        if owner is None and path.startswith("/usr/local/include/node/"):
            pending.append(
                {
                    "component": c["bom-ref"],
                    "path": path,
                    "reason": "Node header descendant ownership unverified; file retained",
                    "next": "Verify exact distribution manifest or identify included software",
                }
            )
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
