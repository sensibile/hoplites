#!/usr/bin/env python3
"""Shipped Python license and RECORD-backed pip vendoring, without executing the image."""

import base64
import copy
import csv
import hashlib
import io
import posixpath
import re
import tarfile
from normalize_syft_bom import normalize

RULE_VERSION = "python-shipped-v1"
LAUNCHER_URL = "https://raw.githubusercontent.com/pypa/distlib/0.4.2/PC/launcher.c"
LAUNCHER_SHA256 = "a0e60a3e9717a2e519120ae19d9c81564f934f38aa322062c26dc21e6c10c0fd"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enrich(bom, files, rules, launcher_source=None):
    result = copy.deepcopy(bom)
    candidates = [
        c
        for c in result["components"]
        if c.get("name") == "python" and c.get("purl", "").startswith("pkg:generic/python@")
    ]
    if not candidates:
        return result, {"rule_version": RULE_VERSION, "changes": [], "unresolved": []}, {}
    if len(candidates) != 1:
        raise ValueError("Ambiguous Python runtime")
    python = candidates[0]
    version = python["version"]
    minor = ".".join(version.split(".")[:2])
    base = "usr/local/lib/python" + minor + "/"
    site = base + "site-packages/"
    marker = "usr/local/include/python" + minor + "/patchlevel.h"
    if marker not in files or not re.search(
        rb'#define\s+PY_VERSION\s+"' + re.escape(version.encode()) + rb'"', files[marker]
    ):
        raise ValueError("Python version marker mismatch")
    changes, pending, sources = [], [], {marker: files[marker]}

    def license_for(component):
        matches = [
            r
            for r in rules
            if r["name"] == component["name"] and r["version"] == component["version"]
        ]
        if not matches:
            pending.append(
                {
                    "component": component["name"],
                    "version": component["version"],
                    "reason": "Shipped license rule missing",
                    "next": "Review shipped terms and add exact hash in a new migration",
                }
            )
            return
        expressions = {r["expression"] for r in matches}
        if len(expressions) != 1:
            raise ValueError("Conflicting shipped license rules")
        for r in matches:
            if r["path"] not in files or sha(files[r["path"]]) != r["sha256"]:
                raise ValueError("Shipped license hash mismatch: " + r["path"])
            sources[r["path"]] = files[r["path"]]
        before = copy.deepcopy(component.get("licenses"))
        component["licenses"] = [{"expression": expressions.pop()}]
        component.setdefault("properties", []).append(
            {
                "name": "hoplites:python:license-assessment",
                "value": "reviewed-shipped-terms; distribution-level; embedded-code-applicability-not-exhaustively-audited",
            }
        )
        changes.append(
            {
                "bom_ref": component["bom-ref"],
                "field": "licenses",
                "before": before,
                "after": component["licenses"],
                "sources": [dict(r) for r in matches],
            }
        )

    license_for(python)
    pips = [c for c in result["components"] if c.get("purl", "").startswith("pkg:pypi/pip@")]
    ownership = []
    record = {}
    vendors = {}
    pip = None
    if len(pips) > 1:
        raise ValueError("Ambiguous pip distribution")
    if pips:
        pip = pips[0]
        metadata = site + "pip-" + pip["version"] + ".dist-info/"
        if b"Version: " + pip["version"].encode() + b"\n" not in files.get(
            metadata + "METADATA", b""
        ):
            raise ValueError("pip metadata version mismatch")
        license_for(pip)
        for path in [metadata + "METADATA", metadata + "RECORD", site + "pip/_vendor/vendor.txt"]:
            sources[path] = files[path]
        for path, checksum, size in csv.reader(io.StringIO(files[metadata + "RECORD"].decode())):
            resolved = posixpath.normpath(site + path)
            if not resolved.startswith("usr/local/") or resolved in record:
                raise ValueError("Unsafe or duplicate pip RECORD path")
            if checksum.startswith("sha256="):
                expected = base64.urlsafe_b64decode(
                    checksum[7:] + "=" * (-len(checksum[7:]) % 4)
                ).hex()
                if (
                    resolved not in files
                    or sha(files[resolved]) != expected
                    or len(files[resolved]) != int(size)
                ):
                    raise ValueError("pip RECORD hash/size mismatch: " + resolved)
                record[resolved] = expected
        for line in sources[site + "pip/_vendor/vendor.txt"].decode().splitlines():
            if "==" not in line:
                continue
            name, v = line.strip().split("==")
            name = name.lower()
            module = {
                "setuptools": "pkg_resources",
                "pyproject-hooks": "pyproject_hooks",
                "tomli-w": "tomli_w",
            }.get(name, name)
            prefix = site + "pip/_vendor/" + module + "/"
            present = [path for path in record if path.startswith(prefix)]
            if not present:
                pending.append(
                    {
                        "component": name,
                        "version": v,
                        "reason": "Vendor manifest entry without installed RECORD files",
                        "next": "Check vendoring patches and module layout",
                    }
                )
                continue
            c = {
                "type": "library",
                "name": name,
                "version": v,
                "purl": "pkg:pypi/" + name + "@" + v,
                "bom-ref": "hoplites:pip-vendor:" + name + "@" + v,
                "properties": [
                    {
                        "name": "hoplites:python:version-assessment",
                        "value": "shipped-vendor-manifest; pip patches may differ from upstream release",
                    }
                ],
            }
            if any(x.get("purl") == c["purl"] for x in result["components"]):
                raise ValueError("Vendor already catalogued; explicit reconciliation required")
            license_for(c)
            result["components"].append(c)
            vendors[prefix] = c
            changes.append(
                {
                    "field": "component",
                    "before": None,
                    "after": copy.deepcopy(c),
                    "source": site + "pip/_vendor/vendor.txt",
                }
            )
        deps = result.setdefault("dependencies", [])
        node = next((d for d in deps if d["ref"] == pip["bom-ref"]), None)
        if node is None:
            node = {"ref": pip["bom-ref"], "dependsOn": []}
            deps.append(node)
        node.setdefault("dependsOn", []).extend(
            c["bom-ref"] for c in vendors.values() if c["bom-ref"] not in node.get("dependsOn", [])
        )

    launcher_paths = {}
    for c in result["components"]:
        if c.get("name") != "Simple Launcher":
            continue
        locations = [
            p["value"].lstrip("/")
            for p in c.get("properties", [])
            if re.fullmatch(r"syft:location:\d+:path", p["name"])
        ]
        if (
            len(locations) != 1
            or locations[0] not in record
            or not locations[0].startswith(site + "pip/_vendor/distlib/")
        ):
            raise ValueError("Launcher not verified by pip RECORD")
        path = locations[0]
        if path in launcher_paths:
            raise ValueError("Duplicate launcher location")
        before = copy.deepcopy(c)
        c["purl"] = (
            "pkg:generic/distlib-launcher@"
            + c["version"]
            + "?file_name="
            + path.rsplit("/", 1)[1]
            + "&sha256="
            + record[path]
        )
        c["hashes"] = [{"alg": "SHA-256", "content": record[path]}]
        if launcher_source is not None:
            if sha(launcher_source) != LAUNCHER_SHA256:
                raise ValueError("Launcher source hash mismatch")
            c["licenses"] = [{"license": {"id": "BSD-2-Clause", "url": LAUNCHER_URL}}]
            c.setdefault("properties", []).append(
                {
                    "name": "hoplites:python:license-assessment",
                    "value": "inferred-from-distlib-0.4.2-source; binary-source-equivalence-unverified",
                }
            )
            sources["upstream/distlib-0.4.2-launcher.c"] = launcher_source
        else:
            pending.append(
                {
                    "component": c["bom-ref"],
                    "reason": "Launcher license source unavailable",
                    "next": "Obtain hash-pinned distlib launcher source",
                }
            )
        launcher_paths[path] = c
        changes.append(
            {
                "bom_ref": c["bom-ref"],
                "before": before,
                "after": copy.deepcopy(c),
                "record_sha256": record[path],
            }
        )

    for c in result["components"]:
        if c.get("type") != "file":
            continue
        path = c["name"].lstrip("/")
        owner = None
        reason = None
        if path in record:
            owner = launcher_paths.get(path) or next(
                (v for prefix, v in vendors.items() if path.startswith(prefix)), pip
            )
            reason = "pip-RECORD-sha256"
        # Link only identified interpreter binaries and release marker/license; retain other stdlib files for later inventory audit.
        elif path in {base + "LICENSE.txt", marker} or path in {
            p["value"].lstrip("/")
            for p in python.get("properties", [])
            if re.fullmatch(r"syft:location:\d+:path", p["name"])
        }:
            owner = python
            reason = "verified-runtime-marker-and-scanner-location"
        if owner is None:
            continue
        declared = next((h["content"] for h in c.get("hashes", []) if h["alg"] == "SHA-256"), None)
        if path not in files or declared != sha(files[path]):
            raise ValueError("Scanner file hash mismatch: " + path)
        ownership.append(
            {
                "bom_ref": c["bom-ref"],
                "status": "linked",
                "path": c["name"],
                "owner_bom_ref": owner["bom-ref"],
                "owner": {"name": owner["name"], "version": owner["version"]},
                "sha256": declared,
                "reason": reason,
            }
        )
    retained_inventory = []
    if pip is not None:
        record_path = site + "pip-" + pip["version"] + ".dist-info/RECORD"
        for c in result["components"]:
            if c.get("type") == "file" and c["name"].lstrip("/") == record_path:
                declared = next(
                    (h["content"] for h in c.get("hashes", []) if h["alg"] == "SHA-256"), None
                )
                if declared != sha(files[record_path]):
                    raise ValueError("RECORD inventory rootfs hash mismatch")
                c.setdefault("properties", []).extend(
                    [
                        {"name": "hoplites:inventory:type", "value": "pip-RECORD"},
                        {"name": "hoplites:inventory:owner-bom-ref", "value": pip["bom-ref"]},
                    ]
                )
                retained_inventory.append(
                    {
                        "component": copy.deepcopy(c),
                        "owner_bom_ref": pip["bom-ref"],
                        "sha256": declared,
                        "assessment": "verified installation manifest; preserved as pip evidence; no self-checksum inferred",
                    }
                )
                ownership.append(
                    {
                        "bom_ref": c["bom-ref"],
                        "status": "linked",
                        "path": c["name"],
                        "owner_bom_ref": pip["bom-ref"],
                        "owner": {"name": pip["name"], "version": pip["version"]},
                        "sha256": declared,
                        "reason": "verified-pip-installation-inventory",
                    }
                )
    result, report = normalize(result, {"files": ownership})
    report.update(
        retained_inventory=retained_inventory,
        rule_version=RULE_VERSION,
        changes=changes,
        unresolved=pending,
        version_marker_sha256=sha(files[marker]),
        limitations=[
            "CPython embedded third-party and remaining stdlib file applicability require further source/header audit",
            "Vendor versions identify shipped declared releases with pip modifications, not byte-identical upstream distributions",
        ],
    )
    return result, report, sources


def process(bom, rootfs, rules, launcher_source=None):
    with tarfile.open(rootfs) as tar:
        files = {}
        for m in tar:
            path = m.name.lstrip("./")
            if path in files:
                raise ValueError("Duplicate rootfs file")
            if m.isfile() and path.startswith("usr/local/"):
                files[path] = tar.extractfile(m).read()
    return enrich(bom, files, rules, launcher_source)
