#!/usr/bin/env python3
"""Map hash-pinned CPython source notices to installed source/build artifacts."""

import ast
import copy
import fnmatch
import hashlib
import tarfile
from license_scope import record as scope_record, attach as scope_attach


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def audit(bom, installed, source, rules, archive_sha256, image_env):
    result = copy.deepcopy(bom)
    candidates = [
        c for c in result["components"] if c.get("purl", "").startswith("pkg:generic/python@")
    ]
    if len(candidates) != 1:
        raise ValueError("Missing/ambiguous CPython runtime")
    python = candidates[0]
    version = python["version"]
    if (
        image_env.get("PYTHON_VERSION") != version
        or image_env.get("PYTHON_SHA256") != archive_sha256
    ):
        raise ValueError("Image build/source association mismatch")
    selected = [r for r in rules if r["version"] == version]
    if any(r["archive_sha256"] != archive_sha256 for r in selected):
        raise ValueError("Reviewed CPython archive mismatch")
    base = "usr/local/lib/python" + ".".join(version.split(".")[:2]) + "/"
    configs = [p for p in installed if p.startswith(base + "_sysconfigdata_") and p.endswith(".py")]
    if len(configs) != 1:
        raise ValueError("Missing/ambiguous installed CPython build metadata")
    tree = ast.parse(installed[configs[0]])
    variables = [
        ast.literal_eval(n.value)
        for n in tree.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "build_time_vars" for t in n.targets)
    ]
    if len(variables) != 1 or not isinstance(variables[0], dict):
        raise ValueError("Invalid CPython build metadata")
    build = variables[0]
    additions, pending, notices = [], [], {configs[0]: installed[configs[0]]}
    for r in selected:
        raw = source.get(r["source_path"])
        notice = source.get(r["notice_path"])
        if (
            raw is None
            or notice is None
            or sha(raw) != r["source_sha256"]
            or sha(notice) != r["notice_sha256"]
        ):
            raise ValueError("CPython reviewed source/notice hash mismatch")
        paths = [p for p in installed if fnmatch.fnmatchcase(p, base + r["installed_selector"])]
        if len(paths) != 1:
            pending.append(
                {
                    "name": r["name"],
                    "reason": "installed artifact selector missing/ambiguous",
                    "next": "Review exact module build and installed layout",
                }
            )
            continue
        path = paths[0]
        if r["mode"] == "source-match":
            if installed[path] != raw:
                pending.append(
                    {
                        "name": r["name"],
                        "path": path,
                        "reason": "installed source differs from pinned upstream; terms not inferred",
                        "next": "Review installed patch and license header",
                    }
                )
                continue
            status = "confirmed-source-bytes-and-notice"
        elif r["mode"] == "binary-build":
            if r["build_indicator"] not in str(build.get(r["build_key"], "")):
                pending.append(
                    {
                        "name": r["name"],
                        "reason": "build indicator absent",
                        "next": "Check external versus bundled library build",
                    }
                )
                continue
            status = "inferred-from-image-source-hash-installed-build-metadata-and-module; rebuilt-byte-equivalence-unverified"
        else:
            raise ValueError("Unknown CPython audit mode")
        notices["cpython/" + r["notice_path"]] = notice
        notices["cpython/" + r["source_path"]] = raw
        additions.append(
            dict(r, installed_path=path, installed_sha256=sha(installed[path]), assessment=status)
        )
        if r["expression"].startswith("LicenseRef-"):
            pending.append(
                {
                    "name": r["name"],
                    "expression": r["expression"],
                    "source_path": r["notice_path"],
                    "reason": "Source terms preserved in per-target scope; canonical SPDX identity unresolved",
                    "next": "Compare exact source notice with SPDX matching templates; preserve attribution and restrictions",
                }
            )
    before = copy.deepcopy(python.get("licenses"))
    if len(before or []) != 1 or "expression" not in before[0]:
        raise ValueError("CPython parent license expression required")
    expression = before[0]["expression"]
    scoped = [
        scope_record(
            python,
            r["name"],
            "installed-source" if r["mode"] == "source-match" else "compiled-extension",
            r["expression"],
            "confirmed" if r["mode"] == "source-match" else "inferred",
            "confirmed" if r["mode"] == "source-match" else "inferred",
            {
                "source_path": r["source_path"],
                "notice_path": r["notice_path"],
                "source_sha256": r["source_sha256"],
                "notice_sha256": r["notice_sha256"],
                "installed_path": r["installed_path"],
                "installed_sha256": r["installed_sha256"],
                "assessment": r["assessment"],
            },
        )
        for r in additions
    ]
    scope_attach(
        python,
        scoped,
        "Project/distribution terms; extension and stdlib terms are separately scoped",
    )
    python["licenses"] = [{"expression": expression}]
    python.setdefault("properties", []).append(
        {
            "name": "hoplites:cpython:embedded-license-assessment",
            "value": "source-matched Python files plus build-associated C modules; see per-term evidence",
        }
    )
    report = {
        "rule_version": "cpython-embedded-v2",
        "license_scopes": scoped,
        "archive_sha256": archive_sha256,
        "image_source_sha256": image_env["PYTHON_SHA256"],
        "build_metadata_path": configs[0],
        "build_metadata_sha256": sha(installed[configs[0]]),
        "before": before,
        "after": python["licenses"],
        "terms": additions,
        "unresolved": pending,
        "limitations": [
            "Compiled module mapping is build association, not a reproduction of binary bytes",
            "LicenseRef notices preserve exact source terms pending canonical ID review",
            "Reviewed selectors do not prove exhaustive absence of other third-party terms",
            "Recipient notices and license fulfillment not verified",
        ],
    }
    return result, report, notices


def process(bom, rootfs, source_archive, rules, image_env):
    installed, source = {}, {}
    with tarfile.open(rootfs) as tar:
        for m in tar:
            path = m.name.lstrip("./")
            if m.isfile() and path.startswith("usr/local/lib/python"):
                if path in installed:
                    raise ValueError("Duplicate installed file")
                installed[path] = tar.extractfile(m).read()
    with tarfile.open(source_archive) as tar:
        for m in tar:
            if m.isfile():
                path = m.name.split("/", 1)[-1]
                if path in source:
                    raise ValueError("Duplicate source file")
                source[path] = tar.extractfile(m).read()
    archive_sha256 = sha(source_archive.read_bytes())
    return audit(bom, installed, source, rules, archive_sha256, image_env)
