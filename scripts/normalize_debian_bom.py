#!/usr/bin/env python3
"""Package view using dpkg file lists and shipped copyright/JRE legal evidence."""

import argparse
import copy
import hashlib
import json
import posixpath
import re
import sqlite3
import tarfile
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from normalize_syft_bom import normalize

RULE_VERSION = "debian-temurin-view-v1"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fields(text):
    result = {}
    current = None
    for line in text.splitlines():
        if line.startswith((" ", "\t")) and current:
            result[current] += "\n" + line[1:]
        elif ":" in line:
            current, value = line.split(":", 1)
            result[current] = value.strip()
    return result


def license_expression(label, aliases, package, doc_hash, refs, reviewed=None):
    # Explicit relationships only; retain ambiguous complete labels as LicenseRef terms.
    label = label.strip()
    if reviewed and (doc_hash, label) in reviewed:
        return reviewed[(doc_hash, label)]
    if re.search(r"\band/or\b|[(),~]", label, re.I):
        parts = None
    else:
        parts = re.split(r"\s+(and|or)\s+", label, flags=re.I)
    if parts and len(parts) > 1:
        return " ".join(
            part.upper()
            if i % 2
            else "(" + license_expression(part, aliases, package, doc_hash, refs, reviewed) + ")"
            for i, part in enumerate(parts)
        )
    if label.lower() in aliases:
        return aliases[label.lower()]
    m = re.fullmatch(r"(L?GPL)(?:v|-)([123](?:\.[01])?)(\+)?", label, re.I)
    if m:
        family, version, later = m.groups()
        version = version if "." in version else version + ".0"
        if (family.upper(), version) in {
            ("GPL", "1.0"),
            ("GPL", "2.0"),
            ("GPL", "3.0"),
            ("LGPL", "2.0"),
            ("LGPL", "2.1"),
            ("LGPL", "3.0"),
        }:
            return family.upper() + "-" + version + ("-or-later" if later else "-only")
    identifier = (
        "LicenseRef-Debian-"
        + re.sub(r"[^A-Za-z0-9.-]", "-", package)
        + "-"
        + sha((doc_hash + label).encode())[:16]
    )
    refs[identifier] = {
        "source_label": label,
        "copyright_sha256": doc_hash,
        "assessment": "verbatim-source-terms; canonical-SPDX-identity-not-resolved",
    }
    return identifier


def process(bom, rootfs, aliases, reviewed=None):
    result = copy.deepcopy(bom)
    for component in result["components"]:
        component["properties"] = [
            p
            for p in component.get("properties", [])
            if not p["name"].startswith(("hoplites:debian:", "hoplites:temurin:", "hoplites:os:"))
        ]
    changes = []
    source_docs = {}
    license_refs = {}
    entries = []
    unresolved = []
    with tarfile.open(rootfs) as tar:
        members = {m.name.lstrip("./"): m for m in tar.getmembers()}

        def read(path, follow_leaf=True):
            path = path.lstrip("/")
            for _ in range(40):
                m = members.get(path)
                if not m:
                    parts = path.split("/")
                    for i in range(1, len(parts)):
                        prefix = "/".join(parts[:i])
                        parent = members.get(prefix)
                        if parent and parent.issym():
                            path = posixpath.normpath(
                                posixpath.join(
                                    posixpath.dirname(prefix), parent.linkname, *parts[i:]
                                )
                            ).lstrip("/")
                            break
                    else:
                        raise ValueError("Missing image file: " + path)
                    continue
                if m.isfile():
                    return tar.extractfile(m).read(), path
                if m.issym():
                    if not follow_leaf:
                        raise ValueError("Leaf symlink does not establish target ownership")
                    path = posixpath.normpath(
                        posixpath.join(posixpath.dirname(path), m.linkname)
                    ).lstrip("/")
                elif m.islnk():
                    path = m.linkname.lstrip("/")
                else:
                    raise ValueError("Not a file: " + path)
            raise ValueError("Symlink loop")

        status_raw, _ = read("var/lib/dpkg/status")
        installed = {}
        for record in (fields(b) for b in status_raw.decode().split("\n\n")):
            if record.get("Status") != "install ok installed":
                continue
            key = (record["Package"], record["Architecture"])
            if key in installed:
                raise ValueError("Duplicate installed dpkg package/architecture")
            installed[key] = record
        packages = {}
        for component in result["components"]:
            if not component.get("purl", "").startswith("pkg:deb/"):
                continue
            qualifier = parse_qs(urlsplit(component["purl"]).query).get("arch")
            candidates = [
                key
                for key in installed
                if key[0] == component["name"] and (qualifier is None or qualifier == [key[1]])
            ]
            if len(candidates) != 1:
                raise ValueError(
                    "Missing/ambiguous dpkg package architecture: " + component["name"]
                )
            key = candidates[0]
            if key in packages:
                raise ValueError("Duplicate SBOM package/architecture")
            packages[key] = component
        if set(packages) != set(installed):
            raise ValueError("SBOM and installed dpkg package set mismatch")
        owners = {}
        resolved_owners = {}
        for key, package in packages.items():
            name, arch = key
            if package["version"] != installed[key]["Version"]:
                raise ValueError("dpkg version mismatch")
            paths = [f"var/lib/dpkg/info/{name}.list", f"var/lib/dpkg/info/{name}:{arch}.list"]
            existing = [p for p in paths if p in members]
            if len(existing) != 1:
                raise ValueError("Missing/ambiguous dpkg file list: " + name)
            raw, resolved = read(existing[0])
            source_docs[resolved] = raw
            for path in raw.decode().splitlines():
                owners.setdefault(path, []).append(key)
                try:
                    _, canonical = read(path, follow_leaf=False)
                except ValueError:
                    continue
                resolved_owners.setdefault("/" + canonical, set()).add(key)
            copyright_path = f"usr/share/doc/{name}/copyright"
            try:
                copyright_raw, resolved = read(copyright_path)
            except ValueError:
                try:
                    copyright_raw, resolved = read(f"usr/share/doc/{name}:{arch}/copyright")
                except ValueError:
                    unresolved.append(
                        {
                            "component": name,
                            "reason": "Shipped copyright document missing; scanner licenses retained",
                            "next": "Find source/packaging terms for exact package version",
                        }
                    )
                    continue
            source_docs[resolved] = copyright_raw
            text = copyright_raw.decode(errors="replace")
            doc_hash = sha(copyright_raw)
            paragraphs = [fields(b) for b in text.split("\n\n")]
            labels = sorted(
                {
                    p["License"].splitlines()[0]
                    for p in paragraphs
                    if "Files" in p and "License" in p
                }
            )
            # Legacy prose remains an exact document reference, not a fabricated SPDX ID.
            if not labels:
                labels = ["Full-copyright-document"]
            expressions = sorted(
                {
                    license_expression(l, aliases, name, doc_hash, license_refs, reviewed)
                    for l in labels
                }
            )
            expression = " AND ".join("(" + e + ")" if " " in e else e for e in expressions)
            before = copy.deepcopy(package.get("licenses"))
            package["licenses"] = [{"expression": expression}]
            package.setdefault("properties", []).extend(
                [
                    {
                        "name": "hoplites:debian:license-assessment",
                        "value": "inferred-source-copyright-aggregate; source-file-applicability-not-confirmed",
                    },
                    {"name": "hoplites:debian:copyright-sha256", "value": doc_hash},
                    {"name": "hoplites:debian:copyright-path", "value": "/" + resolved},
                ]
            )
            changes.append(
                {
                    "bom_ref": package["bom-ref"],
                    "name": name,
                    "before": before,
                    "after": package["licenses"],
                    "copyright_path": "/" + resolved,
                    "copyright_sha256": doc_hash,
                    "source_labels": labels,
                    "scope": "Source copyright paragraph license sets; may overinclude source/build/documentation terms",
                }
            )
        runtime = None
        legal = []
        runtimes = [
            c
            for c in result["components"]
            if c.get("name") == "openjdk" and c.get("type") == "application"
        ]
        temurin = False
        if len(runtimes) == 1 and "opt/java/openjdk/release" in members:
            probe, _ = read("opt/java/openjdk/release")
            temurin = b'IMPLEMENTOR="Eclipse Adoptium"' in probe
        if temurin:
            runtime = runtimes[0]
            release_raw, _ = read("opt/java/openjdk/release")
            release = dict(l.split("=", 1) for l in release_raw.decode().splitlines() if "=" in l)
            if (
                release.get("JAVA_RUNTIME_VERSION", "").strip('"') != runtime["version"]
                or release.get("IMPLEMENTOR", "").strip('"') != "Eclipse Adoptium"
            ):
                raise ValueError("JRE identity/version mismatch")
            source_docs["opt/java/openjdk/release"] = release_raw
            base_license, _ = read("opt/java/openjdk/legal/java.base/LICENSE")
            info, _ = read("opt/java/openjdk/legal/java.base/ADDITIONAL_LICENSE_INFO")
            if b"Version 2, June 1991" not in base_license or b"Classpath" not in info:
                raise ValueError("Unexpected JRE legal terms")
            expressions = {"GPL-2.0-only WITH Classpath-exception-2.0"}
            legal = []
            for path in members:
                if path.startswith("opt/java/openjdk/legal/") and (
                    path.endswith(".md")
                    or Path(path).name
                    in ["LICENSE", "ADDITIONAL_LICENSE_INFO", "ASSEMBLY_EXCEPTION"]
                ):
                    raw, resolved = read(path)
                    source_docs[resolved] = raw
                    if not path.endswith(".md") and Path(path).name != "ASSEMBLY_EXCEPTION":
                        continue
                    identifier = (
                        "LicenseRef-Temurin-"
                        + re.sub(r"[^A-Za-z0-9.-]", "-", Path(path).stem)
                        + "-"
                        + sha(raw)[:16]
                    )
                    expressions.add(identifier)
                    license_refs[identifier] = {
                        "source_path": "/" + resolved,
                        "source_sha256": sha(raw),
                        "assessment": "shipped-legal-document; internal-options-and-notices-retained-verbatim",
                    }
                    legal.append(
                        {
                            "path": "/" + path,
                            "resolved_path": "/" + resolved,
                            "sha256": sha(raw),
                            "identifier": identifier,
                        }
                    )
            expression = " AND ".join(sorted(expressions))
            changes.append(
                {
                    "bom_ref": runtime["bom-ref"],
                    "name": "openjdk",
                    "before": runtime.get("licenses"),
                    "after": [{"expression": expression}],
                }
            )
            runtime["licenses"] = [{"expression": expression}]
            runtime["supplier"] = {"name": "Eclipse Adoptium"}
            runtime.setdefault("properties", []).extend(
                [
                    {
                        "name": "hoplites:temurin:license-scope",
                        "value": "GPLv2 Classpath main terms plus complete shipped legal documents; LicenseRef identities need further canonical mapping",
                    },
                    {"name": "hoplites:temurin:release-sha256", "value": sha(release_raw)},
                ]
            )
            jars = [c for c in result["components"] if c["name"] == "jrt-fs"]
            if len(jars) > 1:
                raise ValueError("Ambiguous jrt-fs artifact")
            if jars:
                changes.append(
                    {
                        "bom_ref": jars[0]["bom-ref"],
                        "name": "jrt-fs",
                        "before": jars[0].get("licenses"),
                        "after": [{"expression": "GPL-2.0-only WITH Classpath-exception-2.0"}],
                        "assessment": "inferred-from-JRE-distribution",
                    }
                )
                jars[0]["licenses"] = [{"expression": "GPL-2.0-only WITH Classpath-exception-2.0"}]
                jars[0].setdefault("properties", []).append(
                    {
                        "name": "hoplites:temurin:license-assessment",
                        "value": "inferred-from-JRE-distribution; module-source-header-verification-pending",
                    }
                )

        # dpkg may list /bin while Syft reports /usr/bin on usrmerged images.
        # Resolve through the actual rootfs links; never assume a prefix alias.
        os = next(c for c in result["components"] if c["type"] == "operating-system")
        os.setdefault("properties", []).append(
            {
                "name": "hoplites:os:license-assessment",
                "value": "distribution-aggregate; licenses-managed-per-component",
            }
        )
        for c in result["components"]:
            if c["type"] != "file":
                continue
            path = c["name"]
            try:
                raw, resolved = read(path)
            except ValueError:
                continue
            hashes = [h["content"] for h in c.get("hashes", []) if h["alg"] == "SHA-256"]
            if hashes != [sha(raw)]:
                continue
            candidate = sorted(
                set(owners.get(path, [])) | resolved_owners.get("/" + resolved, set())
            )
            owner = None
            kind = None
            if len(candidate) == 1:
                owner = packages[candidate[0]]
                kind = "dpkg-file-list-rootfs-resolved"
            elif path.startswith("/var/lib/dpkg/info/"):
                control = Path(path).name.rsplit(".", 1)
                identity = control[0].split(":", 1)
                candidates = [
                    key
                    for key in packages
                    if key[0] == identity[0] and (len(identity) == 1 or key[1] == identity[1])
                ]
                if (
                    len(control) == 2
                    and len(candidates) == 1
                    and control[1]
                    in {
                        "list",
                        "md5sums",
                        "conffiles",
                        "postinst",
                        "postrm",
                        "preinst",
                        "prerm",
                        "config",
                        "templates",
                        "triggers",
                        "shlibs",
                        "symbols",
                    }
                ):
                    owner = packages[candidates[0]]
                    kind = "dpkg-control-file; scripts-remain-part-of-package"
            elif runtime is not None and path.startswith("/opt/java/openjdk/"):
                owner = runtime
                kind = "JRE-release-directory; identity-verified-not-per-file-source-equivalence"
            elif path == "/var/lib/dpkg/status":
                owner = os
                kind = "package-inventory-evidence"
            if owner:
                entries.append(
                    {
                        "bom_ref": c["bom-ref"],
                        "path": path,
                        "status": "linked",
                        "owner_bom_ref": owner["bom-ref"],
                        "owner": {"name": owner["name"], "version": owner["version"]},
                        "source_kind": kind,
                        "file_sha256": sha(raw),
                        "resolved_path": "/" + resolved,
                    }
                )
        normalized, file_report = normalize(result, {"files": entries})
    return (
        normalized,
        {
            "rule_version": RULE_VERSION,
            "changes": changes,
            "license_refs": license_refs,
            **({"unresolved": unresolved} if unresolved else {}),
            "jre_legal_documents": legal,
            "file_normalization": file_report,
            "remaining_count": len(normalized["components"]),
            "limitations": [
                "Debian copyright expressions describe source-file license sets; binary applicability remains inferred.",
                "LicenseRef terms retain complete source text; canonical SPDX mapping is incomplete.",
                "JRE directory ownership is distribution attribution, not a rebuilt-byte equivalence proof.",
                "Recipient notices and license fulfillment are not verified.",
            ],
        },
        source_docs,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("sbom", "rootfs", "output", "evidence", "sources-dir"):
        p.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args()
    if args.output.exists() or args.evidence.exists() or args.sources_dir.exists():
        p.error("Use new output paths")
    db = sqlite3.connect(":memory:")
    for f in sorted((Path(__file__).parents[1] / "migrations").glob("*.sql")):
        db.executescript(f.read_text())
    aliases = dict(db.execute("SELECT label,spdx_expression FROM debian_license_alias"))
    raw = args.sbom.read_bytes()
    reviewed = {
        (r[0], r[1]): r[2]
        for r in db.execute("SELECT copyright_sha256,label,expression FROM debian_reviewed_license")
    }
    result, report, sources = process(json.loads(raw), args.rootfs, aliases, reviewed)
    output = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode()
    report.update(
        input_sha256=sha(raw),
        output_sha256=sha(output),
        rootfs_sha256=sha(args.rootfs.read_bytes()),
    )
    for path, contents in sources.items():
        dest = args.sources_dir / path
        if not dest.resolve().is_relative_to(args.sources_dir.resolve()):
            raise ValueError("Unsafe source path")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(contents)
    args.output.write_bytes(output)
    args.evidence.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(
        json.dumps(
            {
                "remaining": report["remaining_count"],
                "files_collapsed": report["file_normalization"]["removed_count"],
                "retained_files": len(report["file_normalization"]["retained_files"]),
                "license_refs": len(report["license_refs"]),
            }
        )
    )


if __name__ == "__main__":
    main()
