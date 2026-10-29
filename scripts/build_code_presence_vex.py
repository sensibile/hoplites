#!/usr/bin/env python3
"""Build a code-presence VEX for non-distro DT findings from the shipped rootfs."""

import argparse
import hashlib
import json
import posixpath
import sqlite3
import tarfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from code_presence import build, package_roots, sha, verify_sources

SOURCE_KEYS = ("advisory_file", "fix_file", "release_file", "ordering_file", "listing_file")


def load_rules():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    for f in sorted((Path(__file__).parents[1] / "migrations").glob("*.sql")):
        db.executescript(f.read_text())
    return [dict(r) for r in db.execute("SELECT * FROM code_presence_rule ORDER BY cve, target")]


def member_name(member):
    return member.name.removeprefix("./").lstrip("/")


def read_roots(rootfs, wanted):
    """Files under each wanted root. Hard links resolve to their archived data;
    symbolic links are reported and never followed, so the core treats them as unknown."""
    files, links = {}, []
    with tarfile.open(rootfs) as tar:
        for member in tar:
            name = member_name(member)
            if not any(name == r or name.startswith(r + "/") for r in wanted):
                continue
            if member.isfile() or member.islnk():
                files[name] = tar.extractfile(member).read()
            elif member.issym():
                links.append(name)
    return files, links


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def prepare(roots, files, links):
    """Per component: its roots, the files and links under them, and parsed package.json."""
    manifests = {}
    for root in sorted({r for rs in roots.values() for r in rs}):
        raw = files.get(posixpath.join(root, "package.json"))
        if raw is not None:
            try:
                manifests[root] = json.loads(raw)
            except ValueError:
                manifests[root] = None

    def under(path, rs):
        return any(path.startswith(r + "/") for r in rs)

    return {
        ref: (
            rs,
            {k: v for k, v in files.items() if under(k, rs)},
            manifests,
            {p for p in links if under(p, rs)},
        )
        for ref, rs in roots.items()
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ["export", "sbom", "rootfs", "sources", "output", "evidence"]:
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument(
        "--rootfs-sha256", required=True, help="Pinned rootfs hash from the run provenance"
    )
    a = p.parse_args()
    if a.output.exists() or a.evidence.exists():
        p.error("Use new output paths")
    export_raw, sbom_raw = a.export.read_bytes(), a.sbom.read_bytes()
    if file_sha256(a.rootfs) != a.rootfs_sha256:
        p.error("Rootfs hash differs from pinned provenance")
    export, sbom = json.loads(export_raw), json.loads(sbom_raw)
    if export["metadata"]["component"]["version"] != sbom["metadata"]["component"]["version"]:
        p.error("DT project and SBOM describe different image digests")
    rules = load_rules()
    sources = {}
    for rule in rules:
        for key in SOURCE_KEYS:
            path = a.sources / rule[key] if rule.get(key) else None
            if path is not None and path.is_file():
                sources[rule[key]] = path.read_bytes()
    usable, rejected = verify_sources(rules, sources)
    roots = {c["bom-ref"]: package_roots(sbom, c) for c in export.get("components", [])}
    files, links = read_roots(a.rootfs, sorted({r for rs in roots.values() for r in rs}))
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    output, report = build(
        export,
        sbom,
        usable,
        prepare(roots, files, links),
        timestamp,
        "urn:uuid:" + str(uuid.uuid4()),
        rejected,
    )
    raw = (json.dumps(output, indent=2) + "\n").encode()
    report.update(
        rejected_rules=rejected,
        links_under_roots=sorted(links),
        export_sha256=sha(export_raw),
        sbom_sha256=sha(sbom_raw),
        rootfs_sha256=a.rootfs_sha256,
        vex_sha256=sha(raw),
        limitations=[
            "Presence of shipped code only; reachability and exploitability not assessed",
            "Findings absent from DT are not evaluated here; DT 0 findings is not a safety decision",
            "Symbol absence and build-configuration evidence never produce code_not_present",
            "code_not_present needs the shipped file set to equal a reviewed release listing",
        ],
    )
    a.output.write_bytes(raw)
    a.evidence.write_text(json.dumps(report, indent=2) + "\n")
    from collections import Counter

    print(
        json.dumps(
            {
                "grades": dict(Counter(d["grade"] for d in report["decisions"])),
                "states": dict(Counter(d["state"] for d in report["decisions"])),
                "rejected_rules": len(rejected),
            }
        )
    )


if __name__ == "__main__":
    main()
