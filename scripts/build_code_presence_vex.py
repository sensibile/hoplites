#!/usr/bin/env python3
"""Build a code-presence VEX for non-distro DT findings from the shipped rootfs."""

import argparse
import json
import posixpath
import sqlite3
import tarfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from code_presence import build, package_roots, sha, verify_sources


def load_rules():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    for f in sorted((Path(__file__).parents[1] / "migrations").glob("*.sql")):
        db.executescript(f.read_text())
    return [dict(r) for r in db.execute("SELECT * FROM code_presence_rule ORDER BY cve, target")]


def read_roots(rootfs, wanted):
    """Regular files under each wanted root; links are reported, never followed."""
    files, links = {}, []
    with tarfile.open(rootfs) as tar:
        for member in tar:
            name = member.name.lstrip("./")
            if not any(name == r or name.startswith(r + "/") for r in wanted):
                continue
            if member.isfile():
                files[name] = tar.extractfile(member).read()
            elif member.issym() or member.islnk():
                links.append(name)
    return files, links


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
    export_raw, sbom_raw, rootfs_raw = (
        a.export.read_bytes(),
        a.sbom.read_bytes(),
        a.rootfs.read_bytes(),
    )
    if sha(rootfs_raw) != a.rootfs_sha256:
        p.error("Rootfs hash differs from pinned provenance")
    export, sbom = json.loads(export_raw), json.loads(sbom_raw)
    if export["metadata"]["component"]["version"] != sbom["metadata"]["component"]["version"]:
        p.error("DT project and SBOM describe different image digests")
    rules = load_rules()
    sources = {}
    for rule in rules:
        for key in ("advisory_file", "fix_file", "release_file", "ordering_file"):
            path = a.sources / rule[key] if rule.get(key) else None
            if path is not None and path.is_file():
                sources[rule[key]] = path.read_bytes()
    usable, rejected = verify_sources(rules, sources)
    roots = {c["bom-ref"]: package_roots(sbom, c) for c in export.get("components", [])}
    wanted = sorted({r for rs in roots.values() for r in rs})
    files, links = read_roots(a.rootfs, wanted)
    manifests = {}
    for root in wanted:
        raw = files.get(posixpath.join(root, "package.json"))
        if raw is not None:
            try:
                manifests[root] = json.loads(raw)
            except ValueError:
                manifests[root] = None
    prepared = {
        ref: (
            rs,
            {k: v for k, v in files.items() if any(k.startswith(r + "/") for r in rs)},
            manifests,
        )
        for ref, rs in roots.items()
    }
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    output, report = build(
        export, sbom, usable, prepared, timestamp, "urn:uuid:" + str(uuid.uuid4())
    )
    raw = (json.dumps(output, indent=2) + "\n").encode()
    report.update(
        rejected_rules=rejected,
        links_under_roots=links,
        export_sha256=sha(export_raw),
        sbom_sha256=sha(sbom_raw),
        rootfs_sha256=a.rootfs_sha256,
        vex_sha256=sha(raw),
        limitations=[
            "Presence of shipped code only; reachability and exploitability not assessed",
            "Findings absent from DT are not evaluated here; DT 0 findings is not a safety decision",
            "Symbol absence and build-configuration evidence never produce code_not_present",
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
