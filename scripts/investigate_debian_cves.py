#!/usr/bin/env python3
"""Read-only advisory comparison; produces evidence, never applies VEX."""

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path
from normalize_debian_bom import fields
from debian_version import compare


def investigate(bom, tracker, installed):
    components = {c["bom-ref"]: c for c in bom["components"]}
    records = []
    for v in bom.get("vulnerabilities", []):
        for affected in v.get("affects", []):
            c = components.get(affected["ref"], {})
            package = installed.get(c.get("name"))
            row = {
                "cve": v["id"],
                "component": c.get("name"),
                "version": c.get("version"),
                "purl": c.get("purl"),
                "scanner_affects": affected,
                "scanner_source": v.get("source"),
                "scanner_ratings": v.get("ratings"),
                "vex_applied": False,
            }
            if not package or not c.get("purl", "").startswith("pkg:deb/"):
                row.update(
                    assessment="unresolved-non-Debian-or-inventory-missing",
                    next="Use ecosystem advisory and verify exact installed/vendored version",
                )
            else:
                source = package.get("Source", package["Package"])
                match = re.fullmatch(r"([^ ]+)(?: \(([^)]+)\))?", source)
                source_name, source_version = match.group(1), match.group(2) or package["Version"]
                advisory = tracker.get(source_name, {}).get(v["id"], {})
                release = advisory.get("releases", {}).get("bookworm")
                row.update(
                    source_package=source_name,
                    source_version=source_version,
                    vendor_advisory=advisory,
                    vendor_url="https://security-tracker.debian.org/tracker/" + v["id"],
                )
                if not release:
                    row.update(
                        assessment="unresolved-release-advisory-missing",
                        next="Inspect Debian tracker source-package entry and applicability",
                    )
                else:
                    fixed = release.get("fixed_version")
                    if release["status"] == "resolved" and fixed == "0":
                        assessment = (
                            "vendor-resolved-with-zero-fixed-version; review-not-affected-rationale"
                        )
                    elif fixed and fixed != "0" and compare(source_version, fixed) >= 0:
                        assessment = "installed-source-version-at-or-above-vendor-fixed-version"
                    elif release["status"] == "open":
                        assessment = "vendor-open; finding-retained"
                    else:
                        assessment = "unresolved-vendor-status-or-version"
                    row.update(
                        assessment=assessment,
                        next="Review source-package scope and advisory rationale with the hash-pinned Debian VEX adapter",
                    )
            records.append(row)
    return records


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ["bom", "tracker", "rootfs", "output"]:
        p.add_argument("--" + arg, type=Path, required=True)
    a = p.parse_args()
    if a.output.exists():
        p.error("Use new output")
    with tarfile.open(a.rootfs) as t:
        raw = t.extractfile("var/lib/dpkg/status").read()
    packages = {
        r["Package"]: r
        for r in [fields(b) for b in raw.decode().split("\n\n")]
        if r.get("Status") == "install ok installed"
    }
    data = a.tracker.read_bytes()
    report = {
        "source_url": "https://security-tracker.debian.org/tracker/data/json",
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "inventory_sha256": hashlib.sha256(raw).hexdigest(),
        "records": investigate(json.loads(a.bom.read_text()), json.loads(data), packages),
        "limitations": [
            "Read-only current vendor comparison; no VEX or suppression applied",
            "Debian advisory source package scope requires review; Ubuntu adapter must not be used",
            "A scanner omission is not evidence of non-vulnerability",
        ],
    }
    a.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
