#!/usr/bin/env python3
"""Replay Debian/JRE normalization and package its original records and sources."""

import argparse
import csv
import json
import shutil
import sqlite3
from pathlib import Path
from build_evidence_bundle import safe_csv
from normalize_debian_bom import process, sha


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--experiment", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    a = p.parse_args()
    base = a.experiment
    if a.output_dir.exists() or a.output_dir.resolve().is_relative_to(
        base.resolve() / "normalization-v2-sources"
    ):
        p.error("Use a new output outside the sources directory")
    evidence = json.loads((base / "normalization-v2-evidence.json").read_bytes())
    original = (base / "syft.cdx.json").read_bytes()
    normalized = (base / "normalized-v2.cdx.json").read_bytes()
    if (
        sha(original) != evidence["input_sha256"]
        or sha(normalized) != evidence["output_sha256"]
        or sha((base / "rootfs.tar").read_bytes()) != evidence["rootfs_sha256"]
    ):
        raise ValueError("Input/output/rootfs hash mismatch")
    db = sqlite3.connect(":memory:")
    migrations = Path(__file__).parents[1] / "migrations"
    for f in sorted(migrations.glob("*.sql")):
        db.executescript(f.read_text())
    output, report, sources = process(
        json.loads(original),
        base / "rootfs.tar",
        dict(db.execute("SELECT label,spdx_expression FROM debian_license_alias")),
    )
    if output != json.loads(normalized) or any(evidence.get(k) != v for k, v in report.items()):
        raise ValueError("Replay mismatch")
    for path, raw in sources.items():
        if (base / "normalization-v2-sources" / path).read_bytes() != raw:
            raise ValueError("Source mismatch")
    a.output_dir.mkdir(parents=True)
    for name in [
        "syft.cdx.json",
        "trivy.cdx.json",
        "normalized-v2.cdx.json",
        "normalization-v2-evidence.json",
        "image-ref.txt",
        "image-inspect.json",
        "Dockerfile.upstream",
        "dt-upload.json",
        "dt-verification.json",
        "syft-run.json",
        "trivy-run.json",
    ]:
        shutil.copyfile(base / name, a.output_dir / name)
    shutil.copytree(base / "normalization-v2-sources", a.output_dir / "sources")
    shutil.copytree(migrations, a.output_dir / "migrations")
    (a.output_dir / "scripts").mkdir()
    for name in [
        "normalize_debian_bom.py",
        "normalize_syft_bom.py",
        "build_debian_evidence_bundle.py",
        "build_evidence_bundle.py",
    ]:
        shutil.copyfile(Path(__file__).with_name(name), a.output_dir / "scripts" / name)
    with (a.output_dir / "excluded-files.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["file", "original_bom_ref", "sha256", "owner", "version", "evidence"])
        for item in report["file_normalization"]["removed_files"]:
            r = item["ownership"]
            w.writerow(
                [
                    safe_csv(value)
                    for value in [
                        r["path"],
                        r["bom_ref"],
                        r["file_sha256"],
                        r["owner"]["name"],
                        r["owner"]["version"],
                        r["source_kind"],
                    ]
                ]
            )
    (a.output_dir / "README.txt").write_text(
        "Original and normalized BOMs, 3934 exclusion records, source copyright/JRE legal documents and replay scripts.\nLicenseRef expressions retain terms whose canonical SPDX mapping is unresolved. Debian source-file applicability is inferred.\nNo image contents were removed. Rootfs is retained separately. Hashes prove consistency, not authenticity or fulfillment.\n"
    )
    files = [
        {"path": str(f.relative_to(a.output_dir)), "sha256": sha(f.read_bytes())}
        for f in sorted(a.output_dir.rglob("*"))
        if f.is_file()
    ]
    (a.output_dir / "manifest.json").write_text(
        json.dumps(
            {
                "verification": "Full normalization replay and source comparison passed",
                "rootfs_sha256": evidence["rootfs_sha256"],
                "files": files,
            },
            indent=2,
        )
        + "\n"
    )
    print(
        json.dumps(
            {
                "verified_files": len(files),
                "excluded_records": report["file_normalization"]["removed_count"],
            }
        )
    )


if __name__ == "__main__":
    main()
