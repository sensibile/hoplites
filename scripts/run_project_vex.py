#!/usr/bin/env python3
"""Export DT findings, select distro-specific evidence, build VEX, optionally apply."""

import argparse
import json
import subprocess
import sys
import urllib.request
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in [
        "project",
        "sbom",
        "normalization-evidence",
        "rootfs",
        "reviewed-sources",
        "output-dir",
        "cache",
    ]:
        p.add_argument("--" + name, required=True)
    p.add_argument("--commit")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--debian-tracker")
    p.add_argument("--debian-tracker-sha256")
    a = p.parse_args()
    out = Path(a.output_dir)
    if out.exists():
        p.error("Use new output directory")
    key = (
        subprocess.run(
            [
                "security",
                "find-generic-password",
                "-a",
                "hoplites",
                "-s",
                "hoplites-dependency-track",
                "-w",
            ],
            capture_output=True,
            check=True,
        )
        .stdout.decode()
        .strip()
    )
    # Only local DT is supported; no credentials are forwarded to the public advisory source.
    import uuid

    project = str(uuid.UUID(a.project))
    req = urllib.request.Request(
        "http://localhost:18080/api/v1/vex/cyclonedx/project/" + project, headers={"X-Api-Key": key}
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        export = r.read()
    out.mkdir(parents=True)
    (out / "before-vex.json").write_bytes(export)
    scripts = Path(__file__).parent

    def run(name, args):
        subprocess.run([sys.executable, str(scripts / name), *map(str, args)], check=True)

    import tarfile

    with tarfile.open(a.rootfs) as t:
        release = t.extractfile("usr/lib/os-release").read().decode()
    distro = (
        dict(line.split("=", 1) for line in release.splitlines() if "=" in line)
        .get("ID", "")
        .strip('"')
    )
    if distro == "debian":
        if not a.debian_tracker or not a.debian_tracker_sha256:
            p.error(
                "Debian VEX requires a reviewed --debian-tracker and --debian-tracker-sha256; Ubuntu data is not used"
            )
        import hashlib

        raw = Path(a.debian_tracker).read_bytes()
        if hashlib.sha256(raw).hexdigest() != a.debian_tracker_sha256:
            p.error("Debian tracker snapshot hash mismatch")
        snapshot = out / "snapshot"
        snapshot.mkdir()
        (snapshot / "debian-security-tracker.json").write_bytes(raw)
        run(
            "build_debian_project_vex.py",
            [
                "--export",
                out / "before-vex.json",
                "--rootfs",
                a.rootfs,
                "--tracker",
                snapshot / "debian-security-tracker.json",
                "--tracker-sha256",
                a.debian_tracker_sha256,
                "--output",
                out / "project.vex.json",
                "--evidence",
                out / "decisions.json",
            ],
        )
    elif distro == "ubuntu":
        collect = [
            "--export",
            out / "before-vex.json",
            "--output-dir",
            out / "snapshot",
            "--cache",
            a.cache,
        ]
        if a.commit:
            collect += ["--commit", a.commit]
        run("collect_project_advisories.py", collect)
        run(
            "build_project_vex.py",
            [
                "--export",
                out / "before-vex.json",
                "--sbom",
                a.sbom,
                "--normalization-evidence",
                a.normalization_evidence,
                "--rootfs",
                a.rootfs,
                "--index",
                out / "snapshot/advisory-index.json",
                "--sources",
                out / "snapshot/advisories",
                "--reviewed-sources",
                a.reviewed_sources,
                "--output",
                out / "project.vex.json",
                "--evidence",
                out / "decisions.json",
            ],
        )
    else:
        p.error("Unsupported VEX distro")
    if a.apply and json.loads((out / "project.vex.json").read_bytes()).get("vulnerabilities"):
        run(
            "apply_dtrack_vex.py",
            [
                "--vex",
                out / "project.vex.json",
                "--project",
                project,
                "--output-dir",
                out / "dt-apply",
                "--refresh-metrics",
            ],
        )
    print(
        json.dumps(
            {
                "project": project,
                "vex": str(out / "project.vex.json"),
                "applied": a.apply and (out / "dt-apply/after.json").exists(),
            }
        )
    )


if __name__ == "__main__":
    main()
