#!/usr/bin/env python3
"""Component-scoped Debian VEX from a hash-pinned vendor snapshot and exact inventory."""

import argparse
import copy
import hashlib
import json
import re
import tarfile
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit
from debian_version import compare
from normalize_debian_bom import fields


def build(export, status, os_release, tracker, source_sha256, source_url, debian_version=None):
    release = {
        k: v.strip('"')
        for k, v in (line.split("=", 1) for line in os_release.decode().splitlines() if "=" in line)
    }
    inventory = {}
    for r in (fields(b) for b in status.decode().split("\n\n")):
        if r.get("Status") == "install ok installed":
            inventory.setdefault(r["Package"], []).append(r)
    if release.get("ID") != "debian" or release.get("VERSION_CODENAME") != "bookworm":
        raise ValueError("Unsupported Debian release; no cross-distro inference")
    result = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": copy.deepcopy(export.get("metadata", {})),
        "components": [],
        "vulnerabilities": [],
    }
    decisions, pending = [], []
    for v in export.get("vulnerabilities", []):
        for a in v.get("affects", []):
            candidates = [c for c in export.get("components", []) if c["bom-ref"] == a["ref"]]
            if len(candidates) != 1:
                raise ValueError("Missing/ambiguous affected component")
            c = candidates[0]
            base = {
                "component_ref": c["bom-ref"],
                "component": c["name"],
                "cve": v["id"],
                "version": c.get("version"),
            }
            try:
                parsed = urlsplit(c.get("purl", ""))
                q = parse_qs(parsed.query)
                items = inventory.get(c["name"], [])
                if "arch" in q:
                    items = [r for r in items if q["arch"] == [r["Architecture"]]]
                if len(items) != 1 or unquote(parsed.path).rsplit("@", 1) != [
                    "deb/debian/" + c["name"],
                    c.get("version"),
                ]:
                    raise ValueError("Debian PURL/inventory identity mismatch")
                inv = items[0]
                distros = {"debian-" + release["VERSION_ID"]}
                if debian_version and re.fullmatch(r"12(?:\.\d+)?", debian_version):
                    distros.add("debian-" + debian_version)
                if inv["Version"] != c["version"] or q.get("distro", []) not in [
                    [d] for d in distros
                ]:
                    raise ValueError("Debian version/distro mismatch")
                source = inv.get("Source", inv["Package"])
                match = re.fullmatch(r"([^ ]+)(?: \(([^)]+)\))?", source)
                if not match:
                    raise ValueError("Invalid source package identity")
                name, version = match.group(1), match.group(2) or inv["Version"]
                advisory = tracker.get(name, {}).get(v["id"])
                if not advisory:
                    raise ValueError("Missing source-package advisory; absence is not safety")
                record = advisory.get("releases", {}).get("bookworm")
                if not record:
                    raise ValueError("Missing bookworm advisory")
                fixed = record.get("fixed_version")
                if (
                    record.get("status") == "resolved"
                    and fixed
                    and fixed != "0"
                    and compare(version, fixed) >= 0
                ):
                    state, basis = (
                        "resolved",
                        "exact installed source version at or above vendor fixed endpoint",
                    )
                elif record.get("status") == "resolved" and fixed == "0":
                    # Zero carries different tracker semantics; require explicit reviewed rationale.
                    state, basis = (
                        "in_triage",
                        "vendor zero endpoint needs explicit not-affected rationale",
                    )
                else:
                    state, basis = (
                        "in_triage",
                        "vendor open/undetermined or installed version below fixed endpoint; finding retained",
                    )
                detail = f"Hoplites debian-project-vex-v1; bookworm; binary={c['name']}@{c['version']}; source={name}@{version}; vendor={record}; basis={basis}; snapshot={source_url}; SHA-256={source_sha256}. Vendor scope/version assessment; runtime exploitability not tested."
                finding = copy.deepcopy(v)
                finding["affects"] = [{"ref": c["bom-ref"]}]
                finding["analysis"] = {"state": state, "detail": detail}
                result["vulnerabilities"].append(finding)
                if c not in result["components"]:
                    result["components"].append(copy.deepcopy(c))
                decisions.append(
                    dict(
                        base,
                        state=state,
                        source_package=name,
                        source_version=version,
                        fixed_version=fixed,
                        vendor_status=record.get("status"),
                        source_sha256=source_sha256,
                        basis=basis,
                    )
                )
            except ValueError as error:
                pending.append(
                    dict(
                        base,
                        reason=str(error),
                        next="Inspect exact Debian source-package scope/version and vendor rationale",
                    )
                )
    return result, {
        "rule_version": "debian-project-vex-v1",
        "source_sha256": source_sha256,
        "decisions": decisions,
        "unresolved": pending,
        "applied": False,
        "limitations": [
            "Draft VEX only; applying requires matching actual DT findings and separate requery",
            "Open/zero-endpoint/unknown entries never become suppression",
            "Only Debian bookworm is supported; Ubuntu adapter not used",
        ],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ["export", "rootfs", "tracker", "tracker-sha256", "output", "evidence"]:
        p.add_argument("--" + name, type=str if name == "tracker-sha256" else Path, required=True)
    a = p.parse_args()
    if a.output.exists() or a.evidence.exists():
        p.error("Use new output paths")
    raw = a.tracker.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != a.tracker_sha256:
        p.error("Vendor snapshot hash mismatch")
    with tarfile.open(a.rootfs) as t:
        status = t.extractfile("var/lib/dpkg/status").read()
        release = t.extractfile("usr/lib/os-release").read()
        point = t.extractfile("etc/debian_version").read().decode().strip()
    result, evidence = build(
        json.loads(a.export.read_text()),
        status,
        release,
        json.loads(raw),
        actual,
        "https://security-tracker.debian.org/tracker/data/json",
        point,
    )
    output = (json.dumps(result, indent=2) + "\n").encode()
    evidence.update(
        vex_sha256=hashlib.sha256(output).hexdigest(),
        status_sha256=hashlib.sha256(status).hexdigest(),
        export_sha256=hashlib.sha256(a.export.read_bytes()).hexdigest(),
    )
    a.output.write_bytes(output)
    a.evidence.write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
